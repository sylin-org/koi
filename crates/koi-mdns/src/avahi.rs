//! Linux mDNS provider backed by Avahi's system D-Bus API.
//!
//! The adapter owns Avahi entry groups and browse objects, translates their
//! signals into provider-neutral observations, and performs short, local D-Bus
//! recovery while the runtime supervisor decides whether to change providers.

#![allow(clippy::too_many_arguments)] // Avahi's fixed D-Bus method signatures.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::{mpsc, oneshot};
use zbus::names::BusName;
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

use crate::adapter::{
    AdapterApi, AdapterReadiness, AdapterReport, MdnsAdapter, MdnsCapabilities, ProbeFact,
};
use crate::error::{MdnsError, Result};
use crate::provider::{
    MdnsProvider, ProviderAddress, ProviderBrowse, ProviderEvent, ProviderService, ProviderStatus,
};

const AVAHI_DESTINATION: &str = "org.freedesktop.Avahi";
const AVAHI_IF_UNSPEC: i32 = -1;
const AVAHI_PROTO_UNSPEC: i32 = -1;
const AVAHI_PROTO_INET: i32 = 0;
const AVAHI_PROTO_INET6: i32 = 1;
const AVAHI_SERVER_RUNNING: i32 = 2;
const AVAHI_SERVER_FAILURE: i32 = 4;
const AVAHI_ENTRY_GROUP_ESTABLISHED: i32 = 2;
const AVAHI_ENTRY_GROUP_COLLISION: i32 = 3;
const AVAHI_ENTRY_GROUP_FAILURE: i32 = 4;
const AVAHI_FLAGS_NONE: u32 = 0;
const AVAHI_PUBLISH_NO_REVERSE: u32 = 16;
const COMMAND_CAPACITY: usize = 256;
const BROWSE_CAPACITY: usize = 512;
const AVAHI_PRIORITY: u16 = 300;
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const ENTRY_GROUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COLLISION_ATTEMPTS: usize = 10;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);

type ResolveReply = (
    i32,
    i32,
    String,
    String,
    String,
    String,
    i32,
    String,
    u16,
    Vec<Vec<u8>>,
    u32,
);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ServiceObservationKey {
    interface: i32,
    protocol: i32,
    name: String,
    service_type: String,
    domain: String,
}

#[zbus::proxy(
    default_service = "org.freedesktop.Avahi",
    default_path = "/",
    interface = "org.freedesktop.Avahi.Server"
)]
trait AvahiServer {
    #[zbus(name = "GetVersionString")]
    fn get_version_string(&self) -> zbus::Result<String>;

    #[zbus(name = "GetState")]
    fn get_state(&self) -> zbus::Result<i32>;

    #[zbus(name = "GetAlternativeServiceName")]
    fn get_alternative_service_name(&self, name: &str) -> zbus::Result<String>;

    #[zbus(name = "GetNetworkInterfaceNameByIndex")]
    fn get_network_interface_name_by_index(&self, index: i32) -> zbus::Result<String>;

    #[zbus(name = "ResolveService")]
    fn resolve_service(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        address_protocol: i32,
        flags: u32,
    ) -> zbus::Result<ResolveReply>;

    #[zbus(name = "EntryGroupNew")]
    fn entry_group_new(&self) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "ServiceTypeBrowserNew")]
    fn service_type_browser_new(
        &self,
        interface: i32,
        protocol: i32,
        domain: &str,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "ServiceBrowserNew")]
    fn service_browser_new(
        &self,
        interface: i32,
        protocol: i32,
        service_type: &str,
        domain: &str,
        flags: u32,
    ) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    default_service = "org.freedesktop.Avahi",
    interface = "org.freedesktop.Avahi.EntryGroup"
)]
trait AvahiEntryGroup {
    #[zbus(name = "GetState")]
    fn get_state(&self) -> zbus::Result<i32>;

    #[zbus(name = "AddService")]
    fn add_service(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        service_type: &str,
        domain: &str,
        host: &str,
        port: u16,
        txt: &[Vec<u8>],
    ) -> zbus::Result<()>;

    #[zbus(name = "AddAddress")]
    fn add_address(
        &self,
        interface: i32,
        protocol: i32,
        flags: u32,
        name: &str,
        address: &str,
    ) -> zbus::Result<()>;

    #[zbus(name = "Commit")]
    fn commit(&self) -> zbus::Result<()>;

    #[zbus(name = "Free")]
    fn free(&self) -> zbus::Result<()>;
}

#[zbus::proxy(
    default_service = "org.freedesktop.Avahi",
    interface = "org.freedesktop.Avahi.ServiceBrowser"
)]
trait AvahiServiceBrowser {
    #[zbus(name = "Free")]
    fn free(&self) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemNew")]
    fn service_item_new(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        flags: u32,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "ItemRemove")]
    fn service_item_remove(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        flags: u32,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "Failure")]
    fn service_failure(&self, error: &str) -> zbus::Result<()>;
}

mod type_browser {
    #[zbus::proxy(
        default_service = "org.freedesktop.Avahi",
        interface = "org.freedesktop.Avahi.ServiceTypeBrowser"
    )]
    pub(super) trait AvahiServiceTypeBrowser {
        #[zbus(name = "Free")]
        fn free(&self) -> zbus::Result<()>;

        #[zbus(signal, name = "ItemNew")]
        fn service_type_item_new(
            &self,
            interface: i32,
            protocol: i32,
            service_type: &str,
            domain: &str,
            flags: u32,
        ) -> zbus::Result<()>;

        #[zbus(signal, name = "ItemRemove")]
        fn service_type_item_remove(
            &self,
            interface: i32,
            protocol: i32,
            service_type: &str,
            domain: &str,
            flags: u32,
        ) -> zbus::Result<()>;

        #[zbus(signal, name = "Failure")]
        fn service_type_failure(&self, error: &str) -> zbus::Result<()>;
    }
}

use type_browser::AvahiServiceTypeBrowserProxy;

/// Linux adapter that owns Avahi detection and arming.
#[derive(Debug, Default)]
pub struct AvahiAdapter;

struct ReadyAvahi {
    connection: Connection,
    owner: String,
    version: String,
}

#[async_trait::async_trait]
impl MdnsAdapter for AvahiAdapter {
    fn name(&self) -> &'static str {
        "avahi"
    }

    fn priority(&self) -> u16 {
        AVAHI_PRIORITY
    }

    fn api(&self) -> AdapterApi {
        AdapterApi::SystemDbus
    }

    fn capabilities(&self) -> MdnsCapabilities {
        MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE
    }

    async fn inspect(&self) -> AdapterReport {
        match inspect_avahi(self).await {
            Ok(ready) => ready_report(self, &ready.version),
            Err(report) => report,
        }
    }

    async fn arm(&self) -> Result<Arc<dyn MdnsProvider>> {
        let ready = inspect_avahi(self).await.map_err(|report| {
            MdnsError::Daemon(format!("Avahi cannot be armed: {}", report.detail))
        })?;
        Ok(Arc::new(AvahiMdnsProvider::start(
            ready.connection,
            ready.owner,
            ready.version,
        )))
    }
}

fn ready_report(adapter: &AvahiAdapter, version: &str) -> AdapterReport {
    AdapterReport {
        name: adapter.name(),
        priority: adapter.priority(),
        api: adapter.api(),
        readiness: AdapterReadiness::Ready,
        installed: ProbeFact::Yes,
        configured: ProbeFact::Yes,
        running: ProbeFact::Yes,
        capabilities: adapter.capabilities(),
        detail: format!("{version} running on the system D-Bus"),
    }
}

async fn inspect_avahi(adapter: &AvahiAdapter) -> std::result::Result<ReadyAvahi, AdapterReport> {
    let failed = |readiness, detail| AdapterReport::failed_inspection(adapter, readiness, detail);
    let connection = Connection::system().await.map_err(|error| {
        failed(
            AdapterReadiness::Unavailable,
            format!("system D-Bus unavailable: {error}"),
        )
    })?;

    let dbus = zbus::fdo::DBusProxy::new(&connection)
        .await
        .map_err(|error| {
            failed(
                AdapterReadiness::Unavailable,
                format!("cannot inspect the system D-Bus: {error}"),
            )
        })?;
    let bus_name = BusName::try_from(AVAHI_DESTINATION).map_err(|error| {
        failed(
            AdapterReadiness::Unavailable,
            format!("invalid Avahi D-Bus name: {error}"),
        )
    })?;
    let has_owner = dbus.name_has_owner(bus_name).await.map_err(|error| {
        failed(
            AdapterReadiness::Unavailable,
            format!("cannot determine whether Avahi is running: {error}"),
        )
    })?;
    if !has_owner {
        let installed = dbus
            .list_activatable_names()
            .await
            .map(|names| {
                if names.iter().any(|name| name.as_str() == AVAHI_DESTINATION) {
                    ProbeFact::Yes
                } else {
                    ProbeFact::Unknown
                }
            })
            .unwrap_or(ProbeFact::Unknown);
        return Err(AdapterReport {
            name: adapter.name(),
            priority: adapter.priority(),
            api: adapter.api(),
            readiness: AdapterReadiness::Absent,
            installed,
            configured: ProbeFact::Unknown,
            running: ProbeFact::No,
            capabilities: MdnsCapabilities::default(),
            detail: "no live D-Bus owner; Koi did not activate the stopped service".to_string(),
        });
    }

    let server = AvahiServerProxy::new(&connection).await.map_err(|error| {
        failed(
            AdapterReadiness::Unavailable,
            format!("cannot create the Avahi server proxy: {error}"),
        )
    })?;
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        match server.get_state().await {
            Ok(AVAHI_SERVER_RUNNING) => break,
            Ok(AVAHI_SERVER_FAILURE) => {
                return Err(failed(
                    AdapterReadiness::Unavailable,
                    "Avahi reports a fatal server failure".to_string(),
                ));
            }
            Ok(state) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(state, "Waiting for Avahi to reach running state");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(state) => {
                return Err(failed(
                    AdapterReadiness::Unavailable,
                    format!("Avahi did not reach running state (state {state})"),
                ));
            }
            Err(error) => {
                return Err(failed(
                    AdapterReadiness::Unavailable,
                    format!("Avahi is present but GetState failed: {error}"),
                ));
            }
        }
    }

    let version = server
        .get_version_string()
        .await
        .unwrap_or_else(|_| "version unavailable".to_string());
    let owner = current_owner(&connection)
        .await
        .map_err(|error| failed(AdapterReadiness::Unavailable, error))?
        .ok_or_else(|| {
            failed(
                AdapterReadiness::Unavailable,
                "Avahi disappeared during inspection".to_string(),
            )
        })?;

    Ok(ReadyAvahi {
        connection,
        owner,
        version,
    })
}

/// A real Avahi adapter. All mutating calls are serialized through one actor so
/// publication and withdrawal ordering is deterministic.
pub struct AvahiMdnsProvider {
    connection: Connection,
    command_tx: mpsc::Sender<Command>,
    status: Arc<RwLock<ProviderStatus>>,
}

impl AvahiMdnsProvider {
    fn start(connection: Connection, owner: String, version: String) -> Self {
        let detail = format!("{version} via system D-Bus");
        let status = Arc::new(RwLock::new(ProviderStatus {
            name: "avahi".to_string(),
            healthy: true,
            detail,
        }));
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let actor = AvahiActor {
            connection: connection.clone(),
            command_rx,
            status: Arc::clone(&status),
            version,
            owner: Some(owner),
            registrations: HashMap::new(),
            entry_groups: HashMap::new(),
            browsers: HashMap::new(),
        };
        tokio::spawn(actor.run());
        Self {
            connection,
            command_tx,
            status,
        }
    }

    fn send(&self, command: Command) -> Result<()> {
        self.command_tx
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    MdnsError::Daemon("Avahi command queue full".to_string())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    MdnsError::Daemon("Avahi adapter stopped".to_string())
                }
            })
    }
}

#[async_trait::async_trait]
impl MdnsProvider for AvahiMdnsProvider {
    fn name(&self) -> &'static str {
        "avahi"
    }

    fn api(&self) -> AdapterApi {
        AdapterApi::SystemDbus
    }

    fn capabilities(&self) -> MdnsCapabilities {
        MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE
    }

    fn status(&self) -> ProviderStatus {
        self.status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn register(
        &self,
        name: &str,
        service_type: &str,
        port: u16,
        ip: Option<&str>,
        txt: &HashMap<String, String>,
    ) -> Result<()> {
        validate_instance_name(name)?;
        let ip = ip
            .map(str::parse::<IpAddr>)
            .transpose()
            .map_err(|error| MdnsError::Daemon(format!("invalid service IP: {error}")))?;
        let txt = encode_txt(txt)?;
        let (service_type, domain) = split_service_type(service_type)?;
        self.send(Command::Register(Registration {
            key: registration_key(name, &service_type, &domain),
            name: name.to_string(),
            service_type,
            domain,
            port,
            ip,
            txt,
        }))
    }

    fn unregister(&self, name: &str, service_type: &str) -> Result<()> {
        let (service_type, domain) = split_service_type(service_type)?;
        self.send(Command::Unregister(registration_key(
            name,
            &service_type,
            &domain,
        )))
    }

    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Browse {
                key: service_type.to_string(),
                is_meta,
                reply: reply_tx,
            })
            .await
            .map_err(|_| MdnsError::Daemon("Avahi adapter stopped".to_string()))?;
        reply_rx
            .await
            .map_err(|_| MdnsError::Daemon("Avahi adapter dropped browse reply".to_string()))?
            .map_err(MdnsError::Daemon)
    }

    async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
        let (service_type, domain) = split_service_type(service_type)?;
        resolve_observation(
            &self.connection,
            AVAHI_IF_UNSPEC,
            AVAHI_PROTO_UNSPEC,
            name,
            &service_type,
            &domain,
        )
        .await
        .map_err(MdnsError::Daemon)
    }

    fn stop_browse(&self, service_type: &str) -> Result<()> {
        self.send(Command::StopBrowse(service_type.to_string()))
    }

    async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Shutdown(reply_tx))
            .await
            .map_err(|_| MdnsError::Daemon("Avahi adapter stopped".to_string()))?;
        reply_rx
            .await
            .map_err(|_| MdnsError::Daemon("Avahi adapter dropped shutdown reply".to_string()))
    }
}

enum Command {
    Register(Registration),
    Unregister(String),
    Browse {
        key: String,
        is_meta: bool,
        reply: oneshot::Sender<std::result::Result<ProviderBrowse, String>>,
    },
    StopBrowse(String),
    Shutdown(oneshot::Sender<()>),
}

#[derive(Clone)]
struct Registration {
    key: String,
    name: String,
    service_type: String,
    domain: String,
    port: u16,
    ip: Option<IpAddr>,
    txt: Vec<Vec<u8>>,
}

struct Browser {
    path: OwnedObjectPath,
    is_meta: bool,
    task: tokio::task::JoinHandle<()>,
}

struct AvahiActor {
    connection: Connection,
    command_rx: mpsc::Receiver<Command>,
    status: Arc<RwLock<ProviderStatus>>,
    version: String,
    owner: Option<String>,
    registrations: HashMap<String, Registration>,
    entry_groups: HashMap<String, OwnedObjectPath>,
    browsers: HashMap<String, Browser>,
}

impl AvahiActor {
    async fn run(mut self) {
        let mut reconcile = tokio::time::interval(RECONCILE_INTERVAL);
        reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                command = self.command_rx.recv() => {
                    let Some(command) = command else {
                        self.release_all().await;
                        break;
                    };
                    if !self.handle(command).await {
                        break;
                    }
                }
                _ = reconcile.tick() => self.reconcile().await,
            }
        }
        set_status(&self.status, false, "adapter stopped".to_string());
    }

    async fn handle(&mut self, command: Command) -> bool {
        match command {
            Command::Register(registration) => {
                let key = registration.key.clone();
                self.registrations.insert(key.clone(), registration);
                self.free_entry_group(&key).await;
                if self.owner.is_some() {
                    self.publish(&key).await;
                }
            }
            Command::Unregister(key) => {
                self.registrations.remove(&key);
                self.free_entry_group(&key).await;
            }
            Command::Browse {
                key,
                is_meta,
                reply,
            } => {
                self.free_browser(&key).await;
                let result = self.start_browse(&key, is_meta).await;
                if let Err(error) = &result {
                    tracing::warn!(
                        provider = "avahi",
                        service_type = %key,
                        %error,
                        "mDNS browse startup failed; Koi will retry"
                    );
                }
                let _ = reply.send(result);
            }
            Command::StopBrowse(key) => self.free_browser(&key).await,
            Command::Shutdown(reply) => {
                self.release_all().await;
                let _ = reply.send(());
                return false;
            }
        }
        true
    }

    async fn reconcile(&mut self) {
        let owner = match current_owner(&self.connection).await {
            Ok(owner) => owner,
            Err(error) => {
                self.deactivate();
                set_status(&self.status, false, error);
                return;
            }
        };

        if owner != self.owner {
            tracing::info!(old = ?self.owner, new = ?owner, "Avahi D-Bus owner changed");
            self.deactivate();
            self.owner = owner;
        }
        if self.owner.is_none() {
            set_status(
                &self.status,
                false,
                "Avahi has no live D-Bus owner".to_string(),
            );
            return;
        }

        let server = match AvahiServerProxy::new(&self.connection).await {
            Ok(server) => server,
            Err(error) => {
                self.deactivate();
                set_status(&self.status, false, format!("Avahi proxy failed: {error}"));
                return;
            }
        };
        match server.get_state().await {
            Ok(AVAHI_SERVER_RUNNING) => {}
            Ok(state) => {
                self.deactivate();
                set_status(
                    &self.status,
                    false,
                    format!("Avahi server state is {state}; waiting for running"),
                );
                return;
            }
            Err(error) => {
                self.deactivate();
                set_status(
                    &self.status,
                    false,
                    format!("Avahi health check failed: {error}"),
                );
                return;
            }
        }

        set_status(
            &self.status,
            true,
            format!("{} via system D-Bus", self.version),
        );
        let missing: Vec<String> = self
            .registrations
            .keys()
            .filter(|key| !self.entry_groups.contains_key(*key))
            .cloned()
            .collect();
        for key in missing {
            self.publish(&key).await;
        }
    }

    async fn publish(&mut self, key: &str) {
        let Some(registration) = self.registrations.get(key).cloned() else {
            return;
        };
        match publish(&self.connection, &registration).await {
            Ok((path, effective_name)) => {
                if effective_name != registration.name {
                    tracing::warn!(
                        requested = %registration.name,
                        effective = %effective_name,
                        service_type = %registration.service_type,
                        "mDNS name collision resolved"
                    );
                    if let Some(stored) = self.registrations.get_mut(key) {
                        stored.name.clone_from(&effective_name);
                    }
                }
                tracing::debug!(
                    provider = "avahi",
                    name = %effective_name,
                    service_type = %registration.service_type,
                    "Published mDNS service"
                );
                self.entry_groups.insert(key.to_string(), path);
            }
            Err(error) => {
                // A rejected registration is scoped to that publication. It does
                // not establish that Avahi's D-Bus owner, server, or existing
                // browse streams are unhealthy. The adapter's regular health
                // probe owns that decision and retries every missing entry group.
                tracing::warn!(
                    provider = "avahi",
                    name = %registration.name,
                    service_type = %registration.service_type,
                    %error,
                    "mDNS publish failed"
                );
            }
        }
    }

    async fn start_browse(
        &mut self,
        key: &str,
        is_meta: bool,
    ) -> std::result::Result<ProviderBrowse, String> {
        if self.owner.is_none() {
            return Err("Avahi is not running".to_string());
        }
        let server = AvahiServerProxy::new(&self.connection)
            .await
            .map_err(|error| format!("cannot create Avahi server proxy: {error}"))?;
        let path = if is_meta {
            server
                .service_type_browser_new(
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    "local",
                    AVAHI_FLAGS_NONE,
                )
                .await
                .map_err(|error| format!("cannot start Avahi type browser: {error}"))?
        } else {
            let (service_type, domain) = split_service_type(key).map_err(|e| e.to_string())?;
            server
                .service_browser_new(
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    &service_type,
                    &domain,
                    AVAHI_FLAGS_NONE,
                )
                .await
                .map_err(|error| format!("cannot start Avahi service browser: {error}"))?
        };

        let (tx, rx) = mpsc::channel(BROWSE_CAPACITY);
        let (ready_tx, ready_rx) = oneshot::channel();
        let connection = self.connection.clone();
        let task_path = path.clone();
        let task = if is_meta {
            tokio::spawn(async move {
                pump_service_types(connection, task_path, tx, ready_tx).await;
            })
        } else {
            tokio::spawn(async move {
                pump_services(connection, task_path, tx, ready_tx).await;
            })
        };
        match ready_rx.await {
            Ok(Ok(())) => {
                self.browsers.insert(
                    key.to_string(),
                    Browser {
                        path,
                        is_meta,
                        task,
                    },
                );
                Ok(rx)
            }
            Ok(Err(error)) => {
                task.abort();
                free_browser_object(&self.connection, &path, is_meta).await;
                Err(error)
            }
            Err(_) => {
                task.abort();
                free_browser_object(&self.connection, &path, is_meta).await;
                Err("Avahi browse pump stopped during startup".to_string())
            }
        }
    }

    async fn free_entry_group(&mut self, key: &str) {
        if let Some(path) = self.entry_groups.remove(key) {
            if let Ok(builder) = AvahiEntryGroupProxy::builder(&self.connection).path(path) {
                match builder.build().await {
                    Ok(proxy) => {
                        let _ = proxy.free().await;
                    }
                    Err(error) => tracing::debug!(%error, "Failed to open Avahi entry group"),
                }
            }
        }
    }

    async fn free_browser(&mut self, key: &str) {
        if let Some(browser) = self.browsers.remove(key) {
            browser.task.abort();
            free_browser_object(&self.connection, &browser.path, browser.is_meta).await;
        }
    }

    fn deactivate(&mut self) {
        self.entry_groups.clear();
        for (_, browser) in self.browsers.drain() {
            browser.task.abort();
        }
    }

    async fn release_all(&mut self) {
        let browser_keys: Vec<String> = self.browsers.keys().cloned().collect();
        for key in browser_keys {
            self.free_browser(&key).await;
        }
        let group_keys: Vec<String> = self.entry_groups.keys().cloned().collect();
        for key in group_keys {
            self.free_entry_group(&key).await;
        }
    }
}

async fn publish(
    connection: &Connection,
    registration: &Registration,
) -> std::result::Result<(OwnedObjectPath, String), String> {
    let server = AvahiServerProxy::new(connection)
        .await
        .map_err(|error| format!("cannot create Avahi server proxy: {error}"))?;
    let mut host = registration.ip.map(|_| explicit_address_host());

    let mut candidate = registration.name.clone();
    for _ in 0..MAX_COLLISION_ATTEMPTS {
        let path = server
            .entry_group_new()
            .await
            .map_err(|error| format!("EntryGroupNew failed: {error}"))?;
        let group = AvahiEntryGroupProxy::builder(connection)
            .path(path.clone())
            .map_err(|error| format!("invalid Avahi entry-group path: {error}"))?
            .build()
            .await
            .map_err(|error| format!("cannot create Avahi entry-group proxy: {error}"))?;

        if let Err(error) = group
            .add_service(
                AVAHI_IF_UNSPEC,
                AVAHI_PROTO_UNSPEC,
                AVAHI_FLAGS_NONE,
                &candidate,
                &registration.service_type,
                &registration.domain,
                host.as_deref().unwrap_or_default(),
                registration.port,
                &registration.txt,
            )
            .await
        {
            let _ = group.free().await;
            return Err(format!("AddService failed: {error}"));
        }

        if let Some(ip) = registration.ip {
            let protocol = if ip.is_ipv4() {
                AVAHI_PROTO_INET
            } else {
                AVAHI_PROTO_INET6
            };
            if let Err(error) = group
                .add_address(
                    AVAHI_IF_UNSPEC,
                    protocol,
                    // The machine's primary hostname already owns the reverse
                    // PTR for a local interface address. This alias only needs
                    // the forward A/AAAA record used by its service SRV target.
                    AVAHI_PUBLISH_NO_REVERSE,
                    host.as_deref().expect("explicit IP has a host alias"),
                    &ip.to_string(),
                )
                .await
            {
                let _ = group.free().await;
                return Err(format!("AddAddress failed: {error}"));
            }
        }

        if let Err(error) = group.commit().await {
            let _ = group.free().await;
            return Err(format!("EntryGroup Commit failed: {error}"));
        }
        match await_entry_group(&group).await {
            Ok(()) => return Ok((path, candidate)),
            Err(EntryGroupOutcome::Collision) => {
                let _ = group.free().await;
                candidate = server
                    .get_alternative_service_name(&candidate)
                    .await
                    .map_err(|error| format!("GetAlternativeServiceName failed: {error}"))?;
                if registration.ip.is_some() {
                    host = Some(explicit_address_host());
                }
            }
            Err(EntryGroupOutcome::Failure(error)) => {
                let _ = group.free().await;
                return Err(error);
            }
        }
    }
    Err(format!(
        "could not find a collision-free name after {MAX_COLLISION_ATTEMPTS} attempts"
    ))
}

enum EntryGroupOutcome {
    Collision,
    Failure(String),
}

async fn await_entry_group(
    group: &AvahiEntryGroupProxy<'_>,
) -> std::result::Result<(), EntryGroupOutcome> {
    let deadline = tokio::time::Instant::now() + ENTRY_GROUP_TIMEOUT;
    loop {
        match group.get_state().await {
            Ok(AVAHI_ENTRY_GROUP_ESTABLISHED) => return Ok(()),
            Ok(AVAHI_ENTRY_GROUP_COLLISION) => return Err(EntryGroupOutcome::Collision),
            Ok(AVAHI_ENTRY_GROUP_FAILURE) => {
                return Err(EntryGroupOutcome::Failure(
                    "Avahi entry group reports failure".to_string(),
                ));
            }
            Ok(state) if tokio::time::Instant::now() < deadline => {
                tracing::trace!(state, "Waiting for Avahi entry group");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(state) => {
                return Err(EntryGroupOutcome::Failure(format!(
                    "Avahi entry group did not establish (state {state})"
                )));
            }
            Err(error) => {
                return Err(EntryGroupOutcome::Failure(format!(
                    "Avahi EntryGroup GetState failed: {error}"
                )));
            }
        }
    }
}

async fn pump_services(
    connection: Connection,
    path: OwnedObjectPath,
    tx: mpsc::Sender<ProviderEvent>,
    ready: oneshot::Sender<std::result::Result<(), String>>,
) {
    let proxy = match AvahiServiceBrowserProxy::builder(&connection).path(path) {
        Ok(builder) => match builder.build().await {
            Ok(proxy) => proxy,
            Err(error) => {
                let _ = ready.send(Err(format!("cannot build Avahi service browser: {error}")));
                return;
            }
        },
        Err(error) => {
            let _ = ready.send(Err(format!("invalid Avahi service-browser path: {error}")));
            return;
        }
    };
    let mut added = match proxy.receive_service_item_new().await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!("cannot subscribe to Avahi ItemNew: {error}")));
            return;
        }
    };
    let mut removed = match proxy.receive_service_item_remove().await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "cannot subscribe to Avahi ItemRemove: {error}"
            )));
            return;
        }
    };
    let mut failures = match proxy.receive_service_failure().await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!("cannot subscribe to Avahi Failure: {error}")));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        return;
    }

    let mut resolutions = tokio::task::JoinSet::new();
    let mut pending = HashMap::new();
    let mut next_resolution = 0_u64;

    loop {
        tokio::select! {
            message = added.next() => {
                let Some(message) = message else { break };
                let args = match message.args() {
                    Ok(args) => args,
                    Err(error) => {
                        tracing::warn!(%error, "Invalid Avahi ItemNew signal");
                        continue;
                    }
                };
                if resolutions.len() >= BROWSE_CAPACITY {
                    tracing::warn!(
                        capacity = BROWSE_CAPACITY,
                        "Avahi service resolution queue is full"
                    );
                    continue;
                }
                let key = ServiceObservationKey {
                    interface: *args.interface(),
                    protocol: *args.protocol(),
                    name: args.name().to_string(),
                    service_type: args.service_type().to_string(),
                    domain: args.domain().to_string(),
                };
                next_resolution = next_resolution.wrapping_add(1);
                let sequence = next_resolution;
                pending.insert(key.clone(), sequence);
                let resolution_connection = connection.clone();
                resolutions.spawn(async move {
                    let result = resolve_observation(
                        &resolution_connection,
                        key.interface,
                        key.protocol,
                        &key.name,
                        &key.service_type,
                        &key.domain,
                    ).await;
                    (key, sequence, result)
                });
            }
            message = removed.next() => {
                let Some(message) = message else { break };
                let args = match message.args() {
                    Ok(args) => args,
                    Err(error) => {
                        tracing::warn!(%error, "Invalid Avahi ItemRemove signal");
                        continue;
                    }
                };
                pending.remove(&ServiceObservationKey {
                    interface: *args.interface(),
                    protocol: *args.protocol(),
                    name: args.name().to_string(),
                    service_type: args.service_type().to_string(),
                    domain: args.domain().to_string(),
                });
                if tx.send(ProviderEvent::Removed {
                    name: args.name().to_string(),
                    service_type: args.service_type().to_string(),
                }).await.is_err() {
                    return;
                }
            }
            message = failures.next() => {
                if let Some(message) = message {
                    match message.args() {
                        Ok(args) => tracing::warn!(error = args.error(), "Avahi service browser failed"),
                        Err(error) => tracing::warn!(%error, "Invalid Avahi Failure signal"),
                    }
                }
                break;
            }
            resolution = resolutions.join_next(), if !resolutions.is_empty() => {
                let Some(resolution) = resolution else { continue };
                let (key, sequence, result) = match resolution {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::debug!(%error, "Avahi service resolution task stopped");
                        continue;
                    }
                };
                if pending.get(&key).copied() != Some(sequence) {
                    continue;
                }
                pending.remove(&key);
                match result {
                    Ok(service) => {
                        if tx.send(ProviderEvent::Resolved(service)).await.is_err() {
                            return;
                        }
                    }
                    Err(error) => tracing::debug!(%error, "Avahi service resolve failed"),
                }
            }
        }
    }
    resolutions.abort_all();
    tracing::warn!(
        provider = "avahi",
        "mDNS service browser ended; Koi will retry"
    );
}

async fn pump_service_types(
    connection: Connection,
    path: OwnedObjectPath,
    tx: mpsc::Sender<ProviderEvent>,
    ready: oneshot::Sender<std::result::Result<(), String>>,
) {
    let proxy = match AvahiServiceTypeBrowserProxy::builder(&connection).path(path) {
        Ok(builder) => match builder.build().await {
            Ok(proxy) => proxy,
            Err(error) => {
                let _ = ready.send(Err(format!("cannot build Avahi type browser: {error}")));
                return;
            }
        },
        Err(error) => {
            let _ = ready.send(Err(format!("invalid Avahi type-browser path: {error}")));
            return;
        }
    };
    let mut added = match proxy.receive_service_type_item_new().await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "cannot subscribe to Avahi type ItemNew: {error}"
            )));
            return;
        }
    };
    let mut removed = match proxy.receive_service_type_item_remove().await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "cannot subscribe to Avahi type ItemRemove: {error}"
            )));
            return;
        }
    };
    let mut failures = match proxy.receive_service_type_failure().await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "cannot subscribe to Avahi type Failure: {error}"
            )));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        return;
    }

    loop {
        tokio::select! {
            message = added.next() => {
                let Some(message) = message else { break };
                let args = match message.args() {
                    Ok(args) => args,
                    Err(error) => {
                        tracing::warn!(%error, "Invalid Avahi type ItemNew signal");
                        continue;
                    }
                };
                let service_type = args.service_type().trim_end_matches('.').to_string();
                if tx.send(ProviderEvent::Found(ProviderService {
                    name: service_type,
                    service_type: String::new(),
                    host: None,
                    addresses: Vec::new(),
                    port: None,
                    txt: HashMap::new(),
                })).await.is_err() {
                    return;
                }
            }
            message = removed.next() => {
                let Some(message) = message else { break };
                let args = match message.args() {
                    Ok(args) => args,
                    Err(error) => {
                        tracing::warn!(%error, "Invalid Avahi type ItemRemove signal");
                        continue;
                    }
                };
                if tx.send(ProviderEvent::Removed {
                    name: args.service_type().trim_end_matches('.').to_string(),
                    service_type: String::new(),
                }).await.is_err() {
                    return;
                }
            }
            message = failures.next() => {
                if let Some(message) = message {
                    match message.args() {
                        Ok(args) => tracing::warn!(error = args.error(), "Avahi type browser failed"),
                        Err(error) => tracing::warn!(%error, "Invalid Avahi type Failure signal"),
                    }
                }
                break;
            }
        }
    }
    tracing::warn!(
        provider = "avahi",
        "mDNS type browser ended; Koi will retry"
    );
}

async fn resolve_observation(
    connection: &Connection,
    interface: i32,
    protocol: i32,
    name: &str,
    service_type: &str,
    domain: &str,
) -> std::result::Result<ProviderService, String> {
    let server = AvahiServerProxy::new(connection)
        .await
        .map_err(|error| format!("cannot create Avahi server proxy: {error}"))?;
    let v4 = server.resolve_service(
        interface,
        protocol,
        name,
        service_type,
        domain,
        AVAHI_PROTO_INET,
        AVAHI_FLAGS_NONE,
    );
    let v6 = server.resolve_service(
        interface,
        protocol,
        name,
        service_type,
        domain,
        AVAHI_PROTO_INET6,
        AVAHI_FLAGS_NONE,
    );
    let (v4, v6) = tokio::join!(v4, v6);
    let replies: Vec<ResolveReply> = [v4.ok(), v6.ok()].into_iter().flatten().collect();
    if replies.is_empty() {
        return Err(format!(
            "ResolveService returned no address for {name}.{service_type}.{domain}"
        ));
    }

    let first = &replies[0];
    let interface_name = if first.0 >= 0 {
        server
            .get_network_interface_name_by_index(first.0)
            .await
            .ok()
    } else {
        None
    };
    let mut addresses = Vec::new();
    for reply in &replies {
        let Ok(address) = reply.7.parse::<IpAddr>() else {
            continue;
        };
        let observed = ProviderAddress {
            address,
            interface_index: (reply.0 >= 0).then_some(reply.0 as u32),
            interface_name: interface_name.clone(),
        };
        if !addresses.contains(&observed) {
            addresses.push(observed);
        }
    }

    Ok(ProviderService {
        name: first.2.clone(),
        service_type: first.3.clone(),
        host: (!first.5.is_empty()).then(|| first.5.clone()),
        addresses,
        port: Some(first.8),
        txt: decode_txt(&first.9),
    })
}

async fn current_owner(connection: &Connection) -> std::result::Result<Option<String>, String> {
    let dbus = zbus::fdo::DBusProxy::new(connection)
        .await
        .map_err(|error| format!("cannot create system D-Bus proxy: {error}"))?;
    let name = BusName::try_from(AVAHI_DESTINATION)
        .map_err(|error| format!("invalid Avahi D-Bus name: {error}"))?;
    match dbus.get_name_owner(name).await {
        Ok(owner) => Ok(Some(owner.to_string())),
        Err(zbus::fdo::Error::NameHasNoOwner(_)) => Ok(None),
        Err(error) => Err(format!("cannot inspect Avahi D-Bus owner: {error}")),
    }
}

async fn free_browser_object(connection: &Connection, path: &OwnedObjectPath, is_meta: bool) {
    if is_meta {
        if let Ok(builder) = AvahiServiceTypeBrowserProxy::builder(connection).path(path.clone()) {
            if let Ok(proxy) = builder.build().await {
                let _ = proxy.free().await;
            }
        }
    } else if let Ok(builder) = AvahiServiceBrowserProxy::builder(connection).path(path.clone()) {
        if let Ok(proxy) = builder.build().await {
            let _ = proxy.free().await;
        }
    }
}

fn split_service_type(service_type: &str) -> Result<(String, String)> {
    let canonical = service_type.trim_end_matches('.');
    let Some(short) = canonical.strip_suffix(".local") else {
        return Err(MdnsError::Daemon(format!(
            "Avahi requires a canonical local service type, got {service_type}"
        )));
    };
    if short.is_empty() {
        return Err(MdnsError::Daemon("empty Avahi service type".to_string()));
    }
    Ok((short.to_string(), "local".to_string()))
}

fn registration_key(name: &str, service_type: &str, domain: &str) -> String {
    format!("{name}.{service_type}.{domain}.")
}

fn explicit_address_host() -> String {
    // An explicit address needs its own host record. Reusing Avahi's machine
    // hostname attempts to claim a name the daemon already owns, while sharing
    // one synthetic hostname across registrations makes their entry groups
    // contend with each other. A per-attempt alias keeps each SRV + A/AAAA set
    // self-contained and lets Avahi retire it atomically.
    format!("koi-{}.local", uuid::Uuid::now_v7().simple())
}

fn validate_instance_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        return Err(MdnsError::Daemon(
            "DNS-SD instance names must contain 1-63 UTF-8 bytes".to_string(),
        ));
    }
    Ok(())
}

fn encode_txt(txt: &HashMap<String, String>) -> Result<Vec<Vec<u8>>> {
    txt.iter()
        .map(|(key, value)| {
            if key.is_empty() || key.contains('=') {
                return Err(MdnsError::Daemon(format!("invalid DNS-SD TXT key '{key}'")));
            }
            let item = format!("{key}={value}").into_bytes();
            if item.len() > u8::MAX as usize {
                return Err(MdnsError::Daemon(format!(
                    "DNS-SD TXT item '{key}' exceeds 255 bytes"
                )));
            }
            Ok(item)
        })
        .collect()
}

fn decode_txt(items: &[Vec<u8>]) -> HashMap<String, String> {
    items
        .iter()
        .filter_map(|item| {
            let text = String::from_utf8_lossy(item);
            let (key, value) = text.split_once('=').unwrap_or((&text, ""));
            (!key.is_empty()).then(|| (key.to_string(), value.to_string()))
        })
        .collect()
}

fn set_status(status: &RwLock<ProviderStatus>, healthy: bool, detail: String) {
    let mut status = status
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    status.healthy = healthy;
    status.detail = detail;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_type_is_split_for_avahi() {
        assert_eq!(
            split_service_type("_http._tcp.local.").unwrap(),
            ("_http._tcp".to_string(), "local".to_string())
        );
        assert!(split_service_type("_http._tcp.example.com.").is_err());
    }

    #[test]
    fn txt_round_trips_and_rejects_oversize_items() {
        let txt = HashMap::from([
            ("path".to_string(), "/api".to_string()),
            ("version".to_string(), "1".to_string()),
        ]);
        let encoded = encode_txt(&txt).unwrap();
        assert_eq!(decode_txt(&encoded), txt);
        assert!(encode_txt(&HashMap::from([("large".to_string(), "x".repeat(256))])).is_err());
    }

    #[test]
    fn explicit_address_hosts_are_valid_isolated_local_aliases() {
        let first = explicit_address_host();
        let second = explicit_address_host();
        let label = first.strip_suffix(".local").expect("local host alias");

        assert_ne!(first, second);
        assert!(label.len() <= 63);
        assert!(label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'));
    }

    #[test]
    fn zbus_is_isolated_to_linux_system_adapters() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&src_dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            if matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("avahi.rs" | "systemd_resolved.rs")
            ) {
                continue;
            }
            let contents = std::fs::read_to_string(&path).expect("read source file");
            if contents.contains("zbus") {
                offenders.push(path.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "zbus must remain inside Linux system adapters; offenders: {offenders:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a running Avahi daemon on the system bus"]
    async fn real_avahi_adapter_inspects_as_a_full_provider() {
        let adapter = AvahiAdapter;
        let report = adapter.inspect().await;
        assert!(report.satisfies_full_contract(), "Avahi report: {report:?}");
    }

    #[tokio::test]
    #[ignore = "requires a running Avahi daemon on the system bus"]
    async fn real_avahi_publish_browse_resolve_and_remove() {
        let adapter = AvahiAdapter;
        let provider = adapter.arm().await.expect("arm real Avahi provider");
        let mut browse = provider
            .browse("_koi-test._tcp.local.", false)
            .await
            .expect("start real Avahi browse");
        let name = format!("koi-avahi-{}", std::process::id());
        provider
            .register(
                &name,
                "_koi-test._tcp.local.",
                43123,
                None,
                &HashMap::from([("source".to_string(), "koi".to_string())]),
            )
            .expect("queue real Avahi publication");

        let resolved = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                match browse.recv().await {
                    Some(ProviderEvent::Resolved(service)) if service.name == name => {
                        break service
                    }
                    Some(_) => continue,
                    None => panic!("Avahi browse ended before resolution"),
                }
            }
        })
        .await
        .expect("resolve the real Avahi publication");
        assert_eq!(resolved.port, Some(43123));
        assert_eq!(resolved.txt.get("source"), Some(&"koi".to_string()));
        assert!(!resolved.addresses.is_empty());

        provider
            .unregister(&name, "_koi-test._tcp.local.")
            .expect("queue real Avahi withdrawal");
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                match browse.recv().await {
                    Some(ProviderEvent::Removed { name: removed, .. }) if removed == name => break,
                    Some(_) => continue,
                    None => panic!("Avahi browse ended before removal"),
                }
            }
        })
        .await
        .expect("observe the real Avahi withdrawal");

        let explicit_ip = if_addrs::get_if_addrs()
            .expect("enumerate interfaces")
            .into_iter()
            .find_map(|interface| match interface.ip() {
                IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_link_local() => Some(ip),
                _ => None,
            })
            .expect("a live IPv4 interface");
        let explicit_name = format!("koi-avahi-explicit-{}", std::process::id());
        provider
            .register(
                &explicit_name,
                "_koi-test._tcp.local.",
                43124,
                Some(&explicit_ip.to_string()),
                &HashMap::new(),
            )
            .expect("queue real Avahi publication with an explicit address");
        let explicit = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                match browse.recv().await {
                    Some(ProviderEvent::Resolved(service))
                        if service.name == explicit_name
                            && service
                                .addresses
                                .iter()
                                .any(|address| address.address == IpAddr::V4(explicit_ip)) =>
                    {
                        break service;
                    }
                    Some(_) => continue,
                    None => panic!("Avahi browse ended before explicit-IP resolution"),
                }
            }
        })
        .await
        .expect("resolve the explicit-IP Avahi publication");
        assert!(explicit
            .addresses
            .iter()
            .any(|address| address.address == IpAddr::V4(explicit_ip)));
        assert!(provider.status().healthy, "status: {:?}", provider.status());
        provider
            .unregister(&explicit_name, "_koi-test._tcp.local.")
            .expect("withdraw real explicit-IP Avahi publication");
        provider.shutdown().await.expect("shut down Avahi adapter");
    }
}
