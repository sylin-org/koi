//! Linux mDNS provider backed by Avahi's system D-Bus API.
//!
//! The adapter owns Avahi entry groups and browse objects, translates their
//! signals into provider-neutral observations, and keeps desired publications
//! so an Avahi daemon restart can be reconciled without changing providers.

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
const COMMAND_CAPACITY: usize = 256;
const BROWSE_CAPACITY: usize = 512;
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

    #[zbus(name = "GetHostNameFqdn")]
    fn get_host_name_fqdn(&self) -> zbus::Result<String>;

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

/// Result of probing the live Linux Avahi resource.
pub enum AvahiProbe {
    /// Avahi owns its D-Bus name and reports a running server.
    Ready(AvahiMdnsProvider),
    /// Avahi definitely has no live D-Bus owner.
    Absent(String),
    /// Avahi is present but did not become usable; native must not be armed.
    Unavailable(String),
}

/// A real Avahi adapter. All mutating calls are serialized through one actor so
/// publication and withdrawal ordering is deterministic.
pub struct AvahiMdnsProvider {
    command_tx: mpsc::Sender<Command>,
    status: Arc<RwLock<ProviderStatus>>,
}

impl AvahiMdnsProvider {
    /// Probe the system bus without activating a stopped Avahi service.
    ///
    /// A missing owner is the explicit native-fallback case. Once an owner is
    /// observed, any D-Bus or server-state failure remains an Avahi failure so
    /// Koi never starts a second responder beside an unhealthy one.
    pub async fn probe() -> AvahiProbe {
        let connection = match Connection::system().await {
            Ok(connection) => connection,
            Err(error) => {
                return AvahiProbe::Absent(format!("system D-Bus unavailable: {error}"));
            }
        };

        let dbus = match zbus::fdo::DBusProxy::new(&connection).await {
            Ok(proxy) => proxy,
            Err(error) => {
                return AvahiProbe::Unavailable(format!(
                    "cannot inspect the system D-Bus: {error}"
                ));
            }
        };
        let name = match BusName::try_from(AVAHI_DESTINATION) {
            Ok(name) => name,
            Err(error) => {
                return AvahiProbe::Unavailable(format!("invalid Avahi D-Bus name: {error}"));
            }
        };
        match dbus.name_has_owner(name).await {
            Ok(false) => {
                return AvahiProbe::Absent("Avahi has no live system D-Bus owner".to_string());
            }
            Err(error) => {
                return AvahiProbe::Unavailable(format!(
                    "cannot determine whether Avahi is running: {error}"
                ));
            }
            Ok(true) => {}
        }

        let server = match AvahiServerProxy::new(&connection).await {
            Ok(server) => server,
            Err(error) => {
                return AvahiProbe::Unavailable(format!(
                    "cannot create the Avahi server proxy: {error}"
                ));
            }
        };
        let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
        loop {
            match server.get_state().await {
                Ok(AVAHI_SERVER_RUNNING) => break,
                Ok(AVAHI_SERVER_FAILURE) => {
                    return AvahiProbe::Unavailable(
                        "Avahi reports a fatal server failure".to_string(),
                    );
                }
                Ok(state) if tokio::time::Instant::now() < deadline => {
                    tracing::debug!(state, "Waiting for Avahi to reach running state");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(state) => {
                    return AvahiProbe::Unavailable(format!(
                        "Avahi did not reach running state (state {state})"
                    ));
                }
                Err(error) => {
                    return AvahiProbe::Unavailable(format!(
                        "Avahi is present but GetState failed: {error}"
                    ));
                }
            }
        }

        let version = server
            .get_version_string()
            .await
            .unwrap_or_else(|_| "version unavailable".to_string());
        let owner = match current_owner(&connection).await {
            Ok(Some(owner)) => owner,
            Ok(None) => {
                return AvahiProbe::Unavailable("Avahi disappeared during bootstrap".to_string());
            }
            Err(error) => return AvahiProbe::Unavailable(error),
        };

        AvahiProbe::Ready(Self::start(connection, owner, version))
    }

    fn start(connection: Connection, owner: String, version: String) -> Self {
        let detail = format!("{version} via system D-Bus");
        let status = Arc::new(RwLock::new(ProviderStatus {
            name: "avahi",
            healthy: true,
            detail,
        }));
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let actor = AvahiActor {
            connection,
            command_rx,
            status: Arc::clone(&status),
            version,
            owner: Some(owner),
            registrations: HashMap::new(),
            entry_groups: HashMap::new(),
            browsers: HashMap::new(),
        };
        tokio::spawn(actor.run());
        Self { command_tx, status }
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
                    set_status(
                        &self.status,
                        false,
                        format!("Avahi browse startup failed: {error}"),
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
                "Avahi is not running; waiting for the selected provider to return".to_string(),
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
                set_status(
                    &self.status,
                    false,
                    format!(
                        "Avahi could not publish {}.{}: {error}",
                        registration.name, registration.service_type
                    ),
                );
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
        let status = Arc::clone(&self.status);
        let task = if is_meta {
            tokio::spawn(async move {
                pump_service_types(connection, task_path, tx, status, ready_tx).await;
            })
        } else {
            tokio::spawn(async move {
                pump_services(connection, task_path, tx, status, ready_tx).await;
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
    let host = if registration.ip.is_some() {
        server
            .get_host_name_fqdn()
            .await
            .map_err(|error| format!("GetHostNameFqdn failed: {error}"))?
    } else {
        String::new()
    };

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
                &host,
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
                    AVAHI_FLAGS_NONE,
                    &host,
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
    status: Arc<RwLock<ProviderStatus>>,
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
                match resolve_observation(
                    &connection,
                    *args.interface(),
                    *args.protocol(),
                    args.name(),
                    args.service_type(),
                    args.domain(),
                ).await {
                    Ok(service) => {
                        if tx.send(ProviderEvent::Resolved(service)).await.is_err() {
                            return;
                        }
                    }
                    Err(error) => tracing::debug!(%error, "Avahi service resolve failed"),
                }
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
        }
    }
    set_status(
        &status,
        false,
        "Avahi service browser ended; Koi is retrying".to_string(),
    );
}

async fn pump_service_types(
    connection: Connection,
    path: OwnedObjectPath,
    tx: mpsc::Sender<ProviderEvent>,
    status: Arc<RwLock<ProviderStatus>>,
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
    set_status(
        &status,
        false,
        "Avahi type browser ended; Koi is retrying".to_string(),
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
    fn zbus_is_isolated_to_the_avahi_adapter() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&src_dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) == Some("avahi.rs") {
                continue;
            }
            let contents = std::fs::read_to_string(&path).expect("read source file");
            if contents.contains("zbus") {
                offenders.push(path.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "zbus must only be referenced in avahi.rs; offenders: {offenders:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a running Avahi daemon on the system bus"]
    async fn real_avahi_publish_browse_resolve_and_remove() {
        let provider = match AvahiMdnsProvider::probe().await {
            AvahiProbe::Ready(provider) => provider,
            AvahiProbe::Absent(reason) | AvahiProbe::Unavailable(reason) => {
                panic!("Avahi is required for this test: {reason}")
            }
        };
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
        provider
            .unregister(&explicit_name, "_koi-test._tcp.local.")
            .expect("withdraw real explicit-IP Avahi publication");
        provider.shutdown().await.expect("shut down Avahi adapter");
    }
}
