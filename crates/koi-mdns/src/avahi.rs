//! Linux mDNS provider backed by Avahi's system D-Bus API.
//!
//! The adapter owns Avahi entry groups and browse objects, translates their
//! signals into provider-neutral observations, and performs short, local D-Bus
//! recovery while the control plane decides whether to change capability routes.

#![allow(clippy::too_many_arguments)] // Avahi's fixed D-Bus method signatures.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::{mpsc, oneshot, watch};
use zbus::names::BusName;
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

use crate::adapter::{
    failed_assessment, MdnsAdapter, MdnsCapabilities, MdnsProviderReport, ProbeFact, ProviderApi,
    ProviderAvailability, ProviderDescriptor, ProviderSessionState,
};
use crate::error::{MdnsError, ProviderFailure, ProviderOperation, Result};
use crate::provider::{
    provider_error, Announcement, BrowseLease, ProviderAddress, ProviderBrowse, ProviderEvent,
    ProviderService, ProviderSession, PublicationLease,
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

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor::new(
    "avahi",
    AVAHI_PRIORITY,
    ProviderApi::SystemDbus,
    MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
);

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
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn assess(&self) -> MdnsProviderReport {
        match inspect_avahi(self).await {
            Ok(ready) => ready_report(self, &ready.version),
            Err(report) => report,
        }
    }

    async fn open(&self) -> Result<Arc<dyn ProviderSession>> {
        let ready = inspect_avahi(self).await.map_err(|report| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Open,
                ProviderFailure::Unavailable,
                report.detail,
            )
        })?;
        Ok(Arc::new(AvahiSession::start(
            ready.connection,
            ready.owner,
            ready.version,
        )))
    }
}

fn ready_report(_adapter: &AvahiAdapter, version: &str) -> MdnsProviderReport {
    MdnsProviderReport {
        name: DESCRIPTOR.name.to_string(),
        priority: DESCRIPTOR.priority,
        api: DESCRIPTOR.api,
        availability: ProviderAvailability::Ready,
        installed: ProbeFact::Yes,
        configured: ProbeFact::Yes,
        running: ProbeFact::Yes,
        capabilities: DESCRIPTOR.capabilities,
        session: None,
        detail: format!("{version} running on the system D-Bus"),
    }
}

async fn inspect_avahi(
    _adapter: &AvahiAdapter,
) -> std::result::Result<ReadyAvahi, MdnsProviderReport> {
    let failed = |availability, detail| failed_assessment(DESCRIPTOR, availability, detail);
    let connection = Connection::system().await.map_err(|error| {
        failed(
            ProviderAvailability::Unavailable,
            format!("system D-Bus unavailable: {error}"),
        )
    })?;

    let dbus = zbus::fdo::DBusProxy::new(&connection)
        .await
        .map_err(|error| {
            failed(
                ProviderAvailability::Unavailable,
                format!("cannot inspect the system D-Bus: {error}"),
            )
        })?;
    let bus_name = BusName::try_from(AVAHI_DESTINATION).map_err(|error| {
        failed(
            ProviderAvailability::Unavailable,
            format!("invalid Avahi D-Bus name: {error}"),
        )
    })?;
    let has_owner = dbus.name_has_owner(bus_name).await.map_err(|error| {
        failed(
            ProviderAvailability::Unavailable,
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
        return Err(MdnsProviderReport {
            name: DESCRIPTOR.name.to_string(),
            priority: DESCRIPTOR.priority,
            api: DESCRIPTOR.api,
            availability: ProviderAvailability::Absent,
            installed,
            configured: ProbeFact::Unknown,
            running: ProbeFact::No,
            capabilities: MdnsCapabilities::default(),
            session: None,
            detail: "no live D-Bus owner; Koi did not activate the stopped service".to_string(),
        });
    }

    let server = AvahiServerProxy::new(&connection).await.map_err(|error| {
        failed(
            ProviderAvailability::Unavailable,
            format!("cannot create the Avahi server proxy: {error}"),
        )
    })?;
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        match server.get_state().await {
            Ok(AVAHI_SERVER_RUNNING) => break,
            Ok(AVAHI_SERVER_FAILURE) => {
                return Err(failed(
                    ProviderAvailability::Unavailable,
                    "Avahi reports a fatal server failure".to_string(),
                ));
            }
            Ok(state) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(state, "Waiting for Avahi to reach running state");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(state) => {
                return Err(failed(
                    ProviderAvailability::Unavailable,
                    format!("Avahi did not reach running state (state {state})"),
                ));
            }
            Err(error) => {
                return Err(failed(
                    ProviderAvailability::Unavailable,
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
        .map_err(|error| failed(ProviderAvailability::Unavailable, error))?
        .ok_or_else(|| {
            failed(
                ProviderAvailability::Unavailable,
                "Avahi disappeared during inspection".to_string(),
            )
        })?;

    Ok(ReadyAvahi {
        connection,
        owner,
        version,
    })
}

/// One opened Avahi provider epoch.
pub struct AvahiSession {
    connection: Connection,
    command_tx: mpsc::Sender<Command>,
    state_rx: watch::Receiver<ProviderSessionState>,
}

impl AvahiSession {
    fn start(connection: Connection, owner: String, version: String) -> Self {
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (state_tx, state_rx) = watch::channel(ProviderSessionState::Ready);
        let actor = AvahiActor {
            connection: connection.clone(),
            command_rx,
            state_tx,
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
            state_rx,
        }
    }

    async fn send(&self, command: Command, operation: ProviderOperation) -> Result<()> {
        self.command_tx.send(command).await.map_err(|_| {
            provider_error(
                DESCRIPTOR.name,
                operation,
                ProviderFailure::Lost,
                "Avahi session stopped",
            )
        })
    }
}

#[async_trait::async_trait]
impl ProviderSession for AvahiSession {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    fn capabilities(&self) -> MdnsCapabilities {
        DESCRIPTOR.capabilities
    }

    fn state(&self) -> watch::Receiver<ProviderSessionState> {
        self.state_rx.clone()
    }

    async fn publish(&self, announcement: &Announcement) -> Result<Box<dyn PublicationLease>> {
        validate_instance_name(&announcement.name)?;
        let txt = encode_txt(&announcement.txt)?;
        let (service_type, domain) = split_service_type(&announcement.service_type)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(
            Command::Publish {
                registration: Registration {
                    key: announcement.id.clone(),
                    name: announcement.name.clone(),
                    service_type,
                    domain,
                    port: announcement.port,
                    ip: announcement.address,
                    txt,
                },
                reply: reply_tx,
            },
            ProviderOperation::Publish,
        )
        .await?;
        reply_rx
            .await
            .map_err(|_| avahi_lost(ProviderOperation::Publish, "actor dropped reply"))??;
        Ok(Box::new(AvahiPublicationLease {
            id: announcement.id.clone(),
            command_tx: self.command_tx.clone(),
            withdrawn: false,
        }))
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
            .map_err(|_| avahi_lost(ProviderOperation::Browse, "actor stopped"))?;
        let events = reply_rx
            .await
            .map_err(|_| avahi_lost(ProviderOperation::Browse, "actor dropped reply"))??;
        Ok(ProviderBrowse::new(
            events,
            Box::new(AvahiBrowseLease {
                key: service_type.to_string(),
                command_tx: self.command_tx.clone(),
                closed: false,
            }),
        ))
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
        .map_err(|error| avahi_protocol(ProviderOperation::Resolve, error))
    }

    async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Shutdown(reply_tx))
            .await
            .map_err(|_| avahi_lost(ProviderOperation::Shutdown, "actor stopped"))?;
        reply_rx
            .await
            .map_err(|_| avahi_lost(ProviderOperation::Shutdown, "actor dropped reply"))?
    }
}

struct AvahiPublicationLease {
    id: String,
    command_tx: mpsc::Sender<Command>,
    withdrawn: bool,
}

#[async_trait::async_trait]
impl PublicationLease for AvahiPublicationLease {
    fn announcement_id(&self) -> &str {
        &self.id
    }

    fn provider_name(&self) -> &'static str {
        DESCRIPTOR.name
    }

    async fn withdraw(&mut self) -> Result<()> {
        if self.withdrawn {
            return Ok(());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        match self
            .command_tx
            .send(Command::Withdraw {
                key: self.id.clone(),
                reply: reply_tx,
            })
            .await
        {
            Ok(()) => {
                reply_rx.await.map_err(|_| {
                    avahi_lost(ProviderOperation::Withdraw, "actor dropped reply")
                })??;
            }
            Err(_) => {
                // A stopped session has already released all D-Bus-owned objects.
            }
        }
        self.withdrawn = true;
        Ok(())
    }
}

struct AvahiBrowseLease {
    key: String,
    command_tx: mpsc::Sender<Command>,
    closed: bool,
}

#[async_trait::async_trait]
impl BrowseLease for AvahiBrowseLease {
    fn provider_name(&self) -> &'static str {
        DESCRIPTOR.name
    }

    async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .command_tx
            .send(Command::CloseBrowse {
                key: self.key.clone(),
                reply: reply_tx,
            })
            .await
            .is_ok()
        {
            reply_rx.await.map_err(|_| {
                avahi_lost(ProviderOperation::Browse, "actor dropped close reply")
            })??;
        }
        self.closed = true;
        Ok(())
    }
}

enum Command {
    Publish {
        registration: Registration,
        reply: oneshot::Sender<Result<()>>,
    },
    Withdraw {
        key: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Browse {
        key: String,
        is_meta: bool,
        reply: oneshot::Sender<Result<mpsc::Receiver<ProviderEvent>>>,
    },
    CloseBrowse {
        key: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Shutdown(oneshot::Sender<Result<()>>),
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

struct BrowserRuntime {
    path: OwnedObjectPath,
    task: Option<tokio::task::JoinHandle<()>>,
}

struct Browser {
    is_meta: bool,
    event_tx: mpsc::Sender<ProviderEvent>,
    runtime: Option<BrowserRuntime>,
}

struct AvahiActor {
    connection: Connection,
    command_rx: mpsc::Receiver<Command>,
    state_tx: watch::Sender<ProviderSessionState>,
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
                        let _ = self.release_all().await;
                        break;
                    };
                    if !self.handle(command).await {
                        break;
                    }
                }
                _ = reconcile.tick() => self.reconcile().await,
            }
        }
        self.state_tx.send_replace(ProviderSessionState::Lost);
    }

    async fn handle(&mut self, command: Command) -> bool {
        match command {
            Command::Publish {
                registration,
                reply,
            } => {
                let key = registration.key.clone();
                let result = if *self.state_tx.borrow() != ProviderSessionState::Ready {
                    Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Publish,
                        ProviderFailure::Recovering,
                        "Avahi is recovering its D-Bus resources",
                    ))
                } else if self.registrations.contains_key(&key) {
                    Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Publish,
                        ProviderFailure::Conflict,
                        format!("publication {key} already exists"),
                    ))
                } else {
                    self.registrations.insert(key.clone(), registration);
                    match self.establish_publication(&key).await {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            self.registrations.remove(&key);
                            Err(error)
                        }
                    }
                };
                let _ = reply.send(result);
            }
            Command::Withdraw { key, reply } => {
                let result = self.free_entry_group(&key).await;
                if result.is_ok() {
                    self.registrations.remove(&key);
                }
                let _ = reply.send(result);
            }
            Command::Browse {
                key,
                is_meta,
                reply,
            } => {
                if self.browsers.contains_key(&key) {
                    let _ = reply.send(Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Browse,
                        ProviderFailure::Conflict,
                        format!("browse already exists for {key}"),
                    )));
                    return true;
                }
                let (event_tx, event_rx) = mpsc::channel(BROWSE_CAPACITY);
                self.browsers.insert(
                    key.clone(),
                    Browser {
                        is_meta,
                        event_tx,
                        runtime: None,
                    },
                );
                let result = self.start_browser_resource(&key).await;
                if let Err(error) = result {
                    let cleanup = self.remove_browser(&key, true).await;
                    let _ = reply.send(cleanup.and(Err(error)));
                } else {
                    if let Err(Ok(_events)) = reply.send(Ok(event_rx)) {
                        let _ = self.remove_browser(&key, true).await;
                    }
                }
            }
            Command::CloseBrowse { key, reply } => {
                let result = self.remove_browser(&key, true).await;
                let _ = reply.send(result);
            }
            Command::Shutdown(reply) => {
                let result = self.release_all().await;
                let complete = result.is_ok();
                let _ = reply.send(result);
                if complete {
                    return false;
                }
            }
        }
        true
    }

    async fn reconcile(&mut self) {
        let owner = match current_owner(&self.connection).await {
            Ok(owner) => owner,
            Err(error) => {
                self.deactivate(false).await;
                self.state_tx.send_replace(ProviderSessionState::Recovering);
                tracing::debug!(provider = DESCRIPTOR.name, %error, "D-Bus owner check failed");
                return;
            }
        };
        if owner != self.owner {
            tracing::info!(provider = DESCRIPTOR.name, old = ?self.owner, new = ?owner, "D-Bus owner epoch changed");
            self.deactivate(false).await;
            self.owner = owner;
        }
        if self.owner.is_none() {
            self.state_tx.send_replace(ProviderSessionState::Recovering);
            return;
        }

        let server = match AvahiServerProxy::new(&self.connection).await {
            Ok(server) => server,
            Err(error) => {
                self.deactivate(true).await;
                self.state_tx.send_replace(ProviderSessionState::Recovering);
                tracing::debug!(provider = DESCRIPTOR.name, %error, "server proxy unavailable");
                return;
            }
        };
        match server.get_state().await {
            Ok(AVAHI_SERVER_RUNNING) => {}
            Ok(AVAHI_SERVER_FAILURE) => {
                self.deactivate(true).await;
                self.state_tx.send_replace(ProviderSessionState::Lost);
                return;
            }
            Ok(state) => {
                self.deactivate(true).await;
                self.state_tx.send_replace(ProviderSessionState::Recovering);
                tracing::debug!(provider = DESCRIPTOR.name, state, "server not running");
                return;
            }
            Err(error) => {
                self.deactivate(true).await;
                self.state_tx.send_replace(ProviderSessionState::Recovering);
                tracing::debug!(provider = DESCRIPTOR.name, %error, "server state unavailable");
                return;
            }
        }

        self.state_tx.send_replace(ProviderSessionState::Recovering);
        let missing_publications = self
            .registrations
            .keys()
            .filter(|key| !self.entry_groups.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        for key in missing_publications {
            if let Err(error) = self.establish_publication(&key).await {
                tracing::warn!(provider = DESCRIPTOR.name, publication = %key, %error, "publication recovery failed");
            }
        }

        let browser_keys = self.browsers.keys().cloned().collect::<Vec<_>>();
        for key in browser_keys {
            let restart = self.browsers.get(&key).is_some_and(|browser| {
                browser.runtime.as_ref().is_none_or(|runtime| {
                    runtime
                        .task
                        .as_ref()
                        .is_none_or(tokio::task::JoinHandle::is_finished)
                })
            });
            if restart {
                if let Err(error) = self.free_browser_runtime(&key, true).await {
                    tracing::warn!(provider = DESCRIPTOR.name, service_type = %key, %error, "stale browse release failed");
                    continue;
                }
                if let Err(error) = self.start_browser_resource(&key).await {
                    tracing::warn!(provider = DESCRIPTOR.name, service_type = %key, %error, "browse recovery failed");
                }
            }
        }

        let synchronized = self.entry_groups.len() == self.registrations.len()
            && self
                .browsers
                .values()
                .all(|browser| browser.runtime.is_some());
        if synchronized {
            self.state_tx.send_replace(ProviderSessionState::Ready);
            tracing::trace!(provider = DESCRIPTOR.name, version = %self.version, "provider session ready");
        }
    }

    async fn establish_publication(&mut self, key: &str) -> Result<()> {
        let registration = self.registrations.get(key).cloned().ok_or_else(|| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Publish,
                ProviderFailure::Rejected,
                format!("unknown publication {key}"),
            )
        })?;
        match publish(&self.connection, &registration).await {
            Ok((path, effective_name)) => {
                if effective_name != registration.name {
                    tracing::warn!(
                        provider = DESCRIPTOR.name,
                        requested = %registration.name,
                        effective = %effective_name,
                        service_type = %registration.service_type,
                        "service-name collision resolved"
                    );
                    if let Some(stored) = self.registrations.get_mut(key) {
                        stored.name = effective_name;
                    }
                }
                self.entry_groups.insert(key.to_string(), path);
                Ok(())
            }
            Err(error) => Err(avahi_protocol(ProviderOperation::Publish, error)),
        }
    }

    async fn start_browser_resource(&mut self, key: &str) -> Result<()> {
        if self.owner.is_none() {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Recovering,
                "Avahi has no live D-Bus owner",
            ));
        }
        let (is_meta, event_tx) = self
            .browsers
            .get(key)
            .map(|browser| (browser.is_meta, browser.event_tx.clone()))
            .ok_or_else(|| avahi_lost(ProviderOperation::Browse, "browse demand vanished"))?;
        let server = AvahiServerProxy::new(&self.connection)
            .await
            .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?;
        let path = if is_meta {
            server
                .service_type_browser_new(
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    "local",
                    AVAHI_FLAGS_NONE,
                )
                .await
                .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?
        } else {
            let (service_type, domain) = split_service_type(key)?;
            server
                .service_browser_new(
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    &service_type,
                    &domain,
                    AVAHI_FLAGS_NONE,
                )
                .await
                .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?
        };
        let (ready_tx, ready_rx) = oneshot::channel();
        let connection = self.connection.clone();
        let task_path = path.clone();
        let task = if is_meta {
            tokio::spawn(async move {
                pump_service_types(connection, task_path, event_tx, ready_tx).await;
            })
        } else {
            tokio::spawn(async move {
                pump_services(connection, task_path, event_tx, ready_tx).await;
            })
        };
        let Some(browser) = self.browsers.get_mut(key) else {
            task.abort();
            free_browser_object(&self.connection, &path, is_meta).await?;
            return Err(avahi_lost(
                ProviderOperation::Browse,
                "browse demand vanished",
            ));
        };
        browser.runtime = Some(BrowserRuntime {
            path,
            task: Some(task),
        });
        match ready_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.free_browser_runtime(key, true).await?;
                Err(avahi_protocol(ProviderOperation::Browse, error))
            }
            Err(_) => {
                self.free_browser_runtime(key, true).await?;
                Err(avahi_lost(
                    ProviderOperation::Browse,
                    "browse pump stopped during establishment",
                ))
            }
        }
    }

    async fn free_entry_group(&mut self, key: &str) -> Result<()> {
        let Some(path) = self.entry_groups.get(key).cloned() else {
            return Ok(());
        };
        let result = async {
            let proxy = AvahiEntryGroupProxy::builder(&self.connection)
                .path(path)
                .map_err(|error| avahi_protocol(ProviderOperation::Withdraw, error))?
                .build()
                .await
                .map_err(|error| avahi_protocol(ProviderOperation::Withdraw, error))?;
            proxy
                .free()
                .await
                .map_err(|error| avahi_protocol(ProviderOperation::Withdraw, error))
        }
        .await;
        self.finish_release(key, result).await
    }

    async fn free_browser_runtime(&mut self, key: &str, free_object: bool) -> Result<()> {
        let Some((is_meta, mut runtime)) = self.browsers.get_mut(key).and_then(|browser| {
            browser
                .runtime
                .take()
                .map(|runtime| (browser.is_meta, runtime))
        }) else {
            return Ok(());
        };
        if let Some(task) = runtime.task.take() {
            task.abort();
            let _ = task.await;
        }
        if free_object {
            if let Err(error) = free_browser_object(&self.connection, &runtime.path, is_meta).await
            {
                if self.owner_advanced().await {
                    return Ok(());
                }
                if let Some(browser) = self.browsers.get_mut(key) {
                    browser.runtime = Some(runtime);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    async fn remove_browser(&mut self, key: &str, free_object: bool) -> Result<()> {
        self.free_browser_runtime(key, free_object).await?;
        self.browsers.remove(key);
        Ok(())
    }

    async fn deactivate(&mut self, free_objects: bool) {
        let group_keys = self.entry_groups.keys().cloned().collect::<Vec<_>>();
        if free_objects {
            for key in group_keys {
                if let Err(error) = self.free_entry_group(&key).await {
                    tracing::debug!(provider = DESCRIPTOR.name, %error, "entry-group release deferred");
                }
            }
        } else {
            self.entry_groups.clear();
        }
        let browser_keys = self.browsers.keys().cloned().collect::<Vec<_>>();
        for key in browser_keys {
            if let Err(error) = self.free_browser_runtime(&key, free_objects).await {
                tracing::debug!(provider = DESCRIPTOR.name, %error, "browser release deferred");
            }
        }
    }

    async fn release_all(&mut self) -> Result<()> {
        let mut first_error = None;
        let browser_keys = self.browsers.keys().cloned().collect::<Vec<_>>();
        for key in browser_keys {
            if let Err(error) = self.remove_browser(&key, true).await {
                first_error.get_or_insert(error);
            }
        }
        let group_keys = self.entry_groups.keys().cloned().collect::<Vec<_>>();
        for key in group_keys {
            if let Err(error) = self.free_entry_group(&key).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            self.registrations.clear();
            Ok(())
        }
    }

    async fn finish_release(&mut self, key: &str, result: Result<()>) -> Result<()> {
        match result {
            Ok(()) => {
                self.entry_groups.remove(key);
                Ok(())
            }
            Err(error) => {
                if self.owner_advanced().await {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn owner_advanced(&mut self) -> bool {
        match current_owner(&self.connection).await {
            Ok(owner) if owner != self.owner => {
                self.owner = owner;
                self.entry_groups.clear();
                let mut tasks = Vec::new();
                for browser in self.browsers.values_mut() {
                    if let Some(runtime) = browser.runtime.take() {
                        if let Some(task) = runtime.task {
                            task.abort();
                            tasks.push(task);
                        }
                    }
                }
                for task in tasks {
                    let _ = task.await;
                }
                true
            }
            _ => false,
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
    let host = registration
        .ip
        .map(|_| explicit_address_host(&registration.key));

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
            let Some(host) = host.as_deref() else {
                let _ = group.free().await;
                return Err("explicit address publication has no host alias".to_string());
            };
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
                    host,
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

async fn free_browser_object(
    connection: &Connection,
    path: &OwnedObjectPath,
    is_meta: bool,
) -> Result<()> {
    if is_meta {
        let proxy = AvahiServiceTypeBrowserProxy::builder(connection)
            .path(path.clone())
            .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?
            .build()
            .await
            .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?;
        proxy
            .free()
            .await
            .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?;
    } else {
        let proxy = AvahiServiceBrowserProxy::builder(connection)
            .path(path.clone())
            .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?
            .build()
            .await
            .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?;
        proxy
            .free()
            .await
            .map_err(|error| avahi_protocol(ProviderOperation::Browse, error))?;
    }
    Ok(())
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

fn explicit_address_host(registration_id: &str) -> String {
    // An explicit address needs its own host record. Reusing Avahi's machine
    // hostname attempts to claim a name the daemon already owns, while sharing
    // one synthetic hostname across registrations makes their entry groups
    // contend with each other. A stable per-registration alias keeps each SRV
    // + A/AAAA set self-contained and survives an Avahi owner-epoch rebuild.
    let hash = registration_id
        .bytes()
        .fold(0xcbf29ce484222325_u64, |hash, byte| {
            hash.wrapping_mul(0x100000001b3) ^ u64::from(byte)
        });
    format!("koi-{hash:016x}.local")
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

fn avahi_lost(operation: ProviderOperation, detail: impl Into<String>) -> MdnsError {
    provider_error(DESCRIPTOR.name, operation, ProviderFailure::Lost, detail)
}

fn avahi_protocol(operation: ProviderOperation, error: impl std::fmt::Display) -> MdnsError {
    provider_error(
        DESCRIPTOR.name,
        operation,
        ProviderFailure::Protocol,
        error.to_string(),
    )
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
        let first = explicit_address_host("first");
        let second = explicit_address_host("second");
        assert_eq!(first, explicit_address_host("first"));
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
        let report = adapter.assess().await;
        assert_eq!(
            report.availability,
            ProviderAvailability::Ready,
            "{report:?}"
        );
        assert!(
            report.capabilities.satisfies_provider_contract(),
            "Avahi report: {report:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a running Avahi daemon on the system bus"]
    async fn real_avahi_publish_browse_resolve_and_remove() {
        let adapter = AvahiAdapter;
        let session = adapter.open().await.expect("open real Avahi session");
        let mut browse = session
            .browse("_koi-test._tcp.local.", false)
            .await
            .expect("start real Avahi browse");
        let name = format!("koi-avahi-{}", std::process::id());
        let announcement = Announcement {
            id: format!("avahi-{}", std::process::id()),
            name: name.clone(),
            service_type: "_koi-test._tcp.local.".to_string(),
            port: 43123,
            address: None,
            txt: HashMap::from([("source".to_string(), "koi".to_string())]),
        };
        let mut lease = session
            .publish(&announcement)
            .await
            .expect("establish real Avahi publication");

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

        lease
            .withdraw()
            .await
            .expect("withdraw real Avahi publication");
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
        let explicit_announcement = Announcement {
            id: format!("avahi-explicit-{}", std::process::id()),
            name: explicit_name.clone(),
            service_type: "_koi-test._tcp.local.".to_string(),
            port: 43124,
            address: Some(IpAddr::V4(explicit_ip)),
            txt: HashMap::new(),
        };
        let mut explicit_lease = session
            .publish(&explicit_announcement)
            .await
            .expect("establish real Avahi publication with an explicit address");
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
        assert_eq!(*session.state().borrow(), ProviderSessionState::Ready);
        explicit_lease
            .withdraw()
            .await
            .expect("withdraw real explicit-IP Avahi publication");
        browse.close().await.expect("close real Avahi browse");
        session.shutdown().await.expect("shut down Avahi session");
    }
}
