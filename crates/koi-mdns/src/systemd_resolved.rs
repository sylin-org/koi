//! Linux mDNS provider backed by systemd-resolved's resolve1 D-Bus API.
//!
//! resolve1 is a partial provider: supported releases can publish DNS-SD
//! services and resolve a specific instance, but expose neither continuous
//! browse nor explicit-address publication. The adapter owns live API/config
//! detection; an opened session owns object paths and reconstructs them across
//! D-Bus owner epochs.

#![allow(clippy::too_many_arguments)] // resolve1's fixed D-Bus signatures.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use tokio::sync::{mpsc, oneshot, watch};
use zbus::message::{Message, Type as MessageType};
use zbus::names::BusName;
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::{Connection, MatchRule, MessageStream};

use crate::adapter::{
    failed_assessment, MdnsAdapter, MdnsCapabilities, MdnsProviderReport, ProbeFact, ProviderApi,
    ProviderAvailability, ProviderDescriptor, ProviderSessionState,
};
use crate::error::{MdnsError, ProviderFailure, ProviderOperation};
use crate::provider::{
    provider_error, Announcement, ProviderAddress, ProviderBrowse, ProviderService,
    ProviderSession, PublicationLease,
};
use crate::Result;

const RESOLVE_DESTINATION: &str = "org.freedesktop.resolve1";
const POLKIT_DESTINATION: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const REGISTER_SERVICE_ACTION: &str = "org.freedesktop.resolve1.register-service";
const DNSSD_SERVICE_INTERFACE: &str = "org.freedesktop.resolve1.DnssdService";
const CONFLICT_MEMBER: &str = "Conflicted";
const RESOLVED_PRIORITY: u16 = 200;
const COMMAND_CAPACITY: usize = 256;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
/// resolve1 accepts `RegisterService` before mDNS conflict probing completes.
/// Its object emits `Conflicted` and is withdrawn if that later probe loses.
const PUBLICATION_SETTLE_INTERVAL: Duration = Duration::from_secs(5);

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor::new(
    "systemd-resolved",
    RESOLVED_PRIORITY,
    ProviderApi::SystemDbus,
    MdnsCapabilities {
        publish: true,
        withdraw: true,
        continuous_browse: false,
        browse_resolves: false,
        direct_resolve: true,
        explicit_address: false,
    },
);

type ResolveServiceReply = (
    Vec<(u16, u16, u16, String, Vec<(i32, i32, Vec<u8>)>, String)>,
    Vec<Vec<u8>>,
    String,
    String,
    String,
    u64,
);

#[zbus::proxy(
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1",
    interface = "org.freedesktop.resolve1.Manager"
)]
trait ResolveManager {
    #[zbus(property, name = "MulticastDNS")]
    fn multicast_dns(&self) -> zbus::Result<String>;

    #[zbus(name = "RegisterService")]
    fn register_service(
        &self,
        id: &str,
        name_template: &str,
        service_type: &str,
        service_port: u16,
        service_priority: u16,
        service_weight: u16,
        txt_data: Vec<HashMap<String, Vec<u8>>>,
    ) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "UnregisterService")]
    fn unregister_service(&self, service_path: &OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(name = "ResolveService")]
    fn resolve_service(
        &self,
        interface_index: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        family: i32,
        flags: u64,
    ) -> zbus::Result<ResolveServiceReply>;
}

#[zbus::proxy(
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1",
    interface = "org.freedesktop.DBus.Introspectable"
)]
trait ResolveIntrospectable {
    #[zbus(name = "Introspect")]
    fn introspect(&self) -> zbus::Result<String>;
}

#[derive(Debug, Default)]
pub struct SystemdResolvedAdapter;

#[async_trait::async_trait]
impl MdnsAdapter for SystemdResolvedAdapter {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn assess(&self) -> MdnsProviderReport {
        match inspect_resolved().await {
            Ok(ready) => ready.report,
            Err(report) => report,
        }
    }

    async fn open(&self) -> Result<Arc<dyn ProviderSession>> {
        let ready = inspect_resolved().await.map_err(|report| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Open,
                ProviderFailure::Unavailable,
                report.detail,
            )
        })?;
        Ok(Arc::new(
            ResolvedSession::start(ready.connection, ready.owner, ready.capabilities).await?,
        ))
    }
}

struct ResolvedInspection {
    connection: Connection,
    owner: String,
    capabilities: MdnsCapabilities,
    report: MdnsProviderReport,
}

async fn inspect_resolved() -> std::result::Result<ResolvedInspection, MdnsProviderReport> {
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
    let bus_name = BusName::try_from(RESOLVE_DESTINATION).map_err(|error| {
        failed(
            ProviderAvailability::Unavailable,
            format!("invalid resolve1 D-Bus name: {error}"),
        )
    })?;
    let has_owner = dbus.name_has_owner(bus_name).await.map_err(|error| {
        failed(
            ProviderAvailability::Unavailable,
            format!("cannot determine whether resolve1 is running: {error}"),
        )
    })?;
    if !has_owner {
        let installed = dbus
            .list_activatable_names()
            .await
            .map(|names| {
                if names
                    .iter()
                    .any(|name| name.as_str() == RESOLVE_DESTINATION)
                {
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
            detail: "resolve1 has no live D-Bus owner; Koi did not activate it".to_string(),
        });
    }

    let (owner, mode, capabilities, authorization) =
        inspect_live(&connection).await.map_err(|error| {
            failed(
                ProviderAvailability::Unavailable,
                format!("resolve1 live API inspection failed: {error}"),
            )
        })?;
    let configured = configured_fact(&mode);
    let has_operation = capabilities.publish || capabilities.direct_resolve;
    if configured != ProbeFact::Yes || !has_operation {
        return Err(MdnsProviderReport {
            name: DESCRIPTOR.name.to_string(),
            priority: DESCRIPTOR.priority,
            api: DESCRIPTOR.api,
            availability: ProviderAvailability::Unavailable,
            installed: ProbeFact::Yes,
            configured,
            running: ProbeFact::Yes,
            capabilities,
            session: None,
            detail: format!(
                "resolve1 MulticastDNS={mode}; {authorization}; usable APIs {}; continuous browse and explicit-address publication unavailable",
                capabilities.summary()
            ),
        });
    }

    let report = MdnsProviderReport {
        name: DESCRIPTOR.name.to_string(),
        priority: DESCRIPTOR.priority,
        api: DESCRIPTOR.api,
        availability: ProviderAvailability::Ready,
        installed: ProbeFact::Yes,
        configured,
        running: ProbeFact::Yes,
        capabilities,
        session: None,
        detail: format!(
            "resolve1 MulticastDNS={mode}; {authorization}; live APIs {}; continuous browse and explicit-address publication unavailable",
            capabilities.summary()
        ),
    };
    Ok(ResolvedInspection {
        connection,
        owner,
        capabilities,
        report,
    })
}

async fn inspect_live(
    connection: &Connection,
) -> std::result::Result<(String, String, MdnsCapabilities, String), String> {
    let owner = current_owner(connection)
        .await?
        .ok_or_else(|| "resolve1 has no live D-Bus owner".to_string())?;
    let manager = ResolveManagerProxy::new(connection)
        .await
        .map_err(|error| format!("cannot create resolve1 manager proxy: {error}"))?;
    let mode = manager
        .multicast_dns()
        .await
        .map_err(|error| format!("MulticastDNS property failed: {error}"))?;
    let introspection = ResolveIntrospectableProxy::new(connection)
        .await
        .map_err(|error| format!("cannot create introspection proxy: {error}"))?
        .introspect()
        .await
        .map_err(|error| format!("API introspection failed: {error}"))?;
    let api_capabilities = capabilities_from(&mode, &introspection, true);
    let (publication_authorized, authorization) = if api_capabilities.publish {
        publication_authorization(connection).await
    } else {
        (
            false,
            "publication API or announce mode unavailable".to_string(),
        )
    };
    Ok((
        owner,
        mode.clone(),
        capabilities_from(&mode, &introspection, publication_authorized),
        authorization,
    ))
}

/// Check the exact non-interactive authorization resolve1 will apply to this
/// session's system-bus identity. Merely introspecting `RegisterService` is not
/// enough: user-scoped daemons commonly see the method but are denied by
/// polkit, while resolution remains available.
async fn publication_authorization(connection: &Connection) -> (bool, String) {
    let Some(unique_name) = connection.unique_name() else {
        return (
            false,
            "publication authorization unavailable: connection has no unique bus name".to_string(),
        );
    };
    let authority = match zbus::Proxy::new(
        connection,
        POLKIT_DESTINATION,
        POLKIT_PATH,
        POLKIT_INTERFACE,
    )
    .await
    {
        Ok(authority) => authority,
        Err(error) => {
            return publication_authorization_without_polkit(format!(
                "cannot create polkit proxy: {error}"
            ));
        }
    };
    let subject_details = HashMap::from([("name", Value::from(unique_name.as_str()))]);
    let subject = ("system-bus-name", subject_details);
    let details = HashMap::<&str, &str>::new();
    let result: zbus::Result<(bool, bool, HashMap<String, String>)> = authority
        .call(
            "CheckAuthorization",
            &(subject, REGISTER_SERVICE_ACTION, details, 0_u32, ""),
        )
        .await;
    match result {
        Ok((true, _, _)) => (true, "publication authorized non-interactively".to_string()),
        Ok((false, true, _)) => (
            false,
            "publication requires interactive authorization; using another provider".to_string(),
        ),
        Ok((false, false, _)) => (
            false,
            "publication authorization denied; using another provider".to_string(),
        ),
        Err(error) => publication_authorization_without_polkit(format!(
            "polkit authorization check failed: {error}"
        )),
    }
}

fn publication_authorization_without_polkit(reason: String) -> (bool, String) {
    use std::os::unix::fs::MetadataExt;

    let is_root = std::fs::metadata("/proc/self")
        .map(|metadata| metadata.uid() == 0)
        .unwrap_or(false);
    if is_root {
        (
            true,
            format!("publication allowed for the root service ({reason})"),
        )
    } else {
        (
            false,
            format!(
                "publication authorization could not be proven ({reason}); using another provider"
            ),
        )
    }
}

struct ResolvedSession {
    connection: Connection,
    command_tx: mpsc::Sender<ResolvedCommand>,
    state_rx: watch::Receiver<ProviderSessionState>,
    capabilities: MdnsCapabilities,
}

impl ResolvedSession {
    async fn start(
        connection: Connection,
        owner: String,
        capabilities: MdnsCapabilities,
    ) -> Result<Self> {
        // Arm one owner-epoch signal stream before any registration can be
        // accepted. Per-object subscriptions after RegisterService leave a
        // race in which resolve1 can withdraw an object unseen.
        let conflicts = if capabilities.publish && capabilities.withdraw {
            Some(open_conflict_stream(&connection, &owner, ProviderOperation::Open).await?)
        } else {
            None
        };
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CAPACITY);
        let (state_tx, state_rx) = watch::channel(ProviderSessionState::Ready);
        tokio::spawn(
            ResolvedActor {
                connection: connection.clone(),
                command_rx,
                state_tx,
                capabilities,
                owner: Some(owner),
                definitions: HashMap::new(),
                paths: HashMap::new(),
                conflicts,
            }
            .run(),
        );
        Ok(Self {
            connection,
            command_tx,
            state_rx,
            capabilities,
        })
    }
}

#[async_trait::async_trait]
impl ProviderSession for ResolvedSession {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    fn capabilities(&self) -> MdnsCapabilities {
        self.capabilities
    }

    fn state(&self) -> watch::Receiver<ProviderSessionState> {
        self.state_rx.clone()
    }

    async fn publish(&self, announcement: &Announcement) -> Result<Box<dyn PublicationLease>> {
        if !self.capabilities.publish || !self.capabilities.withdraw {
            return Err(resolved_unavailable(
                ProviderOperation::Publish,
                "resolve1 publication is not available in the live API/configuration",
            ));
        }
        if announcement.address.is_some() {
            return Err(resolved_unavailable(
                ProviderOperation::Publish,
                "resolve1 cannot publish an explicit service address",
            ));
        }
        let (service_type, _) = split_service_type(&announcement.service_type)?;
        let definition = ResolvedRegistration {
            key: announcement.id.clone(),
            name: announcement.name.clone(),
            service_type,
            port: announcement.port,
            txt: announcement
                .txt
                .iter()
                .map(|(key, value)| (key.clone(), value.as_bytes().to_vec()))
                .collect(),
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ResolvedCommand::Publish {
                definition,
                reply: reply_tx,
            })
            .await
            .map_err(|_| resolved_lost(ProviderOperation::Publish, "session actor stopped"))?;
        reply_rx
            .await
            .map_err(|_| resolved_lost(ProviderOperation::Publish, "actor dropped reply"))??;
        Ok(Box::new(ResolvedPublicationLease {
            id: announcement.id.clone(),
            command_tx: self.command_tx.clone(),
            withdrawn: false,
        }))
    }

    async fn browse(&self, _service_type: &str, _is_meta: bool) -> Result<ProviderBrowse> {
        Err(resolved_unavailable(
            ProviderOperation::Browse,
            "resolve1 does not expose continuous DNS-SD browse",
        ))
    }

    async fn resolve(&self, name: &str, service_type: &str) -> Result<ProviderService> {
        if !self.capabilities.direct_resolve {
            return Err(resolved_unavailable(
                ProviderOperation::Resolve,
                "resolve1 direct service resolution is unavailable",
            ));
        }
        resolve_service(&self.connection, name, service_type).await
    }

    async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ResolvedCommand::Shutdown(reply_tx))
            .await
            .map_err(|_| resolved_lost(ProviderOperation::Shutdown, "session actor stopped"))?;
        reply_rx
            .await
            .map_err(|_| resolved_lost(ProviderOperation::Shutdown, "actor dropped reply"))?
    }
}

struct ResolvedPublicationLease {
    id: String,
    command_tx: mpsc::Sender<ResolvedCommand>,
    withdrawn: bool,
}

#[async_trait::async_trait]
impl PublicationLease for ResolvedPublicationLease {
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
            .send(ResolvedCommand::Withdraw {
                key: self.id.clone(),
                reply: reply_tx,
            })
            .await
        {
            Ok(()) => {
                reply_rx.await.map_err(|_| {
                    resolved_lost(ProviderOperation::Withdraw, "actor dropped reply")
                })??;
            }
            Err(_) => {
                // A stopped actor has already released its client-owned objects.
            }
        }
        self.withdrawn = true;
        Ok(())
    }
}

enum ResolvedCommand {
    Publish {
        definition: ResolvedRegistration,
        reply: oneshot::Sender<Result<()>>,
    },
    Withdraw {
        key: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Shutdown(oneshot::Sender<Result<()>>),
}

#[derive(Clone)]
struct ResolvedRegistration {
    key: String,
    name: String,
    service_type: String,
    port: u16,
    txt: HashMap<String, Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
enum ConflictScope {
    Establishing,
    Established(String),
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
enum SettlementEvent<T, E> {
    Signal(T),
    Failed(E),
    Ended,
    Quiet,
}

struct ResolvedActor {
    connection: Connection,
    command_rx: mpsc::Receiver<ResolvedCommand>,
    state_tx: watch::Sender<ProviderSessionState>,
    capabilities: MdnsCapabilities,
    owner: Option<String>,
    definitions: HashMap<String, ResolvedRegistration>,
    paths: HashMap<String, OwnedObjectPath>,
    conflicts: Option<MessageStream>,
}

impl ResolvedActor {
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
                signal = next_conflict_signal(&mut self.conflicts) => {
                    self.handle_conflict_signal(signal).await;
                }
                _ = reconcile.tick() => self.reconcile().await,
            }
        }
        self.state_tx.send_replace(ProviderSessionState::Lost);
    }

    async fn handle(&mut self, command: ResolvedCommand) -> bool {
        match command {
            ResolvedCommand::Publish { definition, reply } => {
                let key = definition.key.clone();
                let result = if *self.state_tx.borrow() != ProviderSessionState::Ready {
                    Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Publish,
                        ProviderFailure::Recovering,
                        "resolve1 is recovering its D-Bus resources",
                    ))
                } else if self.definitions.contains_key(&key) {
                    Err(provider_error(
                        DESCRIPTOR.name,
                        ProviderOperation::Publish,
                        ProviderFailure::Conflict,
                        format!("publication {key} already exists"),
                    ))
                } else {
                    self.definitions.insert(key.clone(), definition);
                    match self.establish(&key).await {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            self.definitions.remove(&key);
                            Err(error)
                        }
                    }
                };
                if let Err(Ok(())) = reply.send(result) {
                    if self.release(&key).await.is_ok() {
                        self.definitions.remove(&key);
                    }
                }
            }
            ResolvedCommand::Withdraw { key, reply } => {
                let result = self.release(&key).await;
                if result.is_ok() {
                    self.definitions.remove(&key);
                }
                let _ = reply.send(result);
            }
            ResolvedCommand::Shutdown(reply) => {
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
        let (owner, _mode, live_capabilities, _authorization) = match inspect_live(&self.connection)
            .await
        {
            Ok(live) => live,
            Err(error) => {
                let observed_owner = current_owner(&self.connection).await.ok().flatten();
                if observed_owner != self.owner {
                    self.paths.clear();
                    self.conflicts = None;
                    self.owner = observed_owner;
                }
                self.state_tx.send_replace(ProviderSessionState::Recovering);
                tracing::debug!(provider = DESCRIPTOR.name, %error, "resolve1 recovery probe failed");
                return;
            }
        };
        if self.owner.as_deref() != Some(owner.as_str()) {
            tracing::info!(provider = DESCRIPTOR.name, old = ?self.owner, new = %owner, "D-Bus owner epoch changed");
            self.paths.clear();
            self.conflicts = None;
            self.owner = Some(owner.clone());
        }
        if !live_capabilities.supports(self.capabilities) {
            self.state_tx.send_replace(ProviderSessionState::Lost);
            return;
        }

        self.state_tx.send_replace(ProviderSessionState::Recovering);
        let observes_publications = self.capabilities.publish && self.capabilities.withdraw;
        if observes_publications && self.conflicts.is_none() {
            match open_conflict_stream(&self.connection, &owner, ProviderOperation::Publish).await {
                Ok(conflicts) => self.conflicts = Some(conflicts),
                Err(error) => {
                    tracing::warn!(provider = DESCRIPTOR.name, %error, "conflict observation recovery failed");
                    return;
                }
            }
        }
        let missing = self
            .definitions
            .keys()
            .filter(|key| !self.paths.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        for key in missing {
            if let Err(error) = self.establish(&key).await {
                tracing::warn!(provider = DESCRIPTOR.name, publication = %key, %error, "publication recovery failed");
            }
        }
        let observation_ready = !observes_publications || self.conflicts.is_some();
        if observation_ready && self.paths.len() == self.definitions.len() {
            self.state_tx.send_replace(ProviderSessionState::Ready);
        }
    }

    async fn establish(&mut self, key: &str) -> Result<()> {
        let definition = self.definitions.get(key).cloned().ok_or_else(|| {
            resolved_lost(
                ProviderOperation::Publish,
                format!("publication definition {key} disappeared"),
            )
        })?;
        if self.paths.contains_key(key) {
            return Ok(());
        }
        let manager = ResolveManagerProxy::new(&self.connection)
            .await
            .map_err(|error| resolved_protocol(ProviderOperation::Publish, error))?;
        let object_id = format!("koi-{}", definition.key);
        let name_template = definition.name.replace('%', "%%");
        let path = manager
            .register_service(
                &object_id,
                &name_template,
                &definition.service_type,
                definition.port,
                0,
                0,
                vec![definition.txt.clone()],
            )
            .await
            .map_err(|error| resolved_protocol(ProviderOperation::Publish, error))?;
        self.await_publication_settlement(&manager, &path, &definition)
            .await?;
        self.paths.insert(key.to_string(), path);
        Ok(())
    }

    async fn await_publication_settlement(
        &mut self,
        manager: &ResolveManagerProxy<'_>,
        path: &OwnedObjectPath,
        definition: &ResolvedRegistration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + PUBLICATION_SETTLE_INTERVAL;
        loop {
            let event = {
                let conflicts = self.conflicts.as_mut().ok_or_else(|| {
                    resolved_recovering(
                        ProviderOperation::Publish,
                        "resolve1 conflict observation is not armed",
                    )
                })?;
                next_settlement_event(conflicts, deadline).await
            };
            match event {
                SettlementEvent::Signal(message) => {
                    let Some(conflicted_path) = conflict_signal_path(&message) else {
                        continue;
                    };
                    match classify_conflict(&self.paths, Some(path), &conflicted_path) {
                        ConflictScope::Establishing => {
                            // resolve1 has already withdrawn the conflicted
                            // record. Explicit cleanup makes a later retry
                            // start from one unambiguous owner.
                            let _ = manager.unregister_service(path).await;
                            return Err(provider_error(
                                DESCRIPTOR.name,
                                ProviderOperation::Publish,
                                ProviderFailure::Conflict,
                                format!(
                                    "resolve1 withdrew {}.{} after mDNS conflict probing",
                                    definition.name, definition.service_type
                                ),
                            ));
                        }
                        ConflictScope::Established(key) => {
                            self.invalidate_conflicted_publication(&key).await;
                        }
                        ConflictScope::Unknown => {
                            tracing::trace!(
                                provider = DESCRIPTOR.name,
                                path = %conflicted_path,
                                "ignoring conflict for an unowned resolve1 object"
                            );
                        }
                    }
                }
                SettlementEvent::Failed(error) => {
                    let _ = manager.unregister_service(path).await;
                    self.lose_conflict_observation(format!(
                        "resolve1 conflict signal stream failed: {error}"
                    ))
                    .await;
                    return Err(resolved_recovering(
                        ProviderOperation::Publish,
                        "resolve1 conflict observation failed during publication",
                    ));
                }
                SettlementEvent::Ended => {
                    let _ = manager.unregister_service(path).await;
                    self.lose_conflict_observation(
                        "resolve1 conflict signal stream ended".to_string(),
                    )
                    .await;
                    return Err(resolved_recovering(
                        ProviderOperation::Publish,
                        "resolve1 conflict observation ended during publication",
                    ));
                }
                SettlementEvent::Quiet => return Ok(()),
            }
        }
    }

    async fn handle_conflict_signal(&mut self, signal: Option<zbus::Result<Message>>) {
        match signal {
            Some(Ok(message)) => {
                let Some(path) = conflict_signal_path(&message) else {
                    return;
                };
                match classify_conflict(&self.paths, None, &path) {
                    ConflictScope::Established(key) => {
                        tracing::warn!(
                            provider = DESCRIPTOR.name,
                            publication = %key,
                            path = %path,
                            "resolve1 withdrew a publication after a late mDNS conflict"
                        );
                        self.invalidate_conflicted_publication(&key).await;
                    }
                    ConflictScope::Establishing | ConflictScope::Unknown => {
                        tracing::trace!(
                            provider = DESCRIPTOR.name,
                            path = %path,
                            "ignoring conflict for an unowned resolve1 object"
                        );
                    }
                }
            }
            Some(Err(error)) => {
                self.lose_conflict_observation(format!(
                    "resolve1 conflict signal stream failed: {error}"
                ))
                .await;
            }
            None => {
                self.lose_conflict_observation("resolve1 conflict signal stream ended".to_string())
                    .await;
            }
        }
    }

    async fn invalidate_conflicted_publication(&mut self, key: &str) {
        let Some(path) = self.paths.remove(key) else {
            return;
        };
        self.state_tx.send_replace(ProviderSessionState::Recovering);
        if let Ok(manager) = ResolveManagerProxy::new(&self.connection).await {
            if let Err(error) = manager.unregister_service(&path).await {
                tracing::debug!(
                    provider = DESCRIPTOR.name,
                    publication = %key,
                    %error,
                    "conflicted resolve1 object cleanup deferred to recovery"
                );
            }
        }
    }

    async fn lose_conflict_observation(&mut self, detail: String) {
        self.conflicts = None;
        self.state_tx.send_replace(ProviderSessionState::Recovering);
        tracing::warn!(provider = DESCRIPTOR.name, %detail, "publication ownership observation lost");

        // Without the signal stream, an object may have been withdrawn without
        // our seeing it. Retire every materialization best-effort and let the
        // adapter's existing desired-definition reconciliation rebuild them
        // only after observation is armed again.
        let paths = std::mem::take(&mut self.paths);
        if let Ok(manager) = ResolveManagerProxy::new(&self.connection).await {
            for (key, path) in paths {
                if let Err(error) = manager.unregister_service(&path).await {
                    tracing::debug!(
                        provider = DESCRIPTOR.name,
                        publication = %key,
                        %error,
                        "resolve1 object cleanup after observer loss was not acknowledged"
                    );
                }
            }
        }
    }

    async fn release(&mut self, key: &str) -> Result<()> {
        let Some(path) = self.paths.get(key).cloned() else {
            return Ok(());
        };
        let manager = ResolveManagerProxy::new(&self.connection)
            .await
            .map_err(|error| resolved_protocol(ProviderOperation::Withdraw, error))?;
        match manager.unregister_service(&path).await {
            Ok(()) => {
                self.paths.remove(key);
                Ok(())
            }
            Err(error) => {
                let owner = current_owner(&self.connection).await.ok().flatten();
                if owner != self.owner {
                    self.paths.clear();
                    self.conflicts = None;
                    self.owner = owner;
                    Ok(())
                } else {
                    Err(resolved_protocol(ProviderOperation::Withdraw, error))
                }
            }
        }
    }

    async fn release_all(&mut self) -> Result<()> {
        let keys = self.paths.keys().cloned().collect::<Vec<_>>();
        let mut first_error = None;
        for key in keys {
            if let Err(error) = self.release(&key).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            self.definitions.clear();
            Ok(())
        }
    }
}

async fn open_conflict_stream(
    connection: &Connection,
    owner: &str,
    operation: ProviderOperation,
) -> Result<MessageStream> {
    let rule = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .sender(owner)
        .map_err(|error| resolved_protocol(operation, error))?
        .interface(DNSSD_SERVICE_INTERFACE)
        .map_err(|error| resolved_protocol(operation, error))?
        .member(CONFLICT_MEMBER)
        .map_err(|error| resolved_protocol(operation, error))?
        .build();
    MessageStream::for_match_rule(rule, connection, Some(COMMAND_CAPACITY))
        .await
        .map_err(|error| resolved_protocol(operation, error))
}

async fn next_conflict_signal(
    conflicts: &mut Option<MessageStream>,
) -> Option<zbus::Result<Message>> {
    match conflicts {
        Some(conflicts) => conflicts.next().await,
        None => std::future::pending().await,
    }
}

async fn next_settlement_event<S, T, E>(
    signals: &mut S,
    deadline: tokio::time::Instant,
) -> SettlementEvent<T, E>
where
    S: Stream<Item = std::result::Result<T, E>> + Unpin,
{
    match tokio::time::timeout_at(deadline, signals.next()).await {
        Ok(Some(Ok(signal))) => SettlementEvent::Signal(signal),
        Ok(Some(Err(error))) => SettlementEvent::Failed(error),
        Ok(None) => SettlementEvent::Ended,
        Err(_) => SettlementEvent::Quiet,
    }
}

fn conflict_signal_path(message: &Message) -> Option<String> {
    message
        .header()
        .path()
        .map(|path| path.as_str().to_string())
}

fn classify_conflict(
    established: &HashMap<String, OwnedObjectPath>,
    establishing: Option<&OwnedObjectPath>,
    conflicted_path: &str,
) -> ConflictScope {
    if establishing.is_some_and(|path| path.as_str() == conflicted_path) {
        return ConflictScope::Establishing;
    }
    established
        .iter()
        .find_map(|(key, path)| {
            (path.as_str() == conflicted_path).then(|| ConflictScope::Established(key.clone()))
        })
        .unwrap_or(ConflictScope::Unknown)
}

async fn resolve_service(
    connection: &Connection,
    name: &str,
    service_type: &str,
) -> Result<ProviderService> {
    let (service_type, domain) = split_service_type(service_type)?;
    let manager = ResolveManagerProxy::new(connection)
        .await
        .map_err(|error| resolved_protocol(ProviderOperation::Resolve, error))?;
    let (srv, txt, canonical_name, canonical_type, _, _) = manager
        .resolve_service(0, name, &service_type, &domain, 0, 0)
        .await
        .map_err(|error| resolved_protocol(ProviderOperation::Resolve, error))?;
    let (_, _, port, host, raw_addresses, canonical_host) =
        srv.into_iter().next().ok_or_else(|| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Resolve,
                ProviderFailure::Rejected,
                format!("resolve1 returned no SRV data for {name}.{service_type}"),
            )
        })?;
    let addresses = raw_addresses
        .into_iter()
        .filter_map(|(interface_index, _family, bytes)| {
            address_from_bytes(&bytes).map(|address| ProviderAddress {
                address,
                interface_index: (interface_index > 0).then_some(interface_index as u32),
                interface_name: None,
            })
        })
        .collect();
    Ok(ProviderService {
        name: if canonical_name.is_empty() {
            name.to_string()
        } else {
            canonical_name
        },
        service_type: canonical_type
            .trim_end_matches('.')
            .trim_end_matches(".local")
            .to_string(),
        host: Some(if canonical_host.is_empty() {
            host
        } else {
            canonical_host
        }),
        addresses,
        port: Some(port),
        txt: decode_txt(&txt),
    })
}

async fn current_owner(connection: &Connection) -> std::result::Result<Option<String>, String> {
    let dbus = zbus::fdo::DBusProxy::new(connection)
        .await
        .map_err(|error| format!("cannot create system D-Bus proxy: {error}"))?;
    let name = BusName::try_from(RESOLVE_DESTINATION)
        .map_err(|error| format!("invalid resolve1 D-Bus name: {error}"))?;
    match dbus.get_name_owner(name).await {
        Ok(owner) => Ok(Some(owner.to_string())),
        Err(zbus::fdo::Error::NameHasNoOwner(_)) => Ok(None),
        Err(error) => Err(format!("cannot inspect resolve1 D-Bus owner: {error}")),
    }
}

fn split_service_type(value: &str) -> Result<(String, String)> {
    let canonical = value.trim_end_matches('.');
    let without_local = canonical.strip_suffix(".local").ok_or_else(|| {
        MdnsError::InvalidServiceType(format!("resolve1 only supports .local: {value}"))
    })?;
    if !without_local.starts_with('_') || !without_local.contains("._") {
        return Err(MdnsError::InvalidServiceType(value.to_string()));
    }
    Ok((without_local.to_string(), "local".to_string()))
}

fn address_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
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

fn configured_fact(mode: &str) -> ProbeFact {
    match mode {
        "yes" | "resolve" => ProbeFact::Yes,
        "no" => ProbeFact::No,
        _ => ProbeFact::Unknown,
    }
}

fn capabilities_from(
    mode: &str,
    introspection: &str,
    publication_authorized: bool,
) -> MdnsCapabilities {
    let method = |name: &str| introspection.contains(&format!("<method name=\"{name}\""));
    let mode_supports_mdns = matches!(mode, "yes" | "resolve");
    let can_publish = publication_authorized && mode == "yes" && method("RegisterService");
    MdnsCapabilities {
        publish: can_publish,
        withdraw: can_publish && method("UnregisterService"),
        continuous_browse: false,
        browse_resolves: false,
        direct_resolve: mode_supports_mdns && method("ResolveService"),
        explicit_address: false,
    }
}

fn resolved_unavailable(operation: ProviderOperation, detail: impl Into<String>) -> MdnsError {
    provider_error(
        DESCRIPTOR.name,
        operation,
        ProviderFailure::Unavailable,
        detail,
    )
}

fn resolved_recovering(operation: ProviderOperation, detail: impl Into<String>) -> MdnsError {
    provider_error(
        DESCRIPTOR.name,
        operation,
        ProviderFailure::Recovering,
        detail,
    )
}

fn resolved_lost(operation: ProviderOperation, detail: impl Into<String>) -> MdnsError {
    provider_error(DESCRIPTOR.name, operation, ProviderFailure::Lost, detail)
}

fn resolved_protocol(operation: ProviderOperation, error: impl std::fmt::Display) -> MdnsError {
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
    use futures_util::stream;

    #[test]
    fn live_api_shape_remains_a_partial_collaborator() {
        let xml = r#"
            <method name="RegisterService"/>
            <method name="UnregisterService"/>
            <method name="ResolveService"/>
        "#;
        let capabilities = capabilities_from("yes", xml, true);
        assert!(capabilities.publish);
        assert!(capabilities.withdraw);
        assert!(capabilities.direct_resolve);
        assert!(!capabilities.continuous_browse);
        assert!(!capabilities.explicit_address);
        assert!(!capabilities.satisfies_provider_contract());
    }

    #[test]
    fn resolve_only_mode_does_not_claim_publication() {
        let xml = r#"
            <method name="RegisterService"/>
            <method name="UnregisterService"/>
            <method name="ResolveService"/>
        "#;
        let capabilities = capabilities_from("resolve", xml, true);
        assert!(!capabilities.publish);
        assert!(!capabilities.withdraw);
        assert!(capabilities.direct_resolve);
    }

    #[test]
    fn unknown_mode_claims_no_capabilities() {
        let xml = r#"<method name="ResolveService"/>"#;
        assert_eq!(
            capabilities_from("future-value", xml, true),
            MdnsCapabilities::default()
        );
    }

    #[test]
    fn unauthorized_publication_keeps_the_resolve_route_available() {
        let xml = r#"
            <method name="RegisterService"/>
            <method name="UnregisterService"/>
            <method name="ResolveService"/>
        "#;
        let capabilities = capabilities_from("yes", xml, false);
        assert!(!capabilities.publish);
        assert!(!capabilities.withdraw);
        assert!(capabilities.direct_resolve);
    }

    #[test]
    fn conflict_scope_distinguishes_establishing_owned_and_foreign_objects() {
        let first = OwnedObjectPath::try_from("/org/freedesktop/resolve1/dnssd/first").unwrap();
        let second = OwnedObjectPath::try_from("/org/freedesktop/resolve1/dnssd/second").unwrap();
        let pending = OwnedObjectPath::try_from("/org/freedesktop/resolve1/dnssd/pending").unwrap();
        let established =
            HashMap::from([("first".to_string(), first), ("second".to_string(), second)]);

        assert_eq!(
            classify_conflict(&established, Some(&pending), pending.as_str()),
            ConflictScope::Establishing
        );
        assert_eq!(
            classify_conflict(
                &established,
                Some(&pending),
                "/org/freedesktop/resolve1/dnssd/second"
            ),
            ConflictScope::Established("second".to_string())
        );
        assert_eq!(
            classify_conflict(
                &established,
                Some(&pending),
                "/org/freedesktop/resolve1/dnssd/foreign"
            ),
            ConflictScope::Unknown
        );
    }

    #[tokio::test]
    async fn publication_settlement_distinguishes_quiet_end_error_and_signal() {
        let soon = || tokio::time::Instant::now() + Duration::from_millis(5);
        let mut quiet = stream::pending::<std::result::Result<(), &'static str>>();
        assert_eq!(
            next_settlement_event(&mut quiet, soon()).await,
            SettlementEvent::Quiet
        );

        let mut ended = stream::empty::<std::result::Result<(), &'static str>>();
        assert_eq!(
            next_settlement_event(&mut ended, soon()).await,
            SettlementEvent::Ended
        );

        let mut failed = stream::iter([Err::<(), _>("observer failed")]);
        assert_eq!(
            next_settlement_event(&mut failed, soon()).await,
            SettlementEvent::Failed("observer failed")
        );

        let mut signaled = stream::iter([Ok::<_, &'static str>(())]);
        assert_eq!(
            next_settlement_event(&mut signaled, soon()).await,
            SettlementEvent::Signal(())
        );
    }

    #[tokio::test]
    #[ignore = "requires systemd-resolved on the system bus"]
    async fn real_resolve1_report_declares_only_live_capabilities() {
        let report = SystemdResolvedAdapter.assess().await;
        assert_eq!(report.name, DESCRIPTOR.name);
        assert_eq!(report.api, ProviderApi::SystemDbus);
        assert!(!report.capabilities.continuous_browse);
        assert_ne!(report.running, ProbeFact::Unknown);
    }

    #[tokio::test]
    #[ignore = "requires writable systemd-resolved DNS-SD D-Bus APIs"]
    async fn real_resolve1_publish_point_resolve_and_withdraw() {
        let adapter = SystemdResolvedAdapter;
        let report = adapter.assess().await;
        assert!(report.capabilities.publish, "resolve1 report: {report:?}");
        assert!(
            report.capabilities.direct_resolve,
            "resolve1 report: {report:?}"
        );
        let session = adapter.open().await.expect("open resolve1 session");
        let name = format!("koi-resolve1-{}", std::process::id());
        let announcement = Announcement {
            id: format!("resolve1-{}", std::process::id()),
            name: name.clone(),
            service_type: "_koi-test._tcp.local.".to_string(),
            port: 43125,
            address: None,
            txt: HashMap::from([("source".to_string(), "resolve1".to_string())]),
        };
        let mut lease = session
            .publish(&announcement)
            .await
            .expect("publish through resolve1");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let resolved = loop {
            match session.resolve(&name, &announcement.service_type).await {
                Ok(service) => break service,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    tracing::debug!(%error, "waiting for resolve1 publication");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("resolve1 publication did not resolve: {error}"),
            }
        };
        assert_eq!(resolved.port, Some(43125));
        assert_eq!(resolved.txt.get("source"), Some(&"resolve1".to_string()));
        lease
            .withdraw()
            .await
            .expect("withdraw resolve1 publication");
        session.shutdown().await.expect("shutdown resolve1 session");
    }
}
