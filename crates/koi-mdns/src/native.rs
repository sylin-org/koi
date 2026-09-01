//! Native Koi mDNS provider backed by `mdns-sd`.
//!
//! This is the only module allowed to import provider-library types. It owns
//! the worker thread, acknowledgement barriers, resource leases, and every
//! conversion into provider-neutral values.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mdns_sd::{
    DaemonEvent, DaemonStatus, ResolvedService, ScopedIp, ServiceDaemon,
    ServiceEvent as MdnsServiceEvent, ServiceInfo, UnregisterStatus,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::{mpsc, oneshot, watch};

use crate::adapter::{
    MdnsAdapter, MdnsCapabilities, MdnsProviderReport, ProbeFact, ProviderApi,
    ProviderAvailability, ProviderDescriptor, ProviderSessionState,
};
use crate::error::{MdnsError, ProviderFailure, ProviderOperation};
use crate::provider::{
    provider_error, Announcement, BrowseLease, ProviderAddress, ProviderBrowse, ProviderEvent,
    ProviderService, ProviderSession, PublicationLease,
};
use crate::Result;

const BROWSE_CHANNEL_CAPACITY: usize = 512;
const COMMAND_CAPACITY: usize = 256;
const NATIVE_PRIORITY: u16 = 100;
const STARTUP_STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const PUBLICATION_TIMEOUT: Duration = Duration::from_secs(4);
const BROWSE_START_TIMEOUT: Duration = Duration::from_secs(2);
const RESOURCE_RELEASE_TIMEOUT: Duration = Duration::from_secs(3);

const DESCRIPTOR: ProviderDescriptor = ProviderDescriptor::new(
    "native",
    NATIVE_PRIORITY,
    ProviderApi::Embedded,
    MdnsCapabilities::FULL_PROVIDER,
);

/// A short-lived proof that the native engine can use RFC 6762 cooperative
/// socket semantics without evicting an existing participant.
struct CooperativeBind {
    _ipv4: Option<Socket>,
    _ipv6: Option<Socket>,
    detail: String,
}

impl CooperativeBind {
    fn mdns() -> Result<Self> {
        Self::on_port(crate::MDNS_PORT)
    }

    fn on_port(port: u16) -> Result<Self> {
        let ipv4_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        let ipv6_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        let (ipv4, ipv4_error) = cooperative_socket(ipv4_addr);
        let (ipv6, ipv6_error) = cooperative_socket(ipv6_addr);
        if ipv4.is_none() && ipv6.is_none() {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Inspect,
                ProviderFailure::ResourceBusy,
                format!(
                    "cannot cooperatively bind UDP {port} (IPv4: {}; IPv6: {})",
                    ipv4_error.unwrap_or_else(|| "unavailable".to_string()),
                    ipv6_error.unwrap_or_else(|| "unavailable".to_string())
                ),
            ));
        }
        let families = match (ipv4.is_some(), ipv6.is_some()) {
            (true, true) => "IPv4+IPv6",
            (true, false) => "IPv4 only",
            (false, true) => "IPv6 only",
            (false, false) => "no address family",
        };
        Ok(Self {
            _ipv4: ipv4,
            _ipv6: ipv6,
            detail: format!("cooperative UDP {port} bind verified ({families})"),
        })
    }
}

fn cooperative_socket(address: SocketAddr) -> (Option<Socket>, Option<String>) {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let result = (|| {
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
        socket.bind(&address.into())?;
        Ok::<Socket, std::io::Error>(socket)
    })();
    match result {
        Ok(socket) => (Some(socket), None),
        Err(error) => (None, Some(error.to_string())),
    }
}

#[derive(Debug, Default)]
pub struct NativeMdnsAdapter;

#[async_trait::async_trait]
impl MdnsAdapter for NativeMdnsAdapter {
    fn descriptor(&self) -> ProviderDescriptor {
        DESCRIPTOR
    }

    async fn assess(&self) -> MdnsProviderReport {
        match CooperativeBind::mdns() {
            Ok(probe) => MdnsProviderReport {
                name: DESCRIPTOR.name.to_string(),
                priority: DESCRIPTOR.priority,
                api: DESCRIPTOR.api,
                availability: ProviderAvailability::Ready,
                installed: ProbeFact::Yes,
                configured: ProbeFact::Yes,
                running: ProbeFact::NotApplicable,
                capabilities: DESCRIPTOR.capabilities,
                session: None,
                detail: format!("built-in engine; {}", probe.detail),
            },
            Err(error) => MdnsProviderReport {
                name: DESCRIPTOR.name.to_string(),
                priority: DESCRIPTOR.priority,
                api: DESCRIPTOR.api,
                availability: ProviderAvailability::Unavailable,
                installed: ProbeFact::Yes,
                configured: ProbeFact::Yes,
                running: ProbeFact::NotApplicable,
                capabilities: MdnsCapabilities::default(),
                session: None,
                detail: error.to_string(),
            },
        }
    }

    async fn open(&self) -> Result<Arc<dyn ProviderSession>> {
        let session = tokio::task::spawn_blocking(NativeSession::new)
            .await
            .map_err(|error| {
                provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Open,
                    ProviderFailure::Lost,
                    format!("worker startup task failed: {error}"),
                )
            })??;
        Ok(Arc::new(session))
    }
}

struct NativeRawBrowse {
    events: mdns_sd::Receiver<MdnsServiceEvent>,
    first: Option<MdnsServiceEvent>,
}

enum NativeCommand {
    Publish {
        info: Box<ServiceInfo>,
        reply: oneshot::Sender<Result<String>>,
    },
    Withdraw {
        fullname: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Browse {
        service_type: String,
        reply: oneshot::Sender<Result<NativeRawBrowse>>,
    },
    CloseBrowse {
        service_type: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<()>>,
    },
}

pub struct NativeSession {
    command_tx: Mutex<std::sync::mpsc::SyncSender<NativeCommand>>,
    state_rx: watch::Receiver<ProviderSessionState>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl NativeSession {
    fn new() -> Result<Self> {
        let cooperative = CooperativeBind::mdns()?;
        let daemon = ServiceDaemon::new().map_err(|error| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Open,
                ProviderFailure::Unavailable,
                error.to_string(),
            )
        })?;
        let status = daemon
            .status()
            .map_err(|error| native_protocol(ProviderOperation::Open, error))?
            .recv_timeout(STARTUP_STATUS_TIMEOUT)
            .map_err(|error| {
                provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Open,
                    ProviderFailure::Timeout,
                    format!("engine did not report readiness: {error}"),
                )
            })?;
        if status != DaemonStatus::Running {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Open,
                ProviderFailure::Lost,
                format!("unexpected startup status: {status:?}"),
            ));
        }
        let monitor = daemon
            .monitor()
            .map_err(|error| native_protocol(ProviderOperation::Open, error))?;
        drop(cooperative);

        let (command_tx, command_rx) = std::sync::mpsc::sync_channel(COMMAND_CAPACITY);
        let (state_tx, state_rx) = watch::channel(ProviderSessionState::Ready);
        let worker = std::thread::Builder::new()
            .name("koi-mdns-native".to_string())
            .spawn(move || native_worker(daemon, monitor, command_rx, state_tx))
            .map_err(|error| {
                provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Open,
                    ProviderFailure::Lost,
                    format!("could not spawn worker: {error}"),
                )
            })?;
        Ok(Self {
            command_tx: Mutex::new(command_tx),
            state_rx,
            worker: Mutex::new(Some(worker)),
        })
    }

    fn send(&self, command: NativeCommand, operation: ProviderOperation) -> Result<()> {
        self.command_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .try_send(command)
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => provider_error(
                    DESCRIPTOR.name,
                    operation,
                    ProviderFailure::ResourceBusy,
                    "native command queue is full",
                ),
                std::sync::mpsc::TrySendError::Disconnected(_) => provider_error(
                    DESCRIPTOR.name,
                    operation,
                    ProviderFailure::Lost,
                    "native worker stopped",
                ),
            })
    }
}

#[async_trait::async_trait]
impl ProviderSession for NativeSession {
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
        let host = match announcement.address {
            Some(_) => explicit_publication_host(&announcement.id),
            None => {
                let hostname = hostname::get()
                    .unwrap_or_else(|_| "localhost".into())
                    .to_string_lossy()
                    .to_string();
                let hostname = hostname.trim_end_matches('.').trim_end_matches(".local");
                format!("{}.local.", dns_label(hostname))
            }
        };
        let properties = announcement
            .txt
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let info = ServiceInfo::new(
            &announcement.service_type,
            &announcement.name,
            &host,
            announcement
                .address
                .map(|address| address.to_string())
                .as_deref()
                .unwrap_or(""),
            announcement.port,
            &properties[..],
        )
        .map_err(|error| native_rejected(ProviderOperation::Publish, error))?;
        let info = if announcement.address.is_none() {
            info.enable_addr_auto()
        } else {
            info
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(
            NativeCommand::Publish {
                info: Box::new(info),
                reply: reply_tx,
            },
            ProviderOperation::Publish,
        )?;
        let fullname = reply_rx
            .await
            .map_err(|_| native_lost(ProviderOperation::Publish, "worker dropped reply"))??;
        Ok(Box::new(NativePublicationLease {
            id: announcement.id.clone(),
            fullname,
            command_tx: self
                .command_tx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            withdrawn: false,
        }))
    }

    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(
            NativeCommand::Browse {
                service_type: service_type.to_string(),
                reply: reply_tx,
            },
            ProviderOperation::Browse,
        )?;
        let raw = reply_rx
            .await
            .map_err(|_| native_lost(ProviderOperation::Browse, "worker dropped reply"))??;
        let (event_tx, event_rx) = mpsc::channel(BROWSE_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            if let Some(first) = raw.first {
                if let NativeEvent::Emit(event) = translate(first, is_meta) {
                    if event_tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
            while let Ok(event) = raw.events.recv_async().await {
                match translate(event, is_meta) {
                    NativeEvent::Emit(event) => {
                        if event_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    NativeEvent::Skip => {}
                    NativeEvent::Stop => break,
                }
            }
        });
        Ok(ProviderBrowse::new(
            event_rx,
            Box::new(NativeBrowseLease {
                service_type: service_type.to_string(),
                command_tx: self
                    .command_tx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
                closed: false,
            }),
        ))
    }

    async fn shutdown(&self) -> Result<()> {
        let Some(worker) = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        else {
            return Ok(());
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        if let Err(error) = self.send(
            NativeCommand::Shutdown { reply: reply_tx },
            ProviderOperation::Shutdown,
        ) {
            join_native_worker(worker).await?;
            return Err(error);
        }
        match reply_rx.await {
            Ok(Ok(())) => join_native_worker(worker).await,
            Ok(Err(error)) => {
                self.worker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .replace(worker);
                Err(error)
            }
            Err(_) => {
                join_native_worker(worker).await?;
                Err(native_lost(
                    ProviderOperation::Shutdown,
                    "worker dropped shutdown reply",
                ))
            }
        }
    }
}

async fn join_native_worker(worker: std::thread::JoinHandle<()>) -> Result<()> {
    tokio::task::spawn_blocking(move || worker.join())
        .await
        .map_err(|error| {
            native_lost(
                ProviderOperation::Shutdown,
                format!("worker join task failed: {error}"),
            )
        })?
        .map_err(|_| native_lost(ProviderOperation::Shutdown, "native worker panicked"))
}

struct NativePublicationLease {
    id: String,
    fullname: String,
    command_tx: std::sync::mpsc::SyncSender<NativeCommand>,
    withdrawn: bool,
}

#[async_trait::async_trait]
impl PublicationLease for NativePublicationLease {
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
        self.command_tx
            .try_send(NativeCommand::Withdraw {
                fullname: self.fullname.clone(),
                reply: reply_tx,
            })
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Withdraw,
                    ProviderFailure::ResourceBusy,
                    "native command queue is full",
                ),
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    native_lost(ProviderOperation::Withdraw, "worker unavailable")
                }
            })?;
        reply_rx
            .await
            .map_err(|_| native_lost(ProviderOperation::Withdraw, "worker dropped reply"))??;
        self.withdrawn = true;
        Ok(())
    }
}

struct NativeBrowseLease {
    service_type: String,
    command_tx: std::sync::mpsc::SyncSender<NativeCommand>,
    closed: bool,
}

#[async_trait::async_trait]
impl BrowseLease for NativeBrowseLease {
    fn provider_name(&self) -> &'static str {
        DESCRIPTOR.name
    }

    async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        match self.command_tx.try_send(NativeCommand::CloseBrowse {
            service_type: self.service_type.clone(),
            reply: reply_tx,
        }) {
            Ok(()) => {
                reply_rx.await.map_err(|_| {
                    native_lost(ProviderOperation::Browse, "worker dropped close reply")
                })??;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                return Err(provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Browse,
                    ProviderFailure::ResourceBusy,
                    "native command queue is full",
                ));
            }
        }
        self.closed = true;
        Ok(())
    }
}

fn native_worker(
    daemon: ServiceDaemon,
    monitor: mdns_sd::Receiver<DaemonEvent>,
    command_rx: std::sync::mpsc::Receiver<NativeCommand>,
    state_tx: watch::Sender<ProviderSessionState>,
) {
    tracing::debug!(provider = DESCRIPTOR.name, "native provider worker started");
    while let Ok(command) = command_rx.recv() {
        match command {
            NativeCommand::Publish { info, reply } => {
                let result = publish_native(&daemon, &monitor, *info);
                if result.as_ref().is_err_and(is_lost_error) {
                    state_tx.send_replace(ProviderSessionState::Lost);
                }
                if let Err(Ok(fullname)) = reply.send(result) {
                    if let Err(error) = withdraw_native(&daemon, &fullname) {
                        tracing::warn!(provider = DESCRIPTOR.name, %error, "cancelled publication cleanup failed; retiring native session");
                        let _ = shutdown_native(&daemon);
                        state_tx.send_replace(ProviderSessionState::Lost);
                    }
                }
            }
            NativeCommand::Withdraw { fullname, reply } => {
                let result = withdraw_native(&daemon, &fullname);
                if result.as_ref().is_err_and(is_lost_error) {
                    state_tx.send_replace(ProviderSessionState::Lost);
                }
                let _ = reply.send(result);
            }
            NativeCommand::Browse {
                service_type,
                reply,
            } => {
                let result = start_native_browse(&daemon, &service_type);
                if result.as_ref().is_err_and(is_lost_error) {
                    state_tx.send_replace(ProviderSessionState::Lost);
                }
                if let Err(Ok(_raw)) = reply.send(result) {
                    if let Err(error) = close_native_browse(&daemon, &service_type) {
                        tracing::warn!(provider = DESCRIPTOR.name, %error, "cancelled browse cleanup failed; retiring native session");
                        let _ = shutdown_native(&daemon);
                        state_tx.send_replace(ProviderSessionState::Lost);
                    }
                }
            }
            NativeCommand::CloseBrowse {
                service_type,
                reply,
            } => {
                let result = close_native_browse(&daemon, &service_type);
                let _ = reply.send(result);
            }
            NativeCommand::Shutdown { reply } => {
                let result = shutdown_native(&daemon);
                let complete = result.is_ok();
                let _ = reply.send(result);
                if complete {
                    break;
                }
            }
        }
    }
    state_tx.send_replace(ProviderSessionState::Lost);
    tracing::debug!(provider = DESCRIPTOR.name, "native provider worker stopped");
}

fn publish_native(
    daemon: &ServiceDaemon,
    monitor: &mdns_sd::Receiver<DaemonEvent>,
    info: ServiceInfo,
) -> Result<String> {
    while monitor.try_recv().is_ok() {}
    let requested = info.get_fullname().to_string();
    daemon
        .register(info)
        .map_err(|error| native_protocol(ProviderOperation::Publish, error))?;
    let deadline = Instant::now() + PUBLICATION_TIMEOUT;
    let mut effective = requested.clone();
    let result = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Publish,
                ProviderFailure::Timeout,
                format!("no announcement confirmation for {effective}"),
            ));
        }
        match monitor.recv_timeout(remaining) {
            Ok(DaemonEvent::Announce(fullname, _))
                if fullname.eq_ignore_ascii_case(&effective)
                    || fullname.eq_ignore_ascii_case(&requested) =>
            {
                break Ok(fullname);
            }
            Ok(DaemonEvent::NameChange(change))
                if change.original.eq_ignore_ascii_case(&effective)
                    || change.original.eq_ignore_ascii_case(&requested) =>
            {
                effective = change.new_name;
            }
            Ok(DaemonEvent::Error(error)) => {
                break Err(native_rejected(ProviderOperation::Publish, error));
            }
            Ok(_) => {}
            Err(error) => {
                break Err(provider_error(
                    DESCRIPTOR.name,
                    ProviderOperation::Publish,
                    ProviderFailure::Timeout,
                    format!("announcement monitor stopped: {error}"),
                ));
            }
        }
    };
    if result.is_err() {
        if let Err(release_error) = withdraw_native(daemon, &effective) {
            let shutdown = shutdown_native(daemon);
            return Err(native_lost(
                ProviderOperation::Publish,
                format!(
                    "publication acknowledgement failed and rollback failed ({release_error}); session shutdown: {}",
                    shutdown
                        .as_ref()
                        .map(|_| "acknowledged".to_string())
                        .unwrap_or_else(|error| error.to_string())
                ),
            ));
        }
    }
    result
}

fn withdraw_native(daemon: &ServiceDaemon, fullname: &str) -> Result<()> {
    let status = daemon
        .unregister(fullname)
        .map_err(|error| native_protocol(ProviderOperation::Withdraw, error))?
        .recv_timeout(RESOURCE_RELEASE_TIMEOUT)
        .map_err(|error| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Withdraw,
                ProviderFailure::Timeout,
                format!("unregister acknowledgement timed out: {error}"),
            )
        })?;
    match status {
        UnregisterStatus::OK | UnregisterStatus::NotFound => Ok(()),
    }
}

fn start_native_browse(daemon: &ServiceDaemon, service_type: &str) -> Result<NativeRawBrowse> {
    let events = daemon
        .browse(service_type)
        .map_err(|error| native_protocol(ProviderOperation::Browse, error))?;
    let first = events.recv_timeout(BROWSE_START_TIMEOUT).map_err(|error| {
        provider_error(
            DESCRIPTOR.name,
            ProviderOperation::Browse,
            ProviderFailure::Timeout,
            format!("browse did not establish: {error}"),
        )
    })?;
    let first = match first {
        MdnsServiceEvent::SearchStarted(_) => None,
        MdnsServiceEvent::SearchStopped(_) => {
            return Err(provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Rejected,
                "browse stopped during establishment",
            ));
        }
        event => Some(event),
    };
    Ok(NativeRawBrowse { events, first })
}

fn close_native_browse(daemon: &ServiceDaemon, service_type: &str) -> Result<()> {
    daemon
        .stop_browse(service_type)
        .map_err(|error| native_protocol(ProviderOperation::Browse, error))?;
    let status = daemon
        .status()
        .map_err(|error| native_protocol(ProviderOperation::Browse, error))?
        .recv_timeout(RESOURCE_RELEASE_TIMEOUT)
        .map_err(|error| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Browse,
                ProviderFailure::Timeout,
                format!("browse close barrier timed out: {error}"),
            )
        })?;
    if status == DaemonStatus::Running {
        Ok(())
    } else {
        Err(native_lost(
            ProviderOperation::Browse,
            format!("unexpected close-barrier status: {status:?}"),
        ))
    }
}

fn shutdown_native(daemon: &ServiceDaemon) -> Result<()> {
    let status = daemon
        .shutdown()
        .map_err(|error| native_protocol(ProviderOperation::Shutdown, error))?
        .recv_timeout(RESOURCE_RELEASE_TIMEOUT)
        .map_err(|error| {
            provider_error(
                DESCRIPTOR.name,
                ProviderOperation::Shutdown,
                ProviderFailure::Timeout,
                format!("shutdown acknowledgement timed out: {error}"),
            )
        })?;
    if status == DaemonStatus::Shutdown {
        Ok(())
    } else {
        Err(native_lost(
            ProviderOperation::Shutdown,
            format!("unexpected shutdown status: {status:?}"),
        ))
    }
}

enum NativeEvent {
    Emit(ProviderEvent),
    Skip,
    Stop,
}

fn translate(event: MdnsServiceEvent, is_meta: bool) -> NativeEvent {
    match event {
        MdnsServiceEvent::ServiceFound(_, fullname) if is_meta => {
            let type_name = fullname
                .trim_end_matches('.')
                .trim_end_matches(".local")
                .to_string();
            NativeEvent::Emit(ProviderEvent::Found(ProviderService {
                name: type_name,
                service_type: String::new(),
                host: None,
                addresses: Vec::new(),
                port: None,
                txt: HashMap::new(),
            }))
        }
        MdnsServiceEvent::ServiceFound(_, _) => NativeEvent::Skip,
        MdnsServiceEvent::ServiceResolved(resolved) => {
            NativeEvent::Emit(ProviderEvent::Resolved(resolved_to_service(&resolved)))
        }
        MdnsServiceEvent::ServiceRemoved(service_type, fullname) => {
            let (name, service_type) = parse_removed(&service_type, &fullname);
            NativeEvent::Emit(ProviderEvent::Removed { name, service_type })
        }
        MdnsServiceEvent::SearchStarted(_) => NativeEvent::Skip,
        MdnsServiceEvent::SearchStopped(_) => NativeEvent::Stop,
        _ => NativeEvent::Skip,
    }
}

fn parse_removed(service_type: &str, fullname: &str) -> (String, String) {
    let service_type = service_type
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();
    let name = fullname
        .find("._")
        .map(|index| &fullname[..index])
        .unwrap_or(fullname)
        .to_string();
    (name, service_type)
}

fn resolved_to_service(resolved: &ResolvedService) -> ProviderService {
    let fullname = resolved.get_fullname();
    let name = fullname
        .find("._")
        .map(|index| &fullname[..index])
        .unwrap_or(fullname)
        .to_string();
    let service_type = resolved
        .ty_domain
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();
    let host = match resolved.get_hostname() {
        "" => None,
        value => Some(value.to_string()),
    };
    let mut addresses = Vec::new();
    for scoped in resolved.get_addresses() {
        match scoped {
            ScopedIp::V4(v4) if v4.interface_ids().is_empty() => {
                addresses.push(ProviderAddress {
                    address: scoped.to_ip_addr(),
                    interface_index: None,
                    interface_name: None,
                });
            }
            ScopedIp::V4(v4) => {
                addresses.extend(v4.interface_ids().iter().map(|interface| ProviderAddress {
                    address: scoped.to_ip_addr(),
                    interface_index: Some(interface.index),
                    interface_name: Some(interface.name.clone()),
                }));
            }
            ScopedIp::V6(v6) => addresses.push(ProviderAddress {
                address: scoped.to_ip_addr(),
                interface_index: Some(v6.scope_id().index),
                interface_name: Some(v6.scope_id().name.clone()),
            }),
            _ => addresses.push(ProviderAddress {
                address: scoped.to_ip_addr(),
                interface_index: None,
                interface_name: None,
            }),
        }
    }
    let txt = resolved
        .get_properties()
        .iter()
        .map(|property| (property.key().to_string(), property.val_str().to_string()))
        .collect();
    ProviderService {
        name,
        service_type,
        host,
        addresses,
        port: Some(resolved.get_port()),
        txt,
    }
}

fn dns_label(id: &str) -> String {
    let label = id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect::<String>();
    let label = if label.is_empty() {
        "service".to_string()
    } else {
        label
    };
    label.chars().take(63).collect()
}

fn explicit_publication_host(id: &str) -> String {
    let hash = id.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        hash.wrapping_mul(0x100000001b3) ^ u64::from(byte)
    });
    format!("koi-{hash:016x}.local.")
}

fn native_protocol(operation: ProviderOperation, error: impl std::fmt::Display) -> MdnsError {
    provider_error(
        DESCRIPTOR.name,
        operation,
        ProviderFailure::Protocol,
        error.to_string(),
    )
}

fn native_rejected(operation: ProviderOperation, error: impl std::fmt::Display) -> MdnsError {
    provider_error(
        DESCRIPTOR.name,
        operation,
        ProviderFailure::Rejected,
        error.to_string(),
    )
}

fn native_lost(operation: ProviderOperation, detail: impl Into<String>) -> MdnsError {
    provider_error(DESCRIPTOR.name, operation, ProviderFailure::Lost, detail)
}

fn is_lost_error(error: &MdnsError) -> bool {
    matches!(
        error,
        MdnsError::Provider {
            failure: ProviderFailure::Lost,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_event_is_normalized_at_the_adapter_boundary() {
        let (name, service_type) = parse_removed("_http._tcp.local.", "My NAS._http._tcp.local.");
        assert_eq!(name, "My NAS");
        assert_eq!(service_type, "_http._tcp");
    }

    #[test]
    fn explicit_publication_host_is_stable_and_isolated() {
        assert_eq!(dns_label("ab_cd-12"), "abcd-12");
        assert_eq!(
            explicit_publication_host("one"),
            explicit_publication_host("one")
        );
        assert_ne!(
            explicit_publication_host("one"),
            explicit_publication_host("two")
        );
    }

    #[test]
    fn mdns_sd_is_isolated_to_the_native_adapter() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let offenders = std::fs::read_dir(&src_dir)
            .expect("read src dir")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("rs"))
            .filter(|path| path.file_name().and_then(|name| name.to_str()) != Some("native.rs"))
            .filter(|path| {
                std::fs::read_to_string(path).is_ok_and(|contents| contents.contains("mdns_sd"))
            })
            .collect::<Vec<_>>();
        assert!(
            offenders.is_empty(),
            "mdns_sd must only be referenced in native.rs; offenders: {offenders:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cooperative_probe_accepts_an_existing_reuse_holder() {
        let first = CooperativeBind::on_port(0).expect("first cooperative bind");
        let port = first
            ._ipv4
            .as_ref()
            .expect("IPv4 probe")
            .local_addr()
            .expect("probe address")
            .as_socket()
            .expect("IP socket")
            .port();
        let second = CooperativeBind::on_port(port).expect("shared cooperative bind");
        assert!(second._ipv4.is_some());
    }

    #[tokio::test]
    #[ignore = "requires the real host mDNS socket environment"]
    async fn real_native_adapter_opens_and_shuts_down() {
        let adapter = NativeMdnsAdapter;
        let report = adapter.assess().await;
        assert_eq!(
            report.availability,
            ProviderAvailability::Ready,
            "{report:?}"
        );
        let session = adapter.open().await.expect("open native session");
        assert_eq!(*session.state().borrow(), ProviderSessionState::Ready);
        session.shutdown().await.expect("shutdown native session");
    }
}
