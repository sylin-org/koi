use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;
use tokio_util::sync::CancellationToken;

use koi_client::KoiClient;
use koi_common::integration::MdnsDiscoverySnapshot;
use koi_common::peer::Peer;
use koi_common::types::{EventKind, ServiceRecord, ServiceType, META_QUERY};
use koi_dns::DnsEntry;
use koi_dns::{DnsLookupResult, DnsRuntime, DnsRuntimeStatus};
use koi_health::{HealthCheck, HealthRuntime};
use koi_mdns::protocol::{RegisterPayload, RegistrationResult, RenewalResult};
use koi_mdns::{BrowseSubscription as MdnsBrowseHandle, MdnsCore, MdnsEvent};
use koi_proxy::{ProxyEntry, ProxyRuntime, ProxyRuntimeStatus};

use crate::{map_join_error, KoiError, KoiEvent};

/// Hard ceiling on ordered teardown — bounds the cancel/drain/join sequence so a wedged
/// task can never hang the host application's shutdown (mirrors the daemon's limit).
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// Grace period after cancellation for in-flight work to drain before tasks are joined.
const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_millis(500);
/// Retry cadence for a process-derived participation announcement after provider churn.
const PARTICIPATE_ANNOUNCE_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

enum HandleBackend {
    Embedded {
        host: koi_compose::host::HostIdentity,
        mdns: Option<Arc<MdnsCore>>,
        dns: Option<Arc<DnsRuntime>>,
        health: Option<Arc<HealthRuntime>>,
        certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
        proxy: Option<Arc<ProxyRuntime>>,
        udp: Option<Arc<koi_udp::UdpRuntime>>,
        runtime: Option<Arc<koi_runtime::RuntimeCore>>,
        system_status: Arc<koi_compose::status::KoiStatusRuntime>,
        composition: koi_compose::cores::RunningCores,
    },
    Remote {
        client: Arc<KoiClient>,
    },
}

pub struct KoiHandle {
    backend: HandleBackend,
    /// The address the embedded HTTP adapter bound to (`None` if HTTP is disabled
    /// or in remote mode). Populated even for a fixed port; with `http_port(0)` it
    /// carries the OS-assigned ephemeral port.
    http_addr: Option<std::net::SocketAddr>,
    data_dir: Option<std::path::PathBuf>,
    events: broadcast::Sender<KoiEvent>,
    cancel: CancellationToken,
    tasks: std::sync::Mutex<Vec<JoinHandle<()>>>,
}

impl KoiHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_embedded(
        host: koi_compose::host::HostIdentity,
        mdns: Option<Arc<MdnsCore>>,
        dns: Option<Arc<DnsRuntime>>,
        health: Option<Arc<HealthRuntime>>,
        certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
        proxy: Option<Arc<ProxyRuntime>>,
        udp: Option<Arc<koi_udp::UdpRuntime>>,
        runtime: Option<Arc<koi_runtime::RuntimeCore>>,
        system_status: Arc<koi_compose::status::KoiStatusRuntime>,
        composition: koi_compose::cores::RunningCores,
        http_addr: Option<std::net::SocketAddr>,
        data_dir: Option<std::path::PathBuf>,
        events: broadcast::Sender<KoiEvent>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            backend: HandleBackend::Embedded {
                host,
                mdns,
                dns,
                health,
                certmesh,
                proxy,
                udp,
                runtime,
                system_status,
                composition,
            },
            http_addr,
            data_dir,
            events,
            cancel,
            tasks: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn new_remote(
        client: Arc<KoiClient>,
        events: broadcast::Sender<KoiEvent>,
        cancel: CancellationToken,
        tasks: Vec<JoinHandle<()>>,
    ) -> Self {
        Self {
            backend: HandleBackend::Remote { client },
            http_addr: None,
            data_dir: None,
            events,
            cancel,
            tasks: std::sync::Mutex::new(tasks),
        }
    }

    /// Stream host-facing events produced by this in-process composition.
    ///
    /// Client mode has no daemon-wide event transport, so it fails explicitly
    /// instead of returning a stream that can never produce an item.
    pub fn events(&self) -> Result<BroadcastStream<KoiEvent>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { .. } => Ok(BroadcastStream::new(self.events.subscribe())),
            HandleBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "host event stream (the daemon exposes only typed domain streams)",
            )),
        }
    }

    /// Read the current composition status without I/O or awaiting.
    pub fn status(&self) -> Result<Arc<koi_compose::status::KoiStatus>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { system_status, .. } => Ok(system_status.status()),
            HandleBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "cheap local product status; use the daemon inventory API",
            )),
        }
    }

    /// Subscribe to the current composition status and coalesced changes.
    pub fn watch_status(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<Arc<koi_compose::status::KoiStatus>>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { system_status, .. } => Ok(system_status.watch_status()),
            HandleBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "local product status subscription",
            )),
        }
    }

    /// The address the embedded HTTP adapter bound to, or `None` when HTTP is
    /// disabled or this is a remote handle. With `Builder::http_port(0)` this
    /// reports the OS-assigned ephemeral port — the supported way to run an
    /// embedded HTTP surface on a free port without racing to pick one.
    pub fn http_addr(&self) -> Option<std::net::SocketAddr> {
        self.http_addr
    }

    /// The port the embedded HTTP adapter bound to (convenience over
    /// [`http_addr`](Self::http_addr)). `None` if HTTP is disabled / remote.
    pub fn bound_http_port(&self) -> Option<u16> {
        self.http_addr.map(|addr| addr.port())
    }

    /// Bind and serve `router` with the same-port posture dial (ADR-020 §5):
    /// plain HTTP while this node is Open, mTLS once it is secure, flipping live
    /// with **no dropped connections** as the posture changes.
    ///
    /// Success is the listener readiness fence. The returned address is the exact
    /// socket acquired from the OS, including its selected port when `addr.port()`
    /// is zero. The serving generation remains owned by this handle's composition;
    /// either [`shutdown`](Self::shutdown) or `cancel` tears it down and reaps its
    /// connections. Embedded only — a remote handle has no local identity to serve
    /// mTLS with.
    pub async fn serve(
        &self,
        router: axum::Router,
        addr: std::net::SocketAddr,
        cancel: CancellationToken,
    ) -> Result<std::net::SocketAddr, KoiError> {
        let (certmesh, composition) = match &self.backend {
            HandleBackend::Embedded {
                certmesh,
                composition,
                ..
            } => (
                certmesh
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("certmesh"))?
                    .clone(),
                composition,
            ),
            HandleBackend::Remote { .. } => {
                return Err(KoiError::RemoteUnsupported(
                    "same-port adaptive serving requires local Certmesh identity",
                ))
            }
        };

        self.start_serving(certmesh, composition, router, addr, cancel, None)
            .await
    }

    /// Become a fully-participating trusted service in one call (ADR-020 §13 — the
    /// "3-line trusted service"):
    ///
    /// 1. acquire/maintain this node's identity (best-effort refresh of a usable
    ///    identity; an honestly Open node stays plaintext, while damaged durable
    ///    membership fails readiness),
    /// 2. bind the real listener and announce `service_type` on the LAN at that
    ///    listener's actual port with the node's
    ///    posture stamped into the TXT, **kept current across posture flips**, and
    /// 3. retain the listener and announcement as one owned serving generation.
    ///
    /// The consumer never branches on posture and never wires identity, discovery,
    /// and serving separately. Success means both the listener and, when mDNS is
    /// enabled, its initial registration are established. The returned address is
    /// the actual bound address, including an OS-selected ephemeral port.
    /// Certificate *renewal* is handled by Koi's certmesh self-management, which is on
    /// by default once this node is a member (ADR-023); a self-driver disables it with
    /// `Builder::certmesh_managed(false)`. Embedded only.
    pub async fn participate(
        &self,
        router: axum::Router,
        addr: std::net::SocketAddr,
        service_type: &str,
        cancel: CancellationToken,
    ) -> Result<std::net::SocketAddr, KoiError> {
        let (certmesh, mdns, composition, hostname) = match &self.backend {
            HandleBackend::Embedded {
                host,
                certmesh,
                mdns,
                composition,
                ..
            } => (
                certmesh
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("certmesh"))?
                    .clone(),
                mdns.clone(),
                composition,
                host.hostname().to_string(),
            ),
            HandleBackend::Remote { .. } => {
                return Err(KoiError::RemoteUnsupported(
                    "participation requires local identity, announcement, and serving",
                ))
            }
        };

        // 1. Refresh best-effort, then decide exclusively from Certmesh's
        // authoritative projection. Only a genuinely Open node may proceed
        // without identity; durable-but-broken membership must never be served
        // or advertised as plaintext.
        ensure_participation_identity(&certmesh, &hostname).await?;

        let announcement = if let Some(mdns) = mdns {
            Some(ParticipationAnnouncementSpec {
                mdns,
                hostname,
                service_type: service_type.to_string(),
            })
        } else {
            tracing::debug!("participate: mDNS disabled — serving without announcing");
            None
        };

        self.start_serving(certmesh, composition, router, addr, cancel, announcement)
            .await
    }

    /// The one acquisition path behind both `serve` and `participate`.
    ///
    /// Nothing is published until the real socket exists. If participation was
    /// requested, its first native registration is also acknowledged before this
    /// method reports readiness. Startup and steady state are admitted to the
    /// composition owner as one generation.
    async fn start_serving(
        &self,
        certmesh: Arc<koi_certmesh::CertmeshCore>,
        composition: &koi_compose::cores::RunningCores,
        router: axum::Router,
        requested_addr: std::net::SocketAddr,
        caller_cancel: CancellationToken,
        announcement: Option<ParticipationAnnouncementSpec>,
    ) -> Result<std::net::SocketAddr, KoiError> {
        // Startup belongs to the serving generation too. In particular, once
        // mDNS has admitted a native publication command, dropping the caller's
        // readiness waiter must not abandon the coherent publication/rollback
        // tail. The admission gate also prevents a newly spawned task from
        // racing ahead of composition ownership.
        let (admitted_tx, admitted_rx) = tokio::sync::oneshot::channel();
        let (readiness_tx, readiness_rx) = tokio::sync::oneshot::channel();
        let lifetime = self.cancel.child_token();
        let owner_cancel = self.cancel.clone();
        let generation = ServingGeneration {
            certmesh,
            router,
            requested_addr,
            owner_cancel,
            caller_cancel,
            lifetime,
            announcement,
        };
        composition.own_task(tokio::spawn(generation.run(admitted_rx, readiness_tx)));

        // A terminal composition aborts the gated task rather than admitting
        // resources. If admission succeeded, the owned generation sends the
        // exact startup result after completing any required rollback.
        if admitted_tx.send(()).is_err() {
            return Err(serving_cancelled());
        }
        let (addr, acknowledge) = readiness_rx
            .await
            .unwrap_or_else(|_| Err(serving_cancelled()))?;
        // No await follows this acknowledgement: once it succeeds, this future
        // returns `Ready(Ok(addr))` in the same poll. The generation therefore
        // cannot mistake a merely queued result for one the caller observed.
        acknowledge.send(()).map_err(|_| serving_cancelled())?;
        Ok(addr)
    }

    /// Subscribe to host-facing events produced by this in-process composition.
    ///
    /// Client mode has no daemon-wide event transport; domain-specific remote
    /// streams remain available through their typed handles.
    pub fn subscribe(&self) -> Result<broadcast::Receiver<KoiEvent>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { .. } => Ok(self.events.subscribe()),
            HandleBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "host event subscription (the daemon exposes only typed domain streams)",
            )),
        }
    }

    pub fn mdns(&self) -> Result<MdnsHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { mdns, .. } => {
                let core = mdns.as_ref().ok_or(KoiError::DisabledCapability("mdns"))?;
                Ok(MdnsHandle::new_embedded(Arc::clone(core)))
            }
            HandleBackend::Remote { client } => Ok(MdnsHandle::new_remote(Arc::clone(client))),
        }
    }

    pub fn dns(&self) -> Result<DnsHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { dns, .. } => {
                let runtime = dns.as_ref().ok_or(KoiError::DisabledCapability("dns"))?;
                Ok(DnsHandle::new_embedded(Arc::clone(runtime)))
            }
            HandleBackend::Remote { client } => Ok(DnsHandle::new_remote(Arc::clone(client))),
        }
    }

    pub fn health(&self) -> Result<HealthHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { health, .. } => {
                let runtime = health
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("health"))?;
                Ok(HealthHandle::new_embedded(Arc::clone(runtime)))
            }
            HandleBackend::Remote { client } => Ok(HealthHandle::new_remote(Arc::clone(client))),
        }
    }

    pub fn certmesh(&self) -> Result<CertmeshHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { certmesh, .. } => {
                let core = certmesh
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("certmesh"))?;
                Ok(CertmeshHandle::new_embedded(Arc::clone(core)))
            }
            HandleBackend::Remote { client } => Ok(CertmeshHandle::new_remote(Arc::clone(client))),
        }
    }

    /// Sign `bytes` into an [`Envelope`](koi_common::envelope::Envelope) (ADR-020 §3)
    /// — top-level shorthand for `certmesh()?.sign(bytes)`. Mode-transparent: a
    /// freshness-stamped passthrough when Open, ES256-signed when Authenticated.
    /// Embedded only.
    pub async fn sign(&self, bytes: &[u8]) -> Result<koi_common::envelope::Envelope, KoiError> {
        self.certmesh()?.sign(bytes).await
    }

    /// Verify an [`Envelope`](koi_common::envelope::Envelope), returning an
    /// [`Assurance`](koi_common::envelope::Assurance) (ADR-020 §3) — top-level
    /// shorthand for `certmesh()?.verify(env)`, symmetric with [`sign`](Self::sign).
    /// Read a trusted identity only via `Assurance::identity()`. Embedded only.
    pub async fn verify(
        &self,
        env: &koi_common::envelope::Envelope,
    ) -> Result<koi_common::envelope::Assurance, KoiError> {
        self.certmesh()?.verify(env).await
    }

    /// Open the encrypted key-value vault for general-purpose secret storage.
    ///
    /// The vault uses platform credential binding (keyring) when available,
    /// with a machine-bound fallback. Each call opens a fresh handle sharing
    /// the same on-disk state.
    pub fn vault(&self) -> Result<koi_crypto::vault::Vault, KoiError> {
        if matches!(&self.backend, HandleBackend::Remote { .. }) {
            return Err(KoiError::RemoteUnsupported(
                "vault access requires local key material",
            ));
        }
        let dir = self
            .data_dir
            .as_ref()
            .ok_or(KoiError::DisabledCapability("vault (no data_dir)"))?;
        koi_crypto::vault::Vault::open(dir)
            .map_err(|e| KoiError::Io(std::io::Error::other(e.to_string())))
    }

    pub fn proxy(&self) -> Result<ProxyHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { proxy, .. } => {
                let runtime = proxy
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("proxy"))?;
                Ok(ProxyHandle::new_embedded(Arc::clone(runtime)))
            }
            HandleBackend::Remote { client } => Ok(ProxyHandle::new_remote(Arc::clone(client))),
        }
    }

    /// Get the UDP runtime handle.
    ///
    /// Only available in embedded mode — remote mode does not support UDP bridging
    /// (the remote daemon itself handles bindings).
    pub fn udp(&self) -> Result<Arc<koi_udp::UdpRuntime>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { udp, .. } => {
                let runtime = udp.as_ref().ok_or(KoiError::DisabledCapability("udp"))?;
                Ok(Arc::clone(runtime))
            }
            HandleBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "UDP runtime handle; use the daemon UDP API",
            )),
        }
    }

    /// Get the runtime adapter core.
    ///
    /// Only available in embedded mode when runtime is enabled.
    pub fn runtime(&self) -> Result<Arc<koi_runtime::RuntimeCore>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { runtime, .. } => {
                let core = runtime
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("runtime"))?;
                Ok(Arc::clone(core))
            }
            HandleBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "container runtime core has no remote facade",
            )),
        }
    }

    pub async fn shutdown(self) -> Result<(), KoiError> {
        match &self.backend {
            HandleBackend::Embedded {
                composition, proxy, ..
            } => {
                // Route through the shared ordered teardown so embedded inherits the same
                // cancel → drain → join → withdraw-announce → per-core goodbye sequence the
                // daemon runs, including the UDP shutdown + drain + hard timeout it omitted.
                koi_compose::cores::ordered_shutdown(
                    &self.cancel,
                    composition,
                    SHUTDOWN_TIMEOUT,
                    SHUTDOWN_DRAIN,
                )
                .await;
                // Ordered teardown owns the one real release transaction. A
                // second call only reads Proxy's retained, outcome-idempotent
                // terminal fence so the embedded boundary cannot invent success.
                if let Some(proxy) = proxy {
                    proxy.shutdown().await?;
                }
                Ok(())
            }
            HandleBackend::Remote { client } => {
                let client = Arc::clone(client);
                let remote_result =
                    match tokio::task::spawn_blocking(move || client.shutdown()).await {
                        Ok(result) => result.map_err(KoiError::Client),
                        Err(error) => Err(map_join_error(error)),
                    };

                // Local adapter tasks are always owned even when the daemon request fails.
                self.cancel.cancel();
                let tasks = {
                    let mut tasks = self
                        .tasks
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    std::mem::take(&mut *tasks)
                };
                for task in tasks {
                    let _ = task.await;
                }
                remote_result
            }
        }
    }
}

async fn ensure_participation_identity(
    certmesh: &koi_certmesh::CertmeshCore,
    hostname: &str,
) -> Result<(), KoiError> {
    if certmesh.ensure_identity().await.is_some() {
        return Ok(());
    }

    let status = certmesh.status();
    use koi_certmesh::{CertmeshError, CertmeshRole, IdentityCondition};
    if status.role == CertmeshRole::Open && status.identity.condition == IdentityCondition::Absent {
        return Ok(());
    }

    let error = match status.identity.condition {
        IdentityCondition::Revoked => CertmeshError::Revoked(hostname.to_string()),
        _ if status.role == CertmeshRole::Authority
            && status
                .authority
                .as_ref()
                .is_some_and(|authority| authority.locked) =>
        {
            CertmeshError::CaLocked
        }
        IdentityCondition::Invalid | IdentityCondition::Expired => {
            CertmeshError::Certificate(status.identity.reason.clone().unwrap_or_else(|| {
                "durable Certmesh membership has no usable local identity".to_string()
            }))
        }
        IdentityCondition::Absent => CertmeshError::Certificate(
            "durable Certmesh membership is missing its local identity".to_string(),
        ),
        IdentityCondition::Healthy => CertmeshError::Internal(
            "Certmesh reports a healthy identity but supplied no TLS material".to_string(),
        ),
    };
    Err(error.into())
}

impl Drop for KoiHandle {
    fn drop(&mut self) {
        // `shutdown()` is the graceful path. This non-async fallback ensures a
        // forgotten handle still cannot detach its owned workers into the host.
        self.cancel.cancel();
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

pub struct KoiBrowseHandle {
    backend: BrowseBackend,
}

/// One item from a browse adapter. Ordinary delivery carries a semantic event;
/// a lagged stream carries the authoritative latest snapshot so consumers can
/// replace, rather than guess at, their current view.
#[derive(Debug, Clone)]
pub enum KoiBrowseItem {
    Event(MdnsEvent),
    Snapshot(MdnsDiscoverySnapshot),
}

enum BrowseBackend {
    Embedded {
        handle: MdnsBrowseHandle,
        core: Arc<MdnsCore>,
    },
    Remote {
        receiver: Mutex<mpsc::Receiver<Result<KoiBrowseItem, KoiError>>>,
        cancellation: koi_client::SseCancellation,
        worker: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    },
}

impl KoiBrowseHandle {
    fn embedded(handle: MdnsBrowseHandle, core: Arc<MdnsCore>) -> Self {
        Self {
            backend: BrowseBackend::Embedded { handle, core },
        }
    }

    fn remote(
        receiver: mpsc::Receiver<Result<KoiBrowseItem, KoiError>>,
        cancellation: koi_client::SseCancellation,
        worker: std::thread::JoinHandle<()>,
    ) -> Self {
        Self {
            backend: BrowseBackend::Remote {
                receiver: Mutex::new(receiver),
                cancellation,
                worker: std::sync::Mutex::new(Some(worker)),
            },
        }
    }

    /// Receive the next event or resynchronization snapshot.
    ///
    /// A clean stream close is `Ok(None)`. Connection establishment fails from
    /// [`MdnsHandle::browse`], while subsequent transport, JSON, and protocol
    /// failures arrive here as `Err`; none are indistinguishable from EOF.
    pub async fn recv(&self) -> Result<Option<KoiBrowseItem>, KoiError> {
        match &self.backend {
            BrowseBackend::Embedded { handle, core } => match handle.recv().await {
                Ok(event) => Ok(Some(KoiBrowseItem::Event(event))),
                Err(koi_mdns::BrowseRecvError::Lagged { .. }) => Ok(Some(KoiBrowseItem::Snapshot(
                    core.discovery_snapshot().as_ref().clone(),
                ))),
                Err(koi_mdns::BrowseRecvError::Closed) => Ok(None),
            },
            BrowseBackend::Remote {
                receiver,
                cancellation,
                worker,
            } => {
                let item = receiver.lock().await.recv().await.transpose();
                if !matches!(&item, Ok(Some(_))) {
                    cancellation.cancel();
                    let joined = join_remote_browse_worker(worker);
                    if item.is_ok() {
                        joined?;
                    }
                }
                item
            }
        }
    }
}

impl Drop for KoiBrowseHandle {
    fn drop(&mut self) {
        if let BrowseBackend::Remote {
            receiver,
            cancellation,
            worker,
        } = &mut self.backend
        {
            // Release a relay blocked on channel backpressure before joining it.
            receiver.get_mut().close();
            cancellation.cancel();
            // `SseStream` has a transport-enforced read bound, so joining here
            // cannot strand a host forever even when the peer goes silent.
            let _ = join_remote_browse_worker(worker);
        }
    }
}

fn join_remote_browse_worker(
    worker: &std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
) -> Result<(), KoiError> {
    let worker = worker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(worker) = worker {
        worker.join().map_err(|_| {
            KoiError::Client(koi_client::ClientError::Transport(
                "remote mDNS browse worker panicked".to_string(),
            ))
        })?;
    }
    Ok(())
}

/// Default discovery window (ADR-020 §8): long enough for mDNS resolution on a
/// quiet LAN, short enough to stay responsive — a sane default so the common
/// `discover(type)` call needs no tuning.
pub const DEFAULT_DISCOVER_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

pub struct MdnsHandle {
    backend: MdnsBackend,
}

enum MdnsBackend {
    Embedded { core: Arc<MdnsCore> },
    Remote { client: Arc<KoiClient> },
}

impl MdnsHandle {
    fn new_embedded(core: Arc<MdnsCore>) -> Self {
        Self {
            backend: MdnsBackend::Embedded { core },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: MdnsBackend::Remote { client },
        }
    }

    pub fn core(&self) -> Result<Arc<MdnsCore>, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(Arc::clone(core)),
            MdnsBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("direct mDNS core access"))
            }
        }
    }

    pub async fn browse(&self, service_type: &str) -> Result<KoiBrowseHandle, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => {
                let handle = core.subscribe_type(service_type).await?;
                Ok(KoiBrowseHandle::embedded(handle, Arc::clone(core)))
            }
            MdnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                let service_type = service_type.to_string();
                // Establish the connection before returning a handle so an
                // unreachable daemon cannot masquerade as a clean, empty stream.
                let stream =
                    tokio::task::spawn_blocking(move || client.browse_stream(&service_type))
                        .await
                        .map_err(map_join_error)??;
                let cancellation = stream.cancellation();
                let (tx, rx) = mpsc::channel(64);
                let worker = std::thread::Builder::new()
                    .name("koi-remote-mdns-browse".to_string())
                    .spawn(move || relay_remote_browse(stream, tx))
                    .map_err(KoiError::Io)?;
                Ok(KoiBrowseHandle::remote(rx, cancellation, worker))
            }
        }
    }

    /// Discover peers of `service_type`, each enriched with its advertised trust
    /// posture, mesh anchor, and identity expiry (ADR-020 §8) — the fleet-wide
    /// trust-legibility primitive. A snapshot collected over
    /// [`DEFAULT_DISCOVER_WINDOW`]; for a custom window use
    /// [`discover_for`](Self::discover_for).
    ///
    /// The posture each peer carries is an **untrusted hint** (ADR-016 §2);
    /// `certmesh().verify(..)` / mTLS adjudicates actual trust. Works in both
    /// embedded and remote mode (it layers on [`browse`](Self::browse)).
    pub async fn discover(&self, service_type: &str) -> Result<Vec<Peer>, KoiError> {
        self.discover_for(service_type, DEFAULT_DISCOVER_WINDOW)
            .await
    }

    /// Like [`discover`](Self::discover) with an explicit collection `window`.
    pub async fn discover_for(
        &self,
        service_type: &str,
        window: std::time::Duration,
    ) -> Result<Vec<Peer>, KoiError> {
        let browse = self.browse(service_type).await?;
        let canonical = if service_type == META_QUERY {
            META_QUERY.to_string()
        } else {
            ServiceType::parse_browse(service_type)
                .map_err(|error| KoiError::Mdns(error.into()))?
                .as_str()
                .to_string()
        };
        let mut records = std::collections::BTreeMap::new();
        let deadline = tokio::time::sleep(window);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                ev = browse.recv() => match ev {
                    Ok(Some(KoiBrowseItem::Event(event))) => apply_peer_event(&mut records, event),
                    Ok(Some(KoiBrowseItem::Snapshot(snapshot))) => {
                        reconcile_peer_snapshot(&mut records, &snapshot, &canonical);
                    }
                    Ok(None) => break,
                    Err(error) => return Err(error),
                },
            }
        }
        // The collection window owns the remote transport. End and reap it
        // before issuing the authoritative snapshot request.
        drop(browse);
        // Deadline and stream delivery are independent. Reconcile once from
        // the authoritative domain snapshot so a committed-but-queued event
        // cannot be omitted from this finite result.
        let snapshot = self.discovery_snapshot().await?;
        reconcile_peer_snapshot(&mut records, &snapshot, &canonical);
        Ok(records.into_values().map(Peer::from_record).collect())
    }

    /// Read the provider-neutral current discovery projection in either mode.
    pub async fn discovery_snapshot(&self) -> Result<Arc<MdnsDiscoverySnapshot>, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.discovery_snapshot()),
            MdnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                let snapshot =
                    tokio::task::spawn_blocking(move || client.mdns_discovery_snapshot())
                        .await
                        .map_err(map_join_error)??;
                Ok(Arc::new(snapshot))
            }
        }
    }

    pub async fn resolve(&self, name: &str) -> Result<ServiceRecord, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.resolve(name).await?),
            MdnsBackend::Remote { client } => {
                let name = name.to_string();
                let client = Arc::clone(client);
                let record = tokio::task::spawn_blocking(move || client.resolve(&name))
                    .await
                    .map_err(map_join_error)??;
                Ok(record)
            }
        }
    }

    /// Register heartbeat-owned presence through the selected mDNS owner.
    ///
    /// `lease_secs` has one meaning in both modes: `None` selects the mDNS
    /// domain default, zero is rejected, and a positive value is the exact
    /// heartbeat lease. Renew the returned id with [`Self::heartbeat`].
    pub async fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.register_heartbeat(payload).await?),
            MdnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                Ok(
                    tokio::task::spawn_blocking(move || client.register(&payload))
                        .await
                        .map_err(map_join_error)??,
                )
            }
        }
    }

    /// Renew one heartbeat-owned registration and return its exact lease.
    pub async fn heartbeat(&self, id: &str) -> Result<RenewalResult, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => {
                let lease_secs = core.heartbeat(id).await?;
                Ok(RenewalResult {
                    id: id.to_string(),
                    lease_secs,
                })
            }
            MdnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                let id = id.to_string();
                Ok(tokio::task::spawn_blocking(move || client.heartbeat(&id))
                    .await
                    .map_err(map_join_error)??)
            }
        }
    }

    pub async fn unregister(&self, id: &str) -> Result<(), KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.unregister(id).await?),
            MdnsBackend::Remote { client } => {
                let id = id.to_string();
                let client = Arc::clone(client);
                Ok(tokio::task::spawn_blocking(move || client.unregister(&id))
                    .await
                    .map_err(map_join_error)??)
            }
        }
    }

    /// Subscribe to the live mDNS lifecycle-event stream (Found / Resolved / Removed).
    ///
    /// Available only in **embedded** mode, where there is a local `MdnsCore` to subscribe
    /// to. In **client (remote)** mode there is no all-types lifecycle stream to forward —
    /// the daemon's `/v1/mdns/subscribe` requires a service type — so this returns
    /// [`KoiError::RemoteUnsupported`]. For a remote event stream, use
    /// [`MdnsHandle::browse`] with a specific service type (it forwards the daemon's SSE).
    ///
    /// Previously this silently returned a dead receiver in remote mode (it yielded nothing,
    /// forever); the typed error makes the limitation visible instead of swallowing it.
    pub fn subscribe(&self) -> Result<broadcast::Receiver<MdnsEvent>, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.subscribe()),
            MdnsBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "mdns subscribe — use mdns.browse(service_type) for a remote event stream",
            )),
        }
    }
}

pub struct DnsHandle {
    backend: DnsBackend,
}

enum DnsBackend {
    Embedded { runtime: Arc<DnsRuntime> },
    Remote { client: Arc<KoiClient> },
}

impl DnsHandle {
    fn new_embedded(runtime: Arc<DnsRuntime>) -> Self {
        Self {
            backend: DnsBackend::Embedded { runtime },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: DnsBackend::Remote { client },
        }
    }

    pub fn runtime(&self) -> Result<Arc<DnsRuntime>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(Arc::clone(runtime)),
            DnsBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("direct DNS runtime access"))
            }
        }
    }

    pub fn core(&self) -> Result<Arc<koi_dns::DnsCore>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(runtime.core()),
            DnsBackend::Remote { .. } => Err(KoiError::RemoteUnsupported("direct DNS core access")),
        }
    }

    /// Read DNS's authoritative current runtime projection in either mode.
    pub async fn status(&self) -> Result<Arc<DnsRuntimeStatus>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(runtime.status()),
            DnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || client.dns_status())
                    .await
                    .map_err(map_join_error)??;
                parse_dns_status(json).map(Arc::new)
            }
        }
    }

    pub async fn lookup(
        &self,
        name: &str,
        record_type: hickory_proto::rr::RecordType,
    ) -> Result<Option<DnsLookupResult>, KoiError> {
        ensure_supported_dns_record_type(record_type)?;
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(runtime.lookup(name, record_type).await?),
            DnsBackend::Remote { client } => {
                let name = name.to_string();
                let client = Arc::clone(client);
                tokio::task::spawn_blocking(move || client.dns_lookup(&name, record_type))
                    .await
                    .map_err(map_join_error)?
                    .map_err(KoiError::Client)
            }
        }
    }

    pub fn list_names(&self) -> Result<Vec<String>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(runtime.list_names()),
            DnsBackend::Remote { client } => parse_dns_names(client.dns_list()?),
        }
    }

    pub async fn start(&self) -> Result<bool, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(runtime.start().await?),
            DnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                tokio::task::spawn_blocking(move || client.dns_start())
                    .await
                    .map_err(map_join_error)?
                    .map_err(KoiError::Client)
            }
        }
    }

    pub async fn stop(&self) -> Result<bool, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(runtime.stop().await?),
            DnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                tokio::task::spawn_blocking(move || client.dns_stop())
                    .await
                    .map_err(map_join_error)?
                    .map_err(KoiError::Client)
            }
        }
    }

    pub fn add_entry(&self, entry: DnsEntry) -> Result<Vec<DnsEntry>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => {
                let entry = normalize_dns_entry(runtime, entry)?;
                Ok(runtime.add_entry(entry)?)
            }
            DnsBackend::Remote { client } => {
                let json = client.dns_add(&entry.name, &entry.ip, entry.ttl)?;
                parse_dns_entries(json)
            }
        }
    }

    /// Remove an operator DNS entry and return the resulting entry set.
    ///
    /// `None` is the domain's explicit not-found result. Embedded and remote
    /// modes preserve that same meaning instead of turning absence into a
    /// successful empty configuration.
    pub fn remove_entry(&self, name: &str) -> Result<Option<Vec<DnsEntry>>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => {
                let name = runtime.normalize_name(name).ok_or_else(|| {
                    KoiError::Dns(koi_dns::DnsError::InvalidEntry(format!(
                        "name `{name}` is outside the configured DNS zone"
                    )))
                })?;
                Ok(runtime.remove_entry(&name)?)
            }
            DnsBackend::Remote { client } => match client.dns_remove(name) {
                Ok(json) => parse_dns_entries(json).map(Some),
                Err(koi_client::ClientError::Api { error, .. }) if error == "not_found" => Ok(None),
                Err(error) => Err(error.into()),
            },
        }
    }
}

pub struct HealthHandle {
    backend: HealthBackend,
}

enum HealthBackend {
    Embedded { runtime: Arc<HealthRuntime> },
    Remote { client: Arc<KoiClient> },
}

impl HealthHandle {
    fn new_embedded(runtime: Arc<HealthRuntime>) -> Self {
        Self {
            backend: HealthBackend::Embedded { runtime },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: HealthBackend::Remote { client },
        }
    }

    pub fn runtime(&self) -> Result<Arc<HealthRuntime>, KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(Arc::clone(runtime)),
            HealthBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("direct Health runtime access"))
            }
        }
    }

    pub fn core(&self) -> Result<Arc<koi_health::HealthCore>, KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.core()),
            HealthBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("direct Health core access"))
            }
        }
    }

    /// Read Health's authoritative current projection in either mode.
    pub async fn status(&self) -> Result<Arc<koi_health::HealthSnapshot>, KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.status()),
            HealthBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || client.health_status())
                    .await
                    .map_err(map_join_error)??;
                parse_health_status(json).map(Arc::new)
            }
        }
    }

    pub async fn add_check(&self, check: HealthCheck) -> Result<(), KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.add_check(check).await?),
            HealthBackend::Remote { client } => {
                let client = Arc::clone(client);
                let check = check.clone();
                let response = tokio::task::spawn_blocking(move || {
                    client.health_add_check(
                        &check.name,
                        check.kind,
                        &check.target,
                        check.interval_secs,
                        check.timeout_secs,
                    )
                })
                .await
                .map_err(map_join_error)??;
                parse_status_ack(&response, "Health add-check response")
            }
        }
    }

    pub async fn remove_check(&self, name: &str) -> Result<(), KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.remove_check(name).await?),
            HealthBackend::Remote { client } => {
                let client = Arc::clone(client);
                let name = name.to_string();
                let response =
                    tokio::task::spawn_blocking(move || client.health_remove_check(&name))
                        .await
                        .map_err(map_join_error)??;
                parse_status_ack(&response, "Health remove-check response")
            }
        }
    }

    pub async fn start(&self) -> Result<bool, KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.start().await?),
            HealthBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "starting Health checks (the daemon has no lifecycle endpoint)",
            )),
        }
    }

    pub async fn stop(&self) -> Result<bool, KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.stop().await?),
            HealthBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "stopping Health checks (the daemon has no lifecycle endpoint)",
            )),
        }
    }
}

pub struct CertmeshHandle {
    backend: CertmeshBackend,
}

enum CertmeshBackend {
    Embedded {
        core: Arc<koi_certmesh::CertmeshCore>,
    },
    Remote {
        client: Arc<KoiClient>,
    },
}

impl CertmeshHandle {
    fn new_embedded(core: Arc<koi_certmesh::CertmeshCore>) -> Self {
        Self {
            backend: CertmeshBackend::Embedded { core },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: CertmeshBackend::Remote { client },
        }
    }

    pub fn core(&self) -> Result<Arc<koi_certmesh::CertmeshCore>, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(Arc::clone(core)),
            CertmeshBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("direct Certmesh core access"))
            }
        }
    }

    /// Read the authoritative Certmesh status in either embedded or remote mode.
    pub async fn status(&self) -> Result<Arc<koi_certmesh::CertmeshStatus>, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.status()),
            CertmeshBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || client.certmesh_status())
                    .await
                    .map_err(map_join_error)??;
                parse_certmesh_status(json).map(Arc::new)
            }
        }
    }

    /// This node's current trust posture — the mode oracle (ADR-020 §0).
    ///
    /// Works in **both** modes (wishlist 1.3): embedded reads the live watch value;
    /// a remote handle queries the daemon's `GET /v1/certmesh/posture` (DAT-gated, so
    /// the handle must carry a token — adopted from the local breadcrumb or set via
    /// `Builder::service_token`). A remote query needs the network, hence `async`.
    pub async fn posture(&self) -> Result<koi_common::posture::Posture, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.posture()),
            CertmeshBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || {
                    client.get_json(koi_certmesh::http::paths::POSTURE)
                })
                .await
                .map_err(map_join_error)??;
                parse_certmesh_posture(json)
            }
        }
    }

    /// Subscribe to the authoritative Certmesh status. Consumers that only care
    /// about posture compare `status.posture`; identity, role, diagnosis and CA
    /// changes travel through the same boundary.
    ///
    /// Ergonomic shorthand for `certmesh()?.core()?.watch_status()`. Embedded
    /// only; returns `RemoteUnsupported` in Remote mode.
    pub fn on_status(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<std::sync::Arc<koi_certmesh::CertmeshStatus>>, KoiError>
    {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.watch_status()),
            CertmeshBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("Certmesh status watch"))
            }
        }
    }

    /// This node's live identity, or `None` if it is Open (ADR-020 §7).
    /// Read-only; embedded only.
    pub async fn local_identity(&self) -> Result<Option<koi_certmesh::Identity>, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.local_identity().await),
            CertmeshBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "local Certmesh identity access",
            )),
        }
    }

    /// Ensure this node holds a current identity, then return it (ADR-020 §7).
    /// Idempotent and mode-transparent; embedded only.
    pub async fn ensure_identity(&self) -> Result<Option<koi_certmesh::Identity>, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.ensure_identity().await),
            CertmeshBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "local Certmesh identity acquisition",
            )),
        }
    }

    /// Sign `bytes` into an `Envelope` (ADR-020 §3). Mode-transparent: a
    /// freshness-stamped passthrough when Open, ES256-signed when Authenticated.
    /// Embedded only.
    pub async fn sign(&self, bytes: &[u8]) -> Result<koi_common::envelope::Envelope, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.sign(bytes).await),
            CertmeshBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("local Certmesh signing"))
            }
        }
    }

    /// Verify an `Envelope`, returning an `Assurance` (ADR-020 §3). Read a trusted
    /// identity only via `Assurance::identity()`. Embedded only.
    pub async fn verify(
        &self,
        env: &koi_common::envelope::Envelope,
    ) -> Result<koi_common::envelope::Assurance, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.verify(env).await),
            CertmeshBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("local Certmesh verification"))
            }
        }
    }

    /// Seal `bytes` into a `Sealed` (ADR-020 §4). The confidentiality rung, today a
    /// signed-not-encrypted passthrough; the consumer codes against the final API
    /// now. Embedded only.
    pub async fn seal(&self, bytes: &[u8]) -> Result<koi_common::sealed::Sealed, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.seal(bytes).await),
            CertmeshBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("local Certmesh sealing"))
            }
        }
    }

    /// Open a `Sealed` → `Opened` (recovered bytes + trust state, ADR-020 §4). A
    /// tampered/rejected message errors rather than yielding bytes. Embedded only.
    pub async fn open(
        &self,
        sealed: &koi_common::sealed::Sealed,
    ) -> Result<koi_common::sealed::Opened, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.open(sealed).await?),
            CertmeshBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("local Certmesh opening"))
            }
        }
    }

    /// Run the trust-doctor (ADR-020 §13) → a structured `TrustDiagnosis`: posture,
    /// identity + renewal health, on-disk-leaf integrity, self-revocation, and the
    /// CA trust-install state, each with an exact remedy. `is_red()`/`exit_code()`
    /// fail loud. In remote mode this calls the daemon's diagnosis endpoint.
    pub async fn diagnose(&self) -> Result<koi_common::diagnosis::TrustDiagnosis, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.diagnose().await),
            CertmeshBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || {
                    client.get_json(koi_certmesh::http::paths::DIAGNOSE)
                })
                .await
                .map_err(map_join_error)??;
                serde_json::from_value(json).map_err(|error| {
                    remote_decode(format!("invalid Certmesh diagnosis response: {error}"))
                })
            }
        }
    }

    /// Build a posture-keyed client to a discovered [`Peer`] (ADR-020 §6): plain
    /// HTTP to an Open peer, mTLS to a secure peer — the caller writes one code
    /// path. Embedded only (a remote handle has no local identity to present).
    ///
    /// Errors loudly (not via an opaque handshake failure) when the peer requires
    /// authentication but this node is Open, or when the peer anchors to a
    /// different mesh — see [`koi_certmesh::CertmeshCore::client_for`].
    pub async fn client_for(&self, peer: &Peer) -> Result<koi_certmesh::PeerClient, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.client_for(peer).await?),
            CertmeshBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "posture-keyed peer client requires local Certmesh identity",
            )),
        }
    }

    /// Build a posture-keyed [`reqwest::Client`] for a discovered [`Peer`] — the
    /// full-traffic dual of [`client_for`](Self::client_for) (wishlist 3.1).
    ///
    /// Unlike [`PeerClient`](koi_certmesh::PeerClient) (GET + JSON-POST only), the
    /// returned `reqwest::Client` carries koi's *transport policy* (plain HTTP to an
    /// Open peer; mTLS presenting this node's leaf + pinning the mesh CA to a secure
    /// peer) while the consumer drives the full request surface itself — every verb,
    /// custom headers, SSE/streaming, large bodies. One mode-transparent client for
    /// *all* inter-node traffic, not just trivial GETs.
    ///
    /// An Open peer yields a plain `reqwest::Client` (no TLS); a secure peer yields
    /// one configured with `use_preconfigured_tls`. Same loud errors as `client_for`
    /// (missing identity, different mesh). Embedded only.
    ///
    /// The raw `rustls::ClientConfig` is available via
    /// `certmesh().core()?.tls_client_config_for(peer)` for consumers driving hyper
    /// or a tower service directly.
    pub async fn reqwest_client_for(&self, peer: &Peer) -> Result<reqwest::Client, KoiError> {
        let core = match &self.backend {
            CertmeshBackend::Embedded { core } => core,
            CertmeshBackend::Remote { .. } => {
                return Err(KoiError::RemoteUnsupported(
                    "posture-keyed reqwest client requires local Certmesh identity",
                ))
            }
        };
        let builder = match core.tls_client_config_for(peer).await? {
            // Secure peer → hand the posture-keyed rustls config to reqwest. The
            // workspace pins a single rustls version, so the `Any` downcast matches.
            Some(config) => reqwest::Client::builder().use_preconfigured_tls(config),
            // Open peer → plain HTTP, no TLS.
            None => reqwest::Client::builder(),
        };
        builder
            .build()
            .map_err(|e| KoiError::Certmesh(koi_certmesh::CertmeshError::Internal(e.to_string())))
    }
}

/// The requested discovery half of a participation generation, before a socket
/// has been acquired. Keeping this separate prevents a caller from publishing a
/// guessed port or manufacturing a host identity.
struct ParticipationAnnouncementSpec {
    mdns: Arc<MdnsCore>,
    hostname: String,
    service_type: String,
}

/// One established, process-derived mDNS registration and the state needed to
/// restamp it after Certmesh posture changes. It is always owned by the same
/// composition task as the listener it describes.
struct ParticipationAnnouncement {
    mdns: Arc<MdnsCore>,
    session: koi_mdns::RegistrationSession,
    status_rx: tokio::sync::watch::Receiver<Arc<koi_certmesh::CertmeshStatus>>,
    hostname: String,
    service_type: String,
    port: u16,
    current_id: Option<String>,
}

impl ParticipationAnnouncement {
    /// Establish the initial registration. Returning success is the discovery
    /// readiness fence; a caller never receives a serving address for an mDNS-
    /// enabled participation whose first publication was not acknowledged.
    async fn establish(
        spec: ParticipationAnnouncementSpec,
        certmesh: &Arc<koi_certmesh::CertmeshCore>,
        port: u16,
    ) -> Result<Self, KoiError> {
        let session = spec.mdns.open_registration_session();
        // Subscribe before capturing the seed so a posture change during native
        // publication remains pending for the steady-state restamp loop.
        let mut status_rx = certmesh.watch_status();
        let status = status_rx.borrow_and_update().clone();
        let current_id = publish_participation_announcement(
            &spec.mdns,
            &session,
            &spec.hostname,
            &spec.service_type,
            port,
            status.as_ref(),
        )
        .await?;

        Ok(Self {
            mdns: spec.mdns,
            session,
            status_rx,
            hostname: spec.hostname,
            service_type: spec.service_type,
            port,
            current_id: Some(current_id),
        })
    }

    /// Keep the posture stamp current. Provider failures retain explicit desired
    /// state and retry on a bounded cadence; they do not terminate the listener
    /// or publish a duplicate record.
    async fn maintain(mut self, cancel: CancellationToken) {
        let mut dirty = self.status_rx.has_changed().unwrap_or(false);
        let mut retry = tokio::time::interval(PARTICIPATE_ANNOUNCE_RETRY);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                changed = self.status_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    dirty = true;
                }
                _ = retry.tick(), if dirty => {}
            }

            if !dirty {
                continue;
            }

            match self.restamp().await {
                Ok(()) => {
                    // A newer posture may have arrived while the native adapter
                    // was settling this generation. Leave it pending instead of
                    // declaring a stale stamp current.
                    dirty = self.status_rx.has_changed().unwrap_or(false);
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "participate: posture restamp failed; retaining intent for retry"
                    );
                    dirty = true;
                    retry.reset();
                }
            }
        }

        self.release().await;
    }

    async fn restamp(&mut self) -> Result<(), KoiError> {
        // Break before make, but keep the established id until native withdrawal
        // is acknowledged. A failed withdrawal therefore retries instead of
        // creating a duplicate publication.
        if let Some(id) = self.current_id.as_deref() {
            self.mdns.unregister(id).await?;
            self.current_id = None;
        }

        let status = self.status_rx.borrow_and_update().clone();
        let id = publish_participation_announcement(
            &self.mdns,
            &self.session,
            &self.hostname,
            &self.service_type,
            self.port,
            status.as_ref(),
        )
        .await?;
        self.current_id = Some(id);
        Ok(())
    }

    /// Best-effort explicit withdrawal followed by session-owned fail-safe
    /// cleanup on drop. The mDNS control plane bounds native operations, so this
    /// cannot make serving shutdown unbounded.
    async fn release(&mut self) {
        let Some(id) = self.current_id.take() else {
            return;
        };
        if let Err(error) = self.mdns.unregister(&id).await {
            tracing::warn!(
                %error,
                %id,
                "participate: explicit mDNS withdrawal failed; session cleanup remains armed"
            );
        }
    }
}

/// Publish this node's `service_type` on the listener's real `port` with one
/// exact Certmesh status stamp (ADR-020 §8).
async fn publish_participation_announcement(
    mdns: &Arc<MdnsCore>,
    session: &koi_mdns::RegistrationSession,
    hostname: &str,
    service_type: &str,
    port: u16,
    status: &koi_certmesh::CertmeshStatus,
) -> Result<String, KoiError> {
    let identity = status.identity.info.as_ref();
    let mut txt = std::collections::HashMap::new();
    koi_common::peer::stamp(
        &mut txt,
        status.posture,
        identity.map(|info| info.ca_fingerprint.as_str()),
        identity.map(|info| info.renewal.expires_at),
    );
    let result = mdns
        .register_with_policy(
            RegisterPayload {
                name: hostname.to_string(),
                service_type: service_type.to_string(),
                port,
                ip: None,
                lease_secs: None,
                txt,
            },
            koi_mdns::LeasePolicy::Session {
                grace: std::time::Duration::ZERO,
            },
            Some(session.id().clone()),
        )
        .await?;
    Ok(result.id)
}

/// Acquire the real socket unless either owner cancelled before readiness.
async fn acquire_listener(
    addr: std::net::SocketAddr,
    owner_cancel: &CancellationToken,
    caller_cancel: &CancellationToken,
) -> Result<tokio::net::TcpListener, KoiError> {
    tokio::select! {
        biased;
        _ = owner_cancel.cancelled() => Err(serving_cancelled()),
        _ = caller_cancel.cancelled() => Err(serving_cancelled()),
        listener = tokio::net::TcpListener::bind(addr) => listener.map_err(KoiError::Io),
    }
}

fn serving_cancelled() -> KoiError {
    KoiError::Io(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "adaptive serving cancelled before readiness",
    ))
}

/// Own one serving generation, including its readiness transaction. The TCP
/// listener and optional mDNS registration are acquired, acknowledged, served,
/// and released by this one composition-owned future.
struct ServingGeneration {
    certmesh: Arc<koi_certmesh::CertmeshCore>,
    router: axum::Router,
    requested_addr: std::net::SocketAddr,
    owner_cancel: CancellationToken,
    caller_cancel: CancellationToken,
    lifetime: CancellationToken,
    announcement: Option<ParticipationAnnouncementSpec>,
}

type ServingReadiness = Result<(std::net::SocketAddr, tokio::sync::oneshot::Sender<()>), KoiError>;

impl ServingGeneration {
    async fn run(
        self,
        admitted: tokio::sync::oneshot::Receiver<()>,
        readiness: tokio::sync::oneshot::Sender<ServingReadiness>,
    ) {
        let Self {
            certmesh,
            router,
            requested_addr,
            owner_cancel,
            caller_cancel,
            lifetime,
            announcement,
        } = self;

        // The task is spawned before it is synchronously transferred to the
        // composition owner. Do not acquire anything until that transfer finishes.
        if admitted.await.is_err() {
            return;
        }

        let listener = match acquire_listener(requested_addr, &owner_cancel, &caller_cancel).await {
            Ok(listener) => listener,
            Err(error) => {
                let _ = readiness.send(Err(error));
                return;
            }
        };
        let local_addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => {
                let _ = readiness.send(Err(KoiError::Io(error)));
                return;
            }
        };

        // Binding is provisional until readiness is acknowledged. A caller that
        // cancelled or stopped waiting releases the socket without ever asking the
        // provider to publish it.
        if owner_cancel.is_cancelled() || caller_cancel.is_cancelled() || readiness.is_closed() {
            let _ = readiness.send(Err(serving_cancelled()));
            return;
        }

        let mut announcement = match announcement {
            Some(spec) => {
                match ParticipationAnnouncement::establish(spec, &certmesh, local_addr.port()).await
                {
                    Ok(announcement) => Some(announcement),
                    Err(error) => {
                        let _ = readiness.send(Err(error));
                        return;
                    }
                }
            }
            None => None,
        };

        // Native publication is an admitted operation and therefore runs to its
        // domain acknowledgement even if the waiter disappears. Only then do we
        // withdraw the provisional presence and release the listener.
        if owner_cancel.is_cancelled() || caller_cancel.is_cancelled() || readiness.is_closed() {
            if let Some(announcement) = announcement.as_mut() {
                announcement.release().await;
            }
            let _ = readiness.send(Err(serving_cancelled()));
            return;
        }

        let (acknowledge_tx, acknowledge_rx) = tokio::sync::oneshot::channel();
        if readiness.send(Ok((local_addr, acknowledge_tx))).is_err() {
            if let Some(announcement) = announcement.as_mut() {
                announcement.release().await;
            }
            return;
        }

        let acknowledged = tokio::select! {
            biased;
            _ = owner_cancel.cancelled() => false,
            _ = caller_cancel.cancelled() => false,
            result = acknowledge_rx => result.is_ok(),
        };
        if !acknowledged {
            if let Some(announcement) = announcement.as_mut() {
                announcement.release().await;
            }
            return;
        }

        run_ready_serving_generation(
            certmesh,
            router,
            listener,
            caller_cancel,
            lifetime,
            announcement,
        )
        .await;
    }
}

/// Drive an already-acknowledged serving generation to bounded teardown.
async fn run_ready_serving_generation(
    certmesh: Arc<koi_certmesh::CertmeshCore>,
    router: axum::Router,
    listener: tokio::net::TcpListener,
    caller_cancel: CancellationToken,
    lifetime: CancellationToken,
    announcement: Option<ParticipationAnnouncement>,
) {
    let serving = crate::serve::run_adaptive_listener(certmesh, router, listener, lifetime.clone());
    tokio::pin!(serving);

    let Some(announcement) = announcement else {
        tokio::select! {
            biased;
            _ = lifetime.cancelled() => {
                observe_serving_result(serving.await);
            }
            _ = caller_cancel.cancelled() => {
                lifetime.cancel();
                observe_serving_result(serving.await);
            }
            result = &mut serving => observe_serving_result(result),
        }
        return;
    };

    let presence = announcement.maintain(lifetime.clone());
    tokio::pin!(presence);
    tokio::select! {
        biased;
        _ = lifetime.cancelled() => {
            let (serving_result, ()) = tokio::join!(serving, presence);
            observe_serving_result(serving_result);
        }
        _ = caller_cancel.cancelled() => {
            lifetime.cancel();
            let (serving_result, ()) = tokio::join!(serving, presence);
            observe_serving_result(serving_result);
        }
        result = &mut serving => {
            observe_serving_result(result);
            lifetime.cancel();
            presence.await;
        }
        () = &mut presence => {
            lifetime.cancel();
            observe_serving_result(serving.await);
        }
    }
}

fn observe_serving_result(result: std::io::Result<()>) {
    if let Err(error) = result {
        tracing::error!(%error, "adaptive serving generation exited after readiness");
    }
}

/// Fold a stream of mDNS lifecycle events into a deduplicated peer snapshot
/// (ADR-020 §8). Resolved records (which carry TXT, hence the trust hints)
/// overwrite an earlier Found for the same name; a Removed drops it. Ordered by
/// name for deterministic output. Pure — unit-tested without the network.
#[cfg(test)]
fn fold_peers(events: impl IntoIterator<Item = MdnsEvent>) -> Vec<Peer> {
    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, ServiceRecord> = BTreeMap::new();
    for ev in events {
        apply_peer_event(&mut by_name, ev);
    }
    by_name.into_values().map(Peer::from_record).collect()
}

fn apply_peer_event(
    by_name: &mut std::collections::BTreeMap<String, ServiceRecord>,
    event: MdnsEvent,
) {
    match event {
        MdnsEvent::Found(record) => {
            by_name.entry(record.name.clone()).or_insert(record);
        }
        MdnsEvent::Resolved(record) => {
            by_name.insert(record.name.clone(), record);
        }
        MdnsEvent::Removed { name, .. } => {
            by_name.remove(&name);
        }
    }
}

fn reconcile_peer_snapshot(
    by_name: &mut std::collections::BTreeMap<String, ServiceRecord>,
    snapshot: &MdnsDiscoverySnapshot,
    canonical_type: &str,
) {
    by_name.clear();
    if canonical_type == META_QUERY {
        for service_type in &snapshot.service_types {
            by_name.insert(
                service_type.clone(),
                ServiceRecord {
                    name: service_type.clone(),
                    service_type: META_QUERY.to_string(),
                    host: None,
                    ip: None,
                    port: None,
                    txt: Default::default(),
                },
            );
        }
        return;
    }
    for record in snapshot.records_for_query(canonical_type) {
        by_name.insert(record.name.clone(), record.clone());
    }
}

pub struct ProxyHandle {
    backend: ProxyBackend,
}

enum ProxyBackend {
    Embedded { runtime: Arc<ProxyRuntime> },
    Remote { client: Arc<KoiClient> },
}

impl ProxyHandle {
    fn new_embedded(runtime: Arc<ProxyRuntime>) -> Self {
        Self {
            backend: ProxyBackend::Embedded { runtime },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: ProxyBackend::Remote { client },
        }
    }

    pub fn runtime(&self) -> Result<Arc<ProxyRuntime>, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(Arc::clone(runtime)),
            ProxyBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("direct Proxy runtime access"))
            }
        }
    }

    pub fn core(&self) -> Result<Arc<koi_proxy::ProxyCore>, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.core()),
            ProxyBackend::Remote { .. } => {
                Err(KoiError::RemoteUnsupported("direct Proxy core access"))
            }
        }
    }

    /// Read Proxy's authoritative current runtime projection in either mode.
    pub async fn status(&self) -> Result<Arc<ProxyRuntimeStatus>, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.status()),
            ProxyBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || client.proxy_status())
                    .await
                    .map_err(map_join_error)??;
                parse_proxy_status(json).map(Arc::new)
            }
        }
    }

    pub async fn entries(&self) -> Result<Vec<ProxyEntry>, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.entries().await),
            ProxyBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || client.proxy_list())
                    .await
                    .map_err(map_join_error)??;
                parse_proxy_entries(json)
            }
        }
    }

    /// Persist and arm one desired proxy entry.
    ///
    /// Success acknowledges the accepted command. Current desired/listener
    /// state remains available through [`Self::entries`] and [`Self::status`];
    /// this command never fabricates an atomic result with a second read.
    pub async fn upsert(&self, entry: ProxyEntry) -> Result<(), KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.upsert(entry).await?),
            ProxyBackend::Remote { client } => {
                let client = Arc::clone(client);
                let response = tokio::task::spawn_blocking(move || {
                    client.proxy_add(
                        &entry.name,
                        entry.listen_port,
                        &entry.backend,
                        entry.allow_remote,
                    )
                })
                .await
                .map_err(map_join_error)??;
                parse_status_ack(&response, "Proxy upsert response")
            }
        }
    }

    /// Remove one desired proxy entry and settle its listener replacement.
    pub async fn remove(&self, name: &str) -> Result<(), KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.remove(name).await?),
            ProxyBackend::Remote { client } => {
                let client = Arc::clone(client);
                let name = name.to_string();
                let response = tokio::task::spawn_blocking(move || client.proxy_remove(&name))
                    .await
                    .map_err(map_join_error)??;
                parse_status_ack(&response, "Proxy remove response")
            }
        }
    }

    pub async fn start_all(&self) -> Result<(), KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.start_all().await?),
            ProxyBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "starting Proxy listeners (the daemon has no lifecycle endpoint)",
            )),
        }
    }

    pub async fn stop_all(&self) -> Result<bool, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.stop_all().await?),
            ProxyBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "stopping Proxy listeners (the daemon has no lifecycle endpoint)",
            )),
        }
    }
}

fn remote_decode(message: impl Into<String>) -> KoiError {
    KoiError::Client(koi_client::ClientError::Decode(message.into()))
}

fn require_fields(
    value: &serde_json::Value,
    fields: &[&str],
    context: &str,
) -> Result<(), KoiError> {
    let object = value
        .as_object()
        .ok_or_else(|| remote_decode(format!("{context} is not a JSON object")))?;
    for field in fields {
        if !object.contains_key(*field) {
            return Err(remote_decode(format!(
                "{context} is missing field `{field}`"
            )));
        }
    }
    Ok(())
}

fn parse_status_ack(json: &serde_json::Value, context: &str) -> Result<(), KoiError> {
    match json.get("status").and_then(serde_json::Value::as_str) {
        Some("ok") => Ok(()),
        Some(status) => Err(remote_decode(format!(
            "{context} has unexpected status `{status}`"
        ))),
        None => Err(remote_decode(format!(
            "{context} is missing string field `status`"
        ))),
    }
}

fn ensure_supported_dns_record_type(
    record_type: hickory_proto::rr::RecordType,
) -> Result<(), KoiError> {
    match record_type {
        hickory_proto::rr::RecordType::A
        | hickory_proto::rr::RecordType::AAAA
        | hickory_proto::rr::RecordType::ANY => Ok(()),
        unsupported => Err(KoiError::Dns(koi_dns::DnsError::InvalidEntry(format!(
            "unsupported DNS address record type: {unsupported}"
        )))),
    }
}

fn normalize_dns_entry(runtime: &DnsRuntime, mut entry: DnsEntry) -> Result<DnsEntry, KoiError> {
    entry.name = runtime.normalize_name(&entry.name).ok_or_else(|| {
        KoiError::Dns(koi_dns::DnsError::InvalidEntry(format!(
            "name `{}` is outside the configured DNS zone",
            entry.name
        )))
    })?;
    entry.ip.parse::<IpAddr>().map_err(|error| {
        KoiError::Dns(koi_dns::DnsError::InvalidEntry(format!(
            "invalid IP `{}`: {error}",
            entry.ip
        )))
    })?;
    Ok(entry)
}

fn parse_dns_names(json: serde_json::Value) -> Result<Vec<String>, KoiError> {
    json.get("names")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| remote_decode("DNS list response is missing array field `names`"))?
        .iter()
        .map(|name| {
            name.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| remote_decode("DNS list response contains a non-string name"))
        })
        .collect()
}

fn parse_dns_entries(json: serde_json::Value) -> Result<Vec<DnsEntry>, KoiError> {
    let entries = json
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| remote_decode("DNS entries response is missing array field `entries`"))?;
    for entry in entries {
        require_fields(entry, &["name", "ip", "ttl"], "DNS entry")?;
    }
    let entries = serde_json::from_value(serde_json::Value::Array(entries.clone()))
        .map_err(|error| remote_decode(format!("invalid DNS entries response: {error}")))?;
    Ok(entries)
}

fn parse_proxy_entries(json: serde_json::Value) -> Result<Vec<ProxyEntry>, KoiError> {
    let entries = json
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| remote_decode("Proxy list response is missing array field `entries`"))?;
    for entry in entries {
        require_fields(
            entry,
            &["name", "listen_port", "backend", "allow_remote"],
            "Proxy entry",
        )?;
    }
    serde_json::from_value(serde_json::Value::Array(entries.clone()))
        .map_err(|error| remote_decode(format!("invalid Proxy list response: {error}")))
}

fn parse_dns_status(json: serde_json::Value) -> Result<DnsRuntimeStatus, KoiError> {
    require_fields(
        &json,
        &[
            "revision",
            "running",
            "desired",
            "state",
            "endpoints",
            "zone",
            "port",
            "records",
        ],
        "DNS status response",
    )?;
    require_fields(
        &json["records"],
        &[
            "static_entries",
            "certmesh_entries",
            "mdns_entries",
            "txt_names",
        ],
        "DNS status record summary",
    )?;
    serde_json::from_value(json)
        .map_err(|error| remote_decode(format!("invalid DNS status response: {error}")))
}

fn parse_health_status(json: serde_json::Value) -> Result<koi_health::HealthSnapshot, KoiError> {
    require_fields(
        &json,
        &["revision", "running", "machines", "services"],
        "Health status response",
    )?;
    serde_json::from_value(json)
        .map_err(|error| remote_decode(format!("invalid Health status response: {error}")))
}

fn parse_proxy_status(json: serde_json::Value) -> Result<ProxyRuntimeStatus, KoiError> {
    require_fields(&json, &["revision", "proxies"], "Proxy status response")?;
    let proxies = json["proxies"]
        .as_array()
        .ok_or_else(|| remote_decode("Proxy status response field `proxies` is not an array"))?;
    for proxy in proxies {
        require_fields(
            proxy,
            &[
                "name",
                "listen_port",
                "backend",
                "allow_remote",
                "cert_source",
                "cert_revision",
                "state",
            ],
            "Proxy listener status",
        )?;
    }
    serde_json::from_value(json)
        .map_err(|error| remote_decode(format!("invalid Proxy status response: {error}")))
}

fn parse_certmesh_status(
    json: serde_json::Value,
) -> Result<koi_certmesh::CertmeshStatus, KoiError> {
    require_fields(
        &json,
        &["revision", "role", "posture", "identity", "diagnosis"],
        "Certmesh status response",
    )?;
    serde_json::from_value(json)
        .map_err(|error| remote_decode(format!("invalid Certmesh status response: {error}")))
}

fn parse_certmesh_posture(
    json: serde_json::Value,
) -> Result<koi_common::posture::Posture, KoiError> {
    require_fields(
        &json,
        &["signed", "encrypted", "level"],
        "Certmesh posture response",
    )?;
    let level = json["level"]
        .as_str()
        .ok_or_else(|| remote_decode("Certmesh posture response field `level` is not a string"))?
        .to_owned();
    let posture: koi_common::posture::Posture = serde_json::from_value(json)
        .map_err(|error| remote_decode(format!("invalid Certmesh posture response: {error}")))?;
    if posture.level().as_wire() != level {
        return Err(remote_decode(format!(
            "Certmesh posture response level `{level}` contradicts signed/encrypted fields"
        )));
    }
    Ok(posture)
}

fn relay_remote_browse<I>(stream: I, tx: mpsc::Sender<Result<KoiBrowseItem, KoiError>>)
where
    I: IntoIterator<Item = koi_client::Result<serde_json::Value>>,
{
    for item in stream {
        let item = item
            .map_err(KoiError::Client)
            .and_then(mdns_browse_item_from_pipeline);
        let terminal = item.is_err();
        if tx.blocking_send(item).is_err() || terminal {
            break;
        }
    }
}

fn mdns_browse_item_from_pipeline(json: serde_json::Value) -> Result<KoiBrowseItem, KoiError> {
    if let Some(code) = json.get("error") {
        let code = code.as_str().ok_or_else(|| {
            remote_decode("mDNS browse error response has a non-string `error` field")
        })?;
        let message = json
            .get("message")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                remote_decode("mDNS browse error response is missing string field `message`")
            })?;
        return Err(KoiError::Client(koi_client::ClientError::Api {
            error: code.to_string(),
            message: message.to_string(),
        }));
    }
    if let Some(snapshot) = json.get("snapshot") {
        require_fields(
            snapshot,
            &["revision", "service_types", "records"],
            "mDNS browse snapshot",
        )?;
        let records = snapshot["records"]
            .as_array()
            .ok_or_else(|| remote_decode("mDNS browse snapshot field `records` is not an array"))?;
        for record in records {
            require_fields(record, &["name", "type", "txt"], "mDNS browse record")?;
        }
        return serde_json::from_value(snapshot.clone())
            .map(KoiBrowseItem::Snapshot)
            .map_err(|error| {
                remote_decode(format!("invalid mDNS browse snapshot response: {error}"))
            });
    }
    mdns_event_from_pipeline(json).map(KoiBrowseItem::Event)
}

fn mdns_event_from_pipeline(json: serde_json::Value) -> Result<MdnsEvent, KoiError> {
    if let Some(found) = json.get("found") {
        let record = parse_service_record(found, "mDNS found response")?;
        return Ok(MdnsEvent::Found(record));
    }
    if let Some(resolved) = json.get("resolved") {
        let record = parse_service_record(resolved, "mDNS resolved response")?;
        return Ok(MdnsEvent::Resolved(record));
    }
    if let Some(event) = json.get("event") {
        let kind: EventKind = serde_json::from_value(event.clone())
            .map_err(|error| remote_decode(format!("invalid mDNS event kind: {error}")))?;
        let service = json
            .get("service")
            .cloned()
            .ok_or_else(|| remote_decode("mDNS event response is missing field `service`"))?;
        let record = parse_service_record(&service, "mDNS event service")?;
        return match kind {
            EventKind::Found => Ok(MdnsEvent::Found(record)),
            EventKind::Resolved => Ok(MdnsEvent::Resolved(record)),
            EventKind::Removed => Ok(MdnsEvent::Removed {
                name: record.name,
                service_type: record.service_type,
            }),
        };
    }
    Err(remote_decode(
        "unrecognized mDNS browse response (expected snapshot, event, found, resolved, or error)",
    ))
}

fn parse_service_record(
    value: &serde_json::Value,
    context: &str,
) -> Result<ServiceRecord, KoiError> {
    require_fields(value, &["name", "type", "txt"], context)?;
    serde_json::from_value(value.clone())
        .map_err(|error| remote_decode(format!("invalid {context}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::mdns_protocol::{
        MdnsCapabilities, MdnsProviderReport, ProbeFact, ProviderApi, ProviderAvailability,
        ProviderSessionState,
    };
    use koi_common::posture::PostureLevel;
    use koi_mdns::adapter::{MdnsAdapter, ProviderDescriptor};
    use koi_mdns::provider::{
        Announcement, BrowseLease, ProviderBrowse, ProviderSession, PublicationLease,
    };
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::{watch, Notify};

    fn rec(name: &str, txt: &[(&str, &str)]) -> ServiceRecord {
        ServiceRecord {
            name: name.to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some(format!("{name}.local")),
            ip: Some("10.0.0.9".to_string()),
            port: Some(8443),
            txt: txt
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn fold_resolved_overwrites_found_for_txt_enrichment() {
        // Found arrives first (no TXT), then Resolved carries the trust hints.
        let peers = fold_peers([
            MdnsEvent::Found(rec("a", &[])),
            MdnsEvent::Resolved(rec("a", &[("fp", "CAFP"), ("posture", "authenticated")])),
        ]);
        assert_eq!(peers.len(), 1, "the two events collapse to one peer");
        assert_eq!(peers[0].level(), PostureLevel::Authenticated);
        assert_eq!(peers[0].fp.as_deref(), Some("CAFP"));
    }

    #[test]
    fn fold_removed_drops_the_peer() {
        let peers = fold_peers([
            MdnsEvent::Found(rec("b", &[])),
            MdnsEvent::Removed {
                name: "b".to_string(),
                service_type: "_http._tcp".to_string(),
            },
        ]);
        assert!(peers.is_empty(), "a removed peer is not in the snapshot");
    }

    #[test]
    fn remote_dns_remove_preserves_the_domains_not_found_result() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind daemon stub");
        let address = listener.local_addr().expect("daemon stub address");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept DNS remove request");
            let mut request = [0_u8; 2048];
            let count = socket.read(&mut request).expect("read DNS remove request");
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("DELETE /v1/dns/remove/missing.internal HTTP/1.1\r\n"));
            let body = br#"{"error":"not_found","message":"entry_not_found"}"#;
            write!(
                socket,
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write DNS remove response head");
            socket
                .write_all(body)
                .expect("write DNS remove response body");
        });

        let dns = DnsHandle::new_remote(Arc::new(KoiClient::new(&format!("http://{address}"))));
        assert_eq!(
            dns.remove_entry("missing.internal")
                .expect("not-found is a typed domain result"),
            None
        );
        server.join().expect("daemon stub");
    }

    #[tokio::test]
    async fn embedded_stop_preserves_terminal_domain_errors() {
        let root = std::env::temp_dir().join(format!(
            "koi-embedded-stop-errors-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&root).expect("create test root");

        let dns_core = koi_dns::DnsCore::open(
            root.join("dns.json"),
            koi_dns::DnsConfig {
                bind_addr: std::net::Ipv4Addr::LOCALHOST.into(),
                port: 0,
                ..Default::default()
            },
            None,
            None,
            None,
        )
        .await
        .expect("DNS core");
        let dns_runtime = Arc::new(DnsRuntime::new(dns_core));
        let dns = DnsHandle::new_embedded(Arc::clone(&dns_runtime));
        assert!(matches!(
            dns.lookup("bad name", hickory_proto::rr::RecordType::A)
                .await,
            Err(KoiError::Dns(koi_dns::DnsError::InvalidName(_)))
        ));
        dns_runtime.shutdown().await;
        assert!(matches!(
            dns.stop().await,
            Err(KoiError::Dns(koi_dns::DnsError::ShutDown))
        ));

        let health_core = Arc::new(
            koi_health::HealthCore::open(
                koi_health::HealthPaths::new(root.join("health.json"), root.join("health.log")),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("Health core"),
        );
        let health_runtime = Arc::new(HealthRuntime::new(health_core));
        health_runtime.shutdown().await;
        let health = HealthHandle::new_embedded(health_runtime);
        assert!(matches!(
            health.stop().await,
            Err(KoiError::Health(koi_health::HealthError::ShutDown))
        ));

        let proxy_core = Arc::new(
            koi_proxy::ProxyCore::open(root.join("proxy.toml"), root.join("proxy-certificates"))
                .expect("Proxy core"),
        );
        let proxy_runtime = Arc::new(ProxyRuntime::new(proxy_core));
        let proxy = ProxyHandle::new_embedded(Arc::clone(&proxy_runtime));
        assert!(!proxy
            .stop_all()
            .await
            .expect("embedded Proxy exposes the accepted no-op"));
        proxy_runtime
            .shutdown()
            .await
            .expect("terminal Proxy shutdown");
        assert!(matches!(
            proxy.stop_all().await,
            Err(KoiError::Proxy(koi_proxy::ProxyError::ShutDown))
        ));

        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[tokio::test]
    async fn remote_dns_stop_preserves_the_daemons_typed_execution_error() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind daemon stub");
        let address = listener.local_addr().expect("daemon stub address");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept DNS stop request");
            let mut request = [0_u8; 2048];
            let count = socket.read(&mut request).expect("read DNS stop request");
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("POST /v1/dns/stop HTTP/1.1\r\n"));
            let body =
                br#"{"error":"shutting_down","message":"DNS runtime has already shut down"}"#;
            write!(
                socket,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write DNS stop response head");
            socket
                .write_all(body)
                .expect("write DNS stop response body");
        });

        let dns = DnsHandle::new_remote(Arc::new(KoiClient::new(&format!("http://{address}"))));
        assert!(matches!(
            dns.stop().await,
            Err(KoiError::Client(koi_client::ClientError::Api { error, .. }))
                if error == "shutting_down"
        ));
        server.join().expect("daemon stub");
    }

    #[tokio::test]
    async fn remote_proxy_mutation_returns_acceptance_without_a_torn_reread() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind daemon stub");
        let address = listener.local_addr().expect("daemon stub address");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept Proxy upsert request");
            let mut request = [0_u8; 4096];
            let count = socket
                .read(&mut request)
                .expect("read Proxy upsert request");
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("POST /v1/proxy/add HTTP/1.1\r\n"));
            let body = br#"{"status":"ok"}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write Proxy upsert response head");
            socket
                .write_all(body)
                .expect("write Proxy upsert response body");
        });

        let proxy = ProxyHandle::new_remote(Arc::new(KoiClient::new(&format!("http://{address}"))));
        proxy
            .upsert(ProxyEntry {
                name: "api".into(),
                listen_port: 8443,
                backend: "http://127.0.0.1:8080".into(),
                allow_remote: false,
            })
            .await
            .expect("daemon accepts Proxy upsert");
        server.join().expect("daemon stub");
    }

    #[test]
    fn fold_orders_peers_by_name() {
        let peers = fold_peers([
            MdnsEvent::Resolved(rec("z", &[])),
            MdnsEvent::Resolved(rec("a", &[])),
            MdnsEvent::Resolved(rec("m", &[])),
        ]);
        let names: Vec<_> = peers.iter().map(|p| p.record.name.clone()).collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn fold_open_peer_has_open_posture() {
        let peers = fold_peers([MdnsEvent::Resolved(rec("plain", &[]))]);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].level(), PostureLevel::Open);
        assert!(!peers[0].is_secure());
    }

    #[test]
    fn lag_snapshot_replaces_stale_peer_projection() {
        let mut peers = std::collections::BTreeMap::from([
            ("stale".to_string(), rec("stale", &[])),
            ("current".to_string(), rec("current", &[])),
        ]);
        let replacement = rec("replacement", &[("posture", "authenticated")]);
        let snapshot = MdnsDiscoverySnapshot {
            revision: 7,
            service_types: vec!["_http._tcp".to_string()],
            records: vec![replacement.clone()],
            sources: Vec::new(),
            observations: Vec::new(),
        };

        reconcile_peer_snapshot(&mut peers, &snapshot, "_http._tcp");

        assert_eq!(peers, [(replacement.name.clone(), replacement)].into());
    }

    #[test]
    fn remote_snapshot_pipeline_item_is_preserved() {
        let snapshot = MdnsDiscoverySnapshot {
            revision: 9,
            service_types: vec!["_http._tcp".to_string()],
            records: vec![rec("remote", &[])],
            sources: Vec::new(),
            observations: Vec::new(),
        };
        let json = serde_json::json!({ "snapshot": snapshot });

        let Ok(KoiBrowseItem::Snapshot(parsed)) = mdns_browse_item_from_pipeline(json) else {
            panic!("snapshot response must survive the remote adapter");
        };

        assert_eq!(parsed.revision, 9);
        assert_eq!(parsed.records[0].name, "remote");
    }

    #[test]
    fn remote_protocol_decoders_reject_partial_or_malformed_payloads() {
        assert!(matches!(
            parse_dns_names(serde_json::json!({ "names": ["ok.internal.", 7] })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_certmesh_posture(serde_json::json!({ "level": "open" })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_certmesh_posture(serde_json::json!({
                "signed": true,
                "encrypted": false,
                "level": "open"
            })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_dns_entries(serde_json::json!({
                "entries": [{ "name": "api.internal.", "ip": "192.0.2.1" }]
            })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_proxy_entries(serde_json::json!({
                "entries": [{
                    "name": "api",
                    "listen_port": 8443,
                    "backend": "http://127.0.0.1:8080"
                }]
            })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_dns_status(serde_json::json!({
                "running": false,
                "desired": false,
                "state": "stopped",
                "endpoints": [],
                "zone": "internal",
                "port": 53,
                "records": {
                    "static_entries": 0,
                    "certmesh_entries": 0,
                    "mdns_entries": 0,
                    "txt_names": 0
                }
            })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_health_status(serde_json::json!({
                "running": false,
                "machines": [],
                "services": []
            })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_proxy_status(serde_json::json!({ "proxies": [] })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_proxy_status(serde_json::json!({
                "revision": 1,
                "proxies": [{
                    "name": "api",
                    "listen_port": 8443,
                    "backend": "http://127.0.0.1:8080",
                    "allow_remote": false,
                    "cert_source": "self-signed",
                    "state": "running"
                }]
            })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            parse_status_ack(&serde_json::json!({ "status": "queued" }), "test response"),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        assert!(matches!(
            ensure_supported_dns_record_type(hickory_proto::rr::RecordType::TXT),
            Err(KoiError::Dns(koi_dns::DnsError::InvalidEntry(_)))
        ));
        assert!(matches!(
            mdns_browse_item_from_pipeline(serde_json::json!({
                "found": { "name": 7 }
            })),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
    }

    #[tokio::test]
    async fn remote_browse_relay_delivers_transport_and_decode_failures() {
        let (tx, mut rx) = mpsc::channel(1);
        tokio::task::spawn_blocking(move || {
            relay_remote_browse(
                vec![Err(koi_client::ClientError::Transport(
                    "stream reset".into(),
                ))],
                tx,
            );
        })
        .await
        .expect("relay task");
        assert!(matches!(
            rx.recv().await.transpose(),
            Err(KoiError::Client(koi_client::ClientError::Transport(message)))
                if message == "stream reset"
        ));

        let (tx, mut rx) = mpsc::channel(1);
        tokio::task::spawn_blocking(move || {
            relay_remote_browse(
                vec![Ok(serde_json::json!({ "snapshot": { "revision": "bad" } }))],
                tx,
            );
        })
        .await
        .expect("relay task");
        assert!(matches!(
            rx.recv().await.transpose(),
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));

        let (tx, mut rx) = mpsc::channel(1);
        tokio::task::spawn_blocking(move || {
            relay_remote_browse(
                vec![Ok(serde_json::json!({
                    "error": "provider_unavailable",
                    "message": "native provider stopped"
                }))],
                tx,
            );
        })
        .await
        .expect("relay task");
        assert!(matches!(
            rx.recv().await.transpose(),
            Err(KoiError::Client(koi_client::ClientError::Api { error, message }))
                if error == "provider_unavailable" && message == "native provider stopped"
        ));

        let (tx, mut rx) = mpsc::channel(1);
        tokio::task::spawn_blocking(move || {
            relay_remote_browse(Vec::<koi_client::Result<serde_json::Value>>::new(), tx);
        })
        .await
        .expect("relay task");
        assert!(matches!(rx.recv().await.transpose(), Ok(None)));
    }

    #[tokio::test]
    async fn remote_browse_connection_failure_is_not_an_empty_stream() {
        let mdns = MdnsHandle::new_remote(Arc::new(KoiClient::new("http://127.0.0.1:1")));
        assert!(matches!(
            mdns.browse("_http._tcp").await,
            Err(KoiError::Client(_))
        ));
    }

    #[tokio::test]
    async fn dropping_remote_browse_cancels_and_joins_its_real_transport_worker() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind SSE server");
        let address = listener.local_addr().expect("SSE address");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept SSE request");
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("set request timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = socket.read(&mut buffer).expect("read SSE request");
                assert!(read > 0, "request closed before headers completed");
                request.extend_from_slice(&buffer[..read]);
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n",
                )
                .expect("write SSE headers");
            let event = concat!(
                "data: {\"found\":{\"name\":\"peer\",\"type\":\"_http._tcp\",",
                "\"host\":\"peer.local\",\"ip\":\"192.0.2.1\",\"port\":80,\"txt\":{}}}\n\n"
            );
            for _ in 0..96 {
                socket
                    .write_all(event.as_bytes())
                    .expect("fill remote browse channel");
            }
            socket.flush().expect("flush browse events");
            for _ in 0..100 {
                if socket.write_all(b": keepalive\n\n").is_err() {
                    return;
                }
                socket.flush().expect("flush SSE keepalive");
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            panic!("remote browse transport remained open after handle drop");
        });

        let mdns = MdnsHandle::new_remote(Arc::new(KoiClient::new(&format!("http://{address}"))));
        let browse = mdns
            .browse("_http._tcp")
            .await
            .expect("establish remote browse");
        // Let the relay hit bounded-channel backpressure. Drop must close the
        // receiver before joining or this case deadlocks independently of I/O.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let started = std::time::Instant::now();
        drop(browse);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "remote browse drop did not promptly join its worker"
        );
        server.join().expect("SSE server observes disconnect");
    }

    #[tokio::test]
    async fn remote_facades_surface_transport_errors_and_unsupported_operations() {
        let client = Arc::new(KoiClient::new("http://127.0.0.1:1"));
        let (events, _) = broadcast::channel(8);
        let handle = KoiHandle::new_remote(client, events, CancellationToken::new(), Vec::new());

        assert!(matches!(
            handle.events(),
            Err(KoiError::RemoteUnsupported(_))
        ));
        assert!(matches!(
            handle.subscribe(),
            Err(KoiError::RemoteUnsupported(_))
        ));
        assert!(matches!(
            handle.status(),
            Err(KoiError::RemoteUnsupported(_))
        ));
        assert!(matches!(
            handle.watch_status(),
            Err(KoiError::RemoteUnsupported(_))
        ));

        let dns = handle.dns().expect("remote DNS facade");
        assert!(matches!(
            dns.lookup("missing.internal", hickory_proto::rr::RecordType::A)
                .await,
            Err(KoiError::Client(_))
        ));
        assert!(matches!(dns.list_names(), Err(KoiError::Client(_))));
        assert!(matches!(dns.stop().await, Err(KoiError::Client(_))));

        let health = handle.health().expect("remote Health facade");
        assert!(matches!(health.status().await, Err(KoiError::Client(_))));
        assert!(matches!(
            health.start().await,
            Err(KoiError::RemoteUnsupported(_))
        ));
        assert!(matches!(
            health.stop().await,
            Err(KoiError::RemoteUnsupported(_))
        ));

        let proxy = handle.proxy().expect("remote Proxy facade");
        assert!(matches!(proxy.entries().await, Err(KoiError::Client(_))));
        assert!(matches!(
            proxy.start_all().await,
            Err(KoiError::RemoteUnsupported(_))
        ));
        assert!(matches!(
            proxy.stop_all().await,
            Err(KoiError::RemoteUnsupported(_))
        ));

        let certmesh = handle.certmesh().expect("remote Certmesh facade");
        assert!(matches!(certmesh.posture().await, Err(KoiError::Client(_))));
        assert!(matches!(
            certmesh.local_identity().await,
            Err(KoiError::RemoteUnsupported(_))
        ));
    }

    #[tokio::test]
    async fn malformed_remote_posture_cannot_fail_open() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind one-shot daemon");
        let addr = listener.local_addr().expect("daemon address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept posture request");
            let mut request = [0_u8; 2048];
            let count = socket.read(&mut request).await.expect("read request");
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("GET /v1/certmesh/posture HTTP/1.1\r\n"));
            let body = br#"{"level":"open"}"#;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("write response head");
            socket.write_all(body).await.expect("write response body");
        });

        let certmesh =
            CertmeshHandle::new_remote(Arc::new(KoiClient::new(&format!("http://{addr}"))));
        assert!(matches!(
            certmesh.posture().await,
            Err(KoiError::Client(koi_client::ClientError::Decode(_)))
        ));
        server.await.expect("one-shot daemon task");
    }

    #[tokio::test]
    async fn remote_shutdown_calls_the_real_daemon_endpoint() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind one-shot daemon");
        let addr = listener.local_addr().expect("daemon address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept shutdown request");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let count = socket.read(&mut buf).await.expect("read request");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..count]);
                if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).expect("HTTP request is UTF-8");
            assert!(
                request.starts_with("POST /v1/admin/shutdown HTTP/1.1\r\n"),
                "unexpected request: {request}"
            );
            let body = br#"{"status":"shutting_down"}"#;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("write response head");
            socket.write_all(body).await.expect("write response body");
        });

        let client = Arc::new(KoiClient::new(&format!("http://{addr}")));
        let (events, _) = broadcast::channel(1);
        KoiHandle::new_remote(client, events, CancellationToken::new(), Vec::new())
            .shutdown()
            .await
            .expect("remote shutdown succeeds");
        server.await.expect("one-shot daemon task");
    }

    // ── participate (ADR-020 §13) ───────────────────────────────────

    struct AbortTestAdapter {
        descriptor: ProviderDescriptor,
        session: Arc<AbortTestSession>,
    }

    impl AbortTestAdapter {
        fn new(withdrawals: Arc<AtomicUsize>) -> Self {
            Self::observed(
                withdrawals,
                Arc::new(std::sync::Mutex::new(Vec::new())),
                Arc::new(AtomicBool::new(false)),
            )
        }

        fn observed(
            withdrawals: Arc<AtomicUsize>,
            publications: Arc<std::sync::Mutex<Vec<Announcement>>>,
            fail_publish: Arc<AtomicBool>,
        ) -> Self {
            Self::configured(withdrawals, publications, fail_publish, None)
        }

        fn blocked(
            withdrawals: Arc<AtomicUsize>,
            publications: Arc<std::sync::Mutex<Vec<Announcement>>>,
            publish_entered: Arc<Notify>,
            publish_release: Arc<Notify>,
        ) -> Self {
            Self::configured(
                withdrawals,
                publications,
                Arc::new(AtomicBool::new(false)),
                Some(PublishBarrier {
                    entered: publish_entered,
                    release: publish_release,
                }),
            )
        }

        fn configured(
            withdrawals: Arc<AtomicUsize>,
            publications: Arc<std::sync::Mutex<Vec<Announcement>>>,
            fail_publish: Arc<AtomicBool>,
            publish_barrier: Option<PublishBarrier>,
        ) -> Self {
            let descriptor = ProviderDescriptor::new(
                "embedded-abort-test",
                u16::MAX,
                ProviderApi::Embedded,
                MdnsCapabilities::FULL_PROVIDER,
            );
            Self {
                descriptor,
                session: Arc::new(AbortTestSession::new(
                    descriptor,
                    withdrawals,
                    publications,
                    fail_publish,
                    publish_barrier,
                )),
            }
        }
    }

    #[async_trait::async_trait]
    impl MdnsAdapter for AbortTestAdapter {
        fn descriptor(&self) -> ProviderDescriptor {
            self.descriptor
        }

        async fn assess(&self) -> MdnsProviderReport {
            MdnsProviderReport {
                name: self.descriptor.name.to_string(),
                priority: self.descriptor.priority,
                api: self.descriptor.api,
                availability: ProviderAvailability::Ready,
                installed: ProbeFact::Yes,
                configured: ProbeFact::Yes,
                running: ProbeFact::Yes,
                capabilities: self.descriptor.capabilities,
                session: None,
                detail: "ready test provider".to_string(),
            }
        }

        async fn open(&self) -> koi_mdns::Result<Arc<dyn ProviderSession>> {
            Ok(self.session.clone())
        }
    }

    struct AbortTestSession {
        descriptor: ProviderDescriptor,
        state: watch::Sender<ProviderSessionState>,
        withdrawals: Arc<AtomicUsize>,
        publications: Arc<std::sync::Mutex<Vec<Announcement>>>,
        fail_publish: Arc<AtomicBool>,
        publish_barrier: Option<PublishBarrier>,
    }

    struct PublishBarrier {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl AbortTestSession {
        fn new(
            descriptor: ProviderDescriptor,
            withdrawals: Arc<AtomicUsize>,
            publications: Arc<std::sync::Mutex<Vec<Announcement>>>,
            fail_publish: Arc<AtomicBool>,
            publish_barrier: Option<PublishBarrier>,
        ) -> Self {
            let (state, _) = watch::channel(ProviderSessionState::Ready);
            Self {
                descriptor,
                state,
                withdrawals,
                publications,
                fail_publish,
                publish_barrier,
            }
        }
    }

    #[async_trait::async_trait]
    impl ProviderSession for AbortTestSession {
        fn descriptor(&self) -> ProviderDescriptor {
            self.descriptor
        }

        fn capabilities(&self) -> MdnsCapabilities {
            self.descriptor.capabilities
        }

        fn state(&self) -> watch::Receiver<ProviderSessionState> {
            self.state.subscribe()
        }

        async fn publish(
            &self,
            announcement: &Announcement,
        ) -> koi_mdns::Result<Box<dyn PublicationLease>> {
            self.publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(announcement.clone());
            if let Some(barrier) = self.publish_barrier.as_ref() {
                barrier.entered.notify_one();
                barrier.release.notified().await;
            }
            if self.fail_publish.load(Ordering::Acquire) {
                return Err(koi_mdns::MdnsError::Daemon(
                    "deterministic publication refusal".to_string(),
                ));
            }
            Ok(Box::new(AbortTestPublication {
                id: announcement.id.clone(),
                withdrawals: Arc::clone(&self.withdrawals),
            }))
        }

        async fn browse(
            &self,
            _service_type: &str,
            _is_meta: bool,
        ) -> koi_mdns::Result<ProviderBrowse> {
            let (_events, receiver) = mpsc::channel(1);
            Ok(ProviderBrowse::new(receiver, Box::new(AbortTestBrowse)))
        }

        async fn shutdown(&self) -> koi_mdns::Result<()> {
            Ok(())
        }
    }

    struct AbortTestPublication {
        id: String,
        withdrawals: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl PublicationLease for AbortTestPublication {
        fn announcement_id(&self) -> &str {
            &self.id
        }

        fn provider_name(&self) -> &'static str {
            "embedded-abort-test"
        }

        async fn withdraw(&mut self) -> koi_mdns::Result<()> {
            self.withdrawals.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct AbortTestBrowse;

    #[async_trait::async_trait]
    impl BrowseLease for AbortTestBrowse {
        fn provider_name(&self) -> &'static str {
            "embedded-abort-test"
        }

        async fn close(&mut self) -> koi_mdns::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn embedded_facade_uses_the_domain_heartbeat_contract() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let adapter: Arc<dyn MdnsAdapter> =
            Arc::new(AbortTestAdapter::new(Arc::clone(&withdrawals)));
        let cancel = CancellationToken::new();
        let core = Arc::new(
            MdnsCore::with_adapters(vec![adapter], cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let handle = MdnsHandle::new_embedded(Arc::clone(&core));

        let registration = handle
            .register(RegisterPayload {
                name: "parity-test".into(),
                service_type: "_parity._tcp".into(),
                port: 4242,
                ip: None,
                lease_secs: Some(30),
                txt: HashMap::new(),
            })
            .await
            .expect("register heartbeat-owned presence");
        assert!(matches!(
            registration.mode,
            koi_mdns::protocol::LeaseMode::Heartbeat
        ));
        assert_eq!(registration.lease_secs, Some(30));

        let renewed = handle
            .heartbeat(&registration.id)
            .await
            .expect("renew heartbeat-owned presence");
        assert_eq!(renewed.id, registration.id);
        assert_eq!(renewed.lease_secs, 30);

        handle
            .unregister(&registration.id)
            .await
            .expect("withdraw heartbeat-owned presence");
        assert_eq!(withdrawals.load(Ordering::Acquire), 1);

        let zero_lease = handle
            .register(RegisterPayload {
                name: "invalid-parity-test".into(),
                service_type: "_parity._tcp".into(),
                port: 4242,
                ip: None,
                lease_secs: Some(0),
                txt: HashMap::new(),
            })
            .await
            .expect_err("zero cannot silently become a permanent registration");
        assert!(matches!(
            zero_lease,
            KoiError::Mdns(koi_mdns::MdnsError::InvalidPayload(_))
        ));

        core.shutdown().await.expect("shutdown mDNS domain");
        cancel.cancel();
    }

    fn open_test_certmesh(tag: &str) -> (Arc<koi_certmesh::CertmeshCore>, std::path::PathBuf) {
        let data_dir = std::env::temp_dir().join(format!(
            "koi-embedded-{tag}-{}-{}",
            std::process::id(),
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&data_dir).expect("create isolated Certmesh root");
        let core = koi_certmesh::CertmeshCore::load_with_paths(
            koi_certmesh::CertmeshPaths::with_data_dir(data_dir.clone()),
            "internal",
            "test-host",
        )
        .expect("construct Open certmesh domain");
        (Arc::new(core), data_dir)
    }

    fn participation_test_handle(
        mdns: Arc<MdnsCore>,
        certmesh: Arc<koi_certmesh::CertmeshCore>,
        cancel: CancellationToken,
    ) -> KoiHandle {
        let composition = koi_compose::cores::RunningCores::default();
        let system_status = Arc::clone(&composition.system_status);
        let (events, _) = broadcast::channel(8);
        KoiHandle::new_embedded(
            koi_compose::host::HostIdentity::from_hostname("test-host").unwrap(),
            Some(mdns),
            None,
            None,
            Some(certmesh),
            None,
            None,
            None,
            system_status,
            composition,
            None,
            None,
            events,
            cancel,
        )
    }

    #[tokio::test]
    async fn usable_identity_participates_but_locked_missing_identity_fails_before_bind() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let publications = Arc::new(std::sync::Mutex::new(Vec::new()));
        let adapter: Arc<dyn MdnsAdapter> = Arc::new(AbortTestAdapter::observed(
            Arc::clone(&withdrawals),
            Arc::clone(&publications),
            Arc::new(AtomicBool::new(false)),
        ));
        let mdns_cancel = CancellationToken::new();
        let mdns = Arc::new(
            MdnsCore::with_adapters(vec![adapter], mdns_cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let (certmesh, data_dir) = open_test_certmesh("participate-identity-readiness");
        let paths = certmesh.paths().clone();
        certmesh
            .create(koi_certmesh::protocol::CreateCaRequest {
                passphrase: "participation-test-passphrase".to_string(),
                entropy_hex: koi_common::encoding::hex_encode(&[41_u8; 32]),
                operator: Some("embedded-test".to_string()),
                enrollment_open: false,
                requires_approval: false,
                auto_unlock: false,
                totp_secret_hex: None,
            })
            .await
            .expect("create usable local authority identity");
        assert_eq!(
            certmesh.status().identity.condition,
            koi_certmesh::IdentityCondition::Healthy
        );

        let handle = participation_test_handle(
            Arc::clone(&mdns),
            Arc::clone(&certmesh),
            CancellationToken::new(),
        );
        let caller_cancel = CancellationToken::new();
        let ready = handle
            .participate(
                axum::Router::new(),
                (std::net::Ipv4Addr::LOCALHOST, 0).into(),
                "_koi-ready._tcp",
                caller_cancel.clone(),
            )
            .await
            .expect("usable identity reaches listener and publication readiness");
        assert_ne!(ready.port(), 0);
        assert_eq!(publications.lock().unwrap().len(), 1);
        caller_cancel.cancel();
        handle.shutdown().await.expect("shutdown usable generation");
        drop(certmesh);

        std::fs::remove_dir_all(paths.certs_dir()).expect("remove authority leaf fixture");
        let locked = Arc::new(
            koi_certmesh::CertmeshCore::load_with_paths(paths, "internal", "test-host")
                .expect("reload locked authority"),
        );
        assert!(
            locked
                .status()
                .authority
                .as_ref()
                .is_some_and(|authority| authority.locked),
            "fixture authority must reload locked"
        );
        let handle = participation_test_handle(Arc::clone(&mdns), locked, CancellationToken::new());
        let reservation = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("reserve a real test address");
        let candidate = reservation.local_addr().expect("reserved address");
        drop(reservation);

        let error = handle
            .participate(
                axum::Router::new(),
                candidate,
                "_koi-ready._tcp",
                CancellationToken::new(),
            )
            .await
            .expect_err("locked authority without identity cannot participate as Open");
        assert!(matches!(
            error,
            KoiError::Certmesh(koi_certmesh::CertmeshError::CaLocked)
        ));
        assert_eq!(
            publications.lock().unwrap().len(),
            1,
            "failed readiness must not announce a second generation"
        );
        let rebound = tokio::net::TcpListener::bind(candidate)
            .await
            .expect("identity failure happened before listener acquisition");
        drop(rebound);

        handle.shutdown().await.expect("shutdown rejected handle");
        mdns.shutdown().await.expect("shutdown mDNS domain");
        mdns_cancel.cancel();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn corrupt_member_fails_participation_before_bind_or_announcement() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let publications = Arc::new(std::sync::Mutex::new(Vec::new()));
        let adapter: Arc<dyn MdnsAdapter> = Arc::new(AbortTestAdapter::observed(
            Arc::clone(&withdrawals),
            Arc::clone(&publications),
            Arc::new(AtomicBool::new(false)),
        ));
        let mdns_cancel = CancellationToken::new();
        let mdns = Arc::new(
            MdnsCore::with_adapters(vec![adapter], mdns_cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let data_dir = std::env::temp_dir().join(format!(
            "koi-embedded-participate-corrupt-member-{}-{}",
            std::process::id(),
            koi_common::id::generate_short_id()
        ));
        let paths = koi_certmesh::CertmeshPaths::with_data_dir(data_dir.clone());
        std::fs::create_dir_all(paths.certmesh_dir()).expect("create Certmesh fixture");
        std::fs::write(paths.member_state_path(), b"{corrupt-member-record")
            .expect("write corrupt durable member marker");
        let certmesh = Arc::new(
            koi_certmesh::CertmeshCore::load_with_paths(paths, "internal", "test-host")
                .expect("load fail-closed corrupt member"),
        );
        assert_eq!(certmesh.status().role, koi_certmesh::CertmeshRole::Member);
        assert_eq!(
            certmesh.status().identity.condition,
            koi_certmesh::IdentityCondition::Invalid
        );
        let handle =
            participation_test_handle(Arc::clone(&mdns), certmesh, CancellationToken::new());
        let reservation = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("reserve a real test address");
        let candidate = reservation.local_addr().expect("reserved address");
        drop(reservation);

        let error = handle
            .participate(
                axum::Router::new(),
                candidate,
                "_koi-ready._tcp",
                CancellationToken::new(),
            )
            .await
            .expect_err("corrupt durable member cannot participate as Open");
        assert!(matches!(
            error,
            KoiError::Certmesh(koi_certmesh::CertmeshError::Certificate(_))
        ));
        assert!(publications.lock().unwrap().is_empty());
        let rebound = tokio::net::TcpListener::bind(candidate)
            .await
            .expect("identity failure happened before listener acquisition");
        drop(rebound);

        handle.shutdown().await.expect("shutdown rejected handle");
        mdns.shutdown().await.expect("shutdown mDNS domain");
        mdns_cancel.cancel();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test(start_paused = true)]
    async fn aborted_participate_announcement_converges_without_cleanup_retry() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let adapter: Arc<dyn MdnsAdapter> =
            Arc::new(AbortTestAdapter::new(Arc::clone(&withdrawals)));
        let mdns_cancel = CancellationToken::new();
        let mdns = Arc::new(
            MdnsCore::with_adapters(vec![adapter], mdns_cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let data_dir = std::env::temp_dir().join(format!(
            "koi-embedded-participate-abort-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let certmesh = Arc::new(
            koi_certmesh::CertmeshCore::load_with_paths(
                koi_certmesh::CertmeshPaths::with_data_dir(data_dir.clone()),
                "internal",
                "abort-test-host",
            )
            .expect("construct Open certmesh domain"),
        );

        let announcement = ParticipationAnnouncement::establish(
            ParticipationAnnouncementSpec {
                mdns: Arc::clone(&mdns),
                hostname: "abort-test-host".to_string(),
                service_type: "_koi-abort._tcp".to_string(),
            },
            &certmesh,
            4242,
        )
        .await
        .expect("establish participation announcement");
        let announce = tokio::spawn(announcement.maintain(CancellationToken::new()));
        let mut status = mdns.watch_status();
        while status.borrow().registrations.alive != 1 {
            status
                .changed()
                .await
                .expect("mDNS status remains available");
        }
        let registrations = mdns.admin_registrations();
        assert_eq!(registrations.len(), 1);
        assert!(matches!(
            registrations[0].1.mode,
            koi_mdns::protocol::LeaseMode::Session
        ));
        assert_eq!(registrations[0].1.grace_secs, 0);

        announce.abort();
        assert!(announce.await.expect_err("task is aborted").is_cancelled());
        assert_eq!(mdns.status().registrations.alive, 0);
        assert_eq!(mdns.status().registrations.draining, 1);

        // No explicit unregister and no second cleanup attempt: dropping the
        // supervisor's one session makes the domain reaper own convergence.
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        for _ in 0..32 {
            if mdns.status().registrations.total == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(mdns.status().registrations.total, 0);
        assert_eq!(withdrawals.load(Ordering::Acquire), 1);

        mdns.shutdown().await.expect("shutdown mDNS domain");
        mdns_cancel.cancel();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn failed_posture_restamp_retains_intent_for_retry() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let publications = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fail_publish = Arc::new(AtomicBool::new(false));
        let adapter: Arc<dyn MdnsAdapter> = Arc::new(AbortTestAdapter::observed(
            Arc::clone(&withdrawals),
            Arc::clone(&publications),
            Arc::clone(&fail_publish),
        ));
        let mdns_cancel = CancellationToken::new();
        let mdns = Arc::new(
            MdnsCore::with_adapters(vec![adapter], mdns_cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let (certmesh, data_dir) = open_test_certmesh("participate-restamp");
        let mut announcement = ParticipationAnnouncement::establish(
            ParticipationAnnouncementSpec {
                mdns: Arc::clone(&mdns),
                hostname: "restamp-test-host".to_string(),
                service_type: "_koi-ready._tcp".to_string(),
            },
            &certmesh,
            4242,
        )
        .await
        .expect("establish initial publication");

        fail_publish.store(true, Ordering::Release);
        assert!(
            announcement.restamp().await.is_err(),
            "provider refusal must leave the restamp dirty"
        );
        assert!(announcement.current_id.is_none());
        assert_eq!(mdns.status().registrations.total, 0);

        fail_publish.store(false, Ordering::Release);
        announcement
            .restamp()
            .await
            .expect("retained restamp intent can converge on retry");
        assert!(announcement.current_id.is_some());
        assert_eq!(mdns.status().registrations.alive, 1);
        assert_eq!(
            publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            3,
            "initial publication, failed restamp, and successful retry"
        );

        announcement.release().await;
        drop(announcement);
        assert_eq!(withdrawals.load(Ordering::Acquire), 2);
        mdns.shutdown().await.expect("shutdown mDNS domain");
        mdns_cancel.cancel();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn occupied_port_fails_before_participation_is_advertised() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let publications = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fail_publish = Arc::new(AtomicBool::new(false));
        let adapter: Arc<dyn MdnsAdapter> = Arc::new(AbortTestAdapter::observed(
            Arc::clone(&withdrawals),
            Arc::clone(&publications),
            fail_publish,
        ));
        let mdns_cancel = CancellationToken::new();
        let mdns = Arc::new(
            MdnsCore::with_adapters(vec![adapter], mdns_cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let (certmesh, data_dir) = open_test_certmesh("participate-occupied");
        let handle =
            participation_test_handle(Arc::clone(&mdns), certmesh, CancellationToken::new());
        let occupied = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("occupy real TCP port");
        let occupied_addr = occupied.local_addr().expect("occupied address");

        let error = handle
            .participate(
                axum::Router::new(),
                occupied_addr,
                "_koi-ready._tcp",
                CancellationToken::new(),
            )
            .await
            .expect_err("occupied port must fail readiness");
        assert!(
            matches!(error, KoiError::Io(ref error) if error.kind() == std::io::ErrorKind::AddrInUse),
            "unexpected occupied-port error: {error}"
        );
        assert!(
            publications
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty(),
            "participation was advertised before its listener existed"
        );
        assert_eq!(mdns.status().registrations.total, 0);
        assert_eq!(withdrawals.load(Ordering::Acquire), 0);

        drop(occupied);
        handle.shutdown().await.expect("shutdown test handle");
        mdns.shutdown().await.expect("shutdown mDNS domain");
        mdns_cancel.cancel();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ephemeral_participation_advertises_actual_port_and_cancels_as_one_generation() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let publications = Arc::new(std::sync::Mutex::new(Vec::new()));
        let adapter: Arc<dyn MdnsAdapter> = Arc::new(AbortTestAdapter::observed(
            Arc::clone(&withdrawals),
            Arc::clone(&publications),
            Arc::new(AtomicBool::new(false)),
        ));
        let mdns_cancel = CancellationToken::new();
        let mdns = Arc::new(
            MdnsCore::with_adapters(vec![adapter], mdns_cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let (certmesh, data_dir) = open_test_certmesh("participate-ephemeral");
        let handle =
            participation_test_handle(Arc::clone(&mdns), certmesh, CancellationToken::new());
        let caller_cancel = CancellationToken::new();

        let addr = handle
            .participate(
                axum::Router::new().route("/ping", axum::routing::get(|| async { "pong" })),
                (std::net::Ipv4Addr::LOCALHOST, 0).into(),
                "_koi-ready._tcp",
                caller_cancel.clone(),
            )
            .await
            .expect("cross listener and publication readiness fence");
        assert_ne!(addr.port(), 0, "OS-selected port must be observable");

        let publication = publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .first()
            .cloned()
            .expect("initial publication was acknowledged before success");
        assert_eq!(publication.port, addr.port());
        assert_eq!(publication.name, "test-host");
        assert_ne!(publication.name, "unknown");
        assert_eq!(mdns.status().registrations.alive, 1);

        let (status, body) = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping")
            .await
            .expect("ready Open listener serves plaintext");
        assert_eq!(status, 200);
        assert_eq!(body, "pong");

        caller_cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let listener_released = std::net::TcpListener::bind(addr).is_ok();
                if listener_released && mdns.status().registrations.total == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("caller cancellation did not reap listener and registration together");
        assert_eq!(withdrawals.load(Ordering::Acquire), 1);

        handle.shutdown().await.expect("shutdown test handle");
        mdns.shutdown().await.expect("shutdown mDNS domain");
        mdns_cancel.cancel();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn initial_publication_failure_rolls_back_ephemeral_listener() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let publications = Arc::new(std::sync::Mutex::new(Vec::new()));
        let adapter: Arc<dyn MdnsAdapter> = Arc::new(AbortTestAdapter::observed(
            Arc::clone(&withdrawals),
            Arc::clone(&publications),
            Arc::new(AtomicBool::new(true)),
        ));
        let mdns_cancel = CancellationToken::new();
        let mdns = Arc::new(
            MdnsCore::with_adapters(vec![adapter], mdns_cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let (certmesh, data_dir) = open_test_certmesh("participate-rollback");
        let handle =
            participation_test_handle(Arc::clone(&mdns), certmesh, CancellationToken::new());

        let error = handle
            .participate(
                axum::Router::new(),
                (std::net::Ipv4Addr::LOCALHOST, 0).into(),
                "_koi-ready._tcp",
                CancellationToken::new(),
            )
            .await
            .expect_err("initial publication refusal must fail participation");
        assert!(matches!(error, KoiError::Mdns(_)));
        let attempted = publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .first()
            .cloned()
            .expect("provider observed the real listener port before refusing it");
        assert_ne!(attempted.port, 0);
        let rebound =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, attempted.port))
                .await
                .expect("failed transaction retained its ephemeral listener");
        assert_eq!(mdns.status().registrations.total, 0);
        assert_eq!(withdrawals.load(Ordering::Acquire), 0);

        drop(rebound);
        handle.shutdown().await.expect("shutdown test handle");
        mdns.shutdown().await.expect("shutdown mDNS domain");
        mdns_cancel.cancel();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn dropped_readiness_waiter_reaps_admitted_publication_and_listener() {
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let publications = Arc::new(std::sync::Mutex::new(Vec::new()));
        let publish_entered = Arc::new(Notify::new());
        let publish_release = Arc::new(Notify::new());
        let adapter: Arc<dyn MdnsAdapter> = Arc::new(AbortTestAdapter::blocked(
            Arc::clone(&withdrawals),
            Arc::clone(&publications),
            Arc::clone(&publish_entered),
            Arc::clone(&publish_release),
        ));
        let mdns_cancel = CancellationToken::new();
        let mdns = Arc::new(
            MdnsCore::with_adapters(vec![adapter], mdns_cancel.clone())
                .await
                .expect("start deterministic mDNS provider"),
        );
        let (certmesh, data_dir) = open_test_certmesh("participate-dropped-waiter");
        let handle = Arc::new(participation_test_handle(
            Arc::clone(&mdns),
            certmesh,
            CancellationToken::new(),
        ));

        let participation = {
            let handle = Arc::clone(&handle);
            tokio::spawn(async move {
                handle
                    .participate(
                        axum::Router::new(),
                        (std::net::Ipv4Addr::LOCALHOST, 0).into(),
                        "_koi-ready._tcp",
                        CancellationToken::new(),
                    )
                    .await
            })
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            publish_entered.notified(),
        )
        .await
        .expect("initial publication never reached the real provider boundary");
        let attempted = publications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .first()
            .cloned()
            .expect("provider captured the bound listener's announcement");
        assert_ne!(attempted.port, 0);

        // Dropping only the public readiness future must not cancel the already
        // admitted native command. The owned generation finishes it, observes
        // that acknowledgement has no waiter, and rolls back both resources.
        participation.abort();
        assert!(participation
            .await
            .expect_err("readiness waiter was aborted")
            .is_cancelled());
        publish_release.notify_one();

        let addr = (std::net::Ipv4Addr::LOCALHOST, attempted.port);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if mdns.status().registrations.total == 0
                    && withdrawals.load(Ordering::Acquire) == 1
                    && std::net::TcpListener::bind(addr).is_ok()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped readiness waiter left provisional resources behind");

        let handle = match Arc::try_unwrap(handle) {
            Ok(handle) => handle,
            Err(_) => panic!("participation waiter retained the embedded handle"),
        };
        handle.shutdown().await.expect("shutdown test handle");
        mdns.shutdown().await.expect("shutdown mDNS domain");
        mdns_cancel.cancel();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn cancellation_before_serve_readiness_acquires_no_listener() {
        let (certmesh, data_dir) = open_test_certmesh("serve-cancelled");
        let composition = koi_compose::cores::RunningCores::default();
        let system_status = Arc::clone(&composition.system_status);
        let (events, _) = broadcast::channel(8);
        let handle = KoiHandle::new_embedded(
            koi_compose::host::HostIdentity::from_hostname("test-host").unwrap(),
            None,
            None,
            None,
            Some(certmesh),
            None,
            None,
            None,
            system_status,
            composition,
            None,
            None,
            events,
            CancellationToken::new(),
        );
        let caller_cancel = CancellationToken::new();
        caller_cancel.cancel();

        let error = handle
            .serve(
                axum::Router::new(),
                (std::net::Ipv4Addr::LOCALHOST, 0).into(),
                caller_cancel,
            )
            .await
            .expect_err("pre-cancelled serve cannot report readiness");
        assert!(
            matches!(error, KoiError::Io(ref error) if error.kind() == std::io::ErrorKind::Interrupted)
        );

        handle.shutdown().await.expect("shutdown test handle");
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn participate_remote_handle_is_disabled() {
        let client = Arc::new(KoiClient::new("http://127.0.0.1:1"));
        let (tx, _) = broadcast::channel(8);
        let handle = KoiHandle::new_remote(client, tx, CancellationToken::new(), Vec::new());
        let router = axum::Router::new();
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
        let err = handle
            .participate(router, addr, "_x._tcp", CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(err, KoiError::RemoteUnsupported(_)));
    }

    #[tokio::test]
    async fn participate_open_node_serves_plaintext() {
        // certmesh on (but no CA → Open), mDNS off (participate just serves plain),
        // isolated data dir. The Open node serves the consumer's router in plaintext
        // with no posture branching by the caller.
        let dir = std::env::temp_dir().join(format!("koi-emb-participate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let koi = crate::Builder::new()
            .data_dir(&dir)
            .service_mode(crate::ServiceMode::EmbeddedOnly)
            .mdns(false)
            .dns_enabled(false)
            .health(false)
            .certmesh(true)
            .proxy(false)
            .build()
            .expect("build");
        let handle = koi.start().await.expect("start");

        let router = axum::Router::new().route("/ping", axum::routing::get(|| async { "pong" }));
        let cancel = CancellationToken::new();
        let addr = handle
            .participate(
                router,
                ([127, 0, 0, 1], 0).into(),
                "_koi-test._tcp",
                cancel.clone(),
            )
            .await
            .expect("participate");
        assert_ne!(addr.port(), 0, "serve reports the OS-selected port");

        let (status, body) = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping")
            .await
            .expect("plain GET to an Open participating node");
        assert_eq!(status, 200);
        assert_eq!(body, "pong");

        cancel.cancel();
        handle.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn handle_shutdown_owns_a_participation_session_lifetime() {
        let dir =
            std::env::temp_dir().join(format!("koi-emb-participate-owned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let koi = crate::Builder::new()
            .data_dir(&dir)
            .service_mode(crate::ServiceMode::EmbeddedOnly)
            .mdns(false)
            .dns_enabled(false)
            .health(false)
            .certmesh(true)
            .proxy(false)
            .build()
            .expect("build");
        let handle = koi.start().await.expect("start");
        let addr = handle
            .participate(
                axum::Router::new(),
                ([127, 0, 0, 1], 0).into(),
                "_koi-owned._tcp",
                CancellationToken::new(),
            )
            .await
            .expect("participate");
        tokio::task::yield_now().await;

        handle.shutdown().await.expect("shutdown");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(listener) = std::net::TcpListener::bind(addr) {
                    drop(listener);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("participating socket remained owned after KoiHandle shutdown");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn dropping_handle_reaps_a_composition_owned_serve_listener() {
        let dir = std::env::temp_dir().join(format!(
            "koi-emb-serve-owner-drop-{}",
            koi_common::id::generate_short_id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let koi = crate::Builder::new()
            .data_dir(&dir)
            .service_mode(crate::ServiceMode::EmbeddedOnly)
            .mdns(false)
            .dns_enabled(false)
            .health(false)
            .certmesh(true)
            .proxy(false)
            .build()
            .expect("build");
        let handle = koi.start().await.expect("start");
        let addr = handle
            .serve(
                axum::Router::new().route("/", axum::routing::get(|| async { "ok" })),
                ([127, 0, 0, 1], 0).into(),
                CancellationToken::new(),
            )
            .await
            .expect("serve");

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("composition-owned listener bound");

        // No graceful shutdown and no caller cancellation: dropping the root
        // owner must still abort and reap the real bound presentation task.
        drop(handle);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(listener) = std::net::TcpListener::bind(addr) {
                    drop(listener);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owner drop released the real serve socket");
        let _ = std::fs::remove_dir_all(dir);
    }

    // ── top-level sign/verify (ADR-020 §3, wishlist I1) ─────────────

    #[tokio::test]
    async fn handle_sign_verify_round_trip_on_open_node() {
        // The top-level KoiHandle::sign / ::verify conveniences delegate to the
        // certmesh handle; an Open node round-trips bytes with an anonymous assurance.
        let dir = std::env::temp_dir().join(format!("koi-emb-handle-sv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let koi = crate::Builder::new()
            .data_dir(&dir)
            .service_mode(crate::ServiceMode::EmbeddedOnly)
            .mdns(false)
            .dns_enabled(false)
            .health(false)
            .certmesh(true)
            .proxy(false)
            .build()
            .expect("build");
        let handle = koi.start().await.expect("start");

        let env = handle.sign(b"hello handle").await.expect("sign");
        let assurance = handle.verify(&env).await.expect("verify");
        assert!(
            assurance.identity().is_none(),
            "an Open node's envelope carries no trusted identity"
        );

        handle.shutdown().await.expect("shutdown");
    }

    // ── seal/open (ADR-020 §4) ──────────────────────────────────────

    #[tokio::test]
    async fn seal_open_round_trip_on_open_node() {
        use koi_common::sealed::Confidentiality;
        let dir = std::env::temp_dir().join(format!("koi-emb-seal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let koi = crate::Builder::new()
            .data_dir(&dir)
            .service_mode(crate::ServiceMode::EmbeddedOnly)
            .mdns(false)
            .dns_enabled(false)
            .health(false)
            .certmesh(true)
            .proxy(false)
            .build()
            .expect("build");
        let handle = koi.start().await.expect("start");
        let cm = handle.certmesh().expect("certmesh handle");

        // Open node: seal is a passthrough (signed-not-encrypted); the same code path
        // round-trips the bytes back with an anonymous assurance.
        let sealed = cm.seal(b"hello seal").await.expect("seal");
        assert_eq!(sealed.confidentiality(), Confidentiality::None);
        let opened = cm.open(&sealed).await.expect("open");
        assert_eq!(opened.payload, b"hello seal");
        assert_eq!(opened.confidentiality, Confidentiality::None);
        assert!(
            opened.assurance.identity().is_none(),
            "an Open node's seal is anonymous, not a trusted identity"
        );

        handle.shutdown().await.expect("shutdown");
    }
}
