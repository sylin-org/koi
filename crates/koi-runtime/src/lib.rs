//! Koi Runtime Adapter — container/service lifecycle integration.
//!
//! Watches container runtime APIs (Docker, Podman) for lifecycle events and
//! drives Koi capabilities: mDNS announce, DNS entry, health check, proxy
//! configuration.
//!
//! The adapter uses a trait-based backend system. Each runtime implements
//! [`RuntimeBackend`] to provide normalized lifecycle events and instance
//! metadata. The [`RuntimeCore`] facade orchestrates the mapping from
//! runtime events to Koi API calls.
//!
//! The `docker` feature (default-on) compiles the bollard-backed Docker/Podman backend.
//! With it off, the runtime capability stays available but Docker/Podman/Auto resolve to
//! [`RuntimeError::BackendUnavailable`]. The selectable backends are Auto/Docker/Podman;
//! other runtimes can be added by implementing [`RuntimeBackend`].
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod backend;
#[cfg(feature = "docker")]
pub mod docker;
pub mod error;
pub mod heuristics;
pub mod http;
pub mod instance;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use koi_common::capability::{Capability, CapabilityStatus};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;

pub use backend::{RuntimeBackend, RuntimeBackendKind, RuntimeEvent};
pub use error::RuntimeError;
pub use instance::{Instance, InstanceState, KoiMetadata, PortMapping};

/// Runtime discovery is optional and must never hold every serving surface
/// hostage. Local Engine API operations should complete quickly; these bounds
/// turn a stale socket or hung desktop runtime into an unavailable capability.
const RUNTIME_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RUNTIME_RECONCILE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for the runtime adapter.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Which backend to use.
    pub backend_kind: RuntimeBackendKind,
    /// Custom socket path (overrides default for the selected backend).
    pub socket_path: Option<String>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            backend_kind: RuntimeBackendKind::Auto,
            socket_path: None,
        }
    }
}

async fn connect_backend(
    backend: &mut dyn RuntimeBackend,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    let name = backend.name();
    tokio::time::timeout(timeout, backend.connect())
        .await
        .map_err(|_| {
            RuntimeError::Connection(format!(
                "{name} connection timed out after {}s",
                timeout.as_secs()
            ))
        })?
}

async fn list_backend_instances(
    backend: &dyn RuntimeBackend,
    timeout: Duration,
) -> Result<Vec<Instance>, RuntimeError> {
    let name = backend.name();
    tokio::time::timeout(timeout, backend.list_instances())
        .await
        .map_err(|_| {
            RuntimeError::Connection(format!(
                "{name} initial reconciliation timed out after {}s",
                timeout.as_secs()
            ))
        })?
}

// ── Internal state ──────────────────────────────────────────────────

struct RuntimeState {
    /// Tracked instances by runtime ID.
    instances: Mutex<HashMap<String, Instance>>,
    /// Backend name (set after connect).
    backend_name: Mutex<Option<String>>,
    /// Whether the watcher is active.
    active: Mutex<bool>,
    /// Event broadcast channel.
    event_tx: broadcast::Sender<RuntimeEvent>,
}

impl RuntimeState {
    /// Apply one normalized backend event to inventory, then publish the same
    /// event to every downstream consumer. Keeping both effects here prevents
    /// real backends and embedded/custom producers from drifting.
    async fn ingest(&self, event: RuntimeEvent) {
        match &event {
            RuntimeEvent::Started(instance) | RuntimeEvent::Updated(instance) => {
                let mut instances = self.instances.lock().await;
                instances.insert(instance.id.clone(), instance.clone());
                tracing::debug!(
                    name = %instance.name,
                    id = %instance.id,
                    "Instance tracked"
                );
            }
            RuntimeEvent::Stopped { id, name } => {
                let mut instances = self.instances.lock().await;
                instances.remove(id.as_str());
                tracing::debug!(name, id, "Instance untracked");
            }
            RuntimeEvent::BackendDisconnected { backend, reason } => {
                *self.active.lock().await = false;
                tracing::warn!(backend, reason, "Backend disconnected");
            }
            RuntimeEvent::BackendReconnected { backend } => {
                *self.active.lock().await = true;
                tracing::info!(backend, "Backend reconnected");
            }
        }
        let _ = self.event_tx.send(event);
    }
}

// ── RuntimeCore facade ──────────────────────────────────────────────

/// Runtime adapter domain facade.
///
/// Wraps the backend and tracked instance state, exposes commands,
/// status, events, and HTTP routes.
pub struct RuntimeCore {
    state: Arc<RuntimeState>,
    config: RuntimeConfig,
}

impl RuntimeCore {
    /// Create a new RuntimeCore with the given configuration.
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            state: Arc::new(RuntimeState {
                instances: Mutex::new(HashMap::new()),
                backend_name: Mutex::new(None),
                active: Mutex::new(false),
                event_tx: koi_common::events::event_channel().0,
            }),
            config,
        }
    }

    /// Build the HTTP router for this domain.
    pub fn routes(&self) -> Router {
        http::routes(Arc::new(RuntimeCore {
            state: Arc::clone(&self.state),
            config: self.config.clone(),
        }))
    }

    /// Subscribe to runtime events.
    pub fn subscribe(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.state.event_tx.subscribe()
    }

    /// Ingest one normalized lifecycle event.
    ///
    /// Runtime backends use this same state-and-fan-out chokepoint internally.
    /// Embedded hosts and tests may use it to connect a custom runtime source
    /// without pretending to be Docker or duplicating Koi's inventory rules.
    pub async fn ingest_event(&self, event: RuntimeEvent) {
        self.state.ingest(event).await;
    }

    /// Get current status.
    pub async fn status(&self) -> http::RuntimeStatus {
        let instances = self.state.instances.lock().await;
        let backend = self.state.backend_name.lock().await;
        let active = *self.state.active.lock().await;

        http::RuntimeStatus {
            active,
            backend: backend.clone(),
            instance_count: instances.len(),
        }
    }

    /// List all tracked instances.
    pub async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
        let instances = self.state.instances.lock().await;
        Ok(instances.values().cloned().collect())
    }

    /// Start watching the runtime backend for lifecycle events.
    ///
    /// This spawns a background task that:
    /// 1. Connects to the runtime backend
    /// 2. Lists existing instances (reconciliation)
    /// 3. Streams lifecycle events
    /// 4. Updates tracked state and broadcasts events
    ///
    /// Returns immediately. The background task runs until the cancel token fires.
    pub async fn start_watching(&self, cancel: CancellationToken) -> Result<(), RuntimeError> {
        let mut backend = self.create_backend()?;

        connect_backend(backend.as_mut(), RUNTIME_CONNECT_TIMEOUT).await?;

        // Store backend name
        *self.state.backend_name.lock().await = Some(backend.name().to_string());
        *self.state.active.lock().await = true;

        // Initial reconciliation: list all running instances
        let existing = list_backend_instances(backend.as_ref(), RUNTIME_RECONCILE_TIMEOUT).await?;
        {
            let mut instances = self.state.instances.lock().await;
            for instance in &existing {
                instances.insert(instance.id.clone(), instance.clone());
            }
        }

        tracing::info!(
            backend = backend.name(),
            instances = existing.len(),
            "Runtime adapter started, initial reconciliation complete"
        );

        // Broadcast initial instances as Started events
        for instance in existing {
            let _ = self.state.event_tx.send(RuntimeEvent::Started(instance));
        }

        // Spawn event watch loop
        let state = Arc::clone(&self.state);
        let (event_tx, mut event_rx) = mpsc::channel(256);

        let watch_cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = backend.watch(event_tx, watch_cancel).await {
                tracing::error!(error = %e, "Runtime watch loop exited with error");
            }
            *state.active.lock().await = false;
            tracing::info!("Runtime watch loop stopped");
        });

        // Spawn event processing loop
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                state.ingest(event).await;
            }
        });

        Ok(())
    }

    /// Create a backend based on the configured kind.
    fn create_backend(&self) -> Result<Box<dyn RuntimeBackend>, RuntimeError> {
        match self.config.backend_kind {
            #[cfg(feature = "docker")]
            RuntimeBackendKind::Docker => {
                let backend = if let Some(ref path) = self.config.socket_path {
                    docker::DockerBackend::with_socket(path.clone())
                } else {
                    docker::DockerBackend::new()
                };
                Ok(Box::new(backend))
            }
            #[cfg(feature = "docker")]
            RuntimeBackendKind::Podman => {
                let backend = if let Some(ref path) = self.config.socket_path {
                    docker::DockerBackend::with_socket(path.clone())
                } else {
                    docker::DockerBackend::podman()
                };
                Ok(Box::new(backend))
            }
            RuntimeBackendKind::Auto => self.auto_detect_backend(),
            // When the `docker` feature is off, Docker/Podman join the same
            // not-compiled-in bucket as the stubbed backends below.
            #[cfg(not(feature = "docker"))]
            RuntimeBackendKind::Docker | RuntimeBackendKind::Podman => {
                Err(RuntimeError::BackendUnavailable(
                    "docker backend not compiled in — rebuild with the `docker` feature \
                     (koi-embedded: features = [\"docker\"]); the koi binary ships it by default"
                        .into(),
                ))
            }
        }
    }

    /// Auto-detect the best available backend.
    fn auto_detect_backend(&self) -> Result<Box<dyn RuntimeBackend>, RuntimeError> {
        #[cfg(all(feature = "docker", windows))]
        {
            // Windows named pipes have no reliable non-blocking stat operation.
            // Probe the Engine API directly under `RUNTIME_CONNECT_TIMEOUT` rather
            // than spawning an unbounded `docker info` child process.
            tracing::debug!("Probing Docker runtime through the local named pipe");
            Ok(Box::new(docker::DockerBackend::new()))
        }

        #[cfg(all(feature = "docker", unix))]
        {
            if docker::is_docker_available() {
                tracing::info!("Auto-detected Docker runtime");
                return Ok(Box::new(docker::DockerBackend::new()));
            }

            if docker::is_podman_available() {
                tracing::info!("Auto-detected Podman runtime");
                return Ok(Box::new(docker::DockerBackend::podman()));
            }

            Err(RuntimeError::BackendUnavailable(
                "no supported runtime detected (checked: Docker, Podman)".into(),
            ))
        }

        #[cfg(not(feature = "docker"))]
        {
            Err(RuntimeError::BackendUnavailable(
                "no runtime backend compiled in (build without the `docker` feature)".into(),
            ))
        }

        #[cfg(all(feature = "docker", not(any(unix, windows))))]
        {
            Err(RuntimeError::BackendUnavailable(
                "no supported runtime detected on this platform".into(),
            ))
        }
    }
}

#[async_trait::async_trait]
impl Capability for RuntimeCore {
    fn name(&self) -> &str {
        "runtime"
    }

    /// Capability status for the unified status endpoint. (Was the bespoke
    /// `capability_status`; folded into the trait in P10.)
    async fn status(&self) -> CapabilityStatus {
        let instances = self.state.instances.lock().await;
        let backend = self.state.backend_name.lock().await;
        let active = *self.state.active.lock().await;

        CapabilityStatus {
            name: "runtime".to_string(),
            healthy: active,
            summary: if active {
                format!(
                    "{}: {} instances",
                    backend.as_deref().unwrap_or("none"),
                    instances.len()
                )
            } else {
                "inactive".to_string()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum HangAt {
        Connect,
        List,
    }

    struct HangingBackend(HangAt);

    #[async_trait::async_trait]
    impl RuntimeBackend for HangingBackend {
        fn name(&self) -> &'static str {
            "hanging-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            match self.0 {
                HangAt::Connect => std::future::pending().await,
                HangAt::List => Ok(()),
            }
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            match self.0 {
                HangAt::Connect => Ok(Vec::new()),
                HangAt::List => std::future::pending().await,
            }
        }

        async fn watch(
            &self,
            _tx: mpsc::Sender<RuntimeEvent>,
            _cancel: CancellationToken,
        ) -> Result<(), RuntimeError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn backend_connection_is_bounded_at_the_runtime_boundary() {
        let mut backend = HangingBackend(HangAt::Connect);
        let error = connect_backend(&mut backend, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Connection(_)));
        assert!(error.to_string().contains("connection timed out"));
    }

    #[tokio::test]
    async fn initial_reconciliation_is_bounded_at_the_runtime_boundary() {
        let backend = HangingBackend(HangAt::List);
        let error = list_backend_instances(&backend, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Connection(_)));
        assert!(error.to_string().contains("reconciliation timed out"));
    }

    #[tokio::test]
    async fn runtime_core_default_status_is_inactive() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let status = core.status().await;
        assert!(!status.active);
        assert_eq!(status.instance_count, 0);
        assert!(status.backend.is_none());
    }

    // With the `docker` feature off, selecting Docker resolves to BackendUnavailable
    // (create_backend errors before any connect), naming the missing feature.
    #[cfg(not(feature = "docker"))]
    #[tokio::test]
    async fn docker_backend_unavailable_without_feature() {
        let core = RuntimeCore::new(RuntimeConfig {
            backend_kind: RuntimeBackendKind::Docker,
            ..Default::default()
        });
        let err = core
            .start_watching(CancellationToken::new())
            .await
            .expect_err("docker backend must be unavailable without the feature");
        assert!(matches!(err, RuntimeError::BackendUnavailable(_)));
        assert!(err.to_string().contains("docker"));
    }

    #[tokio::test]
    async fn list_instances_empty_by_default() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let instances = core.list_instances().await.unwrap();
        assert!(instances.is_empty());
    }

    #[tokio::test]
    async fn ingest_event_is_the_single_inventory_and_fanout_path() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let mut events = core.subscribe();
        let mut instance = Instance {
            id: "synthetic-1".into(),
            name: "before".into(),
            ports: vec![],
            ips: vec![],
            metadata: KoiMetadata::default(),
            backend: "custom".into(),
            state: InstanceState::Running,
            discovered_at: chrono::Utc::now(),
            image: None,
        };

        core.ingest_event(RuntimeEvent::Started(instance.clone()))
            .await;
        assert!(matches!(events.recv().await, Ok(RuntimeEvent::Started(_))));
        assert_eq!(core.list_instances().await.unwrap()[0].name, "before");

        instance.name = "after".into();
        core.ingest_event(RuntimeEvent::Updated(instance.clone()))
            .await;
        assert!(matches!(events.recv().await, Ok(RuntimeEvent::Updated(_))));
        assert_eq!(core.list_instances().await.unwrap()[0].name, "after");

        core.ingest_event(RuntimeEvent::Stopped {
            id: instance.id,
            name: instance.name,
        })
        .await;
        assert!(matches!(
            events.recv().await,
            Ok(RuntimeEvent::Stopped { .. })
        ));
        assert!(core.list_instances().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn backend_connectivity_events_drive_health_at_the_ingest_chokepoint() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        *core.state.active.lock().await = true;

        core.ingest_event(RuntimeEvent::BackendDisconnected {
            backend: "docker".into(),
            reason: "event stream ended".into(),
        })
        .await;
        assert!(!core.status().await.active);

        core.ingest_event(RuntimeEvent::BackendReconnected {
            backend: "docker".into(),
        })
        .await;
        assert!(core.status().await.active);
    }

    #[test]
    fn auto_backend_kind_display() {
        assert_eq!(RuntimeBackendKind::Auto.to_string(), "auto");
        assert_eq!(RuntimeBackendKind::Docker.to_string(), "docker");
    }

    #[test]
    fn backend_kind_from_str() {
        assert_eq!(
            RuntimeBackendKind::from_str_loose("docker"),
            Some(RuntimeBackendKind::Docker)
        );
        assert_eq!(
            RuntimeBackendKind::from_str_loose("podman"),
            Some(RuntimeBackendKind::Podman)
        );
        assert_eq!(
            RuntimeBackendKind::from_str_loose("auto"),
            Some(RuntimeBackendKind::Auto)
        );
        // Removed stub backends are now rejected (no silent fallback).
        assert_eq!(RuntimeBackendKind::from_str_loose("k8s"), None);
        assert_eq!(RuntimeBackendKind::from_str_loose("systemd"), None);
        assert_eq!(RuntimeBackendKind::from_str_loose("incus"), None);
        assert_eq!(RuntimeBackendKind::from_str_loose("unknown"), None);
    }
}
