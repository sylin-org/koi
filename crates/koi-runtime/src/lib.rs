//! Koi Runtime Adapter — container/service lifecycle integration.
//!
//! Watches runtime APIs (Docker, Podman, systemd, Incus, Kubernetes) for
//! lifecycle events and drives Koi capabilities: mDNS announce, DNS entry,
//! health check, proxy configuration.
//!
//! The adapter uses a trait-based backend system. Each runtime implements
//! [`RuntimeBackend`] to provide normalized lifecycle events and instance
//! metadata. The [`RuntimeCore`] facade orchestrates the mapping from
//! runtime events to Koi API calls.

pub mod backend;
pub mod docker;
pub mod error;
pub mod heuristics;
pub mod http;
pub mod instance;

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use koi_common::capability::CapabilityStatus;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;

pub use backend::{RuntimeBackend, RuntimeBackendKind, RuntimeEvent};
pub use error::RuntimeError;
pub use instance::{Instance, InstanceState, KoiMetadata, PortMapping};

/// Capacity for the runtime event broadcast channel.
const BROADCAST_CHANNEL_CAPACITY: usize = 256;

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
                event_tx: broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0,
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

        backend.connect().await?;

        // Store backend name
        *self.state.backend_name.lock().await = Some(backend.name().to_string());
        *self.state.active.lock().await = true;

        // Initial reconciliation: list all running instances
        let existing = backend.list_instances().await?;
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
                match &event {
                    RuntimeEvent::Started(instance) => {
                        let mut instances = state.instances.lock().await;
                        instances.insert(instance.id.clone(), instance.clone());
                        tracing::debug!(
                            name = %instance.name,
                            id = %instance.id,
                            "Instance tracked"
                        );
                    }
                    RuntimeEvent::Stopped { id, name } => {
                        let mut instances = state.instances.lock().await;
                        instances.remove(id.as_str());
                        tracing::debug!(name, id, "Instance untracked");
                    }
                    RuntimeEvent::Updated(instance) => {
                        let mut instances = state.instances.lock().await;
                        instances.insert(instance.id.clone(), instance.clone());
                    }
                    RuntimeEvent::BackendDisconnected { backend, reason } => {
                        tracing::warn!(backend, reason, "Backend disconnected");
                    }
                    RuntimeEvent::BackendReconnected { backend } => {
                        tracing::info!(backend, "Backend reconnected");
                    }
                }
                // Broadcast to subscribers
                let _ = state.event_tx.send(event);
            }
        });

        Ok(())
    }

    /// Capability status for the unified status endpoint.
    pub async fn capability_status(&self) -> CapabilityStatus {
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

    /// Create a backend based on the configured kind.
    fn create_backend(&self) -> Result<Box<dyn RuntimeBackend>, RuntimeError> {
        match self.config.backend_kind {
            RuntimeBackendKind::Docker => {
                let backend = if let Some(ref path) = self.config.socket_path {
                    docker::DockerBackend::with_socket(path.clone())
                } else {
                    docker::DockerBackend::new()
                };
                Ok(Box::new(backend))
            }
            RuntimeBackendKind::Podman => {
                let backend = if let Some(ref path) = self.config.socket_path {
                    docker::DockerBackend::with_socket(path.clone())
                } else {
                    docker::DockerBackend::podman()
                };
                Ok(Box::new(backend))
            }
            RuntimeBackendKind::Auto => self.auto_detect_backend(),
            RuntimeBackendKind::Systemd => Err(RuntimeError::BackendUnavailable(
                "systemd backend not yet implemented".into(),
            )),
            RuntimeBackendKind::Incus => Err(RuntimeError::BackendUnavailable(
                "incus backend not yet implemented".into(),
            )),
            RuntimeBackendKind::Kubernetes => Err(RuntimeError::BackendUnavailable(
                "kubernetes backend not yet implemented".into(),
            )),
        }
    }

    /// Auto-detect the best available backend.
    fn auto_detect_backend(&self) -> Result<Box<dyn RuntimeBackend>, RuntimeError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runtime_core_default_status_is_inactive() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let status = core.status().await;
        assert!(!status.active);
        assert_eq!(status.instance_count, 0);
        assert!(status.backend.is_none());
    }

    #[tokio::test]
    async fn list_instances_empty_by_default() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let instances = core.list_instances().await.unwrap();
        assert!(instances.is_empty());
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
            RuntimeBackendKind::from_str_loose("k8s"),
            Some(RuntimeBackendKind::Kubernetes)
        );
        assert_eq!(RuntimeBackendKind::from_str_loose("unknown"), None);
    }
}
