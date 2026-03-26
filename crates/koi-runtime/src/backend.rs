//! Runtime backend trait.
//!
//! Each container/VM/service runtime implements this trait to provide
//! lifecycle events and instance metadata in a normalized format.

use tokio::sync::mpsc;

use crate::error::RuntimeError;
use crate::instance::Instance;

/// Lifecycle event emitted by a runtime backend.
#[derive(Debug, Clone)]
pub enum RuntimeEvent {
    /// A new instance was detected or an existing one started.
    Started(Instance),
    /// An instance stopped or was destroyed.
    Stopped {
        /// Runtime-assigned instance ID.
        id: String,
        /// Human-readable name.
        name: String,
    },
    /// An instance's metadata or ports changed (e.g., Docker network reconnect).
    Updated(Instance),
    /// The backend lost connection to the runtime API.
    BackendDisconnected { backend: String, reason: String },
    /// The backend reconnected and completed reconciliation.
    BackendReconnected { backend: String },
}

/// A runtime backend that watches lifecycle events and resolves instance metadata.
///
/// Implementations are expected to:
/// - Connect to the runtime API on `connect()`
/// - Stream lifecycle events via the `mpsc::Sender` in `watch()`
/// - Handle reconnection internally (emit `BackendDisconnected`/`BackendReconnected`)
/// - Provide a point-in-time snapshot via `list_instances()`
#[async_trait::async_trait]
pub trait RuntimeBackend: Send + Sync {
    /// Backend name for logging and status (e.g., "docker", "podman", "systemd").
    fn name(&self) -> &'static str;

    /// Attempt to connect to the runtime API.
    ///
    /// Returns an error if the runtime is not available (socket missing,
    /// permission denied, API unreachable).
    async fn connect(&mut self) -> Result<(), RuntimeError>;

    /// List all currently running instances.
    ///
    /// Used for reconciliation on startup: the caller diffs this list
    /// against Koi's current registrations.
    async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError>;

    /// Watch for lifecycle events, sending them to the provided channel.
    ///
    /// This method should run until the cancellation token is triggered
    /// or the channel is closed. It should handle transient failures
    /// (API disconnects) by emitting `BackendDisconnected`, reconnecting,
    /// and emitting `BackendReconnected` with a fresh reconciliation.
    async fn watch(
        &self,
        tx: mpsc::Sender<RuntimeEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), RuntimeError>;
}

/// Selectable runtime backend kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackendKind {
    /// Auto-detect available runtime (Docker → Podman → systemd → Incus).
    Auto,
    /// Docker Engine API.
    Docker,
    /// Podman (Docker-compatible API, different default socket).
    Podman,
    /// systemd D-Bus.
    Systemd,
    /// Incus/LXD REST API.
    Incus,
    /// Kubernetes watch API.
    Kubernetes,
}

impl RuntimeBackendKind {
    /// Parse from a CLI string.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "docker" => Some(Self::Docker),
            "podman" => Some(Self::Podman),
            "systemd" => Some(Self::Systemd),
            "incus" | "lxc" | "lxd" => Some(Self::Incus),
            "kubernetes" | "k8s" => Some(Self::Kubernetes),
            _ => None,
        }
    }
}

impl std::fmt::Display for RuntimeBackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Docker => write!(f, "docker"),
            Self::Podman => write!(f, "podman"),
            Self::Systemd => write!(f, "systemd"),
            Self::Incus => write!(f, "incus"),
            Self::Kubernetes => write!(f, "kubernetes"),
        }
    }
}
