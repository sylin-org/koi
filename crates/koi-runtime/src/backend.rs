//! Runtime backend trait.
//!
//! Each container/VM/service runtime implements this trait to provide
//! lifecycle events and instance metadata in a normalized format.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::error::RuntimeError;
use crate::instance::Instance;

type RuntimeWatch = Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'static>>;

/// A losslessly armed backend observation and its point-in-time inventory.
///
/// The snapshot and watch future share one adapter-owned observation boundary:
/// replaying the watch cannot miss lifecycle changes that race with the snapshot.
/// RuntimeCore publishes the snapshot and its initial semantic facts before polling
/// the already-armed future, then drains buffered replay through the same owned supervisor.
#[must_use = "an armed runtime observation must be handed to RuntimeCore"]
pub struct RuntimeObservation {
    instances: Vec<Instance>,
    watch: RuntimeWatch,
}

impl RuntimeObservation {
    /// Build an armed observation from its initial inventory and watch future.
    pub fn new<F>(instances: Vec<Instance>, watch: F) -> Self
    where
        F: Future<Output = Result<(), RuntimeError>> + Send + 'static,
    {
        Self {
            instances,
            watch: Box::pin(watch),
        }
    }

    pub(crate) fn into_parts(self) -> (Vec<Instance>, RuntimeWatch) {
        (self.instances, self.watch)
    }
}

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
    /// The owned backend watch ended cleanly (normally by cancellation).
    BackendStopped { backend: String },
}

/// A runtime backend that watches lifecycle events and resolves instance metadata.
///
/// Implementations are expected to:
/// - Connect to the runtime API on `connect()`
/// - Establish a lossless snapshot-to-stream boundary in `begin_observation()`
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
    /// Adapters use this while establishing observation and when reconciling
    /// after a reconnect. It is also available for direct diagnostics.
    async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError>;

    /// Establish a lossless initial snapshot and lifecycle-event observation.
    ///
    /// Before returning, the adapter must capture a replay cursor or otherwise
    /// arm observation before taking the returned snapshot. The returned watch
    /// future must resume from that boundary, suppress snapshot/replay duplicates,
    /// and run until cancellation or channel closure. It must directly own its
    /// observation resources and event sender rather than detach child tasks, so
    /// dropping or aborting RuntimeCore's supervisor releases the complete watch.
    /// Transient failures remain adapter-owned and use the normalized backend
    /// connectivity events.
    async fn begin_observation(
        self: Arc<Self>,
        tx: mpsc::Sender<RuntimeEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<RuntimeObservation, RuntimeError>;
}

/// Selectable runtime backend kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackendKind {
    /// Auto-detect available runtime (Docker → Podman).
    Auto,
    /// Docker Engine API.
    Docker,
    /// Podman (Docker-compatible API, different default socket).
    Podman,
}

impl RuntimeBackendKind {
    /// The accepted CLI values, used for help text and validation errors.
    pub const ACCEPTED: &'static [&'static str] = &["auto", "docker", "podman"];

    /// Parse from a CLI string. Returns `None` for unrecognized values; callers
    /// must surface a helpful error rather than falling back silently.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "docker" => Some(Self::Docker),
            "podman" => Some(Self::Podman),
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
        }
    }
}
