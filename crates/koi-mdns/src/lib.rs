//! Koi mDNS — mDNS/DNS-SD service discovery domain.
//!
//! This crate implements the mDNS capability for Koi. It exposes a domain
//! boundary via [`MdnsCore`] with three faces:
//!
//! - **Commands**: Methods that drive domain actions (register, browse, etc.)
//! - **State**: Read-only snapshots (admin_status, admin_registrations)
//! - **Events**: Broadcast channel for service lifecycle events

mod browse;
mod daemon;
pub mod error;
pub mod events;
pub mod http;
pub mod protocol;
mod registry;

pub use self::browse::BrowseHandle;
pub use self::error::{MdnsError, Result};
pub use self::events::MdnsEvent;
pub use self::registry::LeasePolicy;

use std::sync::Arc;
use std::time::Instant;

use self::daemon::MdnsDaemon;
use self::registry::{InsertOutcome, Registry};

use koi_common::capability::{Capability, CapabilityStatus};
use koi_common::id::generate_short_id;
use koi_common::types::{ServiceRecord, ServiceType, SessionId, META_QUERY};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::protocol::{
    AdminRegistration, DaemonStatus, LeaseMode, RegisterPayload, RegistrationResult,
};

/// Capacity for the broadcast channel used by service event subscribers.
const BROADCAST_CHANNEL_CAPACITY: usize = 256;

/// How often the reaper sweeps for expired registrations.
const REAPER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// The core mDNS facade. All adapters interact through this.
pub struct MdnsCore {
    daemon: Arc<MdnsDaemon>,
    registry: Arc<Registry>,
    event_tx: broadcast::Sender<MdnsEvent>,
    started_at: Instant,
}

impl MdnsCore {
    /// Create a new core with a default (never-cancelled) token.
    /// Used by standalone commands where the runtime drops on exit.
    pub fn new() -> Result<Self> {
        Self::with_cancel(CancellationToken::new())
    }

    /// Create a new core with a shared cancellation token.
    /// Used by daemon mode for ordered shutdown.
    pub fn with_cancel(cancel: CancellationToken) -> Result<Self> {
        let daemon = Arc::new(MdnsDaemon::new()?);
        let registry = Arc::new(Registry::new());
        let (event_tx, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        let started_at = Instant::now();

        // Spawn reaper task — sweeps expired registrations every 5 seconds
        let reaper_registry = registry.clone();
        let reaper_daemon = daemon.clone();
        let reaper_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REAPER_INTERVAL);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let expired = reaper_registry.reap();
                        for (id, payload) in &expired {
                            tracing::info!(
                                name = %payload.name, id,
                                reason = "expired",
                                "Service unregistered"
                            );
                            if let Ok(st) = ServiceType::parse(&payload.service_type) {
                                let _ = reaper_daemon.unregister(&payload.name, st.as_str());
                            }
                        }
                    }
                    _ = reaper_cancel.cancelled() => {
                        tracing::debug!("Reaper task stopped");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            daemon,
            registry,
            event_tx,
            started_at,
        })
    }

    // ── Commands ──────────────────────────────────────────────────────

    /// Start browsing for services of the given type.
    /// Pass `META_QUERY` to discover all service types on the network.
    ///
    /// The returned `BrowseHandle` calls `stop_browse` on drop, so the
    /// underlying daemon resource is always cleaned up.
    pub async fn browse(&self, service_type: &str) -> Result<BrowseHandle> {
        let is_meta = service_type == META_QUERY;
        let browse_type = if is_meta {
            META_QUERY.to_string()
        } else {
            ServiceType::parse(service_type)?.as_str().to_string()
        };
        let receiver = self.daemon.browse(&browse_type).await?;
        let event_tx = self.event_tx.clone();
        Ok(BrowseHandle::new(
            receiver,
            event_tx,
            is_meta,
            browse_type,
            self.daemon.clone(),
        ))
    }

    /// Register a service with a default permanent policy.
    pub fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult> {
        self.register_with_policy(payload, LeasePolicy::Permanent, None)
    }

    /// The single registration entry point. Every adapter explicitly chooses a policy.
    pub fn register_with_policy(
        &self,
        payload: RegisterPayload,
        policy: LeasePolicy,
        session_id: Option<SessionId>,
    ) -> Result<RegistrationResult> {
        let st = ServiceType::parse(&payload.service_type)?;
        let new_id = generate_short_id();

        let outcome =
            self.registry
                .insert_or_reconnect(new_id, payload.clone(), policy.clone(), session_id);

        match &outcome {
            InsertOutcome::New { id } => {
                if let Err(e) = self.daemon.register(
                    &payload.name,
                    st.as_str(),
                    payload.port,
                    payload.ip.as_deref(),
                    &payload.txt,
                ) {
                    let _ = self.registry.remove(id);
                    return Err(e);
                }
            }
            InsertOutcome::Reconnected { old_payload, .. } => {
                if old_payload.port != payload.port || old_payload.txt != payload.txt {
                    let _ = self.daemon.unregister(&old_payload.name, st.as_str());
                    if let Err(e) = self.daemon.register(
                        &payload.name,
                        st.as_str(),
                        payload.port,
                        payload.ip.as_deref(),
                        &payload.txt,
                    ) {
                        tracing::warn!(
                            name = %payload.name,
                            error = %e,
                            "Failed to re-register with updated payload during reconnection"
                        );
                    }
                }
            }
        }

        let id = outcome.id().to_string();
        let (mode, lease_secs) = match &policy {
            LeasePolicy::Session { .. } => (LeaseMode::Session, None),
            LeasePolicy::Heartbeat { lease, .. } => (LeaseMode::Heartbeat, Some(lease.as_secs())),
            LeasePolicy::Permanent => (LeaseMode::Permanent, None),
        };

        let result = RegistrationResult {
            id,
            name: payload.name.clone(),
            service_type: st.short().to_string(),
            port: payload.port,
            mode,
            lease_secs,
        };

        tracing::info!(
            name = %result.name,
            service_type = %result.service_type,
            port = result.port,
            id = %result.id,
            "Service registered"
        );

        Ok(result)
    }

    /// Record a heartbeat for a registration. Resets last_seen; revives if draining.
    /// Returns the lease duration in seconds (0 for non-heartbeat policies).
    pub fn heartbeat(&self, id: &str) -> Result<u64> {
        self.registry.heartbeat(id)
    }

    /// Notify the core that a session has disconnected.
    /// All non-permanent registrations for this session begin draining.
    pub fn session_disconnected(&self, session_id: &SessionId) {
        let drained = self.registry.drain_session(session_id);
        for id in &drained {
            tracing::info!(
                id,
                session = %session_id.0,
                "Session disconnected, registration draining"
            );
        }
    }

    /// Unregister a previously registered service.
    pub fn unregister(&self, id: &str) -> Result<()> {
        let payload = self.registry.remove(id)?;
        let st = ServiceType::parse(&payload.service_type)?;
        self.daemon.unregister(&payload.name, st.as_str())?;
        tracing::info!(name = %payload.name, id, reason = "explicit", "Service unregistered");
        Ok(())
    }

    /// Resolve a specific service instance by its full name.
    pub async fn resolve(&self, instance: &str) -> Result<ServiceRecord> {
        self.daemon.resolve(instance).await
    }

    /// Subscribe to all service events. Returns a broadcast receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<MdnsEvent> {
        self.event_tx.subscribe()
    }

    /// Shut down gracefully: unregister all services, then stop the daemon.
    pub async fn shutdown(&self) -> Result<()> {
        let ids: Vec<String> = self.registry.all_ids();
        for id in &ids {
            if let Err(e) = self.unregister(id) {
                tracing::warn!(id, error = %e, "Failed to unregister service during shutdown");
            }
        }
        self.daemon.shutdown().await?;
        tracing::info!("mDNS core shut down");
        Ok(())
    }

    // ── State (read-only snapshots) ──────────────────────────────────

    /// Daemon status overview.
    pub fn admin_status(&self) -> DaemonStatus {
        DaemonStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            platform: std::env::consts::OS.to_string(),
            registrations: self.registry.counts(),
        }
    }

    /// Snapshot all registrations for admin display.
    pub fn admin_registrations(&self) -> Vec<(String, AdminRegistration)> {
        self.registry.snapshot()
    }

    /// Snapshot one registration by ID or prefix.
    pub fn admin_inspect(&self, id_or_prefix: &str) -> Result<AdminRegistration> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        self.registry.snapshot_one(&full_id)
    }

    /// Admin: force-unregister a registration by ID or prefix.
    pub fn admin_force_unregister(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        let payload = self.registry.remove(&full_id)?;
        let st = ServiceType::parse(&payload.service_type)?;
        let _ = self.daemon.unregister(&payload.name, st.as_str());
        tracing::info!(
            name = %payload.name,
            id = %full_id,
            reason = "admin_force",
            "Service unregistered"
        );
        Ok(())
    }

    /// Admin: force-drain a registration by ID or prefix.
    pub fn admin_drain(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        self.registry.force_drain(&full_id)
    }

    /// Admin: force-revive a draining registration by ID or prefix.
    pub fn admin_revive(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        self.registry.force_revive(&full_id)
    }
}

impl Capability for MdnsCore {
    fn name(&self) -> &str {
        "mdns"
    }

    fn status(&self) -> CapabilityStatus {
        let counts = self.registry.counts();
        let summary = format!(
            "{} registered ({} alive, {} draining)",
            counts.total, counts.alive, counts.draining
        );
        CapabilityStatus {
            name: "mdns".to_string(),
            summary,
            healthy: true,
        }
    }
}
