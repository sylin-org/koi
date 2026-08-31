//! Koi mDNS - mDNS/DNS-SD service discovery domain.
//!
//! This crate implements the mDNS capability for Koi. It exposes a domain
//! boundary via [`MdnsCore`] with three faces:
//!
//! - **Commands**: Methods that drive domain actions (register, browse, etc.)
//! - **State**: Read-only snapshots (admin_status, admin_registrations)
//! - **Events**: Broadcast channel for service lifecycle events

pub mod adapter;
#[cfg(target_os = "linux")]
pub mod avahi;
mod daemon;
pub mod error;
pub mod events;
pub mod http;
pub mod native;
pub mod protocol;
pub mod provider;
mod registry;
pub mod supervisor;
#[cfg(target_os = "linux")]
pub mod systemd_resolved;

pub use self::daemon::BrowseSubscription;
pub use self::error::{MdnsError, Result};
pub use self::events::MdnsEvent;
pub use self::registry::LeasePolicy;

use std::sync::Arc;
use std::time::Instant;

use self::daemon::MdnsDaemon;
use self::native::NativeMdnsProvider;
use self::provider::MdnsProvider;
use self::registry::{InsertOutcome, Registry};

use koi_common::capability::{Capability, CapabilityStatus};
use koi_common::firewall::{FirewallPort, FirewallProtocol};
use koi_common::id::generate_short_id;
use koi_common::types::{ServiceRecord, ServiceType, SessionId};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::protocol::{
    AdminRegistration, DaemonStatus, LeaseMode, RegisterPayload, RegistrationResult,
};

/// How often the reaper sweeps for expired registrations.
const REAPER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

fn capability_summary(
    registration_summary: &str,
    provider_healthy: bool,
    activity: crate::daemon::ReceiveActivity,
) -> (String, bool) {
    if !provider_healthy {
        return (
            format!("{registration_summary}; provider unavailable"),
            false,
        );
    }
    let receive = match (activity.browse_active_secs, activity.last_event_age_secs) {
        (Some(active_secs), Some(age)) => format!(
            "; browse active {active_secs}s, observed {} events (last {age}s ago)",
            activity.events_seen
        ),
        (Some(active_secs), None) => {
            format!("; browse active {active_secs}s, no records observed yet")
        }
        (None, _) => String::new(),
    };
    (format!("{registration_summary}{receive}"), true)
}

/// mDNS UDP port.
pub const MDNS_PORT: u16 = 5353;

/// Whether a UDP port is **exclusively free**.
///
/// This is a generic diagnostic used by lab tooling to reserve ephemeral ports.
/// It is deliberately not provider-selection evidence: mDNS participants use
/// cooperative reuse semantics, which each adapter must inspect for itself.
///
/// - **Unix** (the homelab case): fails with `AddrInUse` when ANY socket holds
///   the port, including reuse-holders — exact detection.
/// - **Windows**: plain binds do not conflict unless the holder asked for
///   exclusivity, so this is suitable only for best-effort lab port selection.
///
/// Any non-`AddrInUse` bind error also reports "not free": we could not prove
/// exclusivity, so we degrade instead of starting into an unknown environment.
pub fn udp_port_exclusively_free(port: u16) -> bool {
    match std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)) {
        // Drop closes and releases the hold; the subsequent mdns-sd bind
        // re-acquires with its own reuse semantics.
        Ok(s) => {
            drop(s);
            true
        }
        Err(_) => false,
    }
}

/// Firewall ports required by the mDNS capability.
pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![FirewallPort::new("mDNS", FirewallProtocol::Udp, MDNS_PORT)]
}

/// The core mDNS facade. All adapters interact through this.
pub struct MdnsCore {
    daemon: Arc<MdnsDaemon>,
    registry: Arc<Registry>,
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
        Self::with_provider(Arc::new(NativeMdnsProvider::new()?), cancel)
    }

    /// Create a core around an injected platform provider.
    ///
    /// Production injects the stable runtime supervisor; tests and embedded
    /// callers can inject a deterministic provider at this boundary.
    pub fn with_provider(
        provider: Arc<dyn MdnsProvider>,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let (event_tx, _) = koi_common::events::event_channel();
        let daemon = Arc::new(MdnsDaemon::new(provider, event_tx));
        let registry = Arc::new(Registry::new());
        let started_at = Instant::now();

        // Spawn reaper task - sweeps expired registrations every 5 seconds
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
            started_at,
        })
    }

    // ── Commands ──────────────────────────────────────────────────────

    /// Subscribe to services of the given type.
    /// Pass `META_QUERY` to discover all service types on the network.
    ///
    /// Concurrent subscriptions to one type share a single real browse with
    /// reference-counted fan-out: dropping one subscription never disturbs the
    /// others, and the underlying browse stops only when the last drops.
    pub async fn subscribe_type(&self, service_type: &str) -> Result<BrowseSubscription> {
        let (key, is_meta) = daemon::canonical_key(service_type)?;
        Ok(self.daemon.subscribe_type(&key, is_meta))
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
                session = %session_id.as_str(),
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
        self.daemon.subscribe_all()
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

#[async_trait::async_trait]
impl Capability for MdnsCore {
    fn name(&self) -> &str {
        "mdns"
    }

    async fn status(&self) -> CapabilityStatus {
        let counts = self.registry.counts();
        let provider = self.daemon.provider_status();
        let reg = format!(
            "provider {} ({}); {} registered ({} alive, {} draining)",
            provider.name, provider.detail, counts.total, counts.alive, counts.draining
        );

        // Browse APIs emit changes, not keepalives. Surface activity as evidence,
        // but never turn an ordinarily quiet LAN into a false failure. Provider
        // health belongs to adapter-owned probes and the runtime supervisor.
        let activity = self.daemon.receive_activity();

        let (summary, healthy) = capability_summary(&reg, provider.healthy, activity);

        CapabilityStatus {
            name: "mdns".to_string(),
            summary,
            healthy,
        }
    }
}

#[cfg(test)]
mod capability_status_tests {
    use super::*;
    use crate::daemon::ReceiveActivity;

    #[test]
    fn quiet_event_stream_is_telemetry_not_failure() {
        let (summary, healthy) = capability_summary(
            "provider avahi; 0 registered",
            true,
            ReceiveActivity {
                events_seen: 42,
                last_event_age_secs: Some(100_000),
                browse_active_secs: Some(100_001),
            },
        );
        assert!(healthy);
        assert!(summary.contains("observed 42 events (last 100000s ago)"));
    }

    #[test]
    fn empty_event_stream_states_uncertainty_without_failure() {
        let (summary, healthy) = capability_summary(
            "provider native; 0 registered",
            true,
            ReceiveActivity {
                events_seen: 0,
                last_event_age_secs: None,
                browse_active_secs: Some(100_000),
            },
        );
        assert!(healthy);
        assert!(summary.contains("no records observed yet"));
    }

    #[test]
    fn adapter_failure_remains_authoritative() {
        let (summary, healthy) = capability_summary(
            "provider avahi; 0 registered",
            false,
            ReceiveActivity {
                events_seen: 1_000,
                last_event_age_secs: Some(0),
                browse_active_secs: Some(10),
            },
        );
        assert!(!healthy);
        assert!(summary.ends_with("provider unavailable"));
    }
}

#[cfg(test)]
mod port_probe_tests {
    use super::*;

    #[test]
    fn free_port_reports_free() {
        // OS assigns an unbound ephemeral port: the probe must succeed and
        // release the hold (binding the same port again right after works).
        let probe_ok = {
            let s = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
            let port = s.local_addr().unwrap().port();
            drop(s);
            udp_port_exclusively_free(port)
        };
        assert!(
            probe_ok,
            "an unbound ephemeral port must report exclusively free"
        );
    }

    #[test]
    fn plain_held_port_reports_taken() {
        // Cross-platform deterministic case: a PLAIN holder (no reuse flags)
        // always conflicts with the probe's plain bind.
        let holder = std::net::UdpSocket::bind(("0.0.0.0", 0)).expect("bind");
        let port = holder.local_addr().unwrap().port();
        assert!(
            !udp_port_exclusively_free(port),
            "a plainly held port must not report exclusively free"
        );
        drop(holder);
        assert!(udp_port_exclusively_free(port), "released reports free");
    }

    // NOTE (ADR-030, measured on Ubuntu 24 runner kernel): a SO_REUSEADDR
    // holder does NOT reliably make a no-reuse probe fail — modern kernels
    // permitted the mixed bind in CI. Detecting reuse-holders by bind
    // semantics is therefore not portable; final coexistence behavior is
    // decided by physical validation (test-01 + avahi) and recorded in the
    // ledger. The probe remains as a guard against exclusive holders.
}
