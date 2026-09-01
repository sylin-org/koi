//! Koi mDNS — a provider-agnostic DNS-SD bounded context.
//!
//! [`MdnsCore`] is the application boundary. Registration intent belongs to
//! the registry, browse demand belongs to the discovery hub, provider routing
//! belongs to the control plane, and native resources belong to provider
//! sessions. Public mutation methods are asynchronous because success means a
//! real provider operation has completed.

pub mod adapter;
#[cfg(target_os = "linux")]
pub mod avahi;
mod control_plane;
mod discovery;
pub mod error;
pub mod events;
pub mod http;
pub mod native;
pub mod protocol;
pub mod provider;
mod registry;
#[cfg(target_os = "linux")]
pub mod systemd_resolved;
#[cfg(target_os = "windows")]
pub mod windows_bonjour;
#[cfg(target_os = "windows")]
pub mod windows_dnsapi;

pub use self::discovery::BrowseSubscription;
pub use self::error::{MdnsError, Result};
pub use self::events::MdnsEvent;
pub use self::registry::LeasePolicy;

use std::sync::Arc;
use std::time::{Duration, Instant};

use koi_common::capability::{Capability, CapabilityStatus};
use koi_common::firewall::{FirewallPort, FirewallProtocol};
use koi_common::id::generate_short_id;
use koi_common::mdns_protocol::{ControlPlaneState, MdnsControlPlaneStatus};
use koi_common::types::{ServiceRecord, ServiceType, SessionId};
use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;

use self::adapter::MdnsAdapter;
use self::control_plane::MdnsControlPlane;
use self::discovery::{canonical_key, DiscoveryHub, ReceiveActivity};
use self::registry::{RegistrationAttempt, RegistrationRegistry, WithdrawalAttempt};
use crate::protocol::{
    AdminRegistration, DaemonStatus, LeaseMode, RegisterPayload, RegistrationResult,
};

const REAPER_INTERVAL: Duration = Duration::from_secs(5);

/// mDNS UDP port.
pub const MDNS_PORT: u16 = 5353;

/// Whether a UDP port is exclusively free. This is a lab diagnostic, not
/// provider-selection evidence; adapters probe cooperative mDNS semantics.
pub fn udp_port_exclusively_free(port: u16) -> bool {
    std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![FirewallPort::new("mDNS", FirewallProtocol::Udp, MDNS_PORT)]
}

/// Application façade for registration, discovery, lifecycle, and status.
pub struct MdnsCore {
    discovery: Arc<DiscoveryHub>,
    control_plane: Arc<MdnsControlPlane>,
    registry: Arc<RegistrationRegistry>,
    operation_lock: Arc<Mutex<()>>,
    started_at: Instant,
}

/// A transport connection's registration lifetime.
///
/// The mDNS domain owns this guard so every transport gets identical fail-safe
/// cleanup. Dropping it after EOF, cancellation, a parse failure, or a write
/// failure moves all session-scoped registrations into their grace period.
pub struct RegistrationSession {
    registry: Arc<RegistrationRegistry>,
    id: SessionId,
}

impl RegistrationSession {
    pub fn id(&self) -> &SessionId {
        &self.id
    }
}

impl Drop for RegistrationSession {
    fn drop(&mut self) {
        for id in self.registry.drain_session(&self.id) {
            tracing::info!(id, session = %self.id.as_str(), "Registration draining");
        }
    }
}

impl MdnsCore {
    /// Start with platform-independent native Koi mDNS only.
    pub async fn new() -> Result<Self> {
        Self::with_cancel(CancellationToken::new()).await
    }

    /// Start with native Koi mDNS and a shared shutdown token.
    pub async fn with_cancel(cancel: CancellationToken) -> Result<Self> {
        Self::with_adapters(Vec::new(), cancel).await
    }

    /// Start with the platform adapter catalog. Native Koi is appended by the
    /// control plane as the reserved, always-available fallback.
    pub async fn with_adapters(
        adapters: Vec<Arc<dyn MdnsAdapter>>,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let registry = Arc::new(RegistrationRegistry::new());
        let control_plane = MdnsControlPlane::start(adapters, Arc::clone(&registry)).await?;
        let (event_tx, _) = koi_common::events::event_channel();
        let discovery = Arc::new(DiscoveryHub::new(Arc::clone(&control_plane), event_tx));
        let operation_lock = Arc::new(Mutex::new(()));

        spawn_reaper(
            Arc::clone(&registry),
            Arc::clone(&control_plane),
            Arc::clone(&operation_lock),
            cancel,
        );

        Ok(Self {
            discovery,
            control_plane,
            registry,
            operation_lock,
            started_at: Instant::now(),
        })
    }

    pub async fn subscribe_type(&self, service_type: &str) -> Result<BrowseSubscription> {
        let (key, is_meta) = canonical_key(service_type)?;
        Ok(self.discovery.clone().subscribe_type(&key, is_meta))
    }

    pub async fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult> {
        self.register_with_policy(payload, LeasePolicy::Permanent, None)
            .await
    }

    /// Transactional registration entry point used by every transport.
    pub async fn register_with_policy(
        &self,
        mut payload: RegisterPayload,
        policy: LeasePolicy,
        session_id: Option<SessionId>,
    ) -> Result<RegistrationResult> {
        let service_type = ServiceType::parse(&payload.service_type)?;
        payload.service_type = service_type.as_str().to_string();
        let _operation = self.operation_lock.lock().await;
        let mut transaction = RegistrationTransaction::new(
            Arc::clone(&self.registry),
            self.registry.begin_registration(
                generate_short_id(),
                payload.clone(),
                policy.clone(),
                session_id,
            ),
        );
        let id = transaction.id().to_string();
        let announcement = self.registry.desired_announcement(&id)?;

        self.control_plane.publish(announcement).await?;
        if let Err(error) = self.registry.confirm_publication(&id) {
            let _ = self.control_plane.withdraw(&id).await;
            return Err(error);
        }
        transaction.commit();

        let (mode, lease_secs) = lease_projection(&policy);
        let result = RegistrationResult {
            id,
            name: payload.name,
            service_type: service_type.short().to_string(),
            port: payload.port,
            mode,
            lease_secs,
        };
        tracing::info!(
            name = %result.name,
            service_type = %result.service_type,
            port = result.port,
            id = %result.id,
            "Service publication established"
        );
        Ok(result)
    }

    pub fn heartbeat(&self, id: &str) -> Result<u64> {
        self.registry.heartbeat(id)
    }

    /// Open a transport-owned registration session. Its `Drop` implementation
    /// is the authoritative disconnect signal for session leases.
    pub fn open_registration_session(&self) -> RegistrationSession {
        RegistrationSession {
            registry: Arc::clone(&self.registry),
            id: SessionId::new(generate_short_id()),
        }
    }

    /// Withdraw one registration, acknowledging native resource release before
    /// removing the aggregate from the registry.
    pub async fn unregister(&self, id: &str) -> Result<()> {
        let _operation = self.operation_lock.lock().await;
        self.withdraw_locked(id, "explicit").await
    }

    async fn withdraw_locked(&self, id: &str, reason: &'static str) -> Result<()> {
        let transaction = WithdrawalTransaction::new(
            Arc::clone(&self.registry),
            self.registry.begin_withdrawal(id)?,
        );
        let name = transaction.name().to_string();
        self.control_plane.withdraw(id).await?;
        transaction.commit();
        tracing::info!(%name, id, reason, "Service publication withdrawn");
        Ok(())
    }

    pub async fn resolve(&self, instance: &str) -> Result<ServiceRecord> {
        self.discovery.clone().resolve(instance).await
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MdnsEvent> {
        self.discovery.subscribe_all()
    }

    /// Close browses, withdraw every publication, and release every provider
    /// session. A successful return proves the resources are gone.
    pub async fn shutdown(&self) -> Result<()> {
        let _operation = self.operation_lock.lock().await;
        self.discovery.shutdown_browses().await;

        for id in self.registry.all_ids() {
            if let Err(error) = self.withdraw_locked_without_lock(&id, "shutdown").await {
                tracing::warn!(%id, %error, "Individual shutdown withdrawal will be retried by session shutdown");
            }
        }
        self.control_plane.shutdown().await?;

        // Session shutdown is authoritative release proof. Clear any aggregate
        // whose individual withdrawal failed before the provider epoch closed.
        for id in self.registry.all_ids() {
            if let Ok(attempt) = self.registry.begin_withdrawal(&id) {
                self.registry.commit_withdrawal(attempt);
            }
        }
        tracing::info!("mDNS core shut down");
        Ok(())
    }

    async fn withdraw_locked_without_lock(&self, id: &str, reason: &'static str) -> Result<()> {
        let transaction = WithdrawalTransaction::new(
            Arc::clone(&self.registry),
            self.registry.begin_withdrawal(id)?,
        );
        let name = transaction.name().to_string();
        self.control_plane.withdraw(id).await?;
        transaction.commit();
        tracing::info!(%name, id, reason, "Service publication withdrawn");
        Ok(())
    }

    pub fn admin_status(&self) -> DaemonStatus {
        DaemonStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            platform: std::env::consts::OS.to_string(),
            registrations: self.registry.counts(),
            control_plane: self.control_plane.status(),
        }
    }

    pub fn control_plane_status(&self) -> MdnsControlPlaneStatus {
        self.control_plane.status()
    }

    pub fn admin_registrations(&self) -> Vec<(String, AdminRegistration)> {
        self.registry.snapshot()
    }

    pub fn admin_inspect(&self, id_or_prefix: &str) -> Result<AdminRegistration> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        self.registry.snapshot_one(&full_id)
    }

    pub async fn admin_force_unregister(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        let _operation = self.operation_lock.lock().await;
        self.withdraw_locked(&full_id, "admin_force").await
    }

    pub fn admin_drain(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        self.registry.force_drain(&full_id)
    }

    pub fn admin_revive(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        self.registry.force_revive(&full_id)
    }
}

fn spawn_reaper(
    registry: Arc<RegistrationRegistry>,
    control_plane: Arc<MdnsControlPlane>,
    operation_lock: Arc<Mutex<()>>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REAPER_INTERVAL);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _operation = operation_lock.lock().await;
                    let attempts = match registry.begin_reap() {
                        Ok(attempts) => attempts,
                        Err(error) => {
                            tracing::warn!(%error, "Registration reaper could not build withdrawal intent");
                            continue;
                        }
                    };
                    for attempt in attempts {
                        reap_one(&registry, &control_plane, attempt).await;
                    }
                }
                _ = cancel.cancelled() => break,
            }
        }
        tracing::debug!("mDNS registration reaper stopped");
    });
}

async fn reap_one(
    registry: &Arc<RegistrationRegistry>,
    control_plane: &MdnsControlPlane,
    attempt: WithdrawalAttempt,
) {
    let transaction = WithdrawalTransaction::new(Arc::clone(registry), attempt);
    let id = transaction.id().to_string();
    let name = transaction.name().to_string();
    match control_plane.withdraw(&id).await {
        Ok(()) => {
            transaction.commit();
            tracing::info!(%name, %id, reason = "expired", "Service publication withdrawn");
        }
        Err(error) => {
            tracing::warn!(%name, %id, %error, "Expired publication withdrawal will retry");
        }
    }
}

/// Cancellation-safe registry mutation. Until `commit`, dropping the future
/// restores the exact aggregate that preceded publication.
struct RegistrationTransaction {
    registry: Arc<RegistrationRegistry>,
    attempt: Option<RegistrationAttempt>,
    id: String,
}

impl RegistrationTransaction {
    fn new(registry: Arc<RegistrationRegistry>, attempt: RegistrationAttempt) -> Self {
        let id = attempt.outcome.id().to_string();
        Self {
            registry,
            attempt: Some(attempt),
            id,
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn commit(&mut self) {
        self.attempt.take();
    }
}

impl Drop for RegistrationTransaction {
    fn drop(&mut self) {
        if let Some(attempt) = self.attempt.take() {
            self.registry.rollback_registration(attempt);
        }
    }
}

/// Cancellation-safe withdrawal intent. A dropped operation becomes desired
/// again and control-plane reconciliation restores any already-released lease.
struct WithdrawalTransaction {
    registry: Arc<RegistrationRegistry>,
    attempt: Option<WithdrawalAttempt>,
    id: String,
    name: String,
}

impl WithdrawalTransaction {
    fn new(registry: Arc<RegistrationRegistry>, attempt: WithdrawalAttempt) -> Self {
        let id = attempt.id.clone();
        let name = attempt.announcement.name.clone();
        Self {
            registry,
            attempt: Some(attempt),
            id,
            name,
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn commit(mut self) {
        if let Some(attempt) = self.attempt.take() {
            self.registry.commit_withdrawal(attempt);
        }
    }
}

impl Drop for WithdrawalTransaction {
    fn drop(&mut self) {
        if let Some(attempt) = self.attempt.take() {
            self.registry.rollback_withdrawal(attempt);
        }
    }
}

fn lease_projection(policy: &LeasePolicy) -> (LeaseMode, Option<u64>) {
    match policy {
        LeasePolicy::Session { .. } => (LeaseMode::Session, None),
        LeasePolicy::Heartbeat { lease, .. } => (LeaseMode::Heartbeat, Some(lease.as_secs())),
        LeasePolicy::Permanent => (LeaseMode::Permanent, None),
    }
}

fn capability_summary(
    status: &MdnsControlPlaneStatus,
    registrations: &str,
    activity: ReceiveActivity,
) -> (String, bool) {
    let routes = &status.routes;
    let route_summary = format!(
        "publish {}, browse {}, resolve {}",
        routes.publish.as_deref().unwrap_or("none"),
        routes.browse.as_deref().unwrap_or("none"),
        routes.resolve.as_deref().unwrap_or("browse fallback")
    );
    let receive = match (activity.browse_active_secs, activity.last_event_age_secs) {
        (Some(active), Some(age)) => format!(
            "; browse active {active}s, observed {} events (last {age}s ago)",
            activity.events_seen
        ),
        (Some(active), None) => format!("; browse active {active}s, no records observed yet"),
        (None, _) => String::new(),
    };
    let healthy = matches!(
        status.state,
        ControlPlaneState::Ready | ControlPlaneState::Reconciling
    ) && routes.publish.is_some()
        && routes.browse.is_some()
        && status.publications.failed == 0;
    (
        format!(
            "control plane {:?}; {route_summary}; {registrations}{receive}",
            status.state
        ),
        healthy,
    )
}

#[async_trait::async_trait]
impl Capability for MdnsCore {
    fn name(&self) -> &str {
        "mdns"
    }

    async fn status(&self) -> CapabilityStatus {
        let counts = self.registry.counts();
        let registrations = format!(
            "{} registered ({} alive, {} draining)",
            counts.total, counts.alive, counts.draining
        );
        let status = self.control_plane.status();
        let (summary, healthy) =
            capability_summary(&status, &registrations, self.discovery.receive_activity());
        CapabilityStatus {
            name: "mdns".to_string(),
            summary,
            healthy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn free_port_reports_free_and_held_port_reports_taken() {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).expect("bind");
        let port = socket.local_addr().expect("local address").port();
        assert!(!udp_port_exclusively_free(port));
        drop(socket);
        assert!(udp_port_exclusively_free(port));
    }

    #[test]
    fn dropping_registration_session_drains_its_leases() {
        let registry = Arc::new(RegistrationRegistry::new());
        let session = RegistrationSession {
            registry: Arc::clone(&registry),
            id: SessionId::new("transport-session".to_string()),
        };
        let attempt = registry.begin_registration(
            "registration".to_string(),
            RegisterPayload {
                name: "Session service".to_string(),
                service_type: "_http._tcp".to_string(),
                port: 8080,
                ip: None,
                lease_secs: None,
                txt: HashMap::new(),
            },
            LeasePolicy::Session {
                grace: Duration::from_secs(30),
            },
            Some(session.id().clone()),
        );
        registry.confirm_publication(attempt.outcome.id()).unwrap();
        assert_eq!(registry.counts().alive, 1);

        drop(session);

        assert_eq!(registry.counts().alive, 0);
        assert_eq!(registry.counts().draining, 1);
    }

    #[test]
    fn quiet_browse_is_telemetry_not_failure() {
        let status = MdnsControlPlaneStatus {
            state: ControlPlaneState::Ready,
            routes: koi_common::mdns_protocol::MdnsRoutes {
                publish: Some("avahi".to_string()),
                browse: Some("avahi".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (summary, healthy) = capability_summary(
            &status,
            "0 registered",
            ReceiveActivity {
                events_seen: 0,
                last_event_age_secs: None,
                browse_active_secs: Some(10_000),
            },
        );
        assert!(healthy);
        assert!(summary.contains("no records observed yet"));
    }
}
