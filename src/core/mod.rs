mod daemon;
mod events;
mod registry;

pub use self::events::ServiceEvent;
pub use self::registry::{LeasePolicy, SessionId};

use std::sync::Arc;
use std::time::{Duration, Instant};

use self::daemon::MdnsDaemon;
use self::registry::{InsertOutcome, Registry};

/// Length of short hex IDs generated from UUID v4 (e.g., "a1b2c3d4").
const SHORT_ID_LEN: usize = 8;

/// Capacity for the broadcast channel used by service event subscribers.
const BROADCAST_CHANNEL_CAPACITY: usize = 256;

/// How often the reaper sweeps for expired registrations.
const REAPER_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum allowed length for DNS-SD service names (RFC 6763).
const SERVICE_NAME_MAX_LEN: usize = 15;

use crate::protocol::{
    AdminRegistration, DaemonStatus, LeaseMode, RegisterPayload, RegistrationResult, ServiceRecord,
};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum KoiError {
    #[error("Invalid service type: {0}")]
    InvalidServiceType(String),

    #[error("Registration not found: {0}")]
    RegistrationNotFound(String),

    #[error("Resolve timeout: {0}")]
    ResolveTimeout(String),

    #[error("mDNS daemon error: {0}")]
    Daemon(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Already draining: {0}")]
    AlreadyDraining(String),

    #[error("Not draining: {0}")]
    NotDraining(String),

    #[error("Ambiguous ID prefix: {0}")]
    AmbiguousId(String),
}

pub type Result<T> = std::result::Result<T, KoiError>;

/// Validated DNS-SD service type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceType(String);

impl ServiceType {
    /// Parse and normalize a service type string.
    /// Accepts liberal input: "http", "_http", "_http._tcp", "_http._tcp.local."
    /// Always produces the canonical form: "_name._tcp.local."
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim().trim_end_matches('.');
        let s = s.trim_end_matches(".local");

        let parts: Vec<&str> = s.split('.').collect();

        let (name, proto) = match parts.len() {
            1 => {
                let name = parts[0].strip_prefix('_').unwrap_or(parts[0]);
                (name, "tcp")
            }
            2 => {
                let name = parts[0].strip_prefix('_').unwrap_or(parts[0]);
                let proto = parts[1].strip_prefix('_').unwrap_or(parts[1]);
                (name, proto)
            }
            _ => return Err(KoiError::InvalidServiceType(s.to_string())),
        };

        if proto != "tcp" && proto != "udp" {
            return Err(KoiError::InvalidServiceType(format!(
                "protocol must be tcp or udp, got '{proto}'"
            )));
        }

        if name.is_empty() || name.len() > SERVICE_NAME_MAX_LEN {
            return Err(KoiError::InvalidServiceType(format!(
                "service name must be 1-15 characters, got '{name}'"
            )));
        }

        let canonical = format!("_{name}._{proto}.local.");
        tracing::debug!("Normalized service type: \"{s}\" → \"{canonical}\"");
        Ok(ServiceType(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The short form without ".local." for user-facing output.
    pub fn short(&self) -> &str {
        self.0.trim_end_matches(".local.").trim_end_matches('.')
    }
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.short())
    }
}

/// DNS-SD meta-query type for discovering all service types on the network.
pub const META_QUERY: &str = "_services._dns-sd._udp.local.";

/// The core mDNS facade. All adapters interact through this.
pub struct MdnsCore {
    daemon: Arc<MdnsDaemon>,
    registry: Arc<Registry>,
    event_tx: broadcast::Sender<ServiceEvent>,
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

    /// Start browsing for services of the given type.
    /// Pass `META_QUERY` to discover all service types on the network.
    ///
    /// The returned `BrowseHandle` calls `stop_browse` on drop, so the
    /// underlying daemon resource is always cleaned up.
    pub async fn browse(&self, service_type: &str) -> Result<browse::BrowseHandle> {
        let is_meta = service_type == META_QUERY;
        let browse_type = if is_meta {
            META_QUERY.to_string()
        } else {
            ServiceType::parse(service_type)?.as_str().to_string()
        };
        let receiver = self.daemon.browse(&browse_type).await?;
        let event_tx = self.event_tx.clone();
        Ok(browse::BrowseHandle::new(
            receiver,
            event_tx,
            is_meta,
            browse_type,
            self.daemon.clone(),
        ))
    }

    /// Register a service with a default permanent policy.
    /// Backward-compatible entry point — adapters should prefer `register_with_policy`.
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
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<ServiceEvent> {
        self.event_tx.subscribe()
    }

    // ── Admin methods ─────────────────────────────────────────────────

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
}

/// Generate a short 8-character hex ID from UUID v4.
fn generate_short_id() -> String {
    uuid::Uuid::new_v4().to_string()[..SHORT_ID_LEN].to_string()
}

pub mod browse {
    use std::sync::Arc;

    use super::ServiceEvent;
    use crate::core::daemon::{self, MdnsDaemon};
    use mdns_sd::ServiceEvent as MdnsEvent;
    use tokio::sync::broadcast;

    /// Handle for an active browse operation.
    ///
    /// Owns the lifecycle of a single `stop_browse` call on the daemon.
    /// When dropped, the browse is stopped automatically — no leaked
    /// subscriptions in the mdns-sd engine.
    pub struct BrowseHandle {
        receiver: mdns_sd::Receiver<MdnsEvent>,
        event_tx: broadcast::Sender<ServiceEvent>,
        meta_query: bool,
        browse_type: String,
        daemon: Arc<MdnsDaemon>,
    }

    impl Drop for BrowseHandle {
        fn drop(&mut self) {
            if let Err(e) = self.daemon.stop_browse(&self.browse_type) {
                tracing::debug!(
                    error = %e,
                    browse_type = %self.browse_type,
                    "Failed to stop browse on drop"
                );
            }
        }
    }

    impl BrowseHandle {
        pub(super) fn new(
            receiver: mdns_sd::Receiver<MdnsEvent>,
            event_tx: broadcast::Sender<ServiceEvent>,
            meta_query: bool,
            browse_type: String,
            daemon: Arc<MdnsDaemon>,
        ) -> Self {
            Self {
                receiver,
                event_tx,
                meta_query,
                browse_type,
                daemon,
            }
        }

        /// Receive the next service event asynchronously.
        pub async fn recv(&self) -> Option<ServiceEvent> {
            loop {
                match self.receiver.recv_async().await {
                    Ok(mdns_event) => {
                        let event = match mdns_event {
                            MdnsEvent::ServiceFound(_, fullname) => {
                                if self.meta_query {
                                    // Meta-query: "found" instances are service types
                                    let type_name = fullname
                                        .trim_end_matches('.')
                                        .trim_end_matches(".local")
                                        .to_string();
                                    let record = crate::protocol::ServiceRecord {
                                        name: type_name,
                                        service_type: String::new(),
                                        host: None,
                                        ip: None,
                                        port: None,
                                        txt: Default::default(),
                                    };
                                    let event = ServiceEvent::Found(record);
                                    let _ = self.event_tx.send(event.clone());
                                    event
                                } else {
                                    tracing::debug!(fullname, "Service found (pending resolution)");
                                    continue;
                                }
                            }
                            MdnsEvent::ServiceResolved(resolved) => {
                                let record = daemon::resolved_to_record(&resolved);
                                let event = ServiceEvent::Resolved(record);
                                let _ = self.event_tx.send(event.clone());
                                event
                            }
                            MdnsEvent::ServiceRemoved(_, fullname) => {
                                let event = ServiceEvent::Removed {
                                    name: fullname.clone(),
                                    service_type: String::new(),
                                };
                                let _ = self.event_tx.send(event.clone());
                                event
                            }
                            MdnsEvent::SearchStarted(_) => continue,
                            MdnsEvent::SearchStopped(_) => return None,
                            _ => continue,
                        };
                        return Some(event);
                    }
                    Err(_) => return None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_type_parse_bare_name() {
        let st = ServiceType::parse("http").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
        assert_eq!(st.short(), "_http._tcp");
    }

    #[test]
    fn service_type_parse_with_underscore() {
        let st = ServiceType::parse("_http").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
    }

    #[test]
    fn service_type_parse_full_form() {
        let st = ServiceType::parse("_http._tcp").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
    }

    #[test]
    fn service_type_parse_with_trailing_dot() {
        let st = ServiceType::parse("_http._tcp.").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
    }

    #[test]
    fn service_type_parse_with_local_dot() {
        let st = ServiceType::parse("_http._tcp.local.").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
    }

    #[test]
    fn service_type_parse_udp() {
        let st = ServiceType::parse("_dns._udp").unwrap();
        assert_eq!(st.as_str(), "_dns._udp.local.");
    }

    #[test]
    fn service_type_rejects_invalid_protocol() {
        assert!(ServiceType::parse("_http._xyz").is_err());
    }

    #[test]
    fn service_type_rejects_empty_name() {
        assert!(ServiceType::parse("").is_err());
    }
}
