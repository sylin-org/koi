mod daemon;
mod events;
mod registry;

pub use self::events::ServiceEvent;

use self::daemon::MdnsDaemon;
use self::registry::Registry;

use crate::protocol::{RegisterPayload, RegistrationResult, ServiceRecord};
use thiserror::Error;
use tokio::sync::broadcast;

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

        if name.is_empty() || name.len() > 15 {
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

/// The core mDNS facade. All adapters interact through this.
pub struct MdnsCore {
    daemon: MdnsDaemon,
    registry: Registry,
    event_tx: broadcast::Sender<ServiceEvent>,
}

impl MdnsCore {
    pub fn new() -> Result<Self> {
        let daemon = MdnsDaemon::new()?;
        let registry = Registry::new();
        let (event_tx, _) = broadcast::channel(256);
        Ok(Self {
            daemon,
            registry,
            event_tx,
        })
    }

    /// Start browsing for services of the given type.
    pub fn browse(&self, service_type: &str) -> Result<browse::BrowseHandle> {
        let st = ServiceType::parse(service_type)?;
        let receiver = self.daemon.browse(st.as_str())?;
        let event_tx = self.event_tx.clone();
        Ok(browse::BrowseHandle::new(receiver, event_tx))
    }

    /// Register a service on the local network.
    pub fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult> {
        let st = ServiceType::parse(&payload.service_type)?;
        let id = self.daemon.register(
            &payload.name,
            st.as_str(),
            payload.port,
            &payload.txt,
        )?;
        let result = RegistrationResult {
            id: id.clone(),
            name: payload.name.clone(),
            service_type: st.short().to_string(),
            port: payload.port,
        };
        self.registry.insert(id, payload);
        tracing::info!(
            name = %result.name,
            service_type = %result.service_type,
            port = result.port,
            "Service registered"
        );
        Ok(result)
    }

    /// Unregister a previously registered service.
    pub fn unregister(&self, id: &str) -> Result<()> {
        let payload = self.registry.remove(id)?;
        let st = ServiceType::parse(&payload.service_type)?;
        self.daemon.unregister(&payload.name, st.as_str())?;
        tracing::info!(name = %payload.name, "Service unregistered");
        Ok(())
    }

    /// Resolve a specific service instance by its full name.
    pub async fn resolve(&self, instance: &str) -> Result<ServiceRecord> {
        self.daemon.resolve(instance).await
    }

    /// Subscribe to all service events. Returns a broadcast receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<ServiceEvent> {
        self.event_tx.subscribe()
    }

    /// Shut down gracefully: unregister all services, then stop the daemon.
    pub fn shutdown(&self) -> Result<()> {
        let ids: Vec<String> = self.registry.all_ids();
        for id in &ids {
            if let Err(e) = self.unregister(id) {
                tracing::warn!(id, error = %e, "Failed to unregister service during shutdown");
            }
        }
        self.daemon.shutdown()?;
        tracing::info!("mDNS core shut down");
        Ok(())
    }
}

pub mod browse {
    use super::ServiceEvent;
    use crate::core::daemon;
    use mdns_sd::ServiceEvent as MdnsEvent;
    use tokio::sync::broadcast;

    /// Handle for an active browse operation.
    pub struct BrowseHandle {
        receiver: mdns_sd::Receiver<MdnsEvent>,
        event_tx: broadcast::Sender<ServiceEvent>,
    }

    impl BrowseHandle {
        pub(super) fn new(
            receiver: mdns_sd::Receiver<MdnsEvent>,
            event_tx: broadcast::Sender<ServiceEvent>,
        ) -> Self {
            Self { receiver, event_tx }
        }

        /// Receive the next service event asynchronously.
        pub async fn recv(&self) -> Option<ServiceEvent> {
            loop {
                match self.receiver.recv_async().await {
                    Ok(mdns_event) => {
                        let event = match mdns_event {
                            MdnsEvent::ServiceFound(_, fullname) => {
                                tracing::debug!(fullname, "Service found (pending resolution)");
                                continue;
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
