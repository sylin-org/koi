use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent as MdnsEvent, ServiceInfo};
use std::collections::HashMap;
use std::time::Duration;

use crate::protocol::ServiceRecord;

use super::{KoiError, Result};

/// Wraps the single mdns-sd ServiceDaemon instance.
/// This is the ONLY file that imports mdns_sd types.
pub(crate) struct MdnsDaemon {
    inner: ServiceDaemon,
}

impl MdnsDaemon {
    pub fn new() -> Result<Self> {
        let inner = ServiceDaemon::new().map_err(|e| KoiError::Daemon(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Start browsing for a service type. Returns a receiver for events.
    pub fn browse(&self, service_type: &str) -> Result<mdns_sd::Receiver<MdnsEvent>> {
        self.inner
            .browse(service_type)
            .map_err(|e| KoiError::Daemon(e.to_string()))
    }

    /// Register a service on the network. Returns an opaque ID.
    pub fn register(
        &self,
        name: &str,
        service_type: &str,
        port: u16,
        txt: &HashMap<String, String>,
    ) -> Result<String> {
        let hostname = hostname::get()
            .unwrap_or_else(|_| "localhost".into())
            .to_string_lossy()
            .to_string();

        let host = format!("{hostname}.local.");

        let properties: Vec<(&str, &str)> =
            txt.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let service_info = ServiceInfo::new(
            service_type,
            name,
            &host,
            "",
            port,
            &properties[..],
        )
        .map_err(|e| KoiError::Daemon(e.to_string()))?
        .enable_addr_auto();

        let fullname = service_info.get_fullname().to_string();

        self.inner
            .register(service_info)
            .map_err(|e| KoiError::Daemon(e.to_string()))?;

        let id = uuid::Uuid::new_v4().to_string()[..8].to_string();
        tracing::debug!(fullname, id, "Registered with mdns-sd daemon");
        Ok(id)
    }

    /// Unregister a service by name and type.
    pub fn unregister(&self, name: &str, service_type: &str) -> Result<()> {
        let fullname = format!("{name}.{service_type}");

        let _receiver = self
            .inner
            .unregister(&fullname)
            .map_err(|e| KoiError::Daemon(e.to_string()))?;

        Ok(())
    }

    /// Resolve a specific service instance by its full name.
    pub async fn resolve(&self, instance: &str) -> Result<ServiceRecord> {
        let parts: Vec<&str> = instance.splitn(2, '.').collect();
        if parts.len() < 2 {
            return Err(KoiError::ResolveTimeout(format!(
                "Invalid instance name: {instance}"
            )));
        }
        let service_type = parts[1];

        let receiver = self
            .inner
            .browse(service_type)
            .map_err(|e| KoiError::Daemon(e.to_string()))?;

        let target_name = parts[0];
        let timeout = Duration::from_secs(5);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            tokio::select! {
                result = receiver.recv_async() => {
                    match result {
                        Ok(MdnsEvent::ServiceResolved(resolved)) => {
                            let record = resolved_to_record(&resolved);
                            if record.name == target_name || resolved.get_fullname() == instance {
                                let _ = self.inner.stop_browse(service_type);
                                return Ok(record);
                            }
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = self.inner.stop_browse(service_type);
                    return Err(KoiError::ResolveTimeout(format!(
                        "Could not resolve {instance} within {timeout:?}"
                    )));
                }
            }
        }

        Err(KoiError::ResolveTimeout(format!(
            "Could not resolve {instance}"
        )))
    }

    /// Stop an active browse by service type.
    pub fn stop_browse(&self, service_type: &str) -> Result<()> {
        self.inner
            .stop_browse(service_type)
            .map_err(|e| KoiError::Daemon(e.to_string()))
    }

    /// Shut down the mdns-sd daemon.
    pub fn shutdown(&self) -> Result<()> {
        let _receiver = self
            .inner
            .shutdown()
            .map_err(|e| KoiError::Daemon(e.to_string()))?;
        Ok(())
    }
}

/// Convert mdns-sd ResolvedService into our ServiceRecord.
/// This is the ONE place this conversion happens.
pub(crate) fn resolved_to_record(resolved: &ResolvedService) -> ServiceRecord {
    let fullname = resolved.get_fullname();

    // Extract instance name: "My Server._http._tcp.local." -> "My Server"
    let name = fullname
        .find("._")
        .map(|i| &fullname[..i])
        .unwrap_or(fullname)
        .to_string();

    let service_type = resolved.ty_domain.clone();
    let service_type = service_type
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();

    let host = resolved.get_hostname().to_string();
    let host = if host.is_empty() { None } else { Some(host) };

    // Prefer first IPv4, fallback to first IPv6
    let addresses = resolved.get_addresses();
    let ip = addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addresses.iter().next())
        .map(|a| a.to_ip_addr().to_string());

    if addresses.len() > 1 {
        tracing::trace!(
            name,
            count = addresses.len(),
            selected = ?ip,
            "Multiple IPs found, using first"
        );
    }

    let txt: HashMap<String, String> = resolved
        .get_properties()
        .iter()
        .map(|p| (p.key().to_string(), p.val_str().to_string()))
        .collect();

    ServiceRecord {
        name,
        service_type,
        host,
        ip,
        port: Some(resolved.get_port()),
        txt,
    }
}
