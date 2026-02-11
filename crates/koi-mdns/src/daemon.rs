use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent as MdnsEvent, ServiceInfo};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::oneshot;

use koi_common::types::ServiceRecord;

use crate::error::{MdnsError, Result};

/// How long to wait for a service to resolve before giving up.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

// ── Worker operations ─────────────────────────────────────────────

/// Operations dispatched to the dedicated mDNS worker thread.
///
/// All `ServiceDaemon` interactions are serialized through this queue
/// so that the bounded internal channel in mdns-sd never blocks a
/// tokio thread.
enum MdnsOp {
    Register(Box<ServiceInfo>),
    Unregister(String), // fullname
    Browse {
        service_type: String,
        reply: oneshot::Sender<std::result::Result<mdns_sd::Receiver<MdnsEvent>, String>>,
    },
    StopBrowse(String),
    Shutdown {
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
}

// ── MdnsDaemon ────────────────────────────────────────────────────

/// Wraps the mdns-sd `ServiceDaemon` behind a dedicated worker thread.
///
/// This is the ONLY file that imports mdns_sd types. All interactions
/// with the daemon are serialized through an unbounded command queue,
/// ensuring the daemon's bounded internal channel never blocks callers
/// (especially tokio tasks).
///
/// Fire-and-forget operations (register, unregister, stop_browse)
/// enqueue and return immediately. Operations that need a result
/// (browse, shutdown) await a oneshot reply from the worker.
pub(crate) struct MdnsDaemon {
    op_tx: Mutex<std::sync::mpsc::Sender<MdnsOp>>,
}

impl MdnsDaemon {
    pub fn new() -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;
        let (op_tx, op_rx) = std::sync::mpsc::channel();

        std::thread::Builder::new()
            .name("koi-mdns-ops".into())
            .spawn(move || worker_loop(daemon, op_rx))
            .map_err(|e| MdnsError::Daemon(format!("Failed to spawn mDNS worker: {e}")))?;

        Ok(Self {
            op_tx: Mutex::new(op_tx),
        })
    }

    /// Send an operation to the worker thread.
    fn send(&self, op: MdnsOp) -> Result<()> {
        self.op_tx
            .lock()
            .unwrap()
            .send(op)
            .map_err(|_| MdnsError::Daemon("mDNS worker stopped".into()))
    }

    /// Start browsing for a service type. Returns a receiver for events.
    pub async fn browse(&self, service_type: &str) -> Result<mdns_sd::Receiver<MdnsEvent>> {
        let (tx, rx) = oneshot::channel();
        self.send(MdnsOp::Browse {
            service_type: service_type.to_string(),
            reply: tx,
        })?;
        rx.await
            .map_err(|_| MdnsError::Daemon("mDNS worker dropped reply".into()))?
            .map_err(MdnsError::Daemon)
    }

    /// Register a service on the network (fire-and-forget).
    ///
    /// Validates inputs synchronously, then enqueues the registration
    /// for the worker thread. Returns immediately.
    pub fn register(
        &self,
        name: &str,
        service_type: &str,
        port: u16,
        ip: Option<&str>,
        txt: &HashMap<String, String>,
    ) -> Result<()> {
        let hostname = hostname::get()
            .unwrap_or_else(|_| "localhost".into())
            .to_string_lossy()
            .to_string();

        let host = format!("{hostname}.local.");

        let properties: Vec<(&str, &str)> =
            txt.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let ip_str = ip.unwrap_or("");
        let service_info =
            ServiceInfo::new(service_type, name, &host, ip_str, port, &properties[..])
                .map_err(|e| MdnsError::Daemon(e.to_string()))?;

        // Only auto-detect addresses when no explicit IP was provided.
        let service_info = if ip.is_none() {
            service_info.enable_addr_auto()
        } else {
            service_info
        };

        let fullname = service_info.get_fullname().to_string();
        tracing::debug!(fullname, ?ip, "Queued mDNS register");

        self.send(MdnsOp::Register(Box::new(service_info)))
    }

    /// Unregister a service by name and type (fire-and-forget).
    pub fn unregister(&self, name: &str, service_type: &str) -> Result<()> {
        let fullname = format!("{name}.{service_type}");
        self.send(MdnsOp::Unregister(fullname))
    }

    /// Resolve a specific service instance by its full name.
    pub async fn resolve(&self, instance: &str) -> Result<ServiceRecord> {
        let parts: Vec<&str> = instance.splitn(2, '.').collect();
        if parts.len() < 2 {
            return Err(MdnsError::ResolveTimeout(format!(
                "Invalid instance name: {instance}"
            )));
        }
        let service_type = parts[1];

        let receiver = self.browse(service_type).await?;

        let target_name = parts[0];
        let deadline = tokio::time::Instant::now() + RESOLVE_TIMEOUT;

        loop {
            tokio::select! {
                result = receiver.recv_async() => {
                    match result {
                        Ok(MdnsEvent::ServiceResolved(resolved)) => {
                            let record = resolved_to_record(&resolved);
                            if record.name == target_name || resolved.get_fullname() == instance {
                                let _ = self.stop_browse(service_type);
                                return Ok(record);
                            }
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = self.stop_browse(service_type);
                    return Err(MdnsError::ResolveTimeout(format!(
                        "Could not resolve {instance} within {RESOLVE_TIMEOUT:?}"
                    )));
                }
            }
        }

        Err(MdnsError::ResolveTimeout(format!(
            "Could not resolve {instance}"
        )))
    }

    /// Stop an active browse by service type (fire-and-forget).
    pub fn stop_browse(&self, service_type: &str) -> Result<()> {
        self.send(MdnsOp::StopBrowse(service_type.to_string()))
    }

    /// Shut down the mdns-sd daemon.
    pub async fn shutdown(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(MdnsOp::Shutdown { reply: tx })?;
        rx.await
            .map_err(|_| MdnsError::Daemon("mDNS worker dropped reply".into()))?
            .map_err(MdnsError::Daemon)
    }
}

// ── Worker thread ─────────────────────────────────────────────────

fn worker_loop(daemon: ServiceDaemon, rx: std::sync::mpsc::Receiver<MdnsOp>) {
    tracing::debug!("mDNS worker thread started");

    while let Ok(op) = rx.recv() {
        match op {
            MdnsOp::Register(info) => {
                let fullname = info.get_fullname().to_string();
                if let Err(e) = daemon.register(*info) {
                    tracing::warn!(fullname, error = %e, "mDNS register failed");
                }
            }
            MdnsOp::Unregister(fullname) => {
                if let Err(e) = daemon.unregister(&fullname) {
                    tracing::warn!(fullname, error = %e, "mDNS unregister failed");
                }
            }
            MdnsOp::Browse {
                service_type,
                reply,
            } => {
                let result = daemon.browse(&service_type).map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            MdnsOp::StopBrowse(service_type) => {
                if let Err(e) = daemon.stop_browse(&service_type) {
                    tracing::debug!(service_type, error = %e, "mDNS stop_browse failed");
                }
            }
            MdnsOp::Shutdown { reply } => {
                let result = daemon.shutdown().map(|_| ()).map_err(|e| e.to_string());
                let _ = reply.send(result);
                break;
            }
        }
    }

    tracing::debug!("mDNS worker thread stopped");
}

// ── Service record conversion ─────────────────────────────────────

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
