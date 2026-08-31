//! Native Koi mDNS provider backed by `mdns-sd`.
//!
//! This is the only module allowed to import provider-library types. It owns
//! the dedicated worker thread and translates every raw event into Koi's
//! provider-neutral observation model.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use mdns_sd::{
    ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent as MdnsServiceEvent, ServiceInfo,
};
use tokio::sync::{mpsc, oneshot};

use crate::error::{MdnsError, Result};
use crate::provider::{
    MdnsProvider, ProviderAddress, ProviderBrowse, ProviderEvent, ProviderService, ProviderStatus,
};

const BROWSE_CHANNEL_CAPACITY: usize = 512;

enum NativeOp {
    Register(Box<ServiceInfo>),
    Unregister(String),
    Browse {
        service_type: String,
        reply: oneshot::Sender<std::result::Result<mdns_sd::Receiver<MdnsServiceEvent>, String>>,
    },
    StopBrowse(String),
    Shutdown {
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
}

/// Koi's built-in mDNS/DNS-SD implementation.
pub struct NativeMdnsProvider {
    op_tx: Mutex<std::sync::mpsc::SyncSender<NativeOp>>,
    healthy: Arc<AtomicBool>,
}

impl NativeMdnsProvider {
    pub fn new() -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;
        let (op_tx, op_rx) = std::sync::mpsc::sync_channel(256);
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_health = Arc::clone(&healthy);

        std::thread::Builder::new()
            .name("koi-mdns-native".into())
            .spawn(move || worker_loop(daemon, op_rx, worker_health))
            .map_err(|e| MdnsError::Daemon(format!("Failed to spawn mDNS worker: {e}")))?;

        Ok(Self {
            op_tx: Mutex::new(op_tx),
            healthy,
        })
    }

    fn send(&self, op: NativeOp) -> Result<()> {
        self.op_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .try_send(op)
            .map_err(|e| match e {
                std::sync::mpsc::TrySendError::Full(_) => {
                    MdnsError::Daemon("mDNS worker queue full".into())
                }
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    MdnsError::Daemon("mDNS worker stopped".into())
                }
            })
    }
}

#[async_trait::async_trait]
impl MdnsProvider for NativeMdnsProvider {
    fn name(&self) -> &'static str {
        "native"
    }

    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            name: self.name(),
            healthy: self.healthy.load(Ordering::Relaxed),
            detail: "built-in mdns-sd engine".to_string(),
        }
    }

    fn register(
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

        let service_info = ServiceInfo::new(
            service_type,
            name,
            &host,
            ip.unwrap_or(""),
            port,
            &properties[..],
        )
        .map_err(|e| MdnsError::Daemon(e.to_string()))?;

        let service_info = if ip.is_none() {
            service_info.enable_addr_auto()
        } else {
            service_info
        };

        let fullname = service_info.get_fullname().to_string();
        tracing::debug!(
            provider = self.name(),
            fullname,
            ?ip,
            "Queued mDNS register"
        );
        self.send(NativeOp::Register(Box::new(service_info)))
    }

    fn unregister(&self, name: &str, service_type: &str) -> Result<()> {
        self.send(NativeOp::Unregister(format!("{name}.{service_type}")))
    }

    async fn browse(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NativeOp::Browse {
            service_type: service_type.to_string(),
            reply: reply_tx,
        })?;
        let raw = reply_rx
            .await
            .map_err(|_| MdnsError::Daemon("mDNS worker dropped reply".into()))?
            .map_err(MdnsError::Daemon)?;

        let (tx, rx) = mpsc::channel(BROWSE_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            while let Ok(event) = raw.recv_async().await {
                match translate(event, is_meta) {
                    NativeEvent::Emit(event) => {
                        if tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    NativeEvent::Skip => continue,
                    NativeEvent::Stop => break,
                }
            }
        });
        Ok(rx)
    }

    fn stop_browse(&self, service_type: &str) -> Result<()> {
        self.send(NativeOp::StopBrowse(service_type.to_string()))
    }

    async fn shutdown(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(NativeOp::Shutdown { reply: tx })?;
        rx.await
            .map_err(|_| MdnsError::Daemon("mDNS worker dropped reply".into()))?
            .map_err(MdnsError::Daemon)
    }
}

enum NativeEvent {
    Emit(ProviderEvent),
    Skip,
    Stop,
}

fn translate(event: MdnsServiceEvent, is_meta: bool) -> NativeEvent {
    match event {
        MdnsServiceEvent::ServiceFound(_, fullname) if is_meta => {
            let type_name = fullname
                .trim_end_matches('.')
                .trim_end_matches(".local")
                .to_string();
            NativeEvent::Emit(ProviderEvent::Found(ProviderService {
                name: type_name,
                service_type: String::new(),
                host: None,
                addresses: Vec::new(),
                port: None,
                txt: HashMap::new(),
            }))
        }
        MdnsServiceEvent::ServiceFound(_, _) => NativeEvent::Skip,
        MdnsServiceEvent::ServiceResolved(resolved) => {
            NativeEvent::Emit(ProviderEvent::Resolved(resolved_to_service(&resolved)))
        }
        MdnsServiceEvent::ServiceRemoved(ty_domain, fullname) => {
            let (name, service_type) = parse_removed(&ty_domain, &fullname);
            NativeEvent::Emit(ProviderEvent::Removed { name, service_type })
        }
        MdnsServiceEvent::SearchStarted(_) => NativeEvent::Skip,
        MdnsServiceEvent::SearchStopped(_) => NativeEvent::Stop,
        _ => NativeEvent::Skip,
    }
}

fn parse_removed(ty_domain: &str, fullname: &str) -> (String, String) {
    let service_type = ty_domain
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();
    let instance = fullname
        .find("._")
        .map(|i| &fullname[..i])
        .unwrap_or(fullname)
        .to_string();
    (instance, service_type)
}

fn resolved_to_service(resolved: &ResolvedService) -> ProviderService {
    let fullname = resolved.get_fullname();
    let name = fullname
        .find("._")
        .map(|i| &fullname[..i])
        .unwrap_or(fullname)
        .to_string();
    let service_type = resolved
        .ty_domain
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();
    let host = match resolved.get_hostname() {
        "" => None,
        value => Some(value.to_string()),
    };

    let mut addresses = Vec::new();
    for scoped in resolved.get_addresses() {
        match scoped {
            ScopedIp::V4(v4) if v4.interface_ids().is_empty() => {
                addresses.push(ProviderAddress {
                    address: scoped.to_ip_addr(),
                    interface_index: None,
                    interface_name: None,
                });
            }
            ScopedIp::V4(v4) => {
                addresses.extend(v4.interface_ids().iter().map(|interface| ProviderAddress {
                    address: scoped.to_ip_addr(),
                    interface_index: Some(interface.index),
                    interface_name: Some(interface.name.clone()),
                }));
            }
            ScopedIp::V6(v6) => {
                addresses.push(ProviderAddress {
                    address: scoped.to_ip_addr(),
                    interface_index: Some(v6.scope_id().index),
                    interface_name: Some(v6.scope_id().name.clone()),
                });
            }
            _ => {
                addresses.push(ProviderAddress {
                    address: scoped.to_ip_addr(),
                    interface_index: None,
                    interface_name: None,
                });
            }
        }
    }

    let txt = resolved
        .get_properties()
        .iter()
        .map(|p| (p.key().to_string(), p.val_str().to_string()))
        .collect();

    ProviderService {
        name,
        service_type,
        host,
        addresses,
        port: Some(resolved.get_port()),
        txt,
    }
}

fn worker_loop(
    daemon: ServiceDaemon,
    rx: std::sync::mpsc::Receiver<NativeOp>,
    healthy: Arc<AtomicBool>,
) {
    tracing::debug!("Native mDNS worker thread started");
    while let Ok(op) = rx.recv() {
        match op {
            NativeOp::Register(info) => {
                let fullname = info.get_fullname().to_string();
                if let Err(error) = daemon.register(*info) {
                    healthy.store(false, Ordering::Relaxed);
                    tracing::warn!(fullname, %error, "mDNS register failed");
                } else {
                    healthy.store(true, Ordering::Relaxed);
                }
            }
            NativeOp::Unregister(fullname) => {
                if let Err(error) = daemon.unregister(&fullname) {
                    healthy.store(false, Ordering::Relaxed);
                    tracing::warn!(fullname, %error, "mDNS unregister failed");
                } else {
                    healthy.store(true, Ordering::Relaxed);
                }
            }
            NativeOp::Browse {
                service_type,
                reply,
            } => {
                let result = daemon.browse(&service_type).map_err(|e| e.to_string());
                healthy.store(result.is_ok(), Ordering::Relaxed);
                let _ = reply.send(result);
            }
            NativeOp::StopBrowse(service_type) => {
                if let Err(error) = daemon.stop_browse(&service_type) {
                    healthy.store(false, Ordering::Relaxed);
                    tracing::debug!(service_type, %error, "mDNS stop_browse failed");
                } else {
                    healthy.store(true, Ordering::Relaxed);
                }
            }
            NativeOp::Shutdown { reply } => {
                let result = daemon.shutdown().map(|_| ()).map_err(|e| e.to_string());
                let _ = reply.send(result);
                break;
            }
        }
    }
    healthy.store(false, Ordering::Relaxed);
    tracing::debug!("Native mDNS worker thread stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_event_is_normalized_at_the_adapter_boundary() {
        let (name, service_type) = parse_removed("_http._tcp.local.", "My NAS._http._tcp.local.");
        assert_eq!(name, "My NAS");
        assert_eq!(service_type, "_http._tcp");
    }

    #[test]
    fn mdns_sd_is_isolated_to_the_native_adapter() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&src_dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some("native.rs") {
                continue;
            }
            let contents = std::fs::read_to_string(&path).expect("read source file");
            if contents.contains("mdns_sd") {
                offenders.push(path.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "mdns_sd must only be referenced in native.rs; offenders: {offenders:?}"
        );
    }
}
