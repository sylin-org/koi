//! Koi Proxy — TLS-terminating reverse proxy (Phase 8).

pub mod config;
mod forwarder;
pub mod http;
mod listener;
mod safety;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;

use koi_common::capability::{Capability, CapabilityStatus};

pub use config::ProxyEntry;
pub use safety::ensure_backend_allowed;

/// Capacity for the proxy event broadcast channel.
const BROADCAST_CHANNEL_CAPACITY: usize = 256;

/// Events emitted by the proxy subsystem when entries change.
#[derive(Debug, Clone)]
pub enum ProxyEvent {
    /// A proxy entry was added or updated.
    EntryUpdated { entry: ProxyEntry },
    /// A proxy entry was removed.
    EntryRemoved { name: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("proxy config error: {0}")]
    Config(String),

    #[error("proxy io error: {0}")]
    Io(String),

    #[error("proxy invalid config: {0}")]
    InvalidConfig(String),

    #[error("proxy forward error: {0}")]
    Forward(String),

    #[error("proxy entry not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyStatus {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    pub allow_remote: bool,
    pub running: bool,
}

pub struct ProxyCore {
    entries: Arc<Mutex<Vec<ProxyEntry>>>,
    event_tx: broadcast::Sender<ProxyEvent>,
}

impl ProxyCore {
    pub fn new() -> Result<Self, ProxyError> {
        let entries = config::load_entries()?;
        Ok(Self {
            entries: Arc::new(Mutex::new(entries)),
            event_tx: broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0,
        })
    }

    pub async fn entries(&self) -> Vec<ProxyEntry> {
        self.entries.lock().await.clone()
    }

    pub async fn reload(&self) -> Result<Vec<ProxyEntry>, ProxyError> {
        let entries = config::load_entries()?;
        let mut guard = self.entries.lock().await;
        *guard = entries.clone();
        Ok(entries)
    }

    pub async fn upsert(&self, entry: ProxyEntry) -> Result<Vec<ProxyEntry>, ProxyError> {
        let entries = config::upsert_entry(entry.clone())?;
        let mut guard = self.entries.lock().await;
        *guard = entries.clone();
        let _ = self.event_tx.send(ProxyEvent::EntryUpdated { entry });
        Ok(entries)
    }

    pub async fn remove(&self, name: &str) -> Result<Vec<ProxyEntry>, ProxyError> {
        let entries = config::remove_entry(name)?;
        let mut guard = self.entries.lock().await;
        *guard = entries.clone();
        let _ = self.event_tx.send(ProxyEvent::EntryRemoved {
            name: name.to_string(),
        });
        Ok(entries)
    }

    /// Subscribe to proxy events.
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.event_tx.subscribe()
    }
}

impl Capability for ProxyCore {
    fn name(&self) -> &str {
        "proxy"
    }

    fn status(&self) -> CapabilityStatus {
        CapabilityStatus {
            name: "proxy".to_string(),
            summary: "configured".to_string(),
            healthy: true,
        }
    }
}

struct ProxyInstance {
    entry: ProxyEntry,
    cancel: CancellationToken,
}

/// Runtime controller for proxy listeners.
pub struct ProxyRuntime {
    core: Arc<ProxyCore>,
    instances: Arc<Mutex<HashMap<String, ProxyInstance>>>,
}

impl ProxyRuntime {
    pub fn new(core: Arc<ProxyCore>) -> Self {
        Self {
            core,
            instances: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn core(&self) -> Arc<ProxyCore> {
        Arc::clone(&self.core)
    }

    pub async fn start_all(&self) -> Result<(), ProxyError> {
        let entries = self.core.entries().await;
        self.apply_entries(entries).await
    }

    pub async fn reload(&self) -> Result<(), ProxyError> {
        let entries = self.core.reload().await?;
        self.apply_entries(entries).await
    }

    async fn apply_entries(&self, entries: Vec<ProxyEntry>) -> Result<(), ProxyError> {
        let mut guard = self.instances.lock().await;
        let mut seen = HashMap::new();

        for entry in entries {
            seen.insert(entry.name.clone(), entry.clone());
            let entry_name = entry.name.clone();
            let entry_name_for_task = entry_name.clone();
            let needs_restart = match guard.get(&entry.name) {
                Some(existing) => existing.entry != entry,
                None => true,
            };
            if needs_restart {
                if let Some(existing) = guard.remove(&entry.name) {
                    existing.cancel.cancel();
                }
                let cancel = CancellationToken::new();
                let mut listener =
                    listener::ProxyListener::new(entry.clone(), cancel.clone()).await?;
                let watch = listener.watch_certs().await;
                if let Err(e) = watch {
                    tracing::warn!(error = %e, name = %entry.name, "Failed to watch certs");
                }
                tokio::spawn(async move {
                    if let Err(e) = listener.run().await {
                        tracing::error!(error = %e, name = %entry_name_for_task, "Proxy listener failed");
                    }
                });
                guard.insert(entry_name.clone(), ProxyInstance { entry, cancel });
            }
        }

        let remove_names: Vec<String> = guard
            .keys()
            .filter(|name| !seen.contains_key(*name))
            .cloned()
            .collect();
        for name in remove_names {
            if let Some(instance) = guard.remove(&name) {
                instance.cancel.cancel();
            }
        }

        Ok(())
    }

    pub async fn stop_all(&self) {
        let mut guard = self.instances.lock().await;
        for instance in guard.values() {
            instance.cancel.cancel();
        }
        guard.clear();
    }

    pub async fn status(&self) -> Vec<ProxyStatus> {
        let guard = self.instances.lock().await;
        guard
            .values()
            .map(|instance| ProxyStatus {
                name: instance.entry.name.clone(),
                listen_port: instance.entry.listen_port,
                backend: instance.entry.backend.clone(),
                allow_remote: instance.entry.allow_remote,
                running: true,
            })
            .collect()
    }
}

impl Clone for ProxyRuntime {
    fn clone(&self) -> Self {
        Self {
            core: Arc::clone(&self.core),
            instances: Arc::clone(&self.instances),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_receives_emitted_entry_updated() {
        let (tx, _) = broadcast::channel::<ProxyEvent>(16);
        let mut rx = tx.subscribe();

        let entry = ProxyEntry {
            name: "test-svc".to_string(),
            listen_port: 9090,
            backend: "http://127.0.0.1:8080".to_string(),
            allow_remote: false,
        };
        let _ = tx.send(ProxyEvent::EntryUpdated {
            entry: entry.clone(),
        });

        let event = rx.try_recv().expect("should receive event");
        match event {
            ProxyEvent::EntryUpdated { entry: received } => {
                assert_eq!(received.name, "test-svc");
                assert_eq!(received.listen_port, 9090);
                assert_eq!(received.backend, "http://127.0.0.1:8080");
            }
            other => panic!("expected EntryUpdated, got {other:?}"),
        }
    }

    #[test]
    fn subscribe_receives_emitted_entry_removed() {
        let (tx, _) = broadcast::channel::<ProxyEvent>(16);
        let mut rx = tx.subscribe();

        let _ = tx.send(ProxyEvent::EntryRemoved {
            name: "rm-svc".to_string(),
        });

        let event = rx.try_recv().expect("should receive event");
        match event {
            ProxyEvent::EntryRemoved { name } => {
                assert_eq!(name, "rm-svc");
            }
            other => panic!("expected EntryRemoved, got {other:?}"),
        }
    }

    #[test]
    fn multiple_subscribers_each_receive_event() {
        let (tx, _) = broadcast::channel::<ProxyEvent>(16);
        let mut rx1 = tx.subscribe();
        let mut rx2 = tx.subscribe();

        let _ = tx.send(ProxyEvent::EntryRemoved {
            name: "multi".to_string(),
        });

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }
}
