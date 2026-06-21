//! Koi Proxy - TLS-terminating reverse proxy (Phase 8).

pub mod config;
pub mod http;
mod listener;
mod safety;
mod tls;

#[cfg(test)]
mod data_plane_tests;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, watch, Mutex};
use tokio_util::sync::CancellationToken;

use koi_common::capability::{Capability, CapabilityStatus};

use listener::{spawn_listener, ListenerStatus};

pub use config::ProxyEntry;
pub use safety::{ensure_backend_allowed, parse_backend};

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

    #[error("proxy entry not found: {0}")]
    NotFound(String),
}

/// Runtime status of a single proxy listener.
///
/// `state`/`error` reflect the listener task's real liveness (bind/accept outcome),
/// and `cert_source` records which certificate the listener is serving. This
/// replaces the old hardcoded `running: true`.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ProxyStatus {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    pub allow_remote: bool,
    /// "certmesh" (cert file found on disk) or "self-signed" (generated fallback).
    pub cert_source: String,
    /// "starting" | "running" | "error" | "stopped".
    pub state: String,
    /// Error detail, present only when `state == "error"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct ProxyCore {
    entries: Arc<Mutex<Vec<ProxyEntry>>>,
    event_tx: broadcast::Sender<ProxyEvent>,
    data_dir: Option<std::path::PathBuf>,
}

impl ProxyCore {
    pub fn new() -> Result<Self, ProxyError> {
        let entries = config::load_entries()?;
        Ok(Self {
            entries: Arc::new(Mutex::new(entries)),
            event_tx: koi_common::events::event_channel().0,
            data_dir: None,
        })
    }

    /// Create a ProxyCore that reads/writes config from a custom data directory.
    pub fn with_data_dir(data_dir: &std::path::Path) -> Result<Self, ProxyError> {
        let entries = config::load_entries_with_data_dir(Some(data_dir))?;
        Ok(Self {
            entries: Arc::new(Mutex::new(entries)),
            event_tx: koi_common::events::event_channel().0,
            data_dir: Some(data_dir.to_path_buf()),
        })
    }

    pub async fn entries(&self) -> Vec<ProxyEntry> {
        self.entries.lock().await.clone()
    }

    pub async fn reload(&self) -> Result<Vec<ProxyEntry>, ProxyError> {
        let data_dir = self.data_dir.clone();
        let entries = tokio::task::spawn_blocking(move || {
            config::load_entries_with_data_dir(data_dir.as_deref())
        })
        .await
        .map_err(|e| ProxyError::Io(format!("config task: {e}")))??;
        let mut guard = self.entries.lock().await;
        *guard = entries.clone();
        Ok(entries)
    }

    pub async fn upsert(&self, entry: ProxyEntry) -> Result<Vec<ProxyEntry>, ProxyError> {
        let data_dir = self.data_dir.clone();
        let entry_for_io = entry.clone();
        let entries = tokio::task::spawn_blocking(move || {
            config::upsert_entry_with_data_dir(entry_for_io, data_dir.as_deref())
        })
        .await
        .map_err(|e| ProxyError::Io(format!("config task: {e}")))??;
        let mut guard = self.entries.lock().await;
        *guard = entries.clone();
        let _ = self.event_tx.send(ProxyEvent::EntryUpdated { entry });
        Ok(entries)
    }

    pub async fn remove(&self, name: &str) -> Result<Vec<ProxyEntry>, ProxyError> {
        let data_dir = self.data_dir.clone();
        let name_owned = name.to_string();
        let entries = tokio::task::spawn_blocking(move || {
            config::remove_entry_with_data_dir(&name_owned, data_dir.as_deref())
        })
        .await
        .map_err(|e| ProxyError::Io(format!("config task: {e}")))??;
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

#[async_trait::async_trait]
impl Capability for ProxyCore {
    fn name(&self) -> &str {
        "proxy"
    }

    async fn status(&self) -> CapabilityStatus {
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
    status: watch::Receiver<ListenerStatus>,
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
            let needs_restart = match guard.get(&entry.name) {
                Some(existing) => existing.entry != entry,
                None => true,
            };
            if needs_restart {
                if let Some(existing) = guard.remove(&entry.name) {
                    existing.cancel.cancel();
                }
                let cancel = CancellationToken::new();
                let status = spawn_listener(entry.clone(), cancel.clone());
                guard.insert(
                    entry_name,
                    ProxyInstance {
                        entry,
                        cancel,
                        status,
                    },
                );
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
            .map(|instance| {
                let status = instance.status.borrow();
                ProxyStatus {
                    name: instance.entry.name.clone(),
                    listen_port: instance.entry.listen_port,
                    backend: instance.entry.backend.clone(),
                    allow_remote: instance.entry.allow_remote,
                    cert_source: status.cert_source.as_str().to_string(),
                    state: status.state.as_str().to_string(),
                    error: status.error.clone(),
                }
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

    /// Build a ProxyCore backed by a throwaway data dir so tests never touch the
    /// real on-disk proxy config.
    fn test_core() -> ProxyCore {
        let dir = std::env::temp_dir().join(format!(
            "koi-proxy-test-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        ProxyCore::with_data_dir(&dir).expect("core should build")
    }

    fn sample_entry(name: &str) -> ProxyEntry {
        ProxyEntry {
            name: name.to_string(),
            listen_port: 9090,
            backend: "http://127.0.0.1:8080".to_string(),
            allow_remote: false,
        }
    }

    /// Drives the real ProxyCore command path: subscribe → upsert → assert the
    /// EntryUpdated event is broadcast through the core's own channel. Fails if
    /// `upsert` stops emitting (tests Koi wiring, not tokio).
    #[tokio::test]
    async fn upsert_emits_entry_updated_through_core() {
        let core = test_core();
        let mut rx = core.subscribe();

        core.upsert(sample_entry("test-svc"))
            .await
            .expect("upsert should succeed");

        match rx.try_recv().expect("should receive event") {
            ProxyEvent::EntryUpdated { entry } => {
                assert_eq!(entry.name, "test-svc");
                assert_eq!(entry.listen_port, 9090);
                assert_eq!(entry.backend, "http://127.0.0.1:8080");
            }
            other => panic!("expected EntryUpdated, got {other:?}"),
        }
    }

    /// remove() on an existing entry emits EntryRemoved through the core.
    #[tokio::test]
    async fn remove_emits_entry_removed_through_core() {
        let core = test_core();
        core.upsert(sample_entry("rm-svc"))
            .await
            .expect("upsert should succeed");

        let mut rx = core.subscribe();
        core.remove("rm-svc").await.expect("remove should succeed");

        match rx.try_recv().expect("should receive event") {
            ProxyEvent::EntryRemoved { name } => assert_eq!(name, "rm-svc"),
            other => panic!("expected EntryRemoved, got {other:?}"),
        }
    }

    /// Two subscribers to the same core each receive a core-emitted event.
    #[tokio::test]
    async fn multiple_subscribers_each_receive_core_event() {
        let core = test_core();
        let mut rx1 = core.subscribe();
        let mut rx2 = core.subscribe();

        core.upsert(sample_entry("multi"))
            .await
            .expect("upsert should succeed");

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }
}
