//! Browse abstraction for the mDNS browser.
//!
//! [`BrowseSource`] decouples the browser cache/worker from any concrete mDNS
//! implementation; [`MdnsBrowseAdapter`] is the single adapter wrapping
//! `koi_mdns::MdnsCore` (it replaces the byte-identical copies that previously lived in
//! the binary crate and in koi-embedded). Only Koi types cross this boundary — no
//! `mdns_sd` types escape (they never reach this crate; `MdnsCore` already isolates
//! them per the P05 boundary).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};

use koi_mdns::{MdnsCore, MdnsEvent};

/// A resolved service instance (domain-agnostic mirror of
/// `koi_common::types::ServiceRecord` with guaranteed non-optional fields for the
/// browser cache).
#[derive(Clone, Debug, serde::Serialize)]
pub struct ResolvedService {
    pub name: String,
    pub service_type: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub txt: HashMap<String, String>,
}

impl From<&koi_common::types::ServiceRecord> for ResolvedService {
    fn from(record: &koi_common::types::ServiceRecord) -> Self {
        Self {
            name: record.name.clone(),
            service_type: record.service_type.clone(),
            host: record.host.clone().unwrap_or_default(),
            ip: record.ip.clone().unwrap_or_default(),
            port: record.port.unwrap_or(0),
            txt: record.txt.clone(),
        }
    }
}

/// Domain-agnostic browser event.
#[derive(Clone, Debug)]
pub enum BrowserEvent {
    Found { name: String, service_type: String },
    Resolved(ResolvedService),
    Removed { name: String, service_type: String },
}

/// Error returned by [`BrowseSource::browse`].
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BrowseError(pub String);

/// Handle for receiving events from a single browse operation.
pub struct BrowseHandle {
    rx: mpsc::Receiver<BrowserEvent>,
}

impl BrowseHandle {
    /// Create a new handle from an mpsc receiver.
    pub fn new(rx: mpsc::Receiver<BrowserEvent>) -> Self {
        Self { rx }
    }

    /// Receive the next event, or `None` if the browse stopped.
    pub async fn recv(&mut self) -> Option<BrowserEvent> {
        self.rx.recv().await
    }
}

/// Trait abstracting mDNS browse operations. Implemented by [`MdnsBrowseAdapter`]; a
/// test double can implement it without real multicast.
pub trait BrowseSource: Send + Sync {
    /// Start browsing for the given service type. Returns a handle yielding events.
    fn browse(
        &self,
        service_type: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BrowseHandle, BrowseError>> + Send + '_>,
    >;

    /// Subscribe to the global event broadcast channel.
    fn subscribe(&self) -> broadcast::Receiver<BrowserEvent>;
}

// ── MdnsCore adapter ────────────────────────────────────────────────

/// Adapts `MdnsCore` to [`BrowseSource`]. The single source of truth — both the daemon
/// and koi-embedded use this instead of keeping their own copies.
pub struct MdnsBrowseAdapter {
    core: Arc<MdnsCore>,
    /// Relay sender for the global subscribe channel.
    event_tx: broadcast::Sender<BrowserEvent>,
}

impl MdnsBrowseAdapter {
    /// Create a new adapter wrapping the given `MdnsCore`.
    ///
    /// Spawns a background relay task that converts `MdnsEvent` → `BrowserEvent` on the
    /// global broadcast channel.
    pub fn new(core: Arc<MdnsCore>, cancel: tokio_util::sync::CancellationToken) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(256);
        let adapter = Arc::new(Self {
            core,
            event_tx: event_tx.clone(),
        });

        // Relay MdnsCore's broadcast → BrowserEvent broadcast.
        let mut rx = adapter.core.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = rx.recv() => {
                        match result {
                            Ok(mdns_event) => {
                                if let Some(browser_event) = map_mdns_event(&mdns_event) {
                                    let _ = event_tx.send(browser_event);
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        });

        adapter
    }
}

impl BrowseSource for MdnsBrowseAdapter {
    fn browse(
        &self,
        service_type: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BrowseHandle, BrowseError>> + Send + '_>,
    > {
        let svc_type = service_type.to_string();
        Box::pin(async move {
            let mdns_handle = self
                .core
                .subscribe_type(&svc_type)
                .await
                .map_err(|e| BrowseError(e.to_string()))?;

            let (tx, rx) = mpsc::channel(128);

            // Relay events from the koi-mdns BrowseSubscription into the BrowseHandle's
            // mpsc channel. Dropping the BrowseHandle (rx) breaks `tx.send`, which drops
            // `mdns_handle` and stops the underlying browse (P05 refcount).
            tokio::spawn(async move {
                while let Some(mdns_event) = mdns_handle.recv().await {
                    if let Some(browser_event) = map_mdns_event(&mdns_event) {
                        if tx.send(browser_event).await.is_err() {
                            break;
                        }
                    }
                }
            });

            Ok(BrowseHandle::new(rx))
        })
    }

    fn subscribe(&self) -> broadcast::Receiver<BrowserEvent> {
        self.event_tx.subscribe()
    }
}

/// Convert an `MdnsEvent` to a `BrowserEvent`.
fn map_mdns_event(event: &MdnsEvent) -> Option<BrowserEvent> {
    match event {
        MdnsEvent::Found(record) => Some(BrowserEvent::Found {
            name: record.name.clone(),
            service_type: record.service_type.clone(),
        }),
        MdnsEvent::Resolved(record) => Some(BrowserEvent::Resolved(record.into())),
        MdnsEvent::Removed { name, service_type } => Some(BrowserEvent::Removed {
            name: name.clone(),
            service_type: service_type.clone(),
        }),
    }
}
