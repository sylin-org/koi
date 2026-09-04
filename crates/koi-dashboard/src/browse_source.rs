//! Browse abstraction for the mDNS browser.
//!
//! [`BrowseSource`] decouples the browser cache/worker from any concrete mDNS
//! implementation; [`MdnsBrowseAdapter`] is the single adapter wrapping
//! `koi_mdns::MdnsCore` (it replaces the byte-identical copies that previously lived in
//! the binary crate and in koi-embedded). Only Koi types cross this boundary — no
//! `mdns_sd` types escape (they never reach this crate; `MdnsCore` already isolates
//! them per the P05 boundary).

use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_common::integration::MdnsDiscoverySnapshot;
use koi_common::types::ServiceRecord;
use koi_mdns::{BrowseRecvError, BrowseSubscription, MdnsCore, MdnsEvent};

/// Presentation notification carrying the mDNS domain's service record unchanged.
#[derive(Clone, Debug)]
pub enum BrowserEvent {
    Found(ServiceRecord),
    Resolved(ServiceRecord),
    Removed {
        name: String,
        service_type: String,
    },
    /// One or more best-effort events were lost. Consumers must reread
    /// [`BrowseSource::snapshot`] rather than guessing the missing transitions.
    Resync,
}

/// Error returned by [`BrowseSource::browse`].
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BrowseError(pub String);

/// Handle for receiving events from a single browse operation.
pub struct BrowseHandle {
    receiver: BrowseReceiver,
}

enum BrowseReceiver {
    Channel(mpsc::Receiver<BrowserEvent>),
    // The subscription itself owns mDNS's refcount guard. Keeping it in the
    // handle makes drop the synchronous demand-release boundary; no relay task
    // can outlive the presentation owner while retaining a provider browse.
    Domain(BrowseSubscription),
}

impl BrowseHandle {
    /// Create a new handle from an mpsc receiver.
    pub fn new(rx: mpsc::Receiver<BrowserEvent>) -> Self {
        Self {
            receiver: BrowseReceiver::Channel(rx),
        }
    }

    fn from_domain(subscription: BrowseSubscription) -> Self {
        Self {
            receiver: BrowseReceiver::Domain(subscription),
        }
    }

    /// Receive the next event, or `None` if the browse stopped.
    pub async fn recv(&mut self) -> Option<BrowserEvent> {
        match &mut self.receiver {
            BrowseReceiver::Channel(rx) => rx.recv().await,
            BrowseReceiver::Domain(subscription) => match subscription.recv().await {
                Ok(event) => Some(map_mdns_event(&event)),
                Err(BrowseRecvError::Lagged { dropped }) => {
                    tracing::warn!(
                        dropped,
                        "Dashboard browse handle lagged; requesting snapshot resync"
                    );
                    Some(BrowserEvent::Resync)
                }
                Err(BrowseRecvError::Closed) => None,
            },
        }
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

    /// Subscribe to this adapter instance's event broadcast channel.
    fn subscribe(&self) -> broadcast::Receiver<BrowserEvent>;

    /// Return the mDNS domain's current immutable discovery projection.
    fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot>;

    /// Observe the current discovery projection and future coalesced changes.
    fn watch_snapshot(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>>;
}

// ── MdnsCore adapter ────────────────────────────────────────────────

/// Adapts `MdnsCore` to [`BrowseSource`]. The single source of truth — both the daemon
/// and koi-embedded use this instead of keeping their own copies.
pub struct MdnsBrowseAdapter {
    core: Arc<MdnsCore>,
    /// Relay sender for the adapter-wide subscribe channel.
    event_tx: broadcast::Sender<BrowserEvent>,
    relay_cancel: CancellationToken,
    relay_task: Mutex<Option<JoinHandle<()>>>,
}

impl MdnsBrowseAdapter {
    /// Create a new adapter wrapping the given `MdnsCore`.
    ///
    /// Spawns a background relay task that converts `MdnsEvent` → `BrowserEvent` on the
    /// adapter-wide broadcast channel.
    pub fn new(core: Arc<MdnsCore>, cancel: tokio_util::sync::CancellationToken) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(256);
        // Relay MdnsCore's broadcast → BrowserEvent broadcast.
        let mut rx = core.subscribe();
        let relay_cancel = cancel.child_token();
        let relay_shutdown = relay_cancel.clone();
        let relay_events = event_tx.clone();
        let relay_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = relay_shutdown.cancelled() => break,
                    event = recv_mapped_event(&mut rx) => {
                        match event {
                            Some(event) => {
                                let _ = relay_events.send(event);
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        Arc::new(Self {
            core,
            event_tx,
            relay_cancel,
            relay_task: Mutex::new(Some(relay_task)),
        })
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
            let subscription = self
                .core
                .subscribe_type(&svc_type)
                .await
                .map_err(|e| BrowseError(e.to_string()))?;
            Ok(BrowseHandle::from_domain(subscription))
        })
    }

    fn subscribe(&self) -> broadcast::Receiver<BrowserEvent> {
        self.event_tx.subscribe()
    }

    fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot> {
        self.core.discovery_snapshot()
    }

    fn watch_snapshot(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>> {
        self.core.watch_discovery()
    }
}

impl Drop for MdnsBrowseAdapter {
    fn drop(&mut self) {
        self.relay_cancel.cancel();
        if let Some(task) = self
            .relay_task
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

async fn recv_mapped_event(rx: &mut broadcast::Receiver<MdnsEvent>) -> Option<BrowserEvent> {
    match rx.recv().await {
        Ok(event) => Some(map_mdns_event(&event)),
        Err(broadcast::error::RecvError::Lagged(dropped)) => {
            tracing::warn!(
                dropped,
                "Dashboard event relay lagged; requesting snapshot resync"
            );
            Some(BrowserEvent::Resync)
        }
        Err(broadcast::error::RecvError::Closed) => None,
    }
}

/// Convert an `MdnsEvent` to a `BrowserEvent`.
fn map_mdns_event(event: &MdnsEvent) -> BrowserEvent {
    match event {
        MdnsEvent::Found(record) => BrowserEvent::Found(record.clone()),
        MdnsEvent::Resolved(record) => BrowserEvent::Resolved(record.clone()),
        MdnsEvent::Removed { name, service_type } => BrowserEvent::Removed {
            name: name.clone(),
            service_type: service_type.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upstream_event_lag_becomes_an_explicit_resync() {
        let (tx, mut rx) = broadcast::channel(1);
        let event = |name: &str| MdnsEvent::Removed {
            name: name.to_string(),
            service_type: "_http._tcp.local.".to_string(),
        };

        tx.send(event("first")).unwrap();
        tx.send(event("second")).unwrap();

        assert!(matches!(
            recv_mapped_event(&mut rx).await,
            Some(BrowserEvent::Resync)
        ));
    }

    #[test]
    fn resolved_event_preserves_the_domain_record_and_its_wire_shape() {
        let expected = ServiceRecord {
            name: "partial".to_string(),
            service_type: "_http._tcp.local.".to_string(),
            host: None,
            ip: Some("192.0.2.8".to_string()),
            port: None,
            txt: Default::default(),
        };

        let BrowserEvent::Resolved(actual) = map_mdns_event(&MdnsEvent::Resolved(expected.clone()))
        else {
            panic!("resolved mDNS fact changed event kind");
        };
        assert_eq!(actual, expected);
        let wire = serde_json::to_value(actual).expect("service record JSON");
        assert_eq!(wire["type"], "_http._tcp.local.");
        assert!(wire.get("service_type").is_none());
        assert!(wire.get("host").is_none());
        assert!(wire.get("port").is_none());
    }

    #[test]
    fn dropping_channel_browse_handle_releases_source_demand() {
        let (tx, rx) = mpsc::channel(1);
        let handle = BrowseHandle::new(rx);
        assert!(!tx.is_closed());
        drop(handle);
        assert!(tx.is_closed());
    }
}
