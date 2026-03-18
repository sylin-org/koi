//! Adapts `MdnsCore` to `koi_common::browser::BrowseSource` for
//! the embedded runtime.

use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};

use koi_common::browser::{BrowseError, BrowseHandle, BrowseSource, BrowserEvent};
use koi_mdns::{MdnsCore, MdnsEvent};

pub(crate) struct MdnsBrowseAdapter {
    core: Arc<MdnsCore>,
    event_tx: broadcast::Sender<BrowserEvent>,
}

impl MdnsBrowseAdapter {
    pub(crate) fn new(
        core: Arc<MdnsCore>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(256);
        let adapter = Arc::new(Self {
            core,
            event_tx: event_tx.clone(),
        });

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
                .browse(&svc_type)
                .await
                .map_err(|e| BrowseError(e.to_string()))?;

            let (tx, rx) = mpsc::channel(128);

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
