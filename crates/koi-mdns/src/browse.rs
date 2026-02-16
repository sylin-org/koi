use std::sync::Arc;

use koi_common::types::ServiceRecord;
use mdns_sd::ServiceEvent as MdnsEvent;
use tokio::sync::broadcast;

use crate::daemon::{self, MdnsDaemon};
use crate::events::MdnsEvent as KoiEvent;

/// Handle for an active browse operation.
///
/// Owns the lifecycle of a single `stop_browse` call on the daemon.
/// When dropped, the browse is stopped automatically - no leaked
/// subscriptions in the mdns-sd engine.
pub struct BrowseHandle {
    receiver: mdns_sd::Receiver<MdnsEvent>,
    event_tx: broadcast::Sender<KoiEvent>,
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
    pub(crate) fn new(
        receiver: mdns_sd::Receiver<MdnsEvent>,
        event_tx: broadcast::Sender<KoiEvent>,
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
    pub async fn recv(&self) -> Option<KoiEvent> {
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
                                let record = ServiceRecord {
                                    name: type_name,
                                    service_type: String::new(),
                                    host: None,
                                    ip: None,
                                    port: None,
                                    txt: Default::default(),
                                };
                                let event = KoiEvent::Found(record);
                                let _ = self.event_tx.send(event.clone());
                                event
                            } else {
                                tracing::debug!(fullname, "Service found (pending resolution)");
                                continue;
                            }
                        }
                        MdnsEvent::ServiceResolved(resolved) => {
                            let record = daemon::resolved_to_record(&resolved);
                            let event = KoiEvent::Resolved(record);
                            let _ = self.event_tx.send(event.clone());
                            event
                        }
                        MdnsEvent::ServiceRemoved(_, fullname) => {
                            let event = KoiEvent::Removed {
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
