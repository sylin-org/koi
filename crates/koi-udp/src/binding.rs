//! Active UDP binding — wraps a socket, relay task, and heartbeat state.

use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;

use crate::UdpDatagram;

/// An active UDP binding — owns the socket and a relay task that broadcasts
/// received datagrams to subscribers.
pub struct ActiveBinding {
    id: String,
    local_addr: SocketAddr,
    created_at: DateTime<Utc>,
    lease_secs: u64,
    last_heartbeat: Arc<RwLock<DateTime<Utc>>>,
    tx: broadcast::Sender<UdpDatagram>,
    /// Shared socket for sends (recv is driven by the relay task).
    socket: Arc<UdpSocket>,
    /// Cancels the relay task on shutdown/unbind.
    binding_cancel: CancellationToken,
    relay_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ActiveBinding {
    pub(crate) fn new(
        id: String,
        socket: UdpSocket,
        local_addr: SocketAddr,
        created_at: DateTime<Utc>,
        lease_secs: u64,
        parent_cancel: CancellationToken,
    ) -> Self {
        let (tx, _) = broadcast::channel(512);
        let socket = Arc::new(socket);
        let binding_cancel = parent_cancel.child_token();

        // Spawn relay task: socket → broadcast channel.
        let relay_socket = socket.clone();
        let relay_tx = tx.clone();
        let relay_cancel = binding_cancel.clone();
        let relay_id = id.clone();

        let relay_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    _ = relay_cancel.cancelled() => break,
                    result = relay_socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                use base64::Engine;

                                let datagram = UdpDatagram {
                                    binding_id: relay_id.clone(),
                                    src: src.to_string(),
                                    payload: base64::engine::general_purpose::STANDARD
                                        .encode(&buf[..len]),
                                    received_at: Utc::now(),
                                };

                                // Ignore send errors — means no subscribers
                                let _ = relay_tx.send(datagram);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    binding = %relay_id,
                                    error = %e,
                                    "UDP recv error"
                                );
                                // transient error — keep going
                            }
                        }
                    }
                }
            }
            tracing::debug!(binding = %relay_id, "UDP relay task stopped");
        });

        Self {
            id,
            local_addr,
            created_at,
            lease_secs,
            last_heartbeat: Arc::new(RwLock::new(created_at)),
            tx,
            socket,
            binding_cancel,
            relay_handle: Some(relay_handle),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn lease_secs(&self) -> u64 {
        self.lease_secs
    }

    pub fn last_heartbeat(&self) -> DateTime<Utc> {
        // Use try_read to avoid blocking the reaper — if contended, use created_at as fallback
        match self.last_heartbeat.try_read() {
            Ok(guard) => *guard,
            Err(_) => self.created_at,
        }
    }

    /// Update the heartbeat timestamp (extends the lease).
    pub fn touch(&self) {
        if let Ok(mut guard) = self.last_heartbeat.try_write() {
            *guard = Utc::now();
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<UdpDatagram> {
        self.tx.subscribe()
    }

    /// Send a datagram through this binding's socket.
    pub async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> Result<usize, std::io::Error> {
        self.socket.send_to(buf, dest).await
    }

    /// Cancel the relay task and drop the socket.
    pub fn shutdown(mut self) {
        self.binding_cancel.cancel();
        // JoinHandle will be dropped, task is already cancelled
        self.relay_handle.take();
    }
}
