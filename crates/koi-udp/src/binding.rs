//! Active UDP binding - wraps a socket, relay task, and heartbeat state.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::net::UdpSocket;
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::UdpDatagram;

/// Bound command queue prevents HTTP senders from consuming unbounded memory
/// when the OS socket is backpressured.
const SEND_QUEUE_CAPACITY: usize = 64;

struct LeaseState {
    wire_heartbeat: DateTime<Utc>,
    deadline: Instant,
}

impl LeaseState {
    fn new(wire_heartbeat: DateTime<Utc>, observed: Instant, lease_secs: u64) -> Self {
        Self {
            wire_heartbeat,
            deadline: observed + Duration::from_secs(lease_secs),
        }
    }

    fn touch(
        &mut self,
        observed_wall: DateTime<Utc>,
        observed_monotonic: Instant,
        lease_secs: u64,
    ) -> DateTime<Utc> {
        self.wire_heartbeat = if observed_wall > self.wire_heartbeat {
            observed_wall
        } else {
            self.wire_heartbeat + chrono::TimeDelta::nanoseconds(1)
        };
        self.deadline = observed_monotonic + Duration::from_secs(lease_secs);
        self.wire_heartbeat
    }

    fn is_expired_at(&self, now: Instant) -> bool {
        now >= self.deadline
    }
}

struct SendCommand {
    payload: Vec<u8>,
    dest: SocketAddr,
    reply: oneshot::Sender<std::io::Result<usize>>,
}

/// Cloneable command port for the relay that exclusively owns the socket.
#[derive(Clone)]
pub(crate) struct BindingSender {
    tx: mpsc::Sender<SendCommand>,
}

impl BindingSender {
    pub(crate) async fn send_to(
        &self,
        payload: Vec<u8>,
        dest: SocketAddr,
    ) -> std::io::Result<usize> {
        let (reply, response) = oneshot::channel();
        self.tx
            .send(SendCommand {
                payload,
                dest,
                reply,
            })
            .await
            .map_err(|_| relay_closed())?;
        response.await.map_err(|_| relay_closed())?
    }
}

fn relay_closed() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "UDP binding is closed")
}

/// An active UDP binding - owns the socket and a relay task that broadcasts
/// received datagrams to subscribers.
pub(crate) struct ActiveBinding {
    id: String,
    lease_secs: u64,
    /// Whether this binding may send to / be bound on non-loopback addresses.
    /// Opt-in at bind time; default false keeps a binding loopback-only so a DAT
    /// holder cannot use it as a LAN/internet egress relay (SSRF).
    allow_remote: bool,
    lease: Arc<RwLock<LeaseState>>,
    tx: broadcast::Sender<UdpDatagram>,
    /// The relay is the socket's sole owner; senders submit acknowledged work.
    send_tx: mpsc::Sender<SendCommand>,
    /// Cancels the relay task on shutdown/unbind.
    binding_cancel: CancellationToken,
    relay_handle: Option<tokio::task::JoinHandle<()>>,
    /// Deterministic cancellation point for ownership tests. Production close
    /// has no synthetic pause or alternate resource path.
    #[cfg(test)]
    close_gate: Option<(Arc<Notify>, Arc<Notify>)>,
}

impl ActiveBinding {
    pub(crate) fn new(
        id: String,
        socket: UdpSocket,
        created_at: DateTime<Utc>,
        lease_secs: u64,
        allow_remote: bool,
        parent_cancel: CancellationToken,
    ) -> Self {
        let (tx, _) = broadcast::channel(512);
        let (send_tx, mut send_rx) = mpsc::channel::<SendCommand>(SEND_QUEUE_CAPACITY);
        let binding_cancel = parent_cancel.child_token();

        // The relay owns the socket. Once this task has joined there are no
        // hidden Arc clones capable of retaining the native binding.
        let relay_tx = tx.clone();
        let relay_cancel = binding_cancel.clone();
        let relay_id = id.clone();

        let relay_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    biased;
                    _ = relay_cancel.cancelled() => break,
                    command = send_rx.recv() => {
                        let Some(command) = command else { break; };
                        let result = tokio::select! {
                            biased;
                            _ = relay_cancel.cancelled() => break,
                            result = socket.send_to(&command.payload, command.dest) => result,
                        };
                        let _ = command.reply.send(result);
                    }
                    result = socket.recv_from(&mut buf) => {
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

                                // Ignore send errors - means no subscribers
                                let _ = relay_tx.send(datagram);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    binding = %relay_id,
                                    error = %e,
                                    "UDP recv error"
                                );
                                // transient error - keep going
                            }
                        }
                    }
                }
            }
            tracing::debug!(binding = %relay_id, "UDP relay task stopped");
        });

        Self {
            id,
            lease_secs,
            allow_remote,
            lease: Arc::new(RwLock::new(LeaseState::new(
                created_at,
                Instant::now(),
                lease_secs,
            ))),
            tx,
            send_tx,
            binding_cancel,
            relay_handle: Some(relay_handle),
            #[cfg(test)]
            close_gate: None,
        }
    }

    /// Whether this binding may send to / listen on non-loopback addresses.
    pub(crate) fn allow_remote(&self) -> bool {
        self.allow_remote
    }

    /// Update the display timestamp and extend the real lease against a
    /// monotonic clock, so wall-clock adjustments cannot reap or prolong it.
    pub(crate) fn touch(&self) -> DateTime<Utc> {
        let mut guard = match self.lease.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.touch(Utc::now(), Instant::now(), self.lease_secs)
    }

    pub(crate) fn is_expired_at(&self, now: Instant) -> bool {
        match self.lease.read() {
            Ok(guard) => guard.is_expired_at(now),
            Err(poisoned) => poisoned.into_inner().is_expired_at(now),
        }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<UdpDatagram> {
        self.tx.subscribe()
    }

    pub(crate) fn sender(&self) -> BindingSender {
        BindingSender {
            tx: self.send_tx.clone(),
        }
    }

    /// Cancel and join the task that exclusively owns the socket.
    pub(crate) async fn close(&mut self) {
        self.binding_cancel.cancel();
        #[cfg(test)]
        if let Some((entered, release)) = &self.close_gate {
            entered.notify_one();
            release.notified().await;
        }
        // Borrow the handle in place. If this close future is cancelled, Drop
        // still owns and aborts it instead of turning cancellation into detach.
        if let Some(relay_handle) = self.relay_handle.as_mut() {
            if let Err(error) = (&mut *relay_handle).await {
                tracing::warn!(binding = %self.id, %error, "UDP relay task failed during close");
            }
        }
        self.relay_handle.take();
    }

    #[cfg(test)]
    pub(crate) fn gate_close(&mut self, entered: Arc<Notify>, release: Arc<Notify>) {
        self.close_gate = Some((entered, release));
    }
}

impl Drop for ActiveBinding {
    fn drop(&mut self) {
        // Explicit close awaits this cancellation. The Drop fallback prevents
        // an unwinding or abandoned owner from leaving the relay/socket alive.
        self.binding_cancel.cancel();
        if let Some(relay_handle) = self.relay_handle.as_ref() {
            relay_handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_expiry_uses_monotonic_deadline_when_wall_clock_moves_back() {
        let wall = Utc::now();
        let monotonic = Instant::now();
        let mut lease = LeaseState::new(wall, monotonic, 30);

        assert!(!lease.is_expired_at(monotonic + Duration::from_secs(29)));
        assert!(lease.is_expired_at(monotonic + Duration::from_secs(30)));

        let wire = lease.touch(
            wall - chrono::TimeDelta::days(1),
            monotonic + Duration::from_secs(20),
            30,
        );
        assert!(wire > wall, "wire timestamp remains monotonically useful");
        assert!(!lease.is_expired_at(monotonic + Duration::from_secs(49)));
        assert!(lease.is_expired_at(monotonic + Duration::from_secs(50)));
    }
}
