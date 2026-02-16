//! UDP datagram bridging over HTTP/SSE.
//!
//! Containers cannot bind host UDP sockets directly. This crate exposes a
//! lease-based HTTP API that lets a containerised process:
//!
//! 1. **Bind** a host UDP port (creating a `UdpBinding`).
//! 2. **Receive** datagrams via an SSE stream (`GET /v1/udp/recv/{id}`).
//! 3. **Send** datagrams through the bound socket (`POST /v1/udp/send/{id}`).
//! 4. **Heartbeat** to extend the lease (`POST /v1/udp/heartbeat/{id}`).
//!
//! Bindings expire after `lease_secs` without a heartbeat, at which point the
//! reaper closes the socket. This prevents resource leaks if a container dies.
//!
//! Follows the same Core/Runtime pattern as `koi-health` and `koi-dns`.

mod binding;
pub mod http;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub use binding::ActiveBinding;

// ── Public types ────────────────────────────────────────────────────

/// A datagram received on a bound socket, ready to be relayed over SSE.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UdpDatagram {
    pub binding_id: String,
    pub src: String,
    /// Base64-encoded payload.
    pub payload: String,
    pub received_at: DateTime<Utc>,
}

/// Request to send a datagram through a bound socket.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UdpSendRequest {
    /// Destination address in `host:port` form.
    pub dest: String,
    /// Base64-encoded payload.
    pub payload: String,
}

/// Request body for creating a new binding.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UdpBindRequest {
    /// Port to bind on the host (0 = OS-assigned).
    #[serde(default)]
    pub port: u16,
    /// Bind address. Default `0.0.0.0`.
    #[serde(default = "default_bind_addr")]
    pub addr: String,
    /// Lease duration in seconds. Default 300.
    #[serde(default = "default_lease")]
    pub lease_secs: u64,
}

fn default_bind_addr() -> String {
    "0.0.0.0".to_string()
}

fn default_lease() -> u64 {
    300
}

/// Metadata for a live binding (returned by status endpoint).
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct BindingInfo {
    pub id: String,
    pub local_addr: String,
    pub created_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
    pub lease_secs: u64,
}

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum UdpError {
    #[error("binding not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid address: {0}")]
    InvalidAddr(String),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

// ── UdpRuntime ──────────────────────────────────────────────────────

/// Manages UDP socket bindings, datagram relay, and lease reaping.
pub struct UdpRuntime {
    bindings: Arc<RwLock<HashMap<String, ActiveBinding>>>,
    cancel: CancellationToken,
    reaper_handle: Option<tokio::task::JoinHandle<()>>,
}

impl UdpRuntime {
    /// Create a new runtime. Spawns a lease reaper task.
    pub fn new(cancel: CancellationToken) -> Self {
        let bindings: Arc<RwLock<HashMap<String, ActiveBinding>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let reaper_bindings = bindings.clone();
        let reaper_cancel = cancel.clone();
        let reaper_handle = tokio::spawn(async move {
            Self::reaper_loop(reaper_bindings, reaper_cancel).await;
        });

        Self {
            bindings,
            cancel,
            reaper_handle: Some(reaper_handle),
        }
    }

    /// Create a new UDP binding. Binds a socket and starts a relay task.
    pub async fn bind(&self, req: UdpBindRequest) -> Result<BindingInfo, UdpError> {
        let bind_addr: SocketAddr = format!("{}:{}", req.addr, req.port)
            .parse()
            .map_err(|e| UdpError::InvalidAddr(format!("{}", e)))?;

        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let id = Uuid::now_v7().to_string();
        let now = Utc::now();

        let active = ActiveBinding::new(
            id.clone(),
            socket,
            local_addr,
            now,
            req.lease_secs,
            self.cancel.clone(),
        );

        let info = BindingInfo {
            id: id.clone(),
            local_addr: local_addr.to_string(),
            created_at: now,
            last_heartbeat: now,
            lease_secs: req.lease_secs,
        };

        self.bindings.write().await.insert(id, active);

        tracing::info!(binding = %info.id, addr = %info.local_addr, "UDP binding created");
        Ok(info)
    }

    /// Remove a binding and close its socket.
    pub async fn unbind(&self, id: &str) -> Result<(), UdpError> {
        let binding = self
            .bindings
            .write()
            .await
            .remove(id)
            .ok_or_else(|| UdpError::NotFound(id.to_string()))?;

        binding.shutdown();
        tracing::info!(binding = %id, "UDP binding removed");
        Ok(())
    }

    /// Subscribe to incoming datagrams for a binding.
    pub async fn subscribe(
        &self,
        id: &str,
    ) -> Result<broadcast::Receiver<UdpDatagram>, UdpError> {
        let bindings = self.bindings.read().await;
        let binding = bindings
            .get(id)
            .ok_or_else(|| UdpError::NotFound(id.to_string()))?;
        Ok(binding.subscribe())
    }

    /// Send a datagram through a binding's socket.
    pub async fn send(&self, id: &str, req: UdpSendRequest) -> Result<usize, UdpError> {
        use base64::Engine;

        let dest: SocketAddr = req
            .dest
            .parse()
            .map_err(|e| UdpError::InvalidAddr(format!("{}", e)))?;

        let payload = base64::engine::general_purpose::STANDARD.decode(&req.payload)?;

        let bindings = self.bindings.read().await;
        let binding = bindings
            .get(id)
            .ok_or_else(|| UdpError::NotFound(id.to_string()))?;

        let sent = binding.send_to(&payload, dest).await?;
        Ok(sent)
    }

    /// Extend a binding's lease.
    pub async fn heartbeat(&self, id: &str) -> Result<(), UdpError> {
        let bindings = self.bindings.read().await;
        let binding = bindings
            .get(id)
            .ok_or_else(|| UdpError::NotFound(id.to_string()))?;
        binding.touch();
        Ok(())
    }

    /// List all active bindings.
    pub async fn status(&self) -> Vec<BindingInfo> {
        let bindings = self.bindings.read().await;
        bindings
            .values()
            .map(|b| BindingInfo {
                id: b.id().to_string(),
                local_addr: b.local_addr().to_string(),
                created_at: b.created_at(),
                last_heartbeat: b.last_heartbeat(),
                lease_secs: b.lease_secs(),
            })
            .collect()
    }

    /// Shared bindings ref (for HTTP layer).
    pub(crate) fn bindings(&self) -> &Arc<RwLock<HashMap<String, ActiveBinding>>> {
        &self.bindings
    }

    /// Background task that reaps expired leases every 30 seconds.
    async fn reaper_loop(
        bindings: Arc<RwLock<HashMap<String, ActiveBinding>>>,
        cancel: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    let now = Utc::now();
                    let mut map = bindings.write().await;
                    let expired: Vec<String> = map
                        .iter()
                        .filter(|(_, b)| {
                            let elapsed = now
                                .signed_duration_since(b.last_heartbeat())
                                .num_seconds();
                            elapsed > b.lease_secs() as i64
                        })
                        .map(|(id, _)| id.clone())
                        .collect();

                    for id in expired {
                        if let Some(binding) = map.remove(&id) {
                            binding.shutdown();
                            tracing::info!(binding = %id, "Reaped expired UDP binding");
                        }
                    }
                }
            }
        }
    }

    /// Shut down the runtime — cancel reaper + close all bindings.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.reaper_handle.take() {
            let _ = handle.await;
        }
        let mut map = self.bindings.write().await;
        for (_, binding) in map.drain() {
            binding.shutdown();
        }
        tracing::debug!("UDP runtime shut down");
    }
}
