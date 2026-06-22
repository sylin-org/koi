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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct UdpDatagram {
    pub binding_id: String,
    pub src: String,
    /// Base64-encoded payload.
    pub payload: String,
    pub received_at: DateTime<Utc>,
}

/// Request to send a datagram through a bound socket.
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
pub struct UdpSendRequest {
    /// Destination address in `host:port` form.
    pub dest: String,
    /// Base64-encoded payload.
    pub payload: String,
}

/// Request body for creating a new binding.
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
pub struct UdpBindRequest {
    /// Port to bind on the host (0 = OS-assigned).
    #[serde(default)]
    pub port: u16,
    /// Bind address. Default `127.0.0.1` (loopback); a non-loopback bind requires
    /// `allow_remote = true`.
    #[serde(default = "default_bind_addr")]
    pub addr: String,
    /// Lease duration in seconds. Default 300.
    #[serde(default = "default_lease")]
    pub lease_secs: u64,
    /// Allow binding on / sending to non-loopback addresses. Default `false` keeps
    /// the binding loopback-only so a daemon-token holder cannot turn it into a
    /// LAN/internet egress relay (the host's source address would launder the
    /// traffic — SSRF) or expose an ingest socket to the whole LAN. Opt in only
    /// for genuine cross-host datagram bridging.
    #[serde(default)]
    pub allow_remote: bool,
}

fn default_bind_addr() -> String {
    "127.0.0.1".to_string()
}

/// Validate a datagram destination before egress. Always rejects the unspecified
/// address, multicast, and the IPv4 broadcast address; rejects any non-loopback
/// destination unless the binding opted into `allow_remote`. This stops a token
/// holder from using a binding as an SSRF/egress relay with the host's identity.
fn validate_dest(dest: SocketAddr, allow_remote: bool) -> Result<(), UdpError> {
    let ip = dest.ip();
    let disallowed = ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast());
    if disallowed {
        return Err(UdpError::InvalidAddr(format!(
            "disallowed UDP destination {dest}"
        )));
    }
    if !allow_remote && !ip.is_loopback() {
        return Err(UdpError::InvalidAddr(format!(
            "non-loopback destination {dest} requires allow_remote=true on the binding"
        )));
    }
    Ok(())
}

fn default_lease() -> u64 {
    300
}

/// Maximum lease duration (24 hours) to prevent unbounded resource retention.
const MAX_LEASE_SECS: u64 = 86400;

/// Metadata for a live binding (returned by status endpoint).
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct BindingInfo {
    pub id: String,
    pub local_addr: String,
    pub created_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
    pub lease_secs: u64,
    /// Whether this binding may send to / listen on non-loopback addresses.
    pub allow_remote: bool,
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
    _reaper_handle: tokio::task::JoinHandle<()>,
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
            _reaper_handle: reaper_handle,
        }
    }

    /// Create a new UDP binding. Binds a socket and starts a relay task.
    pub async fn bind(&self, req: UdpBindRequest) -> Result<BindingInfo, UdpError> {
        let bind_addr: SocketAddr = format!("{}:{}", req.addr, req.port)
            .parse()
            .map_err(|e| UdpError::InvalidAddr(format!("{}", e)))?;

        // Secure-by-default: a non-loopback bind exposes an ingest socket to the
        // whole LAN, so it requires an explicit allow_remote opt-in.
        if !req.allow_remote && !bind_addr.ip().is_loopback() {
            return Err(UdpError::InvalidAddr(format!(
                "non-loopback bind {bind_addr} requires allow_remote=true"
            )));
        }

        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let id = Uuid::now_v7().to_string();
        let now = Utc::now();

        let lease_secs = req.lease_secs.min(MAX_LEASE_SECS);

        let active = ActiveBinding::new(
            id.clone(),
            socket,
            local_addr,
            now,
            lease_secs,
            req.allow_remote,
            self.cancel.clone(),
        );

        let info = BindingInfo {
            id: id.clone(),
            local_addr: local_addr.to_string(),
            created_at: now,
            last_heartbeat: now,
            lease_secs,
            allow_remote: req.allow_remote,
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
    pub async fn subscribe(&self, id: &str) -> Result<broadcast::Receiver<UdpDatagram>, UdpError> {
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

        validate_dest(dest, binding.allow_remote())?;

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
                allow_remote: b.allow_remote(),
            })
            .collect()
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

    /// Shut down the runtime - cancel reaper + close all bindings.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let mut map = self.bindings.write().await;
        for (_, binding) in map.drain() {
            binding.shutdown();
        }
        tracing::debug!("UDP runtime shut down");
    }
}

// ── Capability trait ────────────────────────────────────────────────

#[async_trait::async_trait]
impl koi_common::capability::Capability for UdpRuntime {
    fn name(&self) -> &str {
        "udp"
    }

    async fn status(&self) -> koi_common::capability::CapabilityStatus {
        // UdpRuntime also has an inherent (non-trait) `status()` returning Vec<BindingInfo>;
        // this trait impl summarises the binding count. Read the lock directly now that the
        // trait is async (the old try_read fallback is gone).
        let count = self.bindings.read().await.len();

        let summary = if count == 0 {
            "no bindings".to_string()
        } else {
            format!("{count} binding{}", if count == 1 { "" } else { "s" })
        };

        koi_common::capability::CapabilityStatus {
            name: "udp".to_string(),
            summary,
            healthy: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_dest_allows_loopback_by_default() {
        assert!(validate_dest("127.0.0.1:9999".parse().unwrap(), false).is_ok());
        assert!(validate_dest("[::1]:9999".parse().unwrap(), false).is_ok());
    }

    #[test]
    fn validate_dest_rejects_non_loopback_unless_allow_remote() {
        assert!(validate_dest("10.0.0.5:9999".parse().unwrap(), false).is_err());
        assert!(validate_dest("8.8.8.8:53".parse().unwrap(), false).is_err());
        // ...but permitted once the binding opts in.
        assert!(validate_dest("10.0.0.5:9999".parse().unwrap(), true).is_ok());
    }

    #[test]
    fn validate_dest_always_rejects_unspecified_multicast_broadcast() {
        // Even with allow_remote, these are never valid unicast destinations.
        assert!(validate_dest("0.0.0.0:9999".parse().unwrap(), true).is_err());
        assert!(validate_dest("224.0.0.1:9999".parse().unwrap(), true).is_err());
        assert!(validate_dest("255.255.255.255:9999".parse().unwrap(), true).is_err());
    }

    #[tokio::test]
    async fn bind_rejects_non_loopback_without_allow_remote() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let err = rt
            .bind(UdpBindRequest {
                port: 0,
                addr: "0.0.0.0".to_string(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await;
        assert!(matches!(err, Err(UdpError::InvalidAddr(_))));
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn bind_loopback_is_the_safe_default() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let info = rt
            .bind(UdpBindRequest {
                port: 0,
                addr: "127.0.0.1".to_string(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .expect("loopback bind should succeed");
        assert!(!info.allow_remote);
        rt.shutdown().await;
    }
}
