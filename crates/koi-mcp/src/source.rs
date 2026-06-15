//! The `KoiSource` data-source abstraction.
//!
//! koi-mcp's tool handlers are transport-agnostic: they call `KoiSource` methods,
//! not a concrete client. Two backings implement it:
//! - [`ClientSource`] wraps the blocking [`KoiClient`] (HTTP/ureq) for the stdio
//!   `koi mcp serve` path — every call is bridged onto a blocking thread.
//! - `CoreSource` (in the binary crate) calls the live domain cores directly,
//!   async, for the in-process HTTP transport — it never makes an HTTP self-call.
//!
//! The trait is the seam that lets one `Server<S>` and one tool surface serve both.

use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::RecordType;
use koi_client::{ClientError, KoiClient};
use koi_common::mdns_protocol::{RegisterPayload, RegistrationResult};
use koi_common::types::ServiceRecord;
use serde_json::Value;
use tokio::sync::broadcast;

use crate::client::call;
use crate::tools;

/// A source-level error. Carries a display message only — never the token.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SourceError(pub String);

impl From<ClientError> for SourceError {
    fn from(e: ClientError) -> Self {
        SourceError(e.to_string())
    }
}

/// Which MCP resource changed — emitted on the live change stream so the server
/// can send `notifications/resources/updated` to subscribers. `ClientSource`
/// (stdio) has no live stream; only the in-process `CoreSource` produces these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceChange {
    Inventory,
    Health,
    Dns,
    Mdns,
}

/// The data backing for the MCP tool + resource surface. One implementation per
/// transport: the blocking client (stdio) or the live cores (in-process HTTP).
///
/// Methods take owned arguments so both a `spawn_blocking` (client) and a direct
/// `.await` (cores) implementation are natural; the returned `serde_json::Value`s
/// reproduce the daemon's HTTP response shapes so tool output is identical across
/// transports.
#[async_trait::async_trait]
pub trait KoiSource: Send + Sync + 'static {
    /// Whether the underlying daemon/cores are reachable. Tools short-circuit with
    /// an actionable error when this is false.
    async fn is_available(&self) -> bool;

    /// Browse mDNS for `service_type` (or all types when `None`), collecting
    /// deduplicated records for `window`.
    async fn browse(
        &self,
        service_type: Option<String>,
        window: Duration,
    ) -> Result<Vec<ServiceRecord>, SourceError>;

    async fn resolve(&self, instance: String) -> Result<ServiceRecord, SourceError>;

    async fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult, SourceError>;

    async fn unregister(&self, id: String) -> Result<(), SourceError>;

    async fn heartbeat(&self, id: String) -> Result<(), SourceError>;

    async fn unified_status(&self) -> Result<Value, SourceError>;

    async fn health_status(&self) -> Result<Value, SourceError>;

    async fn dns_list(&self) -> Result<Value, SourceError>;

    async fn dns_lookup(&self, name: String, record_type: RecordType)
        -> Result<Value, SourceError>;

    async fn dns_add(
        &self,
        name: String,
        ip: String,
        ttl: Option<u32>,
    ) -> Result<Value, SourceError>;

    async fn dns_remove(&self, name: String) -> Result<Value, SourceError>;

    async fn runtime_instances(&self) -> Result<Value, SourceError>;

    /// A point-in-time snapshot of mDNS-discovered services (the browse cache) for
    /// the `koi://mdns/services` resource — fast and lock-free, NOT a timed browse.
    async fn mdns_snapshot(&self) -> Result<Value, SourceError>;

    /// A live stream of resource-change signals for MCP subscriptions. Returns
    /// `None` when the source cannot push deltas (the stdio client path) — those
    /// resources are then snapshot-only.
    fn change_stream(&self) -> Option<broadcast::Receiver<ResourceChange>> {
        None
    }
}

/// `KoiSource` backed by the blocking [`KoiClient`] — the stdio transport. Every
/// call is bridged onto a blocking thread so the async runtime is never blocked.
#[derive(Clone)]
pub struct ClientSource {
    client: Arc<KoiClient>,
}

impl ClientSource {
    pub fn new(client: Arc<KoiClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl KoiSource for ClientSource {
    async fn is_available(&self) -> bool {
        call(&self.client, |c| c.health()).await.is_ok()
    }

    async fn browse(
        &self,
        service_type: Option<String>,
        window: Duration,
    ) -> Result<Vec<ServiceRecord>, SourceError> {
        call(&self.client, move |c| {
            tools::collect_browse(c, service_type.as_deref(), window)
        })
        .await
        .map_err(SourceError::from)
    }

    async fn resolve(&self, instance: String) -> Result<ServiceRecord, SourceError> {
        call(&self.client, move |c| c.resolve(&instance))
            .await
            .map_err(SourceError::from)
    }

    async fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult, SourceError> {
        call(&self.client, move |c| c.register(&payload))
            .await
            .map_err(SourceError::from)
    }

    async fn unregister(&self, id: String) -> Result<(), SourceError> {
        call(&self.client, move |c| c.unregister(&id))
            .await
            .map_err(SourceError::from)
    }

    async fn heartbeat(&self, id: String) -> Result<(), SourceError> {
        call(&self.client, move |c| c.heartbeat(&id))
            .await
            .map(|_| ())
            .map_err(SourceError::from)
    }

    async fn unified_status(&self) -> Result<Value, SourceError> {
        call(&self.client, |c| c.unified_status())
            .await
            .map_err(SourceError::from)
    }

    async fn health_status(&self) -> Result<Value, SourceError> {
        call(&self.client, |c| c.health_status())
            .await
            .map_err(SourceError::from)
    }

    async fn dns_list(&self) -> Result<Value, SourceError> {
        call(&self.client, |c| c.dns_list())
            .await
            .map_err(SourceError::from)
    }

    async fn dns_lookup(
        &self,
        name: String,
        record_type: RecordType,
    ) -> Result<Value, SourceError> {
        call(&self.client, move |c| c.dns_lookup(&name, record_type))
            .await
            .map_err(SourceError::from)
    }

    async fn dns_add(
        &self,
        name: String,
        ip: String,
        ttl: Option<u32>,
    ) -> Result<Value, SourceError> {
        call(&self.client, move |c| c.dns_add(&name, &ip, ttl))
            .await
            .map_err(SourceError::from)
    }

    async fn dns_remove(&self, name: String) -> Result<Value, SourceError> {
        call(&self.client, move |c| c.dns_remove(&name))
            .await
            .map_err(SourceError::from)
    }

    async fn runtime_instances(&self) -> Result<Value, SourceError> {
        call(&self.client, |c| c.get_json("/v1/runtime/instances"))
            .await
            .map_err(SourceError::from)
    }

    async fn mdns_snapshot(&self) -> Result<Value, SourceError> {
        call(&self.client, |c| c.get_json("/v1/mdns/browser/snapshot"))
            .await
            .map_err(SourceError::from)
    }
}
