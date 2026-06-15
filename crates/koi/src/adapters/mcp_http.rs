//! `CoreSource` — the [`koi_mcp::KoiSource`] backing for the in-process MCP HTTP
//! transport.
//!
//! Unlike the stdio path (which speaks to the daemon over the blocking HTTP
//! client), this source holds the live domain cores directly and calls their
//! async facades — no HTTP self-call, no `spawn_blocking`. It reproduces the same
//! JSON shapes the REST endpoints return so tool output is identical across
//! transports. Cross-domain wiring lives here in the binary, never in koi-mcp
//! (which stays free of domain-crate deps).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::rr::RecordType;
use koi_common::mdns_protocol::{RegisterPayload, RegistrationResult};
use koi_common::types::{ServiceRecord, META_QUERY};
use koi_mcp::{KoiSource, ResourceChange, SourceError};
use koi_mdns::{LeasePolicy, MdnsEvent};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::DaemonCores;

/// Capacity of the resource-change fan-out channel (one sender, many MCP subscribers).
const CHANGE_CHANNEL_CAPACITY: usize = 256;

/// Heartbeat-lease defaults mirroring the `/v1/mdns/announce` HTTP policy
/// (koi-mdns http `DEFAULT_HEARTBEAT_LEASE`/`_GRACE`) so an in-process announce
/// behaves identically: a lease the MCP session renews, draining if the session
/// (and its heartbeat) goes away.
const HEARTBEAT_LEASE: Duration = Duration::from_secs(90);
const HEARTBEAT_GRACE: Duration = Duration::from_secs(30);

/// `KoiSource` backed by the live cores (the in-process HTTP transport).
pub struct CoreSource {
    cores: DaemonCores,
    started_at: Instant,
    http_bind: String,
    /// Fan-out of resource-change signals for MCP `resources/updated` deltas.
    changes: broadcast::Sender<ResourceChange>,
}

impl CoreSource {
    /// Build the source and start the change pump (domain broadcast events →
    /// `ResourceChange`), which runs until `cancel` fires.
    pub fn new(
        cores: DaemonCores,
        started_at: Instant,
        http_bind: String,
        cancel: CancellationToken,
    ) -> Self {
        let (changes, _) = broadcast::channel(CHANGE_CHANNEL_CAPACITY);
        spawn_change_pump(&cores, changes.clone(), cancel);
        Self {
            cores,
            started_at,
            http_bind,
            changes,
        }
    }
}

/// A capability the tool needs is disabled on this daemon.
fn disabled(capability: &str) -> SourceError {
    SourceError(format!(
        "the '{capability}' capability is disabled on this daemon"
    ))
}

#[async_trait]
impl KoiSource for CoreSource {
    async fn is_available(&self) -> bool {
        // The cores are in-process: if the daemon is running, MCP is reachable.
        true
    }

    async fn browse(
        &self,
        service_type: Option<String>,
        window: Duration,
    ) -> Result<Vec<ServiceRecord>, SourceError> {
        let mdns = self.cores.mdns.as_ref().ok_or_else(|| disabled("mdns"))?;
        let ty = service_type.as_deref().unwrap_or(META_QUERY);
        let sub = mdns
            .subscribe_type(ty)
            .await
            .map_err(|e| SourceError(e.to_string()))?;
        let deadline = tokio::time::Instant::now() + window;
        let mut seen: HashMap<String, ServiceRecord> = HashMap::new();
        loop {
            match tokio::time::timeout_at(deadline, sub.recv()).await {
                Ok(Some(MdnsEvent::Found(record) | MdnsEvent::Resolved(record))) => {
                    seen.insert(record.name.clone(), record);
                }
                Ok(Some(MdnsEvent::Removed { .. })) => {}
                Ok(None) => break, // browse closed
                Err(_) => break,   // window elapsed
            }
        }
        Ok(seen.into_values().collect())
    }

    async fn resolve(&self, instance: String) -> Result<ServiceRecord, SourceError> {
        let mdns = self.cores.mdns.as_ref().ok_or_else(|| disabled("mdns"))?;
        mdns.resolve(&instance)
            .await
            .map_err(|e| SourceError(e.to_string()))
    }

    async fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult, SourceError> {
        let mdns = self.cores.mdns.as_ref().ok_or_else(|| disabled("mdns"))?;
        // Mirror koi-mdns http `policy_from_lease_secs`: default to a heartbeat lease.
        let policy = match payload.lease_secs {
            None => LeasePolicy::Heartbeat {
                lease: HEARTBEAT_LEASE,
                grace: HEARTBEAT_GRACE,
            },
            Some(0) => return Err(SourceError("lease_secs must be greater than zero".into())),
            Some(n) => LeasePolicy::Heartbeat {
                lease: Duration::from_secs(n),
                grace: HEARTBEAT_GRACE,
            },
        };
        mdns.register_with_policy(payload, policy, None)
            .map_err(|e| SourceError(e.to_string()))
    }

    async fn unregister(&self, id: String) -> Result<(), SourceError> {
        let mdns = self.cores.mdns.as_ref().ok_or_else(|| disabled("mdns"))?;
        mdns.unregister(&id).map_err(|e| SourceError(e.to_string()))
    }

    async fn heartbeat(&self, id: String) -> Result<(), SourceError> {
        let mdns = self.cores.mdns.as_ref().ok_or_else(|| disabled("mdns"))?;
        mdns.heartbeat(&id)
            .map(|_| ())
            .map_err(|e| SourceError(e.to_string()))
    }

    async fn unified_status(&self) -> Result<Value, SourceError> {
        let capabilities: Vec<_> = koi_compose::status::assemble_capabilities(&self.cores)
            .await
            .into_iter()
            .map(|c| c.status)
            .collect();
        Ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "uptime_secs": self.started_at.elapsed().as_secs(),
            "daemon": true,
            "http_bind": self.http_bind,
            "capabilities": capabilities,
        }))
    }

    async fn health_status(&self) -> Result<Value, SourceError> {
        let health = self
            .cores
            .health
            .as_ref()
            .ok_or_else(|| disabled("health"))?;
        let snapshot = health.core().snapshot().await;
        serde_json::to_value(snapshot).map_err(|e| SourceError(e.to_string()))
    }

    async fn dns_list(&self) -> Result<Value, SourceError> {
        let dns = self.cores.dns.as_ref().ok_or_else(|| disabled("dns"))?;
        let names = dns.core().list_names();
        Ok(json!({ "names": names }))
    }

    async fn dns_lookup(
        &self,
        name: String,
        record_type: RecordType,
    ) -> Result<Value, SourceError> {
        let dns = self.cores.dns.as_ref().ok_or_else(|| disabled("dns"))?;
        match dns.core().lookup(&name, record_type).await {
            Some(result) => {
                let ips: Vec<String> = result.ips.into_iter().map(|ip| ip.to_string()).collect();
                Ok(json!({ "name": result.name, "ips": ips, "source": result.source }))
            }
            None => Err(SourceError("record_not_found".into())),
        }
    }

    async fn dns_add(
        &self,
        name: String,
        ip: String,
        ttl: Option<u32>,
    ) -> Result<Value, SourceError> {
        let dns = self.cores.dns.as_ref().ok_or_else(|| disabled("dns"))?;
        let core = dns.core();
        let zone =
            koi_dns::DnsZone::new(&core.config().zone).map_err(|e| SourceError(e.to_string()))?;
        let normalized = zone
            .normalize_name(&name)
            .ok_or_else(|| SourceError(format!("name '{name}' is outside the zone")))?;
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(SourceError(format!("invalid IP address: {ip}")));
        }
        let entry = koi_config::state::DnsEntry {
            name: normalized,
            ip,
            ttl,
        };
        let entries = core
            .add_entry(entry)
            .map_err(|e| SourceError(e.to_string()))?;
        Ok(json!({ "entries": entries }))
    }

    async fn dns_remove(&self, name: String) -> Result<Value, SourceError> {
        let dns = self.cores.dns.as_ref().ok_or_else(|| disabled("dns"))?;
        let core = dns.core();
        let zone =
            koi_dns::DnsZone::new(&core.config().zone).map_err(|e| SourceError(e.to_string()))?;
        let normalized = zone
            .normalize_name(&name)
            .ok_or_else(|| SourceError(format!("name '{name}' is outside the zone")))?;
        match core
            .remove_entry(&normalized)
            .map_err(|e| SourceError(e.to_string()))?
        {
            Some(entries) => Ok(json!({ "entries": entries })),
            None => Err(SourceError("entry_not_found".into())),
        }
    }

    async fn runtime_instances(&self) -> Result<Value, SourceError> {
        let runtime = self
            .cores
            .runtime
            .as_ref()
            .ok_or_else(|| disabled("runtime"))?;
        let instances = runtime
            .list_instances()
            .await
            .map_err(|e| SourceError(e.to_string()))?;
        serde_json::to_value(instances).map_err(|e| SourceError(e.to_string()))
    }

    async fn mdns_snapshot(&self) -> Result<Value, SourceError> {
        // Lock-free cached records (not a timed browse) — `None` when mDNS is disabled.
        let records = self
            .cores
            .mdns_snapshot
            .as_ref()
            .map(|s| s.cached_records())
            .unwrap_or_default();
        Ok(json!({ "services": records }))
    }

    fn change_stream(&self) -> Option<broadcast::Receiver<ResourceChange>> {
        Some(self.changes.subscribe())
    }
}

/// Bridge the domains' broadcast events into `ResourceChange` signals for MCP
/// resource subscriptions (mirrors `koi_dashboard::forward::spawn_event_forwarder`).
/// Runs until `cancel` fires.
fn spawn_change_pump(
    cores: &DaemonCores,
    tx: broadcast::Sender<ResourceChange>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let mut mdns_rx = cores.mdns.as_ref().map(|c| c.subscribe());
    let mut health_rx = cores.health.as_ref().map(|r| r.core().subscribe());
    let mut dns_rx = cores.dns.as_ref().map(|r| r.core().subscribe());
    let mut runtime_rx = cores.runtime.as_ref().map(|r| r.subscribe());
    tokio::spawn(async move {
        loop {
            let change: Option<ResourceChange> = tokio::select! {
                _ = cancel.cancelled() => break,
                Some(Ok(_)) = recv_opt(&mut mdns_rx) => Some(ResourceChange::Mdns),
                Some(Ok(_)) = recv_opt(&mut health_rx) => Some(ResourceChange::Health),
                Some(Ok(_)) = recv_opt(&mut dns_rx) => Some(ResourceChange::Dns),
                Some(Ok(_)) = recv_opt(&mut runtime_rx) => Some(ResourceChange::Inventory),
            };
            if let Some(change) = change {
                // Ignore send errors: no current subscribers is normal.
                let _ = tx.send(change);
            }
        }
    })
}

/// Await an optional broadcast receiver; `None` (capability absent) leaves its
/// select arm permanently disabled.
async fn recv_opt<T: Clone>(
    rx: &mut Option<broadcast::Receiver<T>>,
) -> Option<Result<T, broadcast::error::RecvError>> {
    match rx.as_mut() {
        Some(rx) => Some(rx.recv().await),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// A trivial `KoiSource` — `tools/list` and `initialize` never touch it, so the
    /// reads return empty and the writes error. This proves the HTTP transport wiring
    /// independently of any live core.
    struct MockSource;

    #[async_trait]
    impl KoiSource for MockSource {
        async fn is_available(&self) -> bool {
            true
        }
        async fn browse(
            &self,
            _service_type: Option<String>,
            _window: Duration,
        ) -> Result<Vec<ServiceRecord>, SourceError> {
            Ok(Vec::new())
        }
        async fn resolve(&self, _instance: String) -> Result<ServiceRecord, SourceError> {
            Err(SourceError("not found".into()))
        }
        async fn register(
            &self,
            _payload: RegisterPayload,
        ) -> Result<RegistrationResult, SourceError> {
            Err(SourceError("mock".into()))
        }
        async fn unregister(&self, _id: String) -> Result<(), SourceError> {
            Ok(())
        }
        async fn heartbeat(&self, _id: String) -> Result<(), SourceError> {
            Ok(())
        }
        async fn unified_status(&self) -> Result<Value, SourceError> {
            Ok(json!({}))
        }
        async fn health_status(&self) -> Result<Value, SourceError> {
            Ok(json!({}))
        }
        async fn dns_list(&self) -> Result<Value, SourceError> {
            Ok(json!({ "names": [] }))
        }
        async fn dns_lookup(
            &self,
            _name: String,
            _record_type: RecordType,
        ) -> Result<Value, SourceError> {
            Err(SourceError("not found".into()))
        }
        async fn dns_add(
            &self,
            _name: String,
            _ip: String,
            _ttl: Option<u32>,
        ) -> Result<Value, SourceError> {
            Err(SourceError("mock".into()))
        }
        async fn dns_remove(&self, _name: String) -> Result<Value, SourceError> {
            Err(SourceError("mock".into()))
        }
        async fn runtime_instances(&self) -> Result<Value, SourceError> {
            Ok(json!([]))
        }
        async fn mdns_snapshot(&self) -> Result<Value, SourceError> {
            Ok(json!({ "services": [] }))
        }
    }

    /// POST one JSON-RPC message to `/v1/mcp` (cloning the shared-session app) and
    /// return (status, assigned-or-echoed session id, body text). The body may be
    /// SSE-framed in stateful mode, so callers substring-match.
    async fn post(
        app: &axum::Router,
        session: Option<&str>,
        body: &str,
    ) -> (StatusCode, Option<String>, String) {
        let mut builder = Request::post("/v1/mcp")
            // rmcp validates the Host header (DNS-rebinding defense); supply one.
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(sid) = session {
            builder = builder.header("mcp-session-id", sid);
        }
        let req = builder.body(Body::from(body.to_string())).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let sid = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, sid, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Drive a full MCP session over the in-process Streamable HTTP transport,
    /// mounted exactly as the daemon mounts it: initialize → initialized →
    /// resources/list → resources/read, asserting the handshake, the session id,
    /// the resource set, and a read snapshot. The tripwire for `/v1/mcp` + resources.
    #[tokio::test]
    async fn streamable_http_session_lists_and_reads_resources() {
        let service = koi_mcp::streamable_http_service(
            std::sync::Arc::new(MockSource),
            vec!["localhost".to_string()],
        );
        let app = axum::Router::new().nest_service("/v1/mcp", service);

        // initialize
        let (status, sid, body) = post(
            &app,
            None,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"itest","version":"0.0.0"}}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "initialize should return 200");
        let sid = sid.expect("stateful transport must assign an mcp-session-id");
        assert!(body.contains("koi-mcp"), "serverInfo missing: {body}");
        assert!(
            body.contains("resources"),
            "capabilities must advertise resources: {body}"
        );

        // initialized notification
        let (status, _, _) = post(
            &app,
            Some(&sid),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .await;
        assert!(status.is_success(), "initialized notif rejected: {status}");

        // resources/list
        let (status, _, body) = post(
            &app,
            Some(&sid),
            r#"{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("koi://lan/inventory") && body.contains("koi://health"),
            "resources/list missing expected URIs: {body}"
        );

        // resources/read — the mock returns instantly, so this is deterministic.
        let (status, _, body) = post(
            &app,
            Some(&sid),
            r#"{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"koi://health"}}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("koi://health"),
            "resources/read must return contents for the uri: {body}"
        );
    }
}
