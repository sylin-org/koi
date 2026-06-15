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
use koi_mcp::{KoiSource, SourceError};
use koi_mdns::{LeasePolicy, MdnsEvent};
use serde_json::{json, Value};

use crate::DaemonCores;

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
}

impl CoreSource {
    pub fn new(cores: DaemonCores, started_at: Instant, http_bind: String) -> Self {
        Self {
            cores,
            started_at,
            http_bind,
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
    }

    /// Drive a real MCP `initialize` over the in-process Streamable HTTP transport
    /// (mounted exactly as the daemon mounts it) and assert the handshake succeeds:
    /// 200, a session id, and the koi-mcp server identity in the body. This is the
    /// tripwire for the `/v1/mcp` HTTP surface.
    #[tokio::test]
    async fn initialize_over_streamable_http() {
        let service = koi_mcp::streamable_http_service(
            std::sync::Arc::new(MockSource),
            vec!["localhost".to_string()],
        );
        let app = axum::Router::new().nest_service("/v1/mcp", service);

        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"itest","version":"0.0.0"}}}"#;
        let req = Request::post("/v1/mcp")
            // rmcp validates the Host header (DNS-rebinding defense); supply one.
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "initialize should return 200"
        );
        assert!(
            resp.headers().get("mcp-session-id").is_some(),
            "stateful transport must assign an mcp-session-id"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("koi-mcp"),
            "initialize result must carry the koi-mcp serverInfo; body was: {text}"
        );
    }
}
