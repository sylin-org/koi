//! `CoreSource` — the [`koi_mcp::KoiSource`] backing for the in-process MCP HTTP
//! transport.
//!
//! Unlike the stdio path (which speaks to the daemon over the blocking HTTP
//! client), this source executes commands against live domain cores and serves
//! presentations from one cached product aggregate — no HTTP self-call or
//! `spawn_blocking`. It reproduces the REST shapes across transports. Cross-domain
//! wiring lives here in koi-serve, never in koi-mcp (which stays free of domain
//! crate dependencies).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::rr::RecordType;
use koi_common::mdns_protocol::{RegisterPayload, RegistrationResult};
use koi_common::types::{ServiceRecord, ServiceType, META_QUERY};
use koi_mcp::{KoiSource, ResourceChange, SourceError};
use koi_mdns::{LeasePolicy, MdnsEvent};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_compose::cores::Cores as DaemonCores;
use koi_compose::status::{KoiStatus, KoiStatusRuntime};

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
    /// This adapter owns its aggregate projection task. Retaining the handle
    /// prevents an HTTP bind/serve failure from detaching the pump.
    change_pump: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    change_pump_cancel: CancellationToken,
}

impl CoreSource {
    /// Build the source and start the aggregate-status change pump, which runs
    /// until `cancel` fires.
    pub fn new(
        cores: DaemonCores,
        started_at: Instant,
        http_bind: String,
        cancel: CancellationToken,
    ) -> Self {
        let (changes, _) = broadcast::channel(CHANGE_CHANNEL_CAPACITY);
        let change_pump_cancel = cancel.child_token();
        let change_pump = spawn_change_pump(
            cores.system_status.clone(),
            changes.clone(),
            change_pump_cancel.clone(),
        );
        Self {
            cores,
            started_at,
            http_bind,
            changes,
            change_pump: tokio::sync::Mutex::new(Some(change_pump)),
            change_pump_cancel,
        }
    }

    /// Stop and reap the source-owned aggregate projection task.
    pub async fn shutdown(&self) {
        self.change_pump_cancel.cancel();
        // Borrow the handle in its owner until completion. If this waiter is
        // cancelled, dropping the mutex guard leaves the task owned for a later
        // shutdown or CoreSource::drop instead of detaching it.
        let mut slot = self.change_pump.lock().await;
        let Some(task) = slot.as_mut() else {
            return;
        };
        if tokio::time::timeout(Duration::from_secs(2), &mut *task)
            .await
            .is_err()
        {
            task.abort();
            let _ = (&mut *task).await;
        }
        slot.take();
    }
}

impl Drop for CoreSource {
    fn drop(&mut self) {
        // Explicit shutdown is used by both serving adapters. This synchronous
        // fallback covers construction/bind failures without spawning a detached
        // async finalizer.
        self.change_pump_cancel.cancel();
        if let Ok(mut slot) = self.change_pump.try_lock() {
            if let Some(task) = slot.take() {
                task.abort();
            }
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
                Ok(Ok(MdnsEvent::Found(record) | MdnsEvent::Resolved(record))) => {
                    seen.insert(record.name.clone(), record);
                }
                Ok(Ok(MdnsEvent::Removed { name, .. })) => {
                    seen.remove(&name);
                }
                Ok(Err(koi_mdns::BrowseRecvError::Lagged { dropped })) => {
                    tracing::warn!(
                        dropped,
                        "MCP mDNS browse lagged; reconciling current discovery state"
                    );
                    reconcile_browse_snapshot(&mut seen, mdns, ty)?;
                }
                Ok(Err(koi_mdns::BrowseRecvError::Closed)) => break,
                Err(_) => break, // window elapsed
            }
        }
        // Events make the timed browse responsive; the final answer is always
        // reconciled from the domain's current state.
        reconcile_browse_snapshot(&mut seen, mdns, ty)?;
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
            .await
            .map_err(|e| SourceError(e.to_string()))
    }

    async fn unregister(&self, id: String) -> Result<(), SourceError> {
        let mdns = self.cores.mdns.as_ref().ok_or_else(|| disabled("mdns"))?;
        mdns.unregister(&id)
            .await
            .map_err(|e| SourceError(e.to_string()))
    }

    async fn heartbeat(&self, id: String) -> Result<(), SourceError> {
        let mdns = self.cores.mdns.as_ref().ok_or_else(|| disabled("mdns"))?;
        mdns.heartbeat(&id)
            .await
            .map(|_| ())
            .map_err(|e| SourceError(e.to_string()))
    }

    async fn health_status(&self) -> Result<Value, SourceError> {
        let status = self.cores.system_status.status();
        let health = status
            .domains
            .health
            .as_ref()
            .ok_or_else(|| disabled("health"))?;
        serde_json::to_value(health).map_err(|e| SourceError(e.to_string()))
    }

    async fn dns_list(&self) -> Result<Value, SourceError> {
        let status = self.cores.system_status.status();
        let names = status
            .domains
            .dns_catalog
            .as_ref()
            .ok_or_else(|| disabled("dns"))?;
        Ok(json!({ "names": &names.names }))
    }

    async fn inventory_snapshot(&self, include: Option<Vec<String>>) -> Result<Value, SourceError> {
        let status = self.cores.system_status.status();
        crate::inventory::project(
            status.as_ref(),
            include.as_deref(),
            self.started_at.elapsed().as_secs(),
            &self.http_bind,
            true,
        )
        .map_err(|error| SourceError(error.to_string()))
    }

    async fn dns_lookup(
        &self,
        name: String,
        record_type: RecordType,
    ) -> Result<Value, SourceError> {
        let dns = self.cores.dns.as_ref().ok_or_else(|| disabled("dns"))?;
        match dns
            .lookup(&name, record_type)
            .await
            .map_err(|error| SourceError(error.to_string()))?
        {
            Some(result) => Ok(json!(result)),
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
        let normalized = dns
            .normalize_name(&name)
            .ok_or_else(|| SourceError(format!("name '{name}' is outside the zone")))?;
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(SourceError(format!("invalid IP address: {ip}")));
        }
        let entry = koi_dns::DnsEntry {
            name: normalized,
            ip,
            ttl,
        };
        let entries = dns
            .add_entry(entry)
            .map_err(|e| SourceError(e.to_string()))?;
        Ok(json!({ "entries": entries }))
    }

    async fn dns_remove(&self, name: String) -> Result<Value, SourceError> {
        let dns = self.cores.dns.as_ref().ok_or_else(|| disabled("dns"))?;
        let normalized = dns
            .normalize_name(&name)
            .ok_or_else(|| SourceError(format!("name '{name}' is outside the zone")))?;
        match dns
            .remove_entry(&normalized)
            .map_err(|e| SourceError(e.to_string()))?
        {
            Some(entries) => Ok(json!({ "entries": entries })),
            None => Err(SourceError("entry_not_found".into())),
        }
    }

    async fn runtime_instances(&self) -> Result<Value, SourceError> {
        let status = self.cores.system_status.status();
        let runtime = status
            .domains
            .runtime
            .as_ref()
            .ok_or_else(|| disabled("runtime"))?;
        serde_json::to_value(&runtime.instances).map_err(|e| SourceError(e.to_string()))
    }

    async fn mdns_snapshot(&self) -> Result<Value, SourceError> {
        let status = self.cores.system_status.status();
        let discovery = status
            .domains
            .mdns_discovery
            .as_ref()
            .ok_or_else(|| disabled("mdns"))?;
        Ok(json!({ "services": &discovery.records }))
    }

    fn change_stream(&self) -> Option<broadcast::Receiver<ResourceChange>> {
        Some(self.changes.subscribe())
    }
}

/// Diff the authoritative aggregate feed into MCP resource invalidations.
/// `watch` coalescing is sufficient because subscribers always reread current
/// state; there is no event history or lag-recovery model here.
fn spawn_change_pump(
    status: std::sync::Arc<KoiStatusRuntime>,
    tx: broadcast::Sender<ResourceChange>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let mut snapshots = status.watch_status();
    let mut previous = snapshots.borrow_and_update().clone();
    tokio::spawn(async move {
        loop {
            let changed = tokio::select! {
                _ = cancel.cancelled() => break,
                changed = snapshots.changed() => changed,
            };
            if changed.is_err() {
                break;
            }
            let current = snapshots.borrow_and_update().clone();
            for change in resource_changes(previous.as_ref(), current.as_ref()) {
                let _ = tx.send(change);
            }
            previous = current;
        }
    })
}

fn resource_changes(previous: &KoiStatus, current: &KoiStatus) -> Vec<ResourceChange> {
    if previous == current {
        return Vec::new();
    }
    let mut changes = vec![ResourceChange::Inventory];
    if previous.domains.health != current.domains.health {
        changes.push(ResourceChange::Health);
    }
    if previous
        .domains
        .dns_catalog
        .as_ref()
        .map(|catalog| &catalog.names)
        != current
            .domains
            .dns_catalog
            .as_ref()
            .map(|catalog| &catalog.names)
    {
        changes.push(ResourceChange::Dns);
    }
    if previous.domains.mdns_discovery != current.domains.mdns_discovery {
        changes.push(ResourceChange::Mdns);
    }
    changes
}

fn reconcile_browse_snapshot(
    seen: &mut HashMap<String, ServiceRecord>,
    mdns: &koi_mdns::MdnsCore,
    service_type: &str,
) -> Result<(), SourceError> {
    let snapshot = mdns.discovery_snapshot();
    seen.clear();
    if service_type == META_QUERY {
        for discovered in &snapshot.service_types {
            seen.insert(
                discovered.clone(),
                ServiceRecord {
                    name: discovered.clone(),
                    service_type: META_QUERY.to_string(),
                    host: None,
                    ip: None,
                    port: None,
                    txt: HashMap::new(),
                },
            );
        }
        return Ok(());
    }

    let canonical = ServiceType::parse_browse(service_type)
        .map_err(|error| SourceError(error.to_string()))?
        .as_str()
        .to_string();
    for record in snapshot.records_for_query(&canonical) {
        seen.insert(record.name.clone(), record.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn core_source_owns_and_idempotently_reaps_its_change_pump() {
        let source = CoreSource::new(
            DaemonCores::default(),
            Instant::now(),
            "127.0.0.1".to_string(),
            CancellationToken::new(),
        );
        assert!(source.change_pump.lock().await.is_some());

        source.shutdown().await;
        source.shutdown().await;

        assert!(source.change_pump.lock().await.is_none());
    }

    #[tokio::test]
    async fn cancelled_shutdown_waiter_does_not_detach_the_change_pump() {
        let source = std::sync::Arc::new(CoreSource::new(
            DaemonCores::default(),
            Instant::now(),
            "127.0.0.1".to_string(),
            CancellationToken::new(),
        ));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocking = tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        });
        started_rx.await.expect("blocking projection started");
        {
            let mut slot = source.change_pump.lock().await;
            if let Some(task) = slot.take() {
                task.abort();
                let _ = task.await;
            }
            *slot = Some(blocking);
        }

        let waiter = tokio::spawn({
            let source = std::sync::Arc::clone(&source);
            async move { source.shutdown().await }
        });
        for _ in 0..32 {
            if source.change_pump.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            source.change_pump.try_lock().is_err(),
            "shutdown waiter never borrowed the owned task"
        );
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(
            source.change_pump.lock().await.is_some(),
            "cancelled waiter detached the projection task"
        );

        release_tx.send(()).expect("release blocking projection");
        source.shutdown().await;
        source.shutdown().await;
        assert!(source.change_pump.lock().await.is_none());
    }

    #[tokio::test]
    async fn disabled_domain_resources_are_not_faked_as_empty_snapshots() {
        let source = CoreSource::new(
            DaemonCores::default(),
            Instant::now(),
            "127.0.0.1".to_string(),
            CancellationToken::new(),
        );

        assert!(source.health_status().await.is_err());
        assert!(source.dns_list().await.is_err());
        assert!(source.mdns_snapshot().await.is_err());
        source.shutdown().await;
    }

    #[test]
    fn aggregate_diff_emits_exact_resource_invalidations() {
        let before = KoiStatus {
            revision: 0,
            capabilities: Vec::new(),
            catalog: std::sync::Arc::new(koi_common::service::CatalogSnapshot::default()),
            domains: koi_compose::status::DomainStatuses::default(),
        };
        assert!(resource_changes(&before, &before).is_empty());

        let mut dns = before.clone();
        dns.revision = 1;
        dns.domains.dns_catalog = Some(
            koi_dns::DnsCatalogSnapshot {
                revision: 1,
                names: vec!["api.internal.".to_string()],
                entries: Vec::new(),
            }
            .into(),
        );
        assert_eq!(
            resource_changes(&before, &dns),
            [ResourceChange::Inventory, ResourceChange::Dns]
        );

        let mut mdns = dns.clone();
        mdns.revision = 2;
        mdns.domains.mdns_discovery = Some(Default::default());
        assert_eq!(
            resource_changes(&dns, &mdns),
            [ResourceChange::Inventory, ResourceChange::Mdns]
        );

        let mut aggregate_only = mdns.clone();
        aggregate_only.revision = 3;
        assert_eq!(
            resource_changes(&mdns, &aggregate_only),
            [ResourceChange::Inventory]
        );
    }

    #[test]
    fn joined_inventory_is_projected_from_one_product_snapshot() {
        let status = KoiStatus {
            revision: 41,
            capabilities: Vec::new(),
            catalog: std::sync::Arc::new(koi_common::service::CatalogSnapshot::default()),
            domains: koi_compose::status::DomainStatuses {
                mdns: Some(
                    koi_mdns::MdnsStatus {
                        revision: 9,
                        ..Default::default()
                    }
                    .into(),
                ),
                health: Some(
                    koi_health::HealthSnapshot {
                        revision: 7,
                        ..Default::default()
                    }
                    .into(),
                ),
                dns_catalog: Some(
                    koi_dns::DnsCatalogSnapshot {
                        revision: 5,
                        names: vec!["api.internal.".to_string()],
                        entries: Vec::new(),
                    }
                    .into(),
                ),
                ..Default::default()
            },
        };

        let inventory =
            crate::inventory::project(&status, None, 12, "127.0.0.1", true).expect("inventory");
        assert_eq!(inventory["status"]["revision"], 41);
        assert_eq!(inventory["status"]["mdns"]["revision"], 9);
        assert_eq!(inventory["status"]["dns"], serde_json::Value::Null);
        assert_eq!(inventory["health"]["revision"], 7);
        assert_eq!(inventory["dns"]["names"][0], "api.internal.");
    }

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
        async fn health_status(&self) -> Result<Value, SourceError> {
            Ok(json!({}))
        }
        async fn dns_list(&self) -> Result<Value, SourceError> {
            Ok(json!({ "names": [] }))
        }
        async fn inventory_snapshot(
            &self,
            _include: Option<Vec<String>>,
        ) -> Result<Value, SourceError> {
            Ok(json!({ "status": {}, "health": null, "dns": { "names": [] } }))
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

    /// True end-to-end: bind the MCP service behind the REAL DAT auth middleware on
    /// a real TCP listener (exactly how the daemon mounts it), then drive it with a
    /// real rmcp MCP client over the wire — with the token (full surface works) and
    /// without (the auth layer rejects). This is the "bring the service up and hit
    /// it from an MCP client" tripwire.
    #[tokio::test]
    async fn mcp_client_over_tcp_through_auth_layer() {
        use axum::http::{HeaderName, HeaderValue};
        use rmcp::transport::streamable_http_client::{
            StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
        };
        use rmcp::ServiceExt as _;

        let token = "itest-token";
        // Mount exactly as http::start does: the rmcp service nested at
        // /v1/mcp, behind the production dat_auth_middleware. Empty allowed_hosts
        // disables rmcp's Host check (the client sends Host: 127.0.0.1:<port>).
        let service = koi_mcp::streamable_http_service(std::sync::Arc::new(MockSource), Vec::new());
        let expected = std::sync::Arc::new(token.to_string());
        let app =
            axum::Router::new()
                .nest_service("/v1/mcp", service)
                .layer(axum::middleware::from_fn(move |req, next| {
                    let expected = expected.clone();
                    crate::http::dat_auth_middleware(req, next, expected)
                }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let url = format!("http://127.0.0.1:{port}/v1/mcp");

        // ── With the token: a real MCP client completes the surface. ──
        let mut headers = HashMap::new();
        headers.insert(
            HeaderName::from_static("x-koi-token"),
            HeaderValue::from_str(token).unwrap(),
        );
        let config =
            StreamableHttpClientTransportConfig::with_uri(url.clone()).custom_headers(headers);
        let transport = StreamableHttpClientTransport::from_config(config);
        let client = ().serve(transport).await.expect("authenticated client should initialize");

        let tools = client.list_tools(None).await.expect("list_tools");
        assert_eq!(
            tools.tools.len(),
            11,
            "expected the 11 v1 tools over the wire"
        );
        let resources = client.list_resources(None).await.expect("list_resources");
        assert!(
            resources
                .resources
                .iter()
                .any(|r| r.uri == "koi://lan/inventory"),
            "resources/list over the wire must include the inventory resource"
        );
        let read = client
            .read_resource(rmcp::model::ReadResourceRequestParams::new("koi://health"))
            .await
            .expect("read_resource");
        assert!(!read.contents.is_empty(), "read must return contents");
        let _ = client.cancel().await;

        // ── Without the token: the real auth layer rejects it. ──
        let config = StreamableHttpClientTransportConfig::with_uri(url);
        let transport = StreamableHttpClientTransport::from_config(config);
        match ().serve(transport).await {
            Err(_) => {} // rejected at initialize — the expected path
            Ok(client) => {
                assert!(
                    client.list_tools(None).await.is_err(),
                    "a tokenless client must be rejected by the auth layer"
                );
                let _ = client.cancel().await;
            }
        }

        server.abort();
    }
}
