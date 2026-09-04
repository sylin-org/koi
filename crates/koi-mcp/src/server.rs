//! The MCP `Server`: tool router, tool handlers, and the `ServerHandler` info.
//!
//! `Server<S>` is generic over a [`KoiSource`] data backing, so the same tool
//! surface serves both the stdio transport (backed by [`crate::ClientSource`], a
//! blocking `KoiClient`) and the in-process HTTP transport (backed by the binary's
//! `CoreSource`, the live domain cores). Handlers call `self.source.<method>()` —
//! they never touch a concrete client. Read tools carry `read_only_hint`; additive
//! writers carry `destructive_hint = false`; removers carry `destructive_hint = true`.
//! The token is never echoed in any tool output.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{
        AnnotateAble, CallToolResult, Content, Implementation, ListResourcesResult,
        PaginatedRequestParams, RawResource, ReadResourceRequestParams, ReadResourceResult,
        Resource, ResourceContents, ResourceUpdatedNotificationParam, ServerCapabilities,
        ServerInfo, SubscribeRequestParams, UnsubscribeRequestParams,
    },
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler,
};
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;

use crate::client::NO_DAEMON_MSG;
use crate::heartbeat::Registry;
use crate::source::{KoiSource, ResourceChange, SourceError};
use crate::tools::{
    self, AnnounceReq, DiscoverReq, DnsAddReq, DnsLookupReq, DnsRemoveReq, InventoryReq,
    ResolveReq, UnregisterReq,
};

/// MCP resource URIs Koi exposes. `read` returns a current snapshot; `subscribe`
/// adds `resources/updated` deltas (in-process transport only — see `KoiSource::change_stream`).
const URI_INVENTORY: &str = "koi://lan/inventory";
const URI_HEALTH: &str = "koi://health";
const URI_DNS: &str = "koi://dns/zone";
const URI_MDNS: &str = "koi://mdns/services";

/// Koi's mDNS convention for advertising an MCP server endpoint on the LAN.
/// No DNS-SD standard for MCP exists yet — see `docs/guides/mcp.md`.
const MCP_SERVICE_TYPE: &str = "_mcp._tcp";

/// Upper bound on `lan_discover` collection, regardless of requested timeout.
const MAX_DISCOVER_SECS: u64 = 10;

/// Default `lan_discover` collection window.
const DEFAULT_DISCOVER_SECS: u64 = 5;

pub struct Server<S> {
    source: Arc<S>,
    registry: Registry,
    /// Live resource subscriptions for this session: uri → the task that forwards
    /// `resources/updated` notifications to the peer. Aborted on unsubscribe.
    subs: Arc<SubscriptionTasks>,
}

#[derive(Default)]
struct SubscriptionTasks {
    tasks: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl SubscriptionTasks {
    async fn stop(&self) {
        let mut tasks = self.tasks.lock().await;
        for task in tasks.values() {
            task.abort();
        }
        while let Some(uri) = tasks.keys().next().cloned() {
            let task = tasks
                .get_mut(&uri)
                .expect("selected subscription remains owned");
            let _ = (&mut *task).await;
            tasks.remove(&uri);
        }
    }
}

impl Drop for SubscriptionTasks {
    fn drop(&mut self) {
        // A transport can disappear without invoking the async service shutdown
        // hook. Subscription relays own no durable state, so abort them at the
        // last session owner rather than letting them retain the peer forever.
        for task in self.tasks.get_mut().values() {
            task.abort();
        }
    }
}

// Hand-written so `Server<S>` is `Clone` without forcing `S: Clone` (the source is
// shared behind an `Arc`). The stdio path clones the server before serving.
impl<S> Clone for Server<S> {
    fn clone(&self) -> Self {
        Self {
            source: Arc::clone(&self.source),
            registry: self.registry.clone(),
            subs: Arc::clone(&self.subs),
        }
    }
}

#[tool_router]
impl<S: KoiSource> Server<S> {
    /// Build a server bound to `source`, with a fresh (empty) announcement
    /// registry. The registry tracks heartbeat tasks for `lan_announce`.
    pub fn new(source: Arc<S>) -> Self {
        Self {
            source,
            registry: Registry::new(),
            subs: Arc::new(SubscriptionTasks::default()),
        }
    }

    // ── Discovery ───────────────────────────────────────────────────

    #[tool(
        description = "Discover services advertised on the local network via mDNS. \
            Use when an agent needs to find what hosts/services exist on the LAN (web UIs, \
            databases, NAS, other agents) before acting. Browses for `type` (e.g. `_http._tcp`) \
            or all types when omitted, collecting for `timeout_secs` (default 5, max 10). \
            Returns a deduplicated list of service records (name, type, host, ip, port, txt). \
            Read-only; no side effects.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn lan_discover(
        &self,
        Parameters(req): Parameters<DiscoverReq>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        let window = Duration::from_secs(
            req.timeout_secs
                .unwrap_or(DEFAULT_DISCOVER_SECS)
                .clamp(1, MAX_DISCOVER_SECS),
        );
        match self.source.browse(req.service_type.clone(), window).await {
            Ok(records) => Ok(structured(serde_json::json!({ "services": records }))),
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    #[tool(
        description = "Resolve one specific mDNS service instance to its connection details. \
            Use after `lan_discover` to get the host, IP, port, and TXT records for a named \
            instance (e.g. `My App._http._tcp.local.`). Returns a single service record. \
            Read-only.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn lan_resolve(
        &self,
        Parameters(req): Parameters<ResolveReq>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        match self.source.resolve(req.instance.clone()).await {
            Ok(record) => Ok(structured(
                serde_json::to_value(record).unwrap_or(serde_json::Value::Null),
            )),
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    #[tool(
        description = "Announce (publish) a service on the local network via mDNS so other \
            hosts and agents can discover it. Use when the agent itself exposes something on the \
            LAN (an HTTP API, a tool endpoint) and wants it findable. Registers with a heartbeat \
            lease and starts an automatic background heartbeat; the registration is unregistered \
            automatically when this MCP server shuts down. Returns the registration id and lease \
            seconds. Side effect: a new mDNS advertisement appears on the network.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn lan_announce(
        &self,
        Parameters(req): Parameters<AnnounceReq>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        let payload = tools::announce_payload(&req);
        match self.source.register(payload).await {
            Ok(result) => {
                let lease_secs = result.lease_secs.unwrap_or(0);
                if lease_secs > 0 {
                    self.registry
                        .track(&self.source, result.id.clone(), lease_secs)
                        .await;
                }
                Ok(structured(serde_json::json!({
                    "id": result.id,
                    "name": result.name,
                    "type": result.service_type,
                    "port": result.port,
                    "lease_secs": lease_secs,
                })))
            }
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    #[tool(
        description = "Unregister a service previously announced with `lan_announce`, by its \
            registration id. Cancels the automatic heartbeat and removes the mDNS advertisement \
            immediately. Use to retract a service before the lease would otherwise expire. \
            Side effect: the advertisement is withdrawn from the network.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true
        )
    )]
    async fn lan_unregister(
        &self,
        Parameters(req): Parameters<UnregisterReq>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        self.registry.untrack(&req.id).await;
        match self.source.unregister(req.id.clone()).await {
            Ok(()) => Ok(structured(serde_json::json!({ "unregistered": req.id }))),
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    // ── DNS ─────────────────────────────────────────────────────────

    #[tool(
        description = "Look up a name through Koi's local DNS resolver. Use to check whether a \
            name resolves and to which IPs before connecting (e.g. `grafana.lan`). `record_type` \
            is A (default), AAAA, or ANY. Returns the resolved IPs and their source. Read-only.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn dns_lookup(
        &self,
        Parameters(req): Parameters<DnsLookupReq>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        let record_type = tools::parse_record_type(req.record_type.as_deref());
        match self.source.dns_lookup(req.name.clone(), record_type).await {
            Ok(value) => Ok(structured(value)),
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    #[tool(
        description = "Add or update a static DNS record in Koi's local resolver, mapping a name \
            to an IP. Use to give a service a stable, human-friendly name (e.g. `app.lan` -> \
            10.0.0.5) that survives container restarts. If `ip` is omitted, Koi resolves the \
            current host's address. Side effect: a persistent DNS record is created/updated.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn dns_add(
        &self,
        Parameters(req): Parameters<DnsAddReq>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        let ip = match tools::resolve_add_ip(req.ip.as_deref()) {
            Ok(ip) => ip,
            Err(msg) => return Ok(text_error(&msg)),
        };
        match self.source.dns_add(req.name.clone(), ip, req.ttl).await {
            Ok(value) => Ok(structured(value)),
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    #[tool(
        description = "Remove a static DNS record from Koi's local resolver by name. Use to \
            retract a name mapping created with `dns_add`. Side effect: the record is deleted.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true
        )
    )]
    async fn dns_remove(
        &self,
        Parameters(req): Parameters<DnsRemoveReq>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        match self.source.dns_remove(req.name.clone()).await {
            Ok(value) => Ok(structured(value)),
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    // ── Aggregate / read-only views ──────────────────────────────────

    #[tool(
        description = "Get a single consolidated view of the LAN substrate: capability status, \
            service health, and the DNS name table, joined into one JSON document. Use this as \
            the agent's first orienting call to understand the whole environment at once instead \
            of issuing several reads. Read-only.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn lan_inventory(
        &self,
        Parameters(req): Parameters<InventoryReq>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        match self.source.inventory_snapshot(req.include.clone()).await {
            Ok(value) => Ok(structured(value)),
            Err(error) => Ok(source_error_result(&error)),
        }
    }

    #[tool(
        description = "Get a snapshot of all health checks the daemon is running (machines and \
            services, with up/down/unknown state). Use to decide whether a target is healthy \
            before routing work to it. Read-only.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn health_snapshot(&self) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        match self.source.health_status().await {
            Ok(value) => Ok(structured(value)),
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    #[tool(
        description = "List the container/service runtime instances Koi is tracking (e.g. Docker \
            containers), with their ports, IPs, and Koi metadata. Use to see what is actually \
            running locally. Read-only.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn runtime_instances(&self) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        match self.source.runtime_instances().await {
            Ok(value) => Ok(structured(value)),
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    #[tool(
        description = "Find other MCP servers advertised on the local network. Browses the \
            `_mcp._tcp` mDNS type (Koi's convention, pending an MCP discovery standard) and \
            returns connectable endpoints with their TXT metadata (transport, path, name). Use \
            to discover peer agents/tools on the LAN. Read-only.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn mcp_servers_on_lan(&self) -> Result<CallToolResult, ErrorData> {
        if let Err(result) = self.require_daemon().await {
            return Ok(result);
        }
        let window = Duration::from_secs(DEFAULT_DISCOVER_SECS);
        match self
            .source
            .browse(Some(MCP_SERVICE_TYPE.to_string()), window)
            .await
        {
            Ok(records) => {
                let servers = tools::to_mcp_endpoints(&records);
                Ok(structured(serde_json::json!({ "servers": servers })))
            }
            Err(e) => Ok(source_error_result(&e)),
        }
    }

    // ── Shared guard ────────────────────────────────────────────────

    /// Probe the source; on failure return a ready-made actionable error result.
    /// The in-process `CoreSource` is always available; the stdio `ClientSource`
    /// probes the daemon over HTTP.
    async fn require_daemon(&self) -> Result<(), CallToolResult> {
        if self.source.is_available().await {
            Ok(())
        } else {
            Err(text_error(NO_DAEMON_MSG))
        }
    }

    /// Unregister every tracked announcement. Call on shutdown.
    pub async fn shutdown(&self) {
        // Keep every handle in the session-owned map until its abort is reaped.
        // Cancelling this waiter therefore leaves the remaining handles owned by
        // `SubscriptionTasks` for a later shutdown/drop instead of detaching them.
        self.subs.stop().await;
        self.registry.shutdown(&self.source).await;
    }
}

#[tool_handler]
impl<S: KoiSource> ServerHandler for Server<S> {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo and Implementation are both #[non_exhaustive] — build via
        // default() and mutate rather than a struct literal.
        let mut implementation = Implementation::default();
        implementation.name = "koi-mcp".to_string();
        implementation.version = env!("CARGO_PKG_VERSION").to_string();

        let mut info = ServerInfo::default();
        info.server_info = implementation;
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .enable_resources_subscribe()
            .build();
        info.instructions = Some(
            "Koi exposes the local network as a substrate for agents: discover, name, and \
             announce LAN services. Tools prefixed `lan_`/`dns_` operate against a running Koi \
             daemon. Start with `lan_inventory` to orient, `lan_discover` to browse, and \
             `lan_announce` to publish your own service (auto-heartbeated, auto-unregistered \
             on shutdown). All mutations require a reachable daemon."
                .to_string(),
        );
        info
    }

    // ── Resources: snapshot-on-read + (in-process) resources/updated deltas ──

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            resource_descriptor(
                URI_INVENTORY,
                "LAN inventory",
                "Joined capability status, service health, and the DNS name table.",
            ),
            resource_descriptor(
                URI_HEALTH,
                "Service health",
                "Snapshot of every machine/service health check.",
            ),
            resource_descriptor(
                URI_DNS,
                "DNS names",
                "All names resolvable by the local DNS resolver.",
            ),
            resource_descriptor(
                URI_MDNS,
                "Discovered LAN services",
                "Cached mDNS-discovered services on the network.",
            ),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let uri = request.uri;
        let value = match uri.as_str() {
            URI_INVENTORY => self
                .source
                .inventory_snapshot(None)
                .await
                .map_err(resource_err)?,
            URI_HEALTH => self.source.health_status().await.map_err(resource_err)?,
            URI_DNS => self.source.dns_list().await.map_err(resource_err)?,
            URI_MDNS => self.source.mdns_snapshot().await.map_err(resource_err)?,
            other => {
                return Err(ErrorData::invalid_params(
                    format!("unknown resource: {other}"),
                    None,
                ))
            }
        };
        let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string());
        let contents = ResourceContents::text(text, &uri).with_mime_type("application/json");
        Ok(ReadResourceResult::new(vec![contents]))
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let uri = request.uri;
        if !is_known_resource(&uri) {
            return Err(ErrorData::invalid_params(
                format!("unknown resource: {uri}"),
                None,
            ));
        }
        // Live deltas need a change stream — only the in-process transport has one.
        // Over stdio the subscription is accepted but only the snapshot (read) is
        // available; this is documented behavior, not an error.
        if let Some(mut rx) = self.source.change_stream() {
            let peer = context.peer.clone();
            let watched = uri.clone();
            let task = tokio::spawn(async move {
                loop {
                    let changed = match rx.recv().await {
                        Ok(change) => change_matches(&watched, change),
                        // Lagged: we missed events — assume the resource changed.
                        Err(broadcast::error::RecvError::Lagged(_)) => true,
                        Err(broadcast::error::RecvError::Closed) => break,
                    };
                    if changed
                        && peer
                            .notify_resource_updated(ResourceUpdatedNotificationParam::new(
                                watched.clone(),
                            ))
                            .await
                            .is_err()
                    {
                        break; // peer/session gone
                    }
                }
            });
            let previous = self.subs.tasks.lock().await.insert(uri, task);
            if let Some(previous) = previous {
                abort_and_reap(previous).await;
            }
        }
        Ok(())
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        if let Some(task) = self.subs.tasks.lock().await.remove(&request.uri) {
            abort_and_reap(task).await;
        }
        Ok(())
    }
}

struct AbortOnDropTask(Option<JoinHandle<()>>);

impl Drop for AbortOnDropTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.as_ref() {
            task.abort();
        }
    }
}

async fn abort_and_reap(task: JoinHandle<()>) {
    let mut task = AbortOnDropTask(Some(task));
    let handle = task.0.as_mut().expect("owned MCP session task");
    handle.abort();
    let _ = handle.await;
    task.0.take();
}

// ── Result helpers (one consistent error pattern) ─────────────────────

/// A successful structured result.
fn structured(value: serde_json::Value) -> CallToolResult {
    CallToolResult::structured(value)
}

/// A tool-level error returned as an error result with a text message.
fn text_error(message: &str) -> CallToolResult {
    CallToolResult::error(vec![Content::text(message.to_string())])
}

/// Map a source error to a tool error result. Never leaks the token.
fn source_error_result(err: &SourceError) -> CallToolResult {
    text_error(&err.to_string())
}

/// Map a source error to an MCP resource error (used by `read_resource`).
fn resource_err(err: SourceError) -> ErrorData {
    ErrorData::internal_error(err.to_string(), None)
}

/// Build a resource descriptor for `list_resources`.
fn resource_descriptor(uri: &str, name: &str, description: &str) -> Resource {
    let mut raw = RawResource::new(uri, name);
    raw.description = Some(description.to_string());
    raw.mime_type = Some("application/json".to_string());
    raw.no_annotation()
}

/// Whether `uri` is one of Koi's exposed MCP resources.
fn is_known_resource(uri: &str) -> bool {
    matches!(uri, URI_INVENTORY | URI_HEALTH | URI_DNS | URI_MDNS)
}

/// Whether a `ResourceChange` should trigger a `resources/updated` for `uri`.
/// Each signal names exactly the resource projection that changed.
fn change_matches(uri: &str, change: ResourceChange) -> bool {
    match uri {
        URI_INVENTORY => change == ResourceChange::Inventory,
        URI_HEALTH => change == ResourceChange::Health,
        URI_DNS => change == ResourceChange::Dns,
        URI_MDNS => change == ResourceChange::Mdns,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_subscription_shutdown_retains_the_join_handle() {
        let subscriptions = Arc::new(SubscriptionTasks::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        });
        started_rx.await.expect("blocking relay started");
        subscriptions
            .tasks
            .lock()
            .await
            .insert(URI_INVENTORY.to_string(), task);

        let stopping = tokio::spawn({
            let subscriptions = Arc::clone(&subscriptions);
            async move { subscriptions.stop().await }
        });
        for _ in 0..32 {
            if subscriptions.tasks.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(subscriptions.tasks.try_lock().is_err());
        stopping.abort();
        assert!(stopping.await.unwrap_err().is_cancelled());
        assert!(
            subscriptions.tasks.lock().await.contains_key(URI_INVENTORY),
            "cancelled waiter detached the relay"
        );

        release_tx.send(()).expect("release blocking relay");
        subscriptions.stop().await;
        subscriptions.stop().await;
        assert!(subscriptions.tasks.lock().await.is_empty());
    }

    #[test]
    fn resource_change_signals_match_one_projection() {
        assert!(change_matches(URI_INVENTORY, ResourceChange::Inventory));
        assert!(!change_matches(URI_INVENTORY, ResourceChange::Health));
        assert!(change_matches(URI_HEALTH, ResourceChange::Health));
        assert!(change_matches(URI_DNS, ResourceChange::Dns));
        assert!(change_matches(URI_MDNS, ResourceChange::Mdns));
    }

    #[test]
    fn domain_resources_match_only_their_domain() {
        assert!(change_matches(URI_HEALTH, ResourceChange::Health));
        assert!(!change_matches(URI_HEALTH, ResourceChange::Dns));
        assert!(change_matches(URI_DNS, ResourceChange::Dns));
        assert!(!change_matches(URI_DNS, ResourceChange::Mdns));
        assert!(change_matches(URI_MDNS, ResourceChange::Mdns));
        assert!(!change_matches(URI_MDNS, ResourceChange::Health));
    }

    #[test]
    fn known_resources_are_recognized() {
        assert!(is_known_resource(URI_INVENTORY));
        assert!(is_known_resource(URI_MDNS));
        assert!(!is_known_resource("koi://nope"));
    }
}
