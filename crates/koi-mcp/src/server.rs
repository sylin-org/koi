//! The MCP `Server`: tool router, tool handlers, and the `ServerHandler` info.
//!
//! `Server<S>` is generic over a [`KoiSource`] data backing, so the same tool
//! surface serves both the stdio transport (backed by [`crate::ClientSource`], a
//! blocking `KoiClient`) and the in-process HTTP transport (backed by the binary's
//! `CoreSource`, the live domain cores). Handlers call `self.source.<method>()` —
//! they never touch a concrete client. Read tools carry `read_only_hint`; additive
//! writers carry `destructive_hint = false`; removers carry `destructive_hint = true`.
//! The token is never echoed in any tool output.

use std::sync::Arc;
use std::time::Duration;

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ErrorData, ServerHandler,
};

use crate::client::NO_DAEMON_MSG;
use crate::heartbeat::Registry;
use crate::source::{KoiSource, SourceError};
use crate::tools::{
    self, AnnounceReq, DiscoverReq, DnsAddReq, DnsLookupReq, DnsRemoveReq, InventoryReq,
    ResolveReq, UnregisterReq,
};

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
}

// Hand-written so `Server<S>` is `Clone` without forcing `S: Clone` (the source is
// shared behind an `Arc`). The stdio path clones the server before serving.
impl<S> Clone for Server<S> {
    fn clone(&self) -> Self {
        Self {
            source: Arc::clone(&self.source),
            registry: self.registry.clone(),
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
        // Three sources, each tolerant of failure so a single disabled capability
        // does not blank the whole inventory. `include` optionally narrows the set.
        let want = |source: &str| tools::inventory_includes(req.include.as_deref(), source);
        let status = if want("status") {
            self.source.unified_status().await.ok()
        } else {
            None
        };
        let health = if want("health") {
            self.source.health_status().await.ok()
        } else {
            None
        };
        let dns = if want("dns") {
            self.source.dns_list().await.ok()
        } else {
            None
        };
        Ok(structured(serde_json::json!({
            "status": status,
            "health": health,
            "dns": dns,
        })))
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
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
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
