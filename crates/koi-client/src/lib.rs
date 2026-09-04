//! HTTP client for communicating with a running Koi daemon.
//!
//! Uses blocking `ureq` - no async runtime dependency on the client path.
//! All paths use `/v1/mdns/` prefix for mDNS domain routes.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use koi_common::api::DnsLookupResult;
use koi_common::integration::MdnsDiscoverySnapshot;
use koi_common::local_control::{
    LocalControlRequest, LocalControlResponse, LocalDaemonAccess, LocalDaemonInfo,
    LOCAL_CONTROL_VERSION,
};
use koi_common::mdns_protocol::{
    AdminRegistration, DaemonStatus, LeaseMode, RegisterPayload, RegistrationResult, RenewalResult,
};
use koi_common::net::resolve_localhost;
use koi_common::pond::PondStatus;
use koi_common::types::{ServiceCheckKind, ServiceRecord};

/// TCP connection timeout for general API requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read timeout for general (non-streaming) API requests.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the fast health check probe.
const HEALTH_TIMEOUT: Duration = Duration::from_millis(200);

/// Maximum time an idle SSE read can remain inside the blocking transport after
/// cancellation. Koi's SSE endpoints emit liveness comments well inside this
/// window; reaching it without cancellation is therefore a terminal transport
/// failure, not an invitation to resume after a possibly partial frame.
pub const SSE_CANCELLATION_BOUND: Duration = Duration::from_secs(2);

// ── Error types ───────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Daemon not reachable: {0}")]
    Unreachable(String),

    /// HTTP 401 from the daemon: the request needs a Daemon Access Token.
    /// Surfaced distinctly (instead of a generic `Api`) so the CLI can print an
    /// actionable hint when talking to an explicit `--endpoint`.
    #[error("remote daemon requires a token (pass --token or set KOI_TOKEN)")]
    Unauthorized,

    #[error("{error}: {message}")]
    Api { error: String, message: String },

    #[error("Request failed: {0}")]
    Transport(String),

    #[error("Invalid response: {0}")]
    Decode(String),
}

impl ClientError {
    /// Whether this error is an HTTP 401 (missing/invalid token).
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, ClientError::Unauthorized)
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Transport outcome for a Pond lifecycle command.
///
/// Terminal daemon shutdown returns the same typed status with HTTP 503. Keeping
/// that disposition prevents callers from confusing an observed unavailable
/// runtime with an acknowledged command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PondCommandOutcome {
    Succeeded(PondStatus),
    Unavailable(PondStatus),
}

/// Evidence about the machine-local daemon owner.
///
/// `Absent` is reserved for a positively missing breadcrumb and every known
/// local-control transport being absent. Permission, parsing, timeout, and
/// protocol failures are `Uncertain`; callers must not turn them into
/// permission to open the same native resources or durable state themselves.
pub enum LocalDaemonObservation<T> {
    Present(T),
    Absent,
    Uncertain(ClientError),
}

impl<T> LocalDaemonObservation<T> {
    fn into_result(self, absent_message: &'static str) -> Result<T> {
        match self {
            Self::Present(value) => Ok(value),
            Self::Absent => Err(ClientError::Unreachable(absent_message.to_string())),
            Self::Uncertain(error) => Err(error),
        }
    }
}

// ── Client ────────────────────────────────────────────────────────

/// Header name for Daemon Access Token authentication.
const DAT_HEADER: &str = "X-Koi-Token";

pub struct KoiClient {
    endpoint: String,
    agent: ureq::Agent,
    /// Daemon Access Token (empty string means no auth).
    token: String,
}

impl KoiClient {
    pub fn new(endpoint: &str) -> Self {
        let clean = endpoint.trim_end_matches('/');
        let resolved = resolve_localhost(clean);
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout_read(READ_TIMEOUT)
            .build();
        Self {
            endpoint: resolved,
            agent,
            token: String::new(),
        }
    }

    /// Create a client with a Daemon Access Token for authenticated requests.
    pub fn with_token(endpoint: &str, token: &str) -> Self {
        let mut client = Self::new(endpoint);
        client.token = token.to_string();
        client
    }

    /// Create a client from the breadcrumb file (endpoint + token).
    ///
    /// Returns `Ok(None)` only if no breadcrumb exists. A malformed or
    /// unreadable owner publication remains an error.
    pub fn from_breadcrumb() -> Result<Option<Self>> {
        koi_config::breadcrumb::read_breadcrumb()
            .map(|breadcrumb| {
                breadcrumb.map(|value| Self::with_token(&value.endpoint, &value.token))
            })
            .map_err(map_breadcrumb_error)
    }

    /// Create a client for the real local daemon, using the private breadcrumb
    /// when readable and the authenticated local-control transport otherwise.
    pub fn from_local() -> Result<Self> {
        let access = local_daemon_access()?;
        Ok(Self::with_token(&access.endpoint, &access.token))
    }

    /// Attach the DAT header to a request if a token is present.
    fn auth_get(&self, url: &str) -> ureq::Request {
        let req = self.agent.get(url);
        if self.token.is_empty() {
            req
        } else {
            req.set(DAT_HEADER, &self.token)
        }
    }

    /// Attach the DAT header to a POST request.
    fn auth_post(&self, url: &str) -> ureq::Request {
        let req = self.agent.post(url);
        if self.token.is_empty() {
            req
        } else {
            req.set(DAT_HEADER, &self.token)
        }
    }

    /// Attach the DAT header to a PUT request.
    fn auth_put(&self, url: &str) -> ureq::Request {
        let req = self.agent.put(url);
        if self.token.is_empty() {
            req
        } else {
            req.set(DAT_HEADER, &self.token)
        }
    }

    /// Attach the DAT header to a DELETE request.
    fn auth_delete(&self, url: &str) -> ureq::Request {
        let req = self.agent.delete(url);
        if self.token.is_empty() {
            req
        } else {
            req.set(DAT_HEADER, &self.token)
        }
    }

    // ── Health ────────────────────────────────────────────────────

    /// Quick health check with a 200ms timeout.
    pub fn health(&self) -> Result<()> {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(HEALTH_TIMEOUT)
            .timeout_read(HEALTH_TIMEOUT)
            .build();
        let url = format!("{}/healthz", self.endpoint);
        agent.get(&url).call().map_err(map_error)?;
        Ok(())
    }

    // ── Service operations (mDNS) ──────────────────────────────────

    pub fn register(&self, payload: &RegisterPayload) -> Result<RegistrationResult> {
        let url = format!("{}/v1/mdns/announce", self.endpoint);
        let json_val =
            serde_json::to_value(payload).map_err(|e| ClientError::Decode(e.to_string()))?;
        let resp = self
            .auth_post(&url)
            .send_json(json_val)
            .map_err(map_error)?;
        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))?;
        let registered = json
            .get("registered")
            .ok_or_else(|| ClientError::Decode("Missing 'registered' in response".to_string()))?;
        require_fields(
            registered,
            &["id", "name", "type", "port", "mode", "lease_secs"],
            "mDNS registration response",
        )?;
        let result: RegistrationResult = extract(&json, "registered")?;
        if result.mode != LeaseMode::Heartbeat {
            return Err(ClientError::Decode(format!(
                "mDNS announce response has non-heartbeat mode `{:?}`",
                result.mode
            )));
        }
        let Some(lease_secs) = result.lease_secs else {
            return Err(ClientError::Decode(
                "mDNS announce response has no heartbeat lease".to_string(),
            ));
        };
        if lease_secs == 0 {
            return Err(ClientError::Decode(
                "mDNS announce response has a zero heartbeat lease".to_string(),
            ));
        }
        match payload.lease_secs {
            Some(requested) if requested != lease_secs => {
                return Err(ClientError::Decode(format!(
                    "mDNS announce acknowledged lease `{lease_secs}` instead of requested lease `{requested}`"
                )));
            }
            _ => {}
        }
        Ok(result)
    }

    pub fn unregister(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/mdns/unregister/{id}", self.endpoint);
        let response = self.auth_delete(&url).call().map_err(map_error)?;
        let json: serde_json::Value = response
            .into_json()
            .map_err(|error| ClientError::Decode(error.to_string()))?;
        let acknowledged: String = extract(&json, "unregistered")?;
        if acknowledged == id {
            Ok(())
        } else {
            Err(ClientError::Decode(format!(
                "unregister acknowledged id `{acknowledged}` instead of requested id `{id}`"
            )))
        }
    }

    pub fn heartbeat(&self, id: &str) -> Result<RenewalResult> {
        let url = format!("{}/v1/mdns/heartbeat/{id}", self.endpoint);
        let resp = self.auth_put(&url).send_bytes(&[]).map_err(map_error)?;
        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))?;
        let renewed: RenewalResult = extract(&json, "renewed")?;
        if renewed.id != id {
            return Err(ClientError::Decode(format!(
                "heartbeat acknowledged id `{}` instead of requested id `{id}`",
                renewed.id
            )));
        }
        if renewed.lease_secs == 0 {
            return Err(ClientError::Decode(
                "heartbeat response has a zero lease".to_string(),
            ));
        }
        Ok(renewed)
    }

    pub fn resolve(&self, instance: &str) -> Result<ServiceRecord> {
        let url = format!("{}/v1/mdns/resolve", self.endpoint);
        let resp = self
            .auth_get(&url)
            .query("name", instance)
            .call()
            .map_err(map_error)?;
        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))?;
        let resolved = json
            .get("resolved")
            .ok_or_else(|| ClientError::Decode("Missing 'resolved' in response".to_string()))?;
        require_fields(resolved, &["name", "type", "txt"], "mDNS resolve response")?;
        extract(&json, "resolved")
    }

    /// Read the mDNS domain's authoritative latest discovery projection.
    pub fn mdns_discovery_snapshot(&self) -> Result<MdnsDiscoverySnapshot> {
        let value = self.get_json("/v1/mdns/snapshot")?;
        require_fields(
            &value,
            &["revision", "service_types", "records"],
            "mDNS discovery snapshot",
        )?;
        let records = value["records"].as_array().ok_or_else(|| {
            ClientError::Decode("mDNS discovery snapshot field `records` is not an array".into())
        })?;
        for record in records {
            require_fields(record, &["name", "type", "txt"], "mDNS discovery record")?;
        }
        serde_json::from_value(value).map_err(|error| ClientError::Decode(error.to_string()))
    }

    /// Start a browse SSE stream. Returns an iterator of JSON events.
    pub fn browse_stream(&self, service_type: &str) -> Result<SseStream> {
        let url = format!("{}/v1/mdns/discover", self.endpoint);
        let mut req = self.stream_agent().get(&url);
        if !self.token.is_empty() {
            req = req.set(DAT_HEADER, &self.token);
        }
        let resp = req
            .query("type", service_type)
            .query("idle_for", "0")
            .call()
            .map_err(map_error)?;
        Ok(SseStream::new(Box::new(resp.into_reader())))
    }

    /// Start an events SSE stream. Returns an iterator of JSON events.
    pub fn events_stream(&self, service_type: &str) -> Result<SseStream> {
        let url = format!("{}/v1/mdns/subscribe", self.endpoint);
        let mut req = self.stream_agent().get(&url);
        if !self.token.is_empty() {
            req = req.set(DAT_HEADER, &self.token);
        }
        let resp = req
            .query("type", service_type)
            .query("idle_for", "0")
            .call()
            .map_err(map_error)?;
        Ok(SseStream::new(Box::new(resp.into_reader())))
    }

    // ── Unified status ─────────────────────────────────────────────

    /// Fetch unified status from `/v1/status`.
    pub fn unified_status(&self) -> Result<serde_json::Value> {
        let url = format!("{}/v1/status", self.endpoint);
        let resp = self.auth_get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    // ── Pond operations ────────────────────────────────────────────

    /// Read the authenticated desired and observed Pond state.
    pub fn pond_status(&self) -> Result<PondStatus> {
        let url = format!("{}/v1/pond", self.endpoint);
        let response = self.auth_get(&url).call().map_err(map_error)?;
        decode_pond_status(response, "Pond status")
    }

    /// Persistently enable Pond and preserve terminal HTTP 503 as typed status.
    pub fn pond_enable(&self) -> Result<PondCommandOutcome> {
        let url = format!("{}/v1/pond", self.endpoint);
        decode_pond_command(self.auth_put(&url).send_json(serde_json::json!({})))
    }

    /// Persistently disable Pond and preserve terminal HTTP 503 as typed status.
    pub fn pond_disable(&self) -> Result<PondCommandOutcome> {
        let url = format!("{}/v1/pond", self.endpoint);
        decode_pond_command(self.auth_delete(&url).send_json(serde_json::json!({})))
    }

    /// Fetch capability, health, and DNS inventory captured from one daemon
    /// aggregate revision. Unlike issuing the three component reads separately,
    /// this cannot assemble a torn cross-domain view.
    pub fn inventory_snapshot(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/inventory")
    }

    /// Fetch the authenticated, domain-owned Certmesh status projection.
    ///
    /// Remote callers need a Daemon Access Token. Discovery and enrollment
    /// preflight must use [`Self::certmesh_bootstrap`] instead.
    pub fn certmesh_status(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/certmesh/status")
    }

    /// Fetch the selected daemon's full Certmesh diagnosis. The caller owns
    /// strict decoding into the domain DTO so this lean client does not depend
    /// on another domain crate.
    pub fn certmesh_diagnosis(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/certmesh/diagnose")
    }

    /// Fetch the selected daemon's CA certificate, preserving the domain's
    /// explicit not-initialized state without converting transport uncertainty
    /// into absence.
    pub fn certmesh_ca_certificate(&self) -> Result<Option<serde_json::Value>> {
        match self.get_json("/v1/certmesh/ca-cert") {
            Ok(response) => Ok(Some(response)),
            Err(ClientError::Api { error, .. }) if error == "ca_not_initialized" => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Fetch the minimal public Certmesh authority preflight.
    ///
    /// This endpoint intentionally carries only the information needed to
    /// select and pin an authority before enrollment; it never exposes roster
    /// or local identity health. The request never carries this client's DAT,
    /// so a local credential cannot leak when the endpoint names a remote CA.
    pub fn certmesh_bootstrap(&self) -> Result<serde_json::Value> {
        let url = format!("{}/v1/certmesh/bootstrap", self.endpoint);
        let resp = self.agent.get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|error| ClientError::Decode(error.to_string()))
    }

    /// Clear Pond's durable current UI selection while retaining immutable generations.
    pub fn pond_clear_ui(&self) -> Result<serde_json::Value> {
        let url = format!("{}/v1/ui", self.endpoint);
        let resp = self.auth_delete(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|error| ClientError::Decode(error.to_string()))
    }

    // ── DNS operations (Phase 6) ───────────────────────────────────

    pub fn dns_status(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/dns/status")
    }

    pub fn dns_lookup(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Option<DnsLookupResult>> {
        let record_type = record_type_str(record_type)?;
        let url = format!("{}/v1/dns/lookup", self.endpoint);
        let resp = match self
            .auth_get(&url)
            .query("name", name)
            .query("type", record_type)
            .call()
        {
            Ok(response) => response,
            Err(error) => match map_error(error) {
                ClientError::Api { error, .. } if error == "not_found" => return Ok(None),
                error => return Err(error),
            },
        };
        resp.into_json()
            .map(Some)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn dns_list(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/dns/list")
    }

    pub fn dns_add(&self, name: &str, ip: &str, ttl: Option<u32>) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "name": name,
            "ip": ip,
            "ttl": ttl,
        });
        self.post_json("/v1/dns/add", &body)
    }

    pub fn dns_remove(&self, name: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/dns/remove/{}", self.endpoint, name);
        let resp = self.auth_delete(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn dns_txt_set(&self, name: &str, value: &str) -> Result<serde_json::Value> {
        self.put_json(
            "/v1/dns/txt",
            &serde_json::json!({ "name": name, "value": value }),
        )
    }

    pub fn dns_txt_clear(&self, name: &str, value: &str) -> Result<serde_json::Value> {
        self.delete_json(
            "/v1/dns/txt",
            &serde_json::json!({ "name": name, "value": value }),
        )
    }

    pub fn dns_start(&self) -> Result<bool> {
        let response = self.post_json("/v1/dns/serve", &serde_json::json!({}))?;
        extract(&response, "started")
    }

    pub fn dns_stop(&self) -> Result<bool> {
        let response = self.post_json("/v1/dns/stop", &serde_json::json!({}))?;
        extract(&response, "stopped")
    }

    // ── Health operations (Phase 7) ───────────────────────────────

    pub fn health_status(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/health/status")
    }

    pub fn health_log(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/health/log")
    }

    pub fn health_add_check(
        &self,
        name: &str,
        kind: ServiceCheckKind,
        target: &str,
        interval_secs: u64,
        timeout_secs: u64,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "name": name,
            "kind": check_kind_str(kind),
            "target": target,
            "interval_secs": interval_secs,
            "timeout_secs": timeout_secs,
        });
        self.post_json("/v1/health/add", &body)
    }

    pub fn health_remove_check(&self, name: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/health/remove/{}", self.endpoint, name);
        let resp = self.auth_delete(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    // ── Trust operations ──────────────────────────────────────────

    /// Read the selected daemon owner's authoritative Trust status.
    pub fn trust_status(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/trust/status")
    }

    /// Install one operator-owned CA root through the selected Trust owner.
    pub fn trust_install(
        &self,
        name: &str,
        source: &str,
        certificate_pem: &str,
    ) -> Result<serde_json::Value> {
        self.post_json(
            "/v1/trust/install",
            &serde_json::json!({
                "name": name,
                "source": source,
                "certificate_pem": certificate_pem,
            }),
        )
    }

    /// Ensure one source-owned CA root through the selected Trust owner.
    pub fn trust_ensure_installed(
        &self,
        name: &str,
        source: &str,
        certificate_pem: &str,
    ) -> Result<serde_json::Value> {
        self.post_json(
            "/v1/trust/ensure",
            &serde_json::json!({
                "name": name,
                "source": source,
                "certificate_pem": certificate_pem,
            }),
        )
    }

    /// Remove one Koi-managed root through the selected Trust owner.
    pub fn trust_remove(&self, name: &str) -> Result<serde_json::Value> {
        self.delete_json("/v1/trust/remove", &serde_json::json!({ "name": name }))
    }

    /// Inspect one certificate through the selected owner's real platform
    /// adapter. This is an operator read and intentionally uses the authenticated
    /// management surface.
    pub fn trust_inspect(&self, certificate_pem: &str) -> Result<serde_json::Value> {
        self.post_json(
            "/v1/trust/inspect",
            &serde_json::json!({ "certificate_pem": certificate_pem }),
        )
    }

    /// Replay pending Trust intent through the selected owner.
    pub fn trust_reconcile(&self) -> Result<serde_json::Value> {
        self.post_json("/v1/trust/reconcile", &serde_json::json!({}))
    }

    // ── Proxy operations (Phase 8) ───────────────────────────────

    pub fn proxy_status(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/proxy/status")
    }

    pub fn proxy_list(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/proxy/list")
    }

    pub fn proxy_add(
        &self,
        name: &str,
        listen_port: u16,
        backend: &str,
        allow_remote: bool,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "name": name,
            "listen_port": listen_port,
            "backend": backend,
            "allow_remote": allow_remote,
        });
        self.post_json("/v1/proxy/add", &body)
    }

    pub fn proxy_remove(&self, name: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/proxy/remove/{}", self.endpoint, name);
        let resp = self.auth_delete(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    // ── UDP operations ─────────────────────────────────────────────

    pub fn udp_status(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/udp/status")
    }

    pub fn udp_bind(
        &self,
        port: u16,
        addr: &str,
        lease_secs: u64,
        allow_remote: bool,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "port": port,
            "addr": addr,
            "lease_secs": lease_secs,
            "allow_remote": allow_remote,
        });
        self.post_json("/v1/udp/bind", &body)
    }

    pub fn udp_unbind(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/udp/bind/{}", self.endpoint, id);
        let resp = self.auth_delete(&url).call().map_err(map_error)?;
        let response = resp
            .into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))?;
        let acknowledged: String = extract(&response, "unbound")?;
        if acknowledged == id {
            Ok(())
        } else {
            Err(ClientError::Decode(format!(
                "UDP unbind acknowledged `{acknowledged}`, expected `{id}`"
            )))
        }
    }

    pub fn udp_send(&self, id: &str, dest: &str, payload_b64: &str) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "dest": dest,
            "payload": payload_b64,
        });
        let path = format!("/v1/udp/send/{id}");
        self.post_json(&path, &body)
    }

    pub fn udp_heartbeat(&self, id: &str) -> Result<serde_json::Value> {
        let path = format!("/v1/udp/heartbeat/{id}");
        self.put_json(&path, &serde_json::json!({}))
    }

    // ── Generic operations ─────────────────────────────────────────

    /// POST JSON to an arbitrary path and return the response as a JSON value.
    pub fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.endpoint);
        let resp = self
            .auth_post(&url)
            .send_json(body.clone())
            .map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// GET JSON from an arbitrary path and return the response as a JSON value.
    pub fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.endpoint);
        let resp = self.auth_get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// PUT JSON to an arbitrary path and return the response as a JSON value.
    pub fn put_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.endpoint);
        let resp = self
            .auth_put(&url)
            .send_json(body.clone())
            .map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// DELETE JSON at an arbitrary path and return the response as a JSON value.
    pub fn delete_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.endpoint);
        let resp = self
            .auth_delete(&url)
            .send_json(body.clone())
            .map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    // ── Admin operations (mDNS) ──────────────────────────────────

    pub fn admin_status(&self) -> Result<DaemonStatus> {
        let url = format!("{}/v1/mdns/admin/status", self.endpoint);
        let resp = self.auth_get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn admin_registrations(&self) -> Result<Vec<AdminRegistration>> {
        let url = format!("{}/v1/mdns/admin/ls", self.endpoint);
        let resp = self.auth_get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn admin_inspect(&self, id: &str) -> Result<AdminRegistration> {
        let url = format!("{}/v1/mdns/admin/inspect/{id}", self.endpoint);
        let resp = self.auth_get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn admin_force_unregister(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/mdns/admin/unregister/{id}", self.endpoint);
        self.auth_delete(&url).call().map_err(map_error)?;
        Ok(())
    }

    pub fn admin_drain(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/mdns/admin/drain/{id}", self.endpoint);
        self.auth_post(&url).call().map_err(map_error)?;
        Ok(())
    }

    pub fn admin_revive(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/mdns/admin/revive/{id}", self.endpoint);
        self.auth_post(&url).call().map_err(map_error)?;
        Ok(())
    }

    // ── Admin operations (system) ────────────────────────────────────

    /// Request a graceful shutdown of the running daemon.
    ///
    /// Success acknowledges the daemon's accepted shutdown command. It does
    /// not claim terminal process completion; the HTTP listener is part of the
    /// generation being torn down and cannot carry that later acknowledgement.
    pub fn shutdown(&self) -> Result<()> {
        let url = format!("{}/v1/admin/shutdown", self.endpoint);
        let response = self.auth_post(&url).call().map_err(map_error)?;
        let json: serde_json::Value = response
            .into_json()
            .map_err(|error| ClientError::Decode(error.to_string()))?;
        match json.get("status").and_then(serde_json::Value::as_str) {
            Some("shutting_down") => Ok(()),
            Some(status) => Err(ClientError::Decode(format!(
                "shutdown response has unexpected status `{status}`"
            ))),
            None => Err(ClientError::Decode(
                "shutdown response is missing string field `status`".to_string(),
            )),
        }
    }

    // ── Private helpers ───────────────────────────────────────────

    /// SSE transport with a bounded individual-read wait. Healthy Koi peers
    /// send keepalive comments before this expires; cancellation and finite
    /// collection deadlines can therefore always reclaim their blocking owner.
    fn stream_agent(&self) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout_read(SSE_CANCELLATION_BOUND)
            .build()
    }
}

/// Resolve credentials for the real local daemon without ever pairing its DAT
/// with a caller-supplied or remote endpoint.
pub fn local_daemon_access() -> Result<LocalDaemonAccess> {
    observe_local_daemon_access().into_result("no local Koi daemon owner was found")
}

/// Observe local daemon ownership without collapsing uncertainty to absence.
pub fn observe_local_daemon_access() -> LocalDaemonObservation<LocalDaemonAccess> {
    match koi_config::breadcrumb::read_breadcrumb() {
        Ok(Some(breadcrumb)) => LocalDaemonObservation::Present(LocalDaemonAccess {
            version: LOCAL_CONTROL_VERSION,
            endpoint: breadcrumb.endpoint,
            token: breadcrumb.token,
            data_root: None,
        }),
        Ok(None) => request_local_access_observation(),
        Err(breadcrumb_error) => match request_local_access_observation() {
            LocalDaemonObservation::Present(access) => LocalDaemonObservation::Present(access),
            LocalDaemonObservation::Absent | LocalDaemonObservation::Uncertain(_) => {
                LocalDaemonObservation::Uncertain(map_breadcrumb_error(breadcrumb_error))
            }
        },
    }
}

fn request_local_access_observation() -> LocalDaemonObservation<LocalDaemonAccess> {
    match request_local_control_observation(&LocalControlRequest::access()) {
        LocalDaemonObservation::Present(response) => match parse_local_access(response) {
            Ok(access) => LocalDaemonObservation::Present(access),
            Err(error) => LocalDaemonObservation::Uncertain(error),
        },
        LocalDaemonObservation::Absent => LocalDaemonObservation::Absent,
        LocalDaemonObservation::Uncertain(error) => LocalDaemonObservation::Uncertain(error),
    }
}

fn parse_local_access(response: LocalControlResponse) -> Result<LocalDaemonAccess> {
    match response {
        LocalControlResponse::Access(access)
            if access.version == LOCAL_CONTROL_VERSION
                && !access.endpoint.is_empty()
                && !access.token.is_empty() =>
        {
            Ok(access)
        }
        LocalControlResponse::Access(_) => Err(ClientError::Decode(
            "invalid local daemon access response".to_string(),
        )),
        LocalControlResponse::Info(_) => Err(ClientError::Decode(
            "local daemon returned info to an access request".to_string(),
        )),
        LocalControlResponse::Error { code, message } => Err(ClientError::Api {
            error: code,
            message,
        }),
    }
}

/// Resolve non-secret facts from the authenticated local-control transport.
///
/// Unlike [`local_daemon_access`], this never falls back to the breadcrumb:
/// the daemon itself is the authority for its launch-time config path.
pub fn local_daemon_info() -> Result<LocalDaemonInfo> {
    observe_local_daemon_info().into_result("no local Koi daemon owner was found")
}

/// Observe the daemon's authoritative launch paths through local control.
pub fn observe_local_daemon_info() -> LocalDaemonObservation<LocalDaemonInfo> {
    match request_local_control_observation(&LocalControlRequest::info()) {
        LocalDaemonObservation::Present(response) => match parse_local_info(response) {
            Ok(info) => LocalDaemonObservation::Present(info),
            Err(error) => LocalDaemonObservation::Uncertain(error),
        },
        LocalDaemonObservation::Absent => LocalDaemonObservation::Absent,
        LocalDaemonObservation::Uncertain(error) => LocalDaemonObservation::Uncertain(error),
    }
}

fn parse_local_info(response: LocalControlResponse) -> Result<LocalDaemonInfo> {
    match response {
        LocalControlResponse::Info(info)
            if info.version == LOCAL_CONTROL_VERSION
                && !info.data_root.is_empty()
                && !info.config_path.is_empty() =>
        {
            Ok(info)
        }
        LocalControlResponse::Info(_) => Err(ClientError::Decode(
            "invalid local daemon info response".to_string(),
        )),
        LocalControlResponse::Access(_) => Err(ClientError::Decode(
            "local daemon returned access to an info request".to_string(),
        )),
        LocalControlResponse::Error { code, message } => Err(ClientError::Api {
            error: code,
            message,
        }),
    }
}

fn request_local_control_observation(
    request: &LocalControlRequest,
) -> LocalDaemonObservation<LocalControlResponse> {
    let request = match serde_json::to_string(request) {
        Ok(request) => request,
        Err(error) => {
            return LocalDaemonObservation::Uncertain(ClientError::Decode(error.to_string()))
        }
    };

    let mut first_uncertainty = None;
    for path in koi_config::breadcrumb::local_control_candidates() {
        match request_local_control_at(&path, &request) {
            Ok(response) => return LocalDaemonObservation::Present(response),
            Err(LocalControlAttemptError::Absent) => {}
            Err(LocalControlAttemptError::Uncertain(error)) => {
                first_uncertainty.get_or_insert(error);
            }
        }
    }
    first_uncertainty.map_or(
        LocalDaemonObservation::Absent,
        LocalDaemonObservation::Uncertain,
    )
}

enum LocalControlAttemptError {
    Absent,
    Uncertain(ClientError),
}

fn request_local_control_at(
    path: &std::path::Path,
    request: &str,
) -> std::result::Result<LocalControlResponse, LocalControlAttemptError> {
    #[cfg(unix)]
    let stream = {
        let stream =
            std::os::unix::net::UnixStream::connect(path).map_err(classify_connect_error)?;
        let timeout = Some(Duration::from_secs(2));
        stream.set_read_timeout(timeout).map_err(|error| {
            LocalControlAttemptError::Uncertain(ClientError::Transport(error.to_string()))
        })?;
        stream.set_write_timeout(timeout).map_err(|error| {
            LocalControlAttemptError::Uncertain(ClientError::Transport(error.to_string()))
        })?;
        stream
    };

    #[cfg(windows)]
    let stream = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(classify_connect_error)?;

    #[cfg(not(any(unix, windows)))]
    return Err(LocalControlAttemptError::Uncertain(
        ClientError::Unreachable("local control is unsupported on this platform".to_string()),
    ));

    #[cfg(any(unix, windows))]
    {
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(b"\n"))
            .and_then(|()| stream.flush())
            .map_err(|error| {
                LocalControlAttemptError::Uncertain(ClientError::Transport(error.to_string()))
            })?;
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|error| {
                LocalControlAttemptError::Uncertain(ClientError::Transport(error.to_string()))
            })?;
        serde_json::from_str::<LocalControlResponse>(line.trim()).map_err(|error| {
            LocalControlAttemptError::Uncertain(ClientError::Decode(error.to_string()))
        })
    }
}

fn classify_connect_error(error: std::io::Error) -> LocalControlAttemptError {
    match error.kind() {
        std::io::ErrorKind::NotFound => LocalControlAttemptError::Absent,
        _ => LocalControlAttemptError::Uncertain(ClientError::Unreachable(error.to_string())),
    }
}

fn map_breadcrumb_error(error: std::io::Error) -> ClientError {
    if error.kind() == std::io::ErrorKind::InvalidData {
        ClientError::Decode(format!("invalid local daemon breadcrumb: {error}"))
    } else {
        ClientError::Transport(format!("cannot read local daemon breadcrumb: {error}"))
    }
}

// ── SSE Stream ────────────────────────────────────────────────────

/// Iterator over Server-Sent Events from the Koi daemon.
///
/// Parses `data: <json>` lines, skipping empty lines and event metadata.
/// Clone [`SseCancellation`] before moving the stream to a blocking worker when
/// another task must stop it. Cancellation is bounded by
/// [`SSE_CANCELLATION_BOUND`] even when the peer becomes completely silent.
pub struct SseStream {
    reader: BufReader<Box<dyn Read + Send>>,
    cancellation: SseCancellation,
    deadline: Option<Instant>,
    terminated: bool,
}

/// Thread-safe stop handle for one [`SseStream`].
///
/// This is deliberately transport-local rather than an async cancellation
/// token: `koi-client` remains a blocking, runtime-independent boundary.
#[derive(Clone, Debug)]
pub struct SseCancellation {
    cancelled: Arc<AtomicBool>,
}

impl SseCancellation {
    /// Request clean local termination of the stream iterator.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl SseStream {
    fn new(reader: Box<dyn Read + Send>) -> Self {
        Self {
            reader: BufReader::new(reader),
            cancellation: SseCancellation {
                cancelled: Arc::new(AtomicBool::new(false)),
            },
            deadline: None,
            terminated: false,
        }
    }

    /// Obtain the stop handle before moving this blocking iterator to its owner.
    pub fn cancellation(&self) -> SseCancellation {
        self.cancellation.clone()
    }

    /// Stop this stream once `deadline` is observed. Koi keepalive comments
    /// provide the normal observation cadence; a silent peer is still bounded
    /// by [`SSE_CANCELLATION_BOUND`].
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    fn stop_requested(&self) -> bool {
        self.cancellation.is_cancelled()
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn terminate(&mut self) {
        self.terminated = true;
        self.cancellation.cancel();
    }
}

impl Iterator for SseStream {
    type Item = Result<serde_json::Value>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.terminated || self.stop_requested() {
                self.terminate();
                return None;
            }
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => {
                    self.terminate();
                    return None;
                }
                Ok(_) => {
                    if self.stop_requested() {
                        self.terminate();
                        return None;
                    }
                    let trimmed = line.trim();
                    if let Some(data) = trimmed.strip_prefix("data:") {
                        let data = data.trim_start();
                        if data.is_empty() {
                            continue;
                        }
                        match serde_json::from_str(data) {
                            Ok(json) => return Some(Ok(json)),
                            Err(e) => {
                                self.terminate();
                                return Some(Err(ClientError::Decode(e.to_string())));
                            }
                        }
                    }
                    continue;
                }
                Err(e) => {
                    let stopped = self.stop_requested();
                    self.terminate();
                    if stopped {
                        return None;
                    }
                    return Some(Err(ClientError::Transport(format!(
                        "SSE stream read failed: {e}"
                    ))));
                }
            }
        }
    }
}

impl Drop for SseStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

// ── Error helpers ─────────────────────────────────────────────────

fn decode_pond_command(
    response: std::result::Result<ureq::Response, ureq::Error>,
) -> Result<PondCommandOutcome> {
    match response {
        Ok(response) => {
            decode_pond_status(response, "Pond command response").map(PondCommandOutcome::Succeeded)
        }
        Err(ureq::Error::Status(503, response)) => {
            decode_pond_status(response, "Pond terminal response")
                .map(PondCommandOutcome::Unavailable)
        }
        Err(error) => Err(map_error(error)),
    }
}

fn decode_pond_status(response: ureq::Response, context: &str) -> Result<PondStatus> {
    response
        .into_json()
        .map_err(|error| ClientError::Decode(format!("invalid {context}: {error}")))
}

fn map_error(e: ureq::Error) -> ClientError {
    match e {
        ureq::Error::Status(401, _resp) => ClientError::Unauthorized,
        ureq::Error::Status(status, resp) => {
            let body = match resp.into_string() {
                Ok(body) => body,
                Err(error) => {
                    return ClientError::Transport(format!(
                        "HTTP {status} error body read failed: {error}"
                    ));
                }
            };
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(json) => match (
                    json.get("error").and_then(serde_json::Value::as_str),
                    json.get("message").and_then(serde_json::Value::as_str),
                ) {
                    (Some(error), Some(message)) => ClientError::Api {
                        error: error.to_string(),
                        message: message.to_string(),
                    },
                    _ => ClientError::Decode(format!(
                        "HTTP {status} error response does not contain string `error` and `message` fields; body: {body}"
                    )),
                },
                Err(error) => ClientError::Decode(format!(
                    "HTTP {status} error response is not valid JSON ({error}); body: {body}"
                )),
            }
        }
        ureq::Error::Transport(t) => ClientError::Unreachable(t.to_string()),
    }
}

fn record_type_str(record_type: RecordType) -> Result<&'static str> {
    match record_type {
        RecordType::A => Ok("A"),
        RecordType::AAAA => Ok("AAAA"),
        RecordType::ANY => Ok("ANY"),
        unsupported => Err(ClientError::Decode(format!(
            "unsupported DNS address record type: {unsupported}"
        ))),
    }
}

fn check_kind_str(kind: ServiceCheckKind) -> &'static str {
    match kind {
        ServiceCheckKind::Http => "http",
        ServiceCheckKind::Tcp => "tcp",
    }
}

fn require_fields(value: &serde_json::Value, fields: &[&str], context: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| ClientError::Decode(format!("{context} is not a JSON object")))?;
    for field in fields {
        if !object.contains_key(*field) {
            return Err(ClientError::Decode(format!(
                "{context} is missing field `{field}`"
            )));
        }
    }
    Ok(())
}

fn extract<T: serde::de::DeserializeOwned>(json: &serde_json::Value, key: &str) -> Result<T> {
    if let Some(err_val) = json.get("error") {
        let error = err_val
            .as_str()
            .ok_or_else(|| ClientError::Decode("error response has non-string `error`".into()))?
            .to_string();
        let message = json
            .get("message")
            .and_then(|m| m.as_str())
            .ok_or_else(|| ClientError::Decode("error response has no string `message`".into()))?
            .to_string();
        return Err(ClientError::Api { error, message });
    }
    json.get(key)
        .ok_or_else(|| ClientError::Decode(format!("Missing '{key}' in response")))
        .and_then(|v| {
            serde_json::from_value(v.clone()).map_err(|e| ClientError::Decode(e.to_string()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ────────────────────────────────────────────────

    fn cursor_stream(input: &str) -> SseStream {
        let cursor = std::io::Cursor::new(input.as_bytes().to_vec());
        SseStream::new(Box::new(cursor))
    }

    fn json_server_once(body: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind stub server");
        let address = listener.local_addr().expect("stub address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("read request");
                assert!(read > 0, "request closed before its headers completed");
                bytes.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8_lossy(&bytes).into_owned();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            request
        });
        (format!("http://{address}"), handle)
    }

    fn error_server_once(status: u16, body: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind stub server");
        let address = listener.local_addr().expect("stub address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("read request");
                assert!(read > 0, "request closed before its headers completed");
                bytes.extend_from_slice(&buffer[..read]);
            }
            let response = format!(
                "HTTP/1.1 {status} Test Error\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write error response");
        });
        (format!("http://{address}"), handle)
    }

    fn captured_json_request(
        response_body: &'static str,
        action: impl FnOnce(&KoiClient) -> Result<serde_json::Value>,
    ) -> String {
        let (endpoint, request) = json_server_once(response_body);
        let client = KoiClient::with_token(&endpoint, "secret-token");
        action(&client).expect("client request");
        request.join().expect("stub server joins").to_lowercase()
    }

    fn silent_sse_server() -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind SSE server");
        let address = listener.local_addr().expect("SSE address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept SSE request");
            stream
                .set_read_timeout(Some(SSE_CANCELLATION_BOUND + Duration::from_secs(2)))
                .expect("set SSE server read timeout");
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("read SSE request");
                assert!(read > 0, "SSE request closed before its headers completed");
                bytes.extend_from_slice(&buffer[..read]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n",
                )
                .expect("write SSE response headers");
            stream.flush().expect("flush SSE response headers");

            // A cancelled reader drops this deliberately incomplete response,
            // which must close the real socket within the client read bound.
            let mut byte = [0_u8; 1];
            let read = stream.read(&mut byte).expect("observe SSE client close");
            assert_eq!(read, 0, "SSE client left its transport connected");
            String::from_utf8(bytes).expect("request is HTTP text")
        });
        (format!("http://{address}"), handle)
    }

    // ── Unauthorized (401) hint tests ───────────────────────────────

    #[test]
    fn unauthorized_displays_actionable_hint() {
        let err = ClientError::Unauthorized;
        assert_eq!(
            err.to_string(),
            "remote daemon requires a token (pass --token or set KOI_TOKEN)"
        );
        assert!(err.is_unauthorized());
    }

    #[test]
    fn non_401_api_error_is_not_unauthorized() {
        let err = ClientError::Api {
            error: "not_found".into(),
            message: "nope".into(),
        };
        assert!(!err.is_unauthorized());
    }

    #[test]
    fn malformed_http_error_never_invents_an_api_code() {
        for body in ["upstream exploded", r#"{"message":"missing code"}"#] {
            let (endpoint, server) = error_server_once(502, body);
            let error = KoiClient::new(&endpoint)
                .get_json("/failure")
                .expect_err("502 must fail");
            let ClientError::Decode(detail) = error else {
                panic!("nonconforming HTTP error must be a decode failure")
            };
            assert!(detail.contains("HTTP 502"));
            assert!(detail.contains(body));
            server.join().expect("error server joins");
        }
    }

    #[test]
    fn conforming_http_error_preserves_daemon_code_and_message() {
        let (endpoint, server) = error_server_once(
            503,
            r#"{"error":"provider_unavailable","message":"native provider stopped"}"#,
        );
        let error = KoiClient::new(&endpoint)
            .get_json("/failure")
            .expect_err("503 must fail");
        assert!(matches!(
            error,
            ClientError::Api { error, message }
                if error == "provider_unavailable" && message == "native provider stopped"
        ));
        server.join().expect("error server joins");
    }

    #[test]
    fn malformed_pipeline_error_never_invents_fields() {
        assert!(matches!(
            extract::<serde_json::Value>(
                &serde_json::json!({ "error": 7, "message": "bad" }),
                "registered"
            ),
            Err(ClientError::Decode(_))
        ));
        assert!(matches!(
            extract::<serde_json::Value>(&serde_json::json!({ "error": "bad" }), "registered"),
            Err(ClientError::Decode(_))
        ));
    }

    #[test]
    fn current_mdns_wire_responses_cannot_fill_missing_fields_with_defaults() {
        let payload = RegisterPayload {
            name: "api".into(),
            service_type: "_http._tcp".into(),
            port: 8080,
            ip: None,
            lease_secs: Some(30),
            txt: Default::default(),
        };
        let (endpoint, server) = json_server_once(
            r#"{"registered":{"id":"r1","name":"api","type":"_http._tcp","port":8080,"mode":"heartbeat"}}"#,
        );
        assert!(matches!(
            KoiClient::new(&endpoint).register(&payload),
            Err(ClientError::Decode(_))
        ));
        server.join().expect("registration stub joins");

        let (endpoint, server) = json_server_once(
            r#"{"registered":{"id":"r1","name":"api","type":"_http._tcp","port":8080,"mode":"permanent","lease_secs":null}}"#,
        );
        assert!(matches!(
            KoiClient::new(&endpoint).register(&payload),
            Err(ClientError::Decode(_))
        ));
        server.join().expect("registration-mode stub joins");

        let (endpoint, server) = json_server_once(
            r#"{"registered":{"id":"r1","name":"api","type":"_http._tcp","port":8080,"mode":"heartbeat","lease_secs":31}}"#,
        );
        assert!(matches!(
            KoiClient::new(&endpoint).register(&payload),
            Err(ClientError::Decode(_))
        ));
        server.join().expect("registration-lease stub joins");

        let (endpoint, server) =
            json_server_once(r#"{"resolved":{"name":"api","type":"_http._tcp","port":8080}}"#);
        assert!(matches!(
            KoiClient::new(&endpoint).resolve("api"),
            Err(ClientError::Decode(_))
        ));
        server.join().expect("resolution stub joins");

        let (endpoint, server) = json_server_once(
            r#"{"revision":1,"service_types":["_http._tcp"],"records":[{"name":"api","type":"_http._tcp"}]}"#,
        );
        assert!(matches!(
            KoiClient::new(&endpoint).mdns_discovery_snapshot(),
            Err(ClientError::Decode(_))
        ));
        server.join().expect("snapshot stub joins");
    }

    #[test]
    fn unregister_requires_the_daemon_to_acknowledge_the_requested_registration() {
        let (endpoint, server) = json_server_once(r#"{"unregistered":"another-id"}"#);
        let error = KoiClient::new(&endpoint)
            .unregister("requested-id")
            .expect_err("mismatched acknowledgement must fail");
        assert!(matches!(error, ClientError::Decode(detail) if detail.contains("another-id")));
        server.join().expect("unregister stub joins");
    }

    #[test]
    fn heartbeat_requires_the_daemon_to_acknowledge_the_requested_registration() {
        let (endpoint, server) =
            json_server_once(r#"{"renewed":{"id":"another-id","lease_secs":30}}"#);
        let error = KoiClient::new(&endpoint)
            .heartbeat("requested-id")
            .expect_err("mismatched acknowledgement must fail");
        assert!(matches!(error, ClientError::Decode(detail) if detail.contains("another-id")));
        server.join().expect("heartbeat stub joins");

        let (endpoint, server) =
            json_server_once(r#"{"renewed":{"id":"requested-id","lease_secs":0}}"#);
        assert!(matches!(
            KoiClient::new(&endpoint).heartbeat("requested-id"),
            Err(ClientError::Decode(_))
        ));
        server.join().expect("zero-heartbeat stub joins");
    }

    #[test]
    fn unsupported_dns_types_fail_before_any_transport_attempt() {
        let error = KoiClient::new("http://127.0.0.1:1")
            .dns_lookup("api.internal", RecordType::TXT)
            .expect_err("TXT is not an address lookup supported by this endpoint");
        assert!(matches!(error, ClientError::Decode(detail) if detail.contains("TXT")));
    }

    #[test]
    fn dns_lookup_decodes_one_strict_shared_result() {
        let (endpoint, server) =
            json_server_once(r#"{"name":"api.internal.","ips":["10.0.0.7"],"source":"static"}"#);
        let result = KoiClient::new(&endpoint)
            .dns_lookup("api.internal", RecordType::A)
            .expect("lookup request")
            .expect("present DNS answer");
        assert_eq!(result.name, "api.internal.");
        assert_eq!(
            result.ips,
            ["10.0.0.7".parse::<std::net::IpAddr>().expect("test IP")]
        );
        assert_eq!(result.source, "static");
        server.join().expect("lookup stub joins");

        for body in [
            r#"{"name":"api.internal.","ips":["not-an-ip"],"source":"static"}"#,
            r#"{"name":"api.internal.","ips":["10.0.0.7"]}"#,
        ] {
            let (endpoint, server) = json_server_once(body);
            assert!(matches!(
                KoiClient::new(&endpoint).dns_lookup("api.internal", RecordType::A),
                Err(ClientError::Decode(_))
            ));
            server.join().expect("malformed lookup stub joins");
        }

        let (endpoint, server) = json_server_once(
            r#"{"name":"api.internal.","ips":["10.0.0.7"],"source":"static","future_metadata":{"observed_at":"later"}}"#,
        );
        assert!(KoiClient::new(&endpoint)
            .dns_lookup("api.internal", RecordType::A)
            .expect("additive response remains decodable")
            .is_some());
        server.join().expect("additive lookup stub joins");
    }

    #[test]
    fn dns_lookup_maps_only_verified_absence_to_none() {
        let (endpoint, server) =
            error_server_once(404, r#"{"error":"not_found","message":"record_not_found"}"#);
        assert!(KoiClient::new(&endpoint)
            .dns_lookup("missing.internal", RecordType::A)
            .expect("verified absence")
            .is_none());
        server.join().expect("absence stub joins");

        for (status, body, expected) in [
            (
                400,
                r#"{"error":"invalid_name","message":"invalid DNS name"}"#,
                "invalid_name",
            ),
            (
                500,
                r#"{"error":"internal","message":"upstream resolver error"}"#,
                "internal",
            ),
        ] {
            let (endpoint, server) = error_server_once(status, body);
            let error = KoiClient::new(&endpoint)
                .dns_lookup("bad name", RecordType::A)
                .expect_err("execution failure cannot become absence");
            assert!(matches!(
                error,
                ClientError::Api { error, .. } if error == expected
            ));
            server.join().expect("error stub joins");
        }
    }

    #[test]
    fn dns_stop_requires_a_boolean_acknowledgement() {
        let (endpoint, server) = json_server_once(r#"{"stopped":false}"#);
        assert!(!KoiClient::new(&endpoint)
            .dns_stop()
            .expect("accepted already-stopped fact"));
        server.join().expect("stop stub joins");

        for body in [r#"{}"#, r#"{"stopped":"yes"}"#] {
            let (endpoint, server) = json_server_once(body);
            assert!(matches!(
                KoiClient::new(&endpoint).dns_stop(),
                Err(ClientError::Decode(_))
            ));
            server.join().expect("malformed stop stub joins");
        }
    }

    #[test]
    fn dns_stop_preserves_the_daemon_execution_error() {
        let (endpoint, server) = error_server_once(
            503,
            r#"{"error":"shutting_down","message":"DNS runtime has already shut down"}"#,
        );
        let error = KoiClient::new(&endpoint)
            .dns_stop()
            .expect_err("closed admission must remain an API error");
        assert!(matches!(
            error,
            ClientError::Api { error, message }
                if error == "shutting_down" && message.contains("shut down")
        ));
        server.join().expect("error stub joins");
    }

    #[test]
    fn udp_unbind_requires_the_exact_binding_acknowledgement() {
        let (endpoint, server) = json_server_once(r#"{"unbound":"requested-id"}"#);
        KoiClient::new(&endpoint)
            .udp_unbind("requested-id")
            .expect("matching binding acknowledgement");
        let request = server.join().expect("unbind stub joins");
        assert!(request.starts_with("DELETE /v1/udp/bind/requested-id "));

        for body in [r#"{}"#, r#"{"unbound":7}"#, r#"{"unbound":"another-id"}"#] {
            let (endpoint, server) = json_server_once(body);
            assert!(matches!(
                KoiClient::new(&endpoint).udp_unbind("requested-id"),
                Err(ClientError::Decode(_))
            ));
            server.join().expect("invalid unbind stub joins");
        }
    }

    #[test]
    fn udp_unbind_preserves_the_daemon_execution_error() {
        let (endpoint, server) = error_server_once(
            500,
            r#"{"error":"internal","message":"UDP command worker stopped unexpectedly"}"#,
        );
        let error = KoiClient::new(&endpoint)
            .udp_unbind("requested-id")
            .expect_err("worker loss must remain an API error");
        assert!(matches!(
            error,
            ClientError::Api { error, message }
                if error == "internal" && message.contains("worker stopped")
        ));
        server.join().expect("error stub joins");
    }

    #[test]
    fn shutdown_requires_the_exact_accepted_command_acknowledgement() {
        for body in [r#"{}"#, r#"{"status":"ok"}"#] {
            let (endpoint, server) = json_server_once(body);
            assert!(matches!(
                KoiClient::new(&endpoint).shutdown(),
                Err(ClientError::Decode(_))
            ));
            server.join().expect("shutdown stub joins");
        }
    }

    // ── KoiClient::new() tests ──────────────────────────────────────

    #[test]
    fn client_new_strips_trailing_slash() {
        // After Happy Eyeballs, localhost is rewritten to a literal IP.
        let client = KoiClient::new("http://localhost:5641/");
        assert!(
            client.endpoint == "http://127.0.0.1:5641"
                || client.endpoint == "http://[::1]:5641"
                || client.endpoint == "http://localhost:5641",
            "unexpected endpoint: {}",
            client.endpoint
        );
        assert!(!client.endpoint.ends_with("/"));
        assert!(client.token.is_empty());
    }

    #[test]
    fn client_with_token_sets_token() {
        let client = KoiClient::with_token("http://10.0.0.1:5641", "my-secret-token");
        assert_eq!(client.endpoint, "http://10.0.0.1:5641");
        assert_eq!(client.token, "my-secret-token");
    }

    #[test]
    fn client_new_preserves_non_localhost() {
        let client = KoiClient::new("http://10.0.0.1:5641");
        assert_eq!(client.endpoint, "http://10.0.0.1:5641");
    }

    #[test]
    fn client_new_strips_multiple_trailing_slashes() {
        let client = KoiClient::new("http://localhost:5641///");
        assert!(!client.endpoint.ends_with("/"));
    }

    #[test]
    fn only_missing_local_control_is_absence() {
        assert!(matches!(
            classify_connect_error(std::io::Error::from(std::io::ErrorKind::NotFound)),
            LocalControlAttemptError::Absent
        ));
        assert!(matches!(
            classify_connect_error(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            LocalControlAttemptError::Uncertain(ClientError::Unreachable(_))
        ));
        assert!(matches!(
            classify_connect_error(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            LocalControlAttemptError::Uncertain(ClientError::Unreachable(_))
        ));
    }

    #[test]
    fn malformed_local_access_is_uncertainty_not_absence() {
        let error = match parse_local_access(LocalControlResponse::Access(LocalDaemonAccess {
            version: LOCAL_CONTROL_VERSION,
            endpoint: String::new(),
            token: String::new(),
            data_root: None,
        })) {
            Ok(_) => panic!("malformed access must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, ClientError::Decode(_)));
    }

    #[test]
    fn breadcrumb_corruption_remains_a_decode_failure() {
        let error = map_breadcrumb_error(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing token",
        ));
        assert!(matches!(error, ClientError::Decode(detail) if detail.contains("missing token")));
    }

    #[test]
    fn health_log_uses_the_daemon_transition_query() {
        let (endpoint, request) = json_server_once(r#"{"entries":"api: up -> down\n"}"#);
        let client = KoiClient::with_token(&endpoint, "secret-token");

        let log = client.health_log().expect("health log response");

        assert_eq!(log["entries"], "api: up -> down\n");
        let request = request.join().expect("stub server joins").to_lowercase();
        assert!(request.starts_with("get /v1/health/log "));
        assert!(request.contains("x-koi-token: secret-token\r\n"));
    }

    #[test]
    fn certmesh_status_uses_the_authenticated_management_route() {
        let (endpoint, request) = json_server_once("{}");
        let client = KoiClient::with_token(&endpoint, "secret-token");

        client.certmesh_status().expect("status response");

        let request = request.join().expect("stub server joins").to_lowercase();
        assert!(request.starts_with("get /v1/certmesh/status "));
        assert!(request.contains("x-koi-token: secret-token\r\n"));
    }

    #[test]
    fn trust_methods_use_only_the_authenticated_owner_routes() {
        let cases = [
            captured_json_request("{}", |client| client.trust_status()),
            captured_json_request("{}", |client| {
                client.trust_install("root", "operator", "pem")
            }),
            captured_json_request("{}", |client| {
                client.trust_ensure_installed("root", "certmesh", "pem")
            }),
            captured_json_request("{}", |client| client.trust_remove("root")),
            captured_json_request("{}", |client| client.trust_inspect("pem")),
            captured_json_request("{}", |client| client.trust_reconcile()),
        ];
        let expected = [
            "get /v1/trust/status ",
            "post /v1/trust/install ",
            "post /v1/trust/ensure ",
            "delete /v1/trust/remove ",
            "post /v1/trust/inspect ",
            "post /v1/trust/reconcile ",
        ];
        for (request, expected_start) in cases.into_iter().zip(expected) {
            assert!(request.starts_with(expected_start), "request: {request:?}");
            assert!(request.contains("x-koi-token: secret-token\r\n"));
        }
    }

    #[test]
    fn certmesh_trust_queries_preserve_absence_and_uncertainty() {
        let request = captured_json_request("{}", |client| client.certmesh_diagnosis());
        assert!(request.starts_with("get /v1/certmesh/diagnose "));
        assert!(request.contains("x-koi-token: secret-token\r\n"));

        let request = captured_json_request(r#"{"ca_cert_pem":"pem"}"#, |client| {
            Ok(client
                .certmesh_ca_certificate()?
                .expect("CA response must remain present"))
        });
        assert!(request.starts_with("get /v1/certmesh/ca-cert "));
        assert!(request.contains("x-koi-token: secret-token\r\n"));

        let (endpoint, server) =
            error_server_once(503, r#"{"error":"ca_not_initialized","message":"no CA"}"#);
        assert!(KoiClient::with_token(&endpoint, "secret-token")
            .certmesh_ca_certificate()
            .unwrap()
            .is_none());
        server.join().unwrap();

        let (endpoint, server) = error_server_once(
            503,
            r#"{"error":"provider_unavailable","message":"owner uncertain"}"#,
        );
        assert!(matches!(
            KoiClient::with_token(&endpoint, "secret-token").certmesh_ca_certificate(),
            Err(ClientError::Api { error, .. }) if error == "provider_unavailable"
        ));
        server.join().unwrap();
    }

    #[test]
    fn inventory_snapshot_uses_one_authenticated_aggregate_route() {
        let (endpoint, request) =
            json_server_once(r#"{"status":{"revision":7},"health":null,"dns":null}"#);
        let client = KoiClient::with_token(&endpoint, "secret-token");

        let snapshot = client.inventory_snapshot().expect("inventory response");

        assert_eq!(snapshot["status"]["revision"], 7);
        let request = request.join().expect("stub server joins").to_lowercase();
        assert!(request.starts_with("get /v1/inventory "));
        assert!(request.contains("x-koi-token: secret-token\r\n"));
    }

    #[test]
    fn certmesh_bootstrap_never_sends_the_daemon_token() {
        let (endpoint, request) = json_server_once(
            r#"{"revision":1,"authority_available":false,"enrollment_open":false,"requires_approval":false}"#,
        );
        let client = KoiClient::with_token(&endpoint, "must-not-leak");

        let bootstrap = client.certmesh_bootstrap().expect("bootstrap response");

        assert_eq!(bootstrap["authority_available"], false);
        let request = request.join().expect("stub server joins").to_lowercase();
        assert!(request.starts_with("get /v1/certmesh/bootstrap "));
        assert!(!request.contains("x-koi-token"));
        assert!(!request.contains("must-not-leak"));
    }

    #[test]
    fn pond_clear_ui_is_an_authenticated_bodyless_delete() {
        let (endpoint, request) =
            json_server_once(r#"{"ok":true,"selected":false,"status_revision":9}"#);
        let client = KoiClient::with_token(&endpoint, "secret-token");

        let cleared = client.pond_clear_ui().expect("clear response");

        assert_eq!(cleared["selected"], false);
        assert_eq!(cleared["status_revision"], 9);
        let request = request.join().expect("stub server joins").to_lowercase();
        assert!(request.starts_with("delete /v1/ui "));
        assert!(request.contains("x-koi-token: secret-token\r\n"));
        assert!(
            request.ends_with("\r\n\r\n"),
            "unexpected request body: {request:?}"
        );
    }

    // ── SSE parsing tests ───────────────────────────────────────────

    #[test]
    fn sse_stream_yields_parsed_json() {
        let input = "data: {\"foo\": 1}\n\n";
        let mut stream = cursor_stream(input);
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item["foo"], 1);
    }

    #[test]
    fn sse_stream_skips_empty_lines() {
        let input = "\n\n\n\n";
        let mut stream = cursor_stream(input);
        assert!(stream.next().is_none());
    }

    #[test]
    fn sse_stream_skips_non_data_lines() {
        let input = ": keepalive\nevent: message\nretry: 1000\n\n";
        let mut stream = cursor_stream(input);
        assert!(stream.next().is_none());
    }

    #[test]
    fn idle_real_sse_read_is_cancelled_and_socket_is_reclaimed_within_bound() {
        let (endpoint, server) = silent_sse_server();
        let stream = KoiClient::new(&endpoint)
            .browse_stream("_http._tcp")
            .expect("establish SSE response");
        let cancellation = stream.cancellation();
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            let mut stream = stream;
            stream.next()
        });

        std::thread::sleep(Duration::from_millis(50));
        cancellation.cancel();
        assert!(worker.join().expect("SSE worker joins").is_none());
        assert!(
            started.elapsed() <= SSE_CANCELLATION_BOUND + Duration::from_millis(750),
            "idle SSE cancellation exceeded its transport bound"
        );
        let request = server.join().expect("SSE server joins");
        assert!(request.contains("type=_http._tcp"));
        assert!(request.contains("idle_for=0"));
    }

    #[test]
    fn sse_stream_handles_leading_space() {
        let input = "data:   {\"hello\": \"world\"}\n";
        let mut stream = cursor_stream(input);
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item["hello"], "world");
    }

    #[test]
    fn sse_stream_handles_no_space() {
        let input = "data:{\"hello\":\"world\"}\n";
        let mut stream = cursor_stream(input);
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item["hello"], "world");
    }

    #[test]
    fn sse_stream_yields_multiple_events() {
        let input = "data: {\"n\": 1}\n\ndata: {\"n\": 2}\n\n";
        let mut stream = cursor_stream(input);
        let first = stream.next().unwrap().unwrap();
        let second = stream.next().unwrap().unwrap();
        assert_eq!(first["n"], 1);
        assert_eq!(second["n"], 2);
    }

    #[test]
    fn sse_stream_returns_none_on_eof() {
        let input = "data: {\"n\": 1}\n";
        let mut stream = cursor_stream(input);
        let _ = stream.next();
        assert!(stream.next().is_none());
    }

    #[test]
    fn sse_stream_decode_error_on_invalid_json() {
        let input = "data: {bad json}\n";
        let mut stream = cursor_stream(input);
        let item = stream.next().unwrap();
        assert!(item.is_err());
        assert!(stream.next().is_none(), "protocol failures are terminal");
    }

    #[test]
    fn sse_stream_transport_error_on_read_failure() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }

        let stream = SseStream::new(Box::new(BrokenReader));
        let mut stream = stream;
        let item = stream.next().unwrap();
        assert!(item.is_err());
        assert!(stream.next().is_none(), "transport failures are terminal");
    }
}
