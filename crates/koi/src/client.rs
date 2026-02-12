//! HTTP client for communicating with a running Koi daemon.
//!
//! Uses blocking `ureq` — no async runtime dependency on the client path.
//! All paths use `/v1/mdns/` prefix for mDNS domain routes.

use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

use koi_common::types::ServiceRecord;

use koi_mdns::protocol::{
    AdminRegistration, DaemonStatus, RegisterPayload, RegistrationResult, RenewalResult,
};
use hickory_proto::rr::RecordType;

/// TCP connection timeout for general API requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read timeout for general (non-streaming) API requests.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the fast health check probe.
const HEALTH_TIMEOUT: Duration = Duration::from_millis(200);

// ── Error types ───────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Daemon not reachable: {0}")]
    Unreachable(String),

    #[error("{error}: {message}")]
    Api { error: String, message: String },

    #[error("Request failed: {0}")]
    Transport(String),

    #[error("Invalid response: {0}")]
    Decode(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

// ── Client ────────────────────────────────────────────────────────

pub struct KoiClient {
    endpoint: String,
    agent: ureq::Agent,
}

impl KoiClient {
    pub fn new(endpoint: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout_read(READ_TIMEOUT)
            .build();
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            agent,
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
        let url = format!("{}/v1/mdns/services", self.endpoint);
        let json_val =
            serde_json::to_value(payload).map_err(|e| ClientError::Decode(e.to_string()))?;
        let resp = self
            .agent
            .post(&url)
            .send_json(json_val)
            .map_err(map_error)?;
        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))?;
        extract(&json, "registered")
    }

    pub fn unregister(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/mdns/services/{id}", self.endpoint);
        self.agent.delete(&url).call().map_err(map_error)?;
        Ok(())
    }

    pub fn heartbeat(&self, id: &str) -> Result<RenewalResult> {
        let url = format!("{}/v1/mdns/services/{id}/heartbeat", self.endpoint);
        let resp = self.agent.put(&url).send_bytes(&[]).map_err(map_error)?;
        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))?;
        extract(&json, "renewed")
    }

    pub fn resolve(&self, instance: &str) -> Result<ServiceRecord> {
        let url = format!("{}/v1/mdns/resolve", self.endpoint);
        let resp = self
            .agent
            .get(&url)
            .query("name", instance)
            .call()
            .map_err(map_error)?;
        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))?;
        extract(&json, "resolved")
    }

    /// Start a browse SSE stream. Returns an iterator of JSON events.
    pub fn browse_stream(&self, service_type: &str) -> Result<SseStream> {
        let url = format!("{}/v1/mdns/browse", self.endpoint);
        let resp = self
            .stream_agent()
            .get(&url)
            .query("type", service_type)
            .call()
            .map_err(map_error)?;
        Ok(SseStream::new(Box::new(resp.into_reader())))
    }

    /// Start an events SSE stream. Returns an iterator of JSON events.
    pub fn events_stream(&self, service_type: &str) -> Result<SseStream> {
        let url = format!("{}/v1/mdns/events", self.endpoint);
        let resp = self
            .stream_agent()
            .get(&url)
            .query("type", service_type)
            .call()
            .map_err(map_error)?;
        Ok(SseStream::new(Box::new(resp.into_reader())))
    }

    // ── Unified status ─────────────────────────────────────────────

    /// Fetch unified status from `/v1/status`.
    pub fn unified_status(&self) -> Result<serde_json::Value> {
        let url = format!("{}/v1/status", self.endpoint);
        let resp = self.agent.get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    // ── DNS operations (Phase 6) ───────────────────────────────────

    pub fn dns_status(&self) -> Result<serde_json::Value> {
        self.get_json("/v1/dns/status")
    }

    pub fn dns_lookup(&self, name: &str, record_type: RecordType) -> Result<serde_json::Value> {
        let url = format!("{}/v1/dns/lookup", self.endpoint);
        let resp = self
            .agent
            .get(&url)
            .query("name", name)
            .query("type", record_type_str(record_type))
            .call()
            .map_err(map_error)?;
        resp.into_json()
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
        self.post_json("/v1/dns/entries", &body)
    }

    pub fn dns_remove(&self, name: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/dns/entries/{}", self.endpoint, name);
        let resp = self.agent.delete(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn dns_start(&self) -> Result<serde_json::Value> {
        self.post_json("/v1/dns/admin/start", &serde_json::json!({}))
    }

    pub fn dns_stop(&self) -> Result<serde_json::Value> {
        self.post_json("/v1/dns/admin/stop", &serde_json::json!({}))
    }

    // ── Generic operations ─────────────────────────────────────────

    /// POST JSON to an arbitrary path and return the response as a JSON value.
    pub fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.endpoint);
        let resp = self
            .agent
            .post(&url)
            .send_json(body.clone())
            .map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// GET JSON from an arbitrary path and return the response as a JSON value.
    pub fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.endpoint);
        let resp = self.agent.get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// PUT JSON to an arbitrary path and return the response as a JSON value.
    pub fn put_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.endpoint);
        let resp = self
            .agent
            .put(&url)
            .send_json(body.clone())
            .map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    // ── Admin operations (mDNS) ──────────────────────────────────

    pub fn admin_status(&self) -> Result<DaemonStatus> {
        let url = format!("{}/v1/mdns/admin/status", self.endpoint);
        let resp = self.agent.get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn admin_registrations(&self) -> Result<Vec<AdminRegistration>> {
        let url = format!("{}/v1/mdns/admin/registrations", self.endpoint);
        let resp = self.agent.get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn admin_inspect(&self, id: &str) -> Result<AdminRegistration> {
        let url = format!("{}/v1/mdns/admin/registrations/{id}", self.endpoint);
        let resp = self.agent.get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn admin_force_unregister(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/mdns/admin/registrations/{id}", self.endpoint);
        self.agent.delete(&url).call().map_err(map_error)?;
        Ok(())
    }

    pub fn admin_drain(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/mdns/admin/registrations/{id}/drain", self.endpoint);
        self.agent.post(&url).call().map_err(map_error)?;
        Ok(())
    }

    pub fn admin_revive(&self, id: &str) -> Result<()> {
        let url = format!("{}/v1/mdns/admin/registrations/{id}/revive", self.endpoint);
        self.agent.post(&url).call().map_err(map_error)?;
        Ok(())
    }

    // ── Admin operations (system) ────────────────────────────────────

    /// Request a graceful shutdown of the running daemon.
    pub fn shutdown(&self) -> Result<()> {
        let url = format!("{}/v1/admin/shutdown", self.endpoint);
        self.agent.post(&url).call().map_err(map_error)?;
        Ok(())
    }

    // ── Certmesh operations (Phase 3) ──────────────────────────────

    /// GET /v1/certmesh/roster — fetch signed roster manifest.
    pub fn get_roster_manifest(&self) -> Result<serde_json::Value> {
        let url = format!("{}/v1/certmesh/roster", self.endpoint);
        let resp = self.agent.get(&url).call().map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// POST /v1/certmesh/renew — push renewed cert to a member.
    ///
    /// `member_endpoint` is the member's HTTP endpoint, not the CA's.
    /// Used when the primary pushes renewals to remote members.
    #[allow(dead_code)]
    pub fn push_renewal(
        &self,
        member_endpoint: &str,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!("{member_endpoint}/v1/certmesh/renew");
        let resp = self
            .agent
            .post(&url)
            .send_json(request.clone())
            .map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// POST /v1/certmesh/health — send health heartbeat.
    pub fn health_heartbeat(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/v1/certmesh/health", self.endpoint);
        let resp = self
            .agent
            .post(&url)
            .send_json(request.clone())
            .map_err(map_error)?;
        resp.into_json()
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    // ── Private helpers ───────────────────────────────────────────

    /// Agent without read timeout for SSE streams.
    fn stream_agent(&self) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .build()
    }
}

// ── SSE Stream ────────────────────────────────────────────────────

/// Iterator over Server-Sent Events from the Koi daemon.
///
/// Parses `data: <json>` lines, skipping empty lines and event metadata.
pub struct SseStream {
    reader: BufReader<Box<dyn Read + Send>>,
}

impl SseStream {
    fn new(reader: Box<dyn Read + Send>) -> Self {
        Self {
            reader: BufReader::new(reader),
        }
    }
}

impl Iterator for SseStream {
    type Item = Result<serde_json::Value>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return None,
                Ok(_) => {
                    let trimmed = line.trim();
                    if let Some(data) = trimmed.strip_prefix("data:") {
                        let data = data.trim_start();
                        if data.is_empty() {
                            continue;
                        }
                        match serde_json::from_str(data) {
                            Ok(json) => return Some(Ok(json)),
                            Err(e) => return Some(Err(ClientError::Decode(e.to_string()))),
                        }
                    }
                    continue;
                }
                Err(e) => return Some(Err(ClientError::Transport(e.to_string()))),
            }
        }
    }
}

// ── Error helpers ─────────────────────────────────────────────────

fn map_error(e: ureq::Error) -> ClientError {
    match e {
        ureq::Error::Status(_status, resp) => {
            let body = resp.into_string().unwrap_or_default();
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                let error = json
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let message = json
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&body)
                    .to_string();
                ClientError::Api { error, message }
            } else {
                ClientError::Api {
                    error: "http_error".into(),
                    message: body,
                }
            }
        }
        ureq::Error::Transport(t) => ClientError::Unreachable(t.to_string()),
    }
}

fn record_type_str(record_type: RecordType) -> &'static str {
    match record_type {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::ANY => "ANY",
        _ => "A",
    }
}

fn extract<T: serde::de::DeserializeOwned>(json: &serde_json::Value, key: &str) -> Result<T> {
    if let Some(err_val) = json.get("error") {
        let error = err_val.as_str().unwrap_or("unknown").to_string();
        let message = json
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error")
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
        SseStream::new(Box::new(std::io::Cursor::new(input.as_bytes().to_vec())))
    }

    /// A reader that always returns an error.
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection lost",
            ))
        }
    }

    // ── SseStream tests ─────────────────────────────────────────────

    #[test]
    fn sse_stream_yields_parsed_json() {
        let mut stream =
            cursor_stream("data: {\"found\":{\"name\":\"S\",\"type\":\"_http._tcp\"}}\n");
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item.get("found").unwrap().get("name").unwrap(), "S");
    }

    #[test]
    fn sse_stream_skips_empty_lines() {
        let mut stream = cursor_stream("\n\ndata: {\"ok\":true}\n\n");
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item.get("ok").unwrap(), true);
        assert!(stream.next().is_none());
    }

    #[test]
    fn sse_stream_skips_non_data_lines() {
        let input = "event: message\nid: 42\n: comment\ndata: {\"v\":1}\n";
        let mut stream = cursor_stream(input);
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item.get("v").unwrap(), 1);
    }

    #[test]
    fn sse_stream_returns_none_on_eof() {
        let mut stream = cursor_stream("");
        assert!(stream.next().is_none());
    }

    #[test]
    fn sse_stream_handles_leading_space() {
        let mut stream = cursor_stream("data: {\"a\":1}\n");
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item.get("a").unwrap(), 1);
    }

    #[test]
    fn sse_stream_handles_no_space() {
        let mut stream = cursor_stream("data:{\"b\":2}\n");
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item.get("b").unwrap(), 2);
    }

    #[test]
    fn sse_stream_decode_error_on_invalid_json() {
        let mut stream = cursor_stream("data: not-json\n");
        let result = stream.next().unwrap();
        assert!(matches!(result, Err(ClientError::Decode(_))));
    }

    #[test]
    fn sse_stream_skips_empty_data() {
        let mut stream = cursor_stream("data: \ndata: {\"ok\":true}\n");
        let item = stream.next().unwrap().unwrap();
        assert_eq!(item.get("ok").unwrap(), true);
    }

    #[test]
    fn sse_stream_yields_multiple_events() {
        let input = "data: {\"a\":1}\n\ndata: {\"b\":2}\n";
        let mut stream = cursor_stream(input);
        let first = stream.next().unwrap().unwrap();
        assert_eq!(first.get("a").unwrap(), 1);
        let second = stream.next().unwrap().unwrap();
        assert_eq!(second.get("b").unwrap(), 2);
    }

    #[test]
    fn sse_stream_transport_error_on_read_failure() {
        let mut stream = SseStream::new(Box::new(FailingReader));
        let result = stream.next().unwrap();
        assert!(matches!(result, Err(ClientError::Transport(_))));
    }

    // ── extract() tests ─────────────────────────────────────────────

    #[test]
    fn extract_returns_value_at_key() {
        let json = serde_json::json!({
            "registered": {
                "id": "abc", "name": "X", "type": "_http._tcp",
                "port": 80, "mode": "session"
            }
        });
        let result: RegistrationResult = extract(&json, "registered").unwrap();
        assert_eq!(result.id, "abc");
        assert_eq!(result.name, "X");
    }

    #[test]
    fn extract_missing_key_returns_decode_error() {
        let json = serde_json::json!({"other": 42});
        let result: Result<serde_json::Value> = extract(&json, "registered");
        match result {
            Err(ClientError::Decode(msg)) => {
                assert!(msg.contains("registered"), "msg: {msg}");
            }
            other => panic!("Expected Decode error, got: {other:?}"),
        }
    }

    #[test]
    fn extract_error_key_returns_api_error() {
        let json = serde_json::json!({"error": "not_found", "message": "gone"});
        let result: Result<serde_json::Value> = extract(&json, "registered");
        match result {
            Err(ClientError::Api { error, message }) => {
                assert_eq!(error, "not_found");
                assert_eq!(message, "gone");
            }
            other => panic!("Expected Api error, got: {other:?}"),
        }
    }

    #[test]
    fn extract_error_without_message_uses_default() {
        let json = serde_json::json!({"error": "x"});
        let result: Result<serde_json::Value> = extract(&json, "key");
        match result {
            Err(ClientError::Api { message, .. }) => {
                assert_eq!(message, "Unknown error");
            }
            other => panic!("Expected Api error, got: {other:?}"),
        }
    }

    #[test]
    fn extract_error_with_non_string_uses_unknown() {
        let json = serde_json::json!({"error": 42, "message": "numeric error code"});
        let result: Result<serde_json::Value> = extract(&json, "key");
        match result {
            Err(ClientError::Api { error, .. }) => {
                assert_eq!(error, "unknown");
            }
            other => panic!("Expected Api error, got: {other:?}"),
        }
    }

    #[test]
    fn extract_deserializes_nested_struct() {
        let json = serde_json::json!({
            "renewed": {"id": "test-id", "lease_secs": 90}
        });
        let result: RenewalResult = extract(&json, "renewed").unwrap();
        assert_eq!(result.id, "test-id");
        assert_eq!(result.lease_secs, 90);
    }

    // ── KoiClient::new() tests ──────────────────────────────────────

    #[test]
    fn client_new_strips_trailing_slash() {
        let client = KoiClient::new("http://localhost:5641/");
        assert_eq!(client.endpoint, "http://localhost:5641");
    }

    #[test]
    fn client_new_preserves_clean_endpoint() {
        let client = KoiClient::new("http://localhost:5641");
        assert_eq!(client.endpoint, "http://localhost:5641");
    }

    #[test]
    fn client_new_strips_multiple_trailing_slashes() {
        let client = KoiClient::new("http://localhost:5641///");
        assert_eq!(client.endpoint, "http://localhost:5641");
    }

    // ── ClientError Display tests ───────────────────────────────────

    #[test]
    fn client_error_unreachable_display() {
        let err = ClientError::Unreachable("timeout".into());
        let msg = err.to_string();
        assert!(msg.contains("Daemon not reachable"), "msg: {msg}");
        assert!(msg.contains("timeout"), "msg: {msg}");
    }

    #[test]
    fn client_error_api_display() {
        let err = ClientError::Api {
            error: "not_found".into(),
            message: "Registration not found".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("not_found"), "msg: {msg}");
        assert!(msg.contains("Registration not found"), "msg: {msg}");
    }

    #[test]
    fn client_error_decode_display() {
        let err = ClientError::Decode("bad json".into());
        let msg = err.to_string();
        assert!(msg.contains("Invalid response"), "msg: {msg}");
        assert!(msg.contains("bad json"), "msg: {msg}");
    }
}
