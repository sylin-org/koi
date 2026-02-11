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
