//! Shared NDJSON request dispatch for pipe and CLI adapters.
//!
//! Both adapters parse the same `Request` enum and produce the same
//! `MdnsPipelineResponse` output. This module factors out the common
//! dispatch and serialization logic.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use koi_common::api::error_body;
use koi_common::error::ErrorCode;
use koi_common::pipeline::PipelineResponse;
use koi_common::types::SessionId;
use koi_mdns::protocol::{
    self as mdns_protocol, MdnsPipelineResponse, RenewalResult, Request, Response,
};
use koi_mdns::{LeasePolicy, MdnsCore};

/// Create a new session ID using the shared short-ID generator.
pub fn new_session_id() -> SessionId {
    SessionId(koi_common::id::generate_short_id())
}

/// Dispatch a single NDJSON request line and write responses to the writer.
pub async fn handle_line<W: AsyncWriteExt + Unpin>(
    core: &MdnsCore,
    session_id: &SessionId,
    line: &str,
    session_grace: Duration,
    writer: &mut W,
) -> anyhow::Result<()> {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(r) => r,
        Err(e) => {
            let resp = PipelineResponse::clean(Response::Error(error_body(
                ErrorCode::ParseError,
                format!("Invalid JSON: {e}"),
            )));
            write_response(writer, &resp).await?;
            return Ok(());
        }
    };

    match request {
        Request::Browse(service_type) => {
            let handle = match core.browse(&service_type).await {
                Ok(h) => h,
                Err(e) => {
                    write_response(writer, &mdns_protocol::error_to_pipeline(&e)).await?;
                    return Ok(());
                }
            };

            while let Some(event) = handle.recv().await {
                write_response(writer, &mdns_protocol::browse_event_to_pipeline(event)).await?;
            }
        }

        Request::Register(payload) => {
            let policy = LeasePolicy::Session {
                grace: session_grace,
            };
            let resp = match core.register_with_policy(payload, policy, Some(session_id.clone())) {
                Ok(result) => PipelineResponse::clean(Response::Registered(result)),
                Err(e) => mdns_protocol::error_to_pipeline(&e),
            };
            write_response(writer, &resp).await?;
        }

        Request::Unregister(id) => {
            let resp = match core.unregister(&id) {
                Ok(()) => PipelineResponse::clean(Response::Unregistered(id)),
                Err(e) => mdns_protocol::error_to_pipeline(&e),
            };
            write_response(writer, &resp).await?;
        }

        Request::Resolve(instance) => {
            let resp = match core.resolve(&instance).await {
                Ok(record) => PipelineResponse::clean(Response::Resolved(record)),
                Err(e) => mdns_protocol::error_to_pipeline(&e),
            };
            write_response(writer, &resp).await?;
        }

        Request::Subscribe(service_type) => {
            let handle = match core.browse(&service_type).await {
                Ok(h) => h,
                Err(e) => {
                    write_response(writer, &mdns_protocol::error_to_pipeline(&e)).await?;
                    return Ok(());
                }
            };

            while let Some(event) = handle.recv().await {
                write_response(writer, &mdns_protocol::subscribe_event_to_pipeline(event)).await?;
            }
        }

        Request::Heartbeat(id) => {
            let resp = match core.heartbeat(&id) {
                Ok(lease_secs) => {
                    PipelineResponse::clean(Response::Renewed(RenewalResult { id, lease_secs }))
                }
                Err(e) => mdns_protocol::error_to_pipeline(&e),
            };
            write_response(writer, &resp).await?;
        }
    }

    Ok(())
}

/// Serialize a pipeline response as NDJSON and write it to the writer.
pub async fn write_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &MdnsPipelineResponse,
) -> std::io::Result<()> {
    // PipelineResponse<Response> serialization is infallible for well-formed types,
    // but we handle the error rather than panicking in production code.
    let out = serde_json::to_string(resp).unwrap_or_else(|e| {
        format!("{{\"error\":\"internal\",\"message\":\"serialization failed: {e}\"}}")
    });
    writer.write_all(out.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::types::ServiceRecord;
    use std::collections::HashMap;

    // ── new_session_id ──────────────────────────────────────────────

    #[test]
    fn new_session_id_has_correct_length() {
        let sid = new_session_id();
        assert_eq!(sid.0.len(), 8); // SHORT_ID_LEN
    }

    #[test]
    fn new_session_id_is_unique() {
        let a = new_session_id();
        let b = new_session_id();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn new_session_id_is_hex() {
        let sid = new_session_id();
        assert!(
            sid.0.chars().all(|c| c.is_ascii_hexdigit()),
            "session ID should be hex: {}",
            sid.0
        );
    }

    // ── write_response ──────────────────────────────────────────────

    #[tokio::test]
    async fn write_response_outputs_ndjson() {
        let resp = PipelineResponse::clean(Response::Unregistered("abc123".into()));
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).await.unwrap();

        let output = String::from_utf8(buf).unwrap();
        assert!(output.ends_with('\n'));
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(parsed.get("unregistered").unwrap(), "abc123");
    }

    #[tokio::test]
    async fn write_response_found_includes_record() {
        let record = ServiceRecord {
            name: "Test".into(),
            service_type: "_http._tcp".into(),
            host: Some("test.local".into()),
            ip: Some("192.168.1.1".into()),
            port: Some(80),
            txt: HashMap::new(),
        };
        let resp = PipelineResponse::clean(Response::Found(record));
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).await.unwrap();

        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        let found = parsed.get("found").unwrap();
        assert_eq!(found.get("name").unwrap(), "Test");
    }

    #[tokio::test]
    async fn write_response_error_format() {
        let resp = PipelineResponse::clean(Response::Error(error_body(
            ErrorCode::NotFound,
            "Registration not found",
        )));
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).await.unwrap();

        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(parsed.get("error").unwrap(), "not_found");
        assert_eq!(parsed.get("message").unwrap(), "Registration not found");
    }

    #[tokio::test]
    async fn write_response_renewed_format() {
        let resp = PipelineResponse::clean(Response::Renewed(RenewalResult {
            id: "test-id".into(),
            lease_secs: 90,
        }));
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).await.unwrap();

        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        let renewed = parsed.get("renewed").unwrap();
        assert_eq!(renewed.get("id").unwrap(), "test-id");
        assert_eq!(renewed.get("lease_secs").unwrap(), 90);
    }

    #[tokio::test]
    async fn write_response_multiple_writes() {
        let resp1 = PipelineResponse::clean(Response::Unregistered("a".into()));
        let resp2 = PipelineResponse::clean(Response::Unregistered("b".into()));
        let mut buf = Vec::new();
        write_response(&mut buf, &resp1).await.unwrap();
        write_response(&mut buf, &resp2).await.unwrap();

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn write_response_pipeline_ongoing_includes_status() {
        let resp = PipelineResponse::ongoing(Response::Found(ServiceRecord {
            name: "S".into(),
            service_type: "_http._tcp".into(),
            host: None,
            ip: None,
            port: None,
            txt: HashMap::new(),
        }));
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).await.unwrap();

        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(parsed.get("status").unwrap(), "ongoing");
    }
}
