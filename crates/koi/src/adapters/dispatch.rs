//! Shared NDJSON request dispatch for pipe and CLI adapters.
//!
//! Both adapters parse the same `Request` enum and produce the same
//! `MdnsPipelineResponse` output. This module factors out the common
//! dispatch and serialization logic.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use koi_common::error::ErrorCode;
use koi_common::pipeline::PipelineResponse;
use koi_common::types::SessionId;
use koi_mdns::protocol::{self as mdns_protocol, MdnsPipelineResponse, RenewalResult, Request, Response};
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
            let resp = PipelineResponse::clean(Response::Error {
                error: ErrorCode::ParseError,
                message: format!("Invalid JSON: {e}"),
            });
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
    let out = serde_json::to_string(resp)
        .unwrap_or_else(|e| format!("{{\"error\":\"internal\",\"message\":\"serialization failed: {e}\"}}"));
    writer.write_all(out.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}
