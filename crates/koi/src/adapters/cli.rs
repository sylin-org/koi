use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use koi_common::error::ErrorCode;
use koi_common::pipeline::PipelineResponse;
use koi_common::types::SessionId;
use koi_mdns::protocol::{self as mdns_protocol, RenewalResult, Request, Response};
use koi_mdns::{LeasePolicy, MdnsCore};

/// CLI session grace period: 5 seconds (short-lived sessions).
const SESSION_GRACE: Duration = Duration::from_secs(5);

/// Length of generated session IDs.
const SESSION_ID_LEN: usize = 8;

fn new_session_id() -> SessionId {
    SessionId(uuid::Uuid::new_v4().to_string()[..SESSION_ID_LEN].to_string())
}

/// Run the CLI adapter: read NDJSON from stdin, write responses to stdout.
pub async fn start(core: Arc<MdnsCore>) -> anyhow::Result<()> {
    let session_id = new_session_id();
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request = match serde_json::from_str::<Request>(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = PipelineResponse::clean(Response::Error {
                    error: ErrorCode::ParseError,
                    message: format!("Invalid JSON: {e}"),
                });
                write_response(&mut stdout, &resp).await?;
                continue;
            }
        };

        match request {
            Request::Browse(service_type) => {
                let handle = match core.browse(&service_type).await {
                    Ok(h) => h,
                    Err(e) => {
                        write_response(&mut stdout, &mdns_protocol::error_to_pipeline(&e)).await?;
                        continue;
                    }
                };

                while let Some(event) = handle.recv().await {
                    write_response(&mut stdout, &mdns_protocol::browse_event_to_pipeline(event))
                        .await?;
                }
            }

            Request::Register(payload) => {
                let policy = LeasePolicy::Session {
                    grace: SESSION_GRACE,
                };
                let resp =
                    match core.register_with_policy(payload, policy, Some(session_id.clone())) {
                        Ok(result) => PipelineResponse::clean(Response::Registered(result)),
                        Err(e) => mdns_protocol::error_to_pipeline(&e),
                    };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Unregister(id) => {
                let resp = match core.unregister(&id) {
                    Ok(()) => PipelineResponse::clean(Response::Unregistered(id)),
                    Err(e) => mdns_protocol::error_to_pipeline(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Resolve(instance) => {
                let resp = match core.resolve(&instance).await {
                    Ok(record) => PipelineResponse::clean(Response::Resolved(record)),
                    Err(e) => mdns_protocol::error_to_pipeline(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Subscribe(service_type) => {
                let handle = match core.browse(&service_type).await {
                    Ok(h) => h,
                    Err(e) => {
                        write_response(&mut stdout, &mdns_protocol::error_to_pipeline(&e)).await?;
                        continue;
                    }
                };

                while let Some(event) = handle.recv().await {
                    write_response(&mut stdout, &mdns_protocol::subscribe_event_to_pipeline(event))
                        .await?;
                }
            }

            Request::Heartbeat(id) => {
                let resp = match core.heartbeat(&id) {
                    Ok(lease_secs) => {
                        PipelineResponse::clean(Response::Renewed(RenewalResult { id, lease_secs }))
                    }
                    Err(e) => mdns_protocol::error_to_pipeline(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }
        }
    }

    core.session_disconnected(&session_id);
    Ok(())
}

async fn write_response(
    stdout: &mut tokio::io::Stdout,
    resp: &mdns_protocol::MdnsPipelineResponse,
) -> std::io::Result<()> {
    let out = serde_json::to_string(resp).unwrap();
    stdout.write_all(out.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await
}
