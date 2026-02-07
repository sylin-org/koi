use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::core::MdnsCore;
use crate::protocol::request::Request;
use crate::protocol::response::{PipelineResponse, Response};

/// Run the CLI adapter: read NDJSON from stdin, write responses to stdout.
pub async fn start(core: Arc<MdnsCore>) -> anyhow::Result<()> {
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
                    error: "parse_error".into(),
                    message: format!("Invalid JSON: {e}"),
                });
                write_response(&mut stdout, &resp).await?;
                continue;
            }
        };

        match request {
            Request::Browse(service_type) => {
                let handle = match core.browse(&service_type) {
                    Ok(h) => h,
                    Err(e) => {
                        write_response(&mut stdout, &PipelineResponse::from_error(&e)).await?;
                        continue;
                    }
                };

                while let Some(event) = handle.recv().await {
                    write_response(&mut stdout, &PipelineResponse::from_browse_event(event))
                        .await?;
                }
            }

            Request::Register(payload) => {
                let resp = match core.register(payload) {
                    Ok(result) => PipelineResponse::clean(Response::Registered(result)),
                    Err(e) => PipelineResponse::from_error(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Unregister(id) => {
                let resp = match core.unregister(&id) {
                    Ok(()) => PipelineResponse::clean(Response::Unregistered(id)),
                    Err(e) => PipelineResponse::from_error(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Resolve(instance) => {
                let resp = match core.resolve(&instance).await {
                    Ok(record) => PipelineResponse::clean(Response::Resolved(record)),
                    Err(e) => PipelineResponse::from_error(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Subscribe(service_type) => {
                let handle = match core.browse(&service_type) {
                    Ok(h) => h,
                    Err(e) => {
                        write_response(&mut stdout, &PipelineResponse::from_error(&e)).await?;
                        continue;
                    }
                };

                while let Some(event) = handle.recv().await {
                    write_response(
                        &mut stdout,
                        &PipelineResponse::from_subscribe_event(event),
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}

async fn write_response(
    stdout: &mut tokio::io::Stdout,
    resp: &PipelineResponse,
) -> std::io::Result<()> {
    let out = serde_json::to_string(resp).unwrap();
    stdout.write_all(out.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await
}
