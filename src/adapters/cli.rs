use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::core::{MdnsCore, ServiceEvent};
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
                let out = serde_json::to_string(&resp).unwrap();
                stdout.write_all(out.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
                continue;
            }
        };

        match request {
            Request::Browse(service_type) => {
                let handle = match core.browse(&service_type) {
                    Ok(h) => h,
                    Err(e) => {
                        write_error(&mut stdout, &e).await?;
                        continue;
                    }
                };

                // Stream results until the browse ends
                while let Some(event) = handle.recv().await {
                    let resp = match event {
                        ServiceEvent::Resolved(record) | ServiceEvent::Found(record) => {
                            PipelineResponse::clean(Response::Found(record))
                        }
                        ServiceEvent::Removed { name, service_type } => {
                            PipelineResponse::clean(Response::Event {
                                event: crate::protocol::EventKind::Removed,
                                service: crate::protocol::ServiceRecord {
                                    name,
                                    service_type,
                                    host: None,
                                    ip: None,
                                    port: 0,
                                    txt: Default::default(),
                                },
                            })
                        }
                    };
                    let out = serde_json::to_string(&resp).unwrap();
                    stdout.write_all(out.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
            }

            Request::Register(payload) => {
                let resp = match core.register(payload) {
                    Ok(result) => PipelineResponse::clean(Response::Registered(result)),
                    Err(e) => error_response(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Unregister(id) => {
                let resp = match core.unregister(&id) {
                    Ok(()) => PipelineResponse::clean(Response::Unregistered(id)),
                    Err(e) => error_response(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Resolve(instance) => {
                let resp = match core.resolve(&instance).await {
                    Ok(record) => PipelineResponse::clean(Response::Resolved(record)),
                    Err(e) => error_response(&e),
                };
                write_response(&mut stdout, &resp).await?;
            }

            Request::Subscribe(service_type) => {
                // First start a browse to generate events
                let handle = match core.browse(&service_type) {
                    Ok(h) => h,
                    Err(e) => {
                        write_error(&mut stdout, &e).await?;
                        continue;
                    }
                };

                while let Some(event) = handle.recv().await {
                    let resp = match event {
                        ServiceEvent::Found(record) => PipelineResponse::clean(Response::Event {
                            event: crate::protocol::EventKind::Found,
                            service: record,
                        }),
                        ServiceEvent::Resolved(record) => {
                            PipelineResponse::clean(Response::Event {
                                event: crate::protocol::EventKind::Resolved,
                                service: record,
                            })
                        }
                        ServiceEvent::Removed { name, service_type } => {
                            PipelineResponse::clean(Response::Event {
                                event: crate::protocol::EventKind::Removed,
                                service: crate::protocol::ServiceRecord {
                                    name,
                                    service_type,
                                    host: None,
                                    ip: None,
                                    port: 0,
                                    txt: Default::default(),
                                },
                            })
                        }
                    };
                    let out = serde_json::to_string(&resp).unwrap();
                    stdout.write_all(out.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
            }
        }
    }

    Ok(())
}

fn error_response(e: &crate::core::KoiError) -> PipelineResponse {
    let (code, msg) = match e {
        crate::core::KoiError::InvalidServiceType(_) => ("invalid_type", e.to_string()),
        crate::core::KoiError::RegistrationNotFound(_) => ("not_found", e.to_string()),
        crate::core::KoiError::ResolveTimeout(_) => ("resolve_timeout", e.to_string()),
        crate::core::KoiError::Daemon(_) => ("daemon_error", e.to_string()),
        crate::core::KoiError::Io(_) => ("io_error", e.to_string()),
    };
    PipelineResponse::clean(Response::Error {
        error: code.into(),
        message: msg,
    })
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

async fn write_error(
    stdout: &mut tokio::io::Stdout,
    e: &crate::core::KoiError,
) -> std::io::Result<()> {
    write_response(stdout, &error_response(e)).await
}
