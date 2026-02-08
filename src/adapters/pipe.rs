use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use tokio_util::sync::CancellationToken;

use crate::core::{LeasePolicy, MdnsCore, SessionId};
use crate::protocol::error::ErrorCode;
use crate::protocol::request::Request;
use crate::protocol::response::{PipelineResponse, Response};
use crate::protocol::RenewalResult;

/// IPC session grace period: 30 seconds.
const SESSION_GRACE: Duration = Duration::from_secs(30);

/// Length of generated session IDs.
const SESSION_ID_LEN: usize = 8;

fn new_session_id() -> SessionId {
    SessionId(uuid::Uuid::new_v4().to_string()[..SESSION_ID_LEN].to_string())
}

/// Start the IPC adapter with graceful shutdown support.
/// Windows: Named Pipe at `\\.\pipe\koi`
/// Unix: Unix Domain Socket at the given path
pub async fn start(
    core: Arc<MdnsCore>,
    path: std::path::PathBuf,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        start_unix(core, path, cancel).await
    }
    #[cfg(windows)]
    {
        start_windows(core, path, cancel).await
    }
}

#[cfg(unix)]
async fn start_unix(
    core: Arc<MdnsCore>,
    path: std::path::PathBuf,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    // Remove stale socket file
    let _ = std::fs::remove_file(&path);

    let listener = tokio::net::UnixListener::bind(&path)?;
    tracing::info!(path = %path.display(), "IPC adapter listening (Unix socket)");

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _addr) = result?;
                let core = core.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(core, stream).await {
                        tracing::warn!(error = %e, "IPC connection error");
                    }
                });
            }
            _ = cancel.cancelled() => break,
        }
    }
    tracing::debug!("IPC adapter stopped (Unix)");
    Ok(())
}

#[cfg(unix)]
async fn handle_connection(
    core: Arc<MdnsCore>,
    stream: tokio::net::UnixStream,
) -> anyhow::Result<()> {
    let session_id = new_session_id();
    let (reader, mut writer) = stream.into_split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        handle_line(&core, &session_id, &line, &mut writer).await?;
    }
    core.session_disconnected(&session_id);
    Ok(())
}

#[cfg(windows)]
async fn start_windows(
    core: Arc<MdnsCore>,
    path: std::path::PathBuf,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = path.to_string_lossy();

    tracing::info!(pipe = %pipe_name, "IPC adapter listening (Named Pipe)");

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(pipe_name.as_ref())?;

        tokio::select! {
            result = server.connect() => {
                result?;
                let core = core.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_pipe_connection(core, server).await {
                        tracing::warn!(error = %e, "IPC pipe connection error");
                    }
                });
            }
            _ = cancel.cancelled() => break,
        }
    }
    tracing::debug!("IPC adapter stopped (Named Pipe)");
    Ok(())
}

#[cfg(windows)]
async fn handle_pipe_connection(
    core: Arc<MdnsCore>,
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
) -> anyhow::Result<()> {
    let session_id = new_session_id();
    let (reader, mut writer) = tokio::io::split(pipe);
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        handle_line(&core, &session_id, &line, &mut writer).await?;
    }
    core.session_disconnected(&session_id);
    Ok(())
}

async fn handle_line<W: AsyncWriteExt + Unpin>(
    core: &MdnsCore,
    session_id: &SessionId,
    line: &str,
    writer: &mut W,
) -> anyhow::Result<()> {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(r) => r,
        Err(e) => {
            let resp = PipelineResponse::clean(Response::Error {
                error: ErrorCode::ParseError,
                message: format!("Invalid JSON: {e}"),
            });
            write_line(writer, &resp).await?;
            return Ok(());
        }
    };

    match request {
        Request::Browse(service_type) => {
            let handle = match core.browse(&service_type).await {
                Ok(h) => h,
                Err(e) => {
                    write_line(writer, &PipelineResponse::from_error(&e)).await?;
                    return Ok(());
                }
            };

            while let Some(event) = handle.recv().await {
                write_line(writer, &PipelineResponse::from_browse_event(event)).await?;
            }
        }

        Request::Register(payload) => {
            let policy = LeasePolicy::Session {
                grace: SESSION_GRACE,
            };
            let resp = match core.register_with_policy(payload, policy, Some(session_id.clone())) {
                Ok(result) => PipelineResponse::clean(Response::Registered(result)),
                Err(e) => PipelineResponse::from_error(&e),
            };
            write_line(writer, &resp).await?;
        }

        Request::Unregister(id) => {
            let resp = match core.unregister(&id) {
                Ok(()) => PipelineResponse::clean(Response::Unregistered(id)),
                Err(e) => PipelineResponse::from_error(&e),
            };
            write_line(writer, &resp).await?;
        }

        Request::Resolve(instance) => {
            let resp = match core.resolve(&instance).await {
                Ok(record) => PipelineResponse::clean(Response::Resolved(record)),
                Err(e) => PipelineResponse::from_error(&e),
            };
            write_line(writer, &resp).await?;
        }

        Request::Subscribe(service_type) => {
            let handle = match core.browse(&service_type).await {
                Ok(h) => h,
                Err(e) => {
                    write_line(writer, &PipelineResponse::from_error(&e)).await?;
                    return Ok(());
                }
            };

            while let Some(event) = handle.recv().await {
                write_line(writer, &PipelineResponse::from_subscribe_event(event)).await?;
            }
        }

        Request::Heartbeat(id) => {
            let resp = match core.heartbeat(&id) {
                Ok(lease_secs) => {
                    PipelineResponse::clean(Response::Renewed(RenewalResult { id, lease_secs }))
                }
                Err(e) => PipelineResponse::from_error(&e),
            };
            write_line(writer, &resp).await?;
        }
    }

    Ok(())
}

async fn write_line<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &PipelineResponse,
) -> std::io::Result<()> {
    let out = serde_json::to_string(resp).unwrap();
    writer.write_all(out.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}
