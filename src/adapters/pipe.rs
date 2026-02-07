use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::core::MdnsCore;
use crate::protocol::request::Request;
use crate::protocol::response::{PipelineResponse, Response};

/// Start the IPC adapter.
/// Windows: Named Pipe at `\\.\pipe\koi`
/// Unix: Unix Domain Socket at the given path
pub async fn start(core: Arc<MdnsCore>, path: std::path::PathBuf) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        start_unix(core, path).await
    }
    #[cfg(windows)]
    {
        start_windows(core, path).await
    }
}

#[cfg(unix)]
async fn start_unix(core: Arc<MdnsCore>, path: std::path::PathBuf) -> anyhow::Result<()> {
    // Remove stale socket file
    let _ = std::fs::remove_file(&path);

    let listener = tokio::net::UnixListener::bind(&path)?;
    tracing::info!(path = %path.display(), "IPC adapter listening (Unix socket)");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(core, stream).await {
                tracing::warn!(error = %e, "IPC connection error");
            }
        });
    }
}

#[cfg(unix)]
async fn handle_connection(
    core: Arc<MdnsCore>,
    stream: tokio::net::UnixStream,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        handle_line(&core, &line, &mut writer).await?;
    }
    Ok(())
}

#[cfg(windows)]
async fn start_windows(core: Arc<MdnsCore>, _path: std::path::PathBuf) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = r"\\.\pipe\koi";

    tracing::info!(pipe = pipe_name, "IPC adapter listening (Named Pipe)");

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(pipe_name)?;

        server.connect().await?;

        let core = core.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_pipe_connection(core, server).await {
                tracing::warn!(error = %e, "IPC pipe connection error");
            }
        });
    }
}

#[cfg(windows)]
async fn handle_pipe_connection(
    core: Arc<MdnsCore>,
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(pipe);
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        handle_line(&core, &line, &mut writer).await?;
    }
    Ok(())
}

async fn handle_line<W: AsyncWriteExt + Unpin>(
    core: &MdnsCore,
    line: &str,
    writer: &mut W,
) -> anyhow::Result<()> {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(r) => r,
        Err(e) => {
            let resp = PipelineResponse::clean(Response::Error {
                error: "parse_error".into(),
                message: format!("Invalid JSON: {e}"),
            });
            write_line(writer, &resp).await?;
            return Ok(());
        }
    };

    match request {
        Request::Browse(service_type) => {
            let handle = match core.browse(&service_type) {
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
            let resp = match core.register(payload) {
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
            let handle = match core.browse(&service_type) {
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
