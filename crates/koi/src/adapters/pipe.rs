use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};

use tokio_util::sync::CancellationToken;

use koi_mdns::MdnsCore;

use super::dispatch;

/// IPC session grace period: 30 seconds.
const SESSION_GRACE: Duration = Duration::from_secs(30);

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
    let session_id = dispatch::new_session_id();
    let (reader, mut writer) = stream.into_split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        dispatch::handle_line(&core, &session_id, &line, SESSION_GRACE, &mut writer).await?;
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
    let session_id = dispatch::new_session_id();
    let (reader, mut writer) = tokio::io::split(pipe);
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        dispatch::handle_line(&core, &session_id, &line, SESSION_GRACE, &mut writer).await?;
    }
    core.session_disconnected(&session_id);
    Ok(())
}
