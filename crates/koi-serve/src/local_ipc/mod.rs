//! Trusted machine-local control and mDNS session transport.
//!
//! Authentication belongs to the platform adapter; request dispatch and
//! connection lifetime are shared. This keeps the DAT owner-private while
//! allowing the recorded workstation operator to use the real system daemon.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use koi_common::local_control::{
    LocalControlRequest, LocalControlResponse, LocalDaemonAccess, LocalDaemonInfo,
    LOCAL_CONTROL_VERSION,
};
use koi_config::local_access::LocalOperator;
use koi_mdns::MdnsCore;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::dispatch;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// IPC session grace period.
const SESSION_GRACE: Duration = Duration::from_secs(30);
/// Maximum time accepted sessions receive to observe cancellation and exit.
const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Authorization and hand-off material for the local transport.
///
/// Deliberately has no `Debug` implementation because `access` contains the DAT.
#[derive(Clone)]
pub struct LocalControlConfig {
    pub path: PathBuf,
    pub operator: LocalOperator,
    pub access: Option<LocalDaemonAccess>,
    pub info: LocalDaemonInfo,
}

/// One acquired generation of the trusted machine-local transport.
///
/// Construction is the readiness fence: the native endpoint exists, carries
/// its final authorization policy, and is exclusively owned by this value.
/// Running only admits connections to that already-acquired endpoint.
pub struct LocalControl {
    #[cfg(unix)]
    inner: unix::LocalControl,
    #[cfg(windows)]
    inner: windows::LocalControl,
}

impl LocalControl {
    /// Acquire and secure the platform transport before any task or ownership
    /// publication can claim that local control is ready.
    pub fn acquire(config: LocalControlConfig) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                inner: unix::LocalControl::acquire(config)?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                inner: windows::LocalControl::acquire(config)?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = config;
            anyhow::bail!("local IPC is unsupported on this platform")
        }
    }

    /// Serve the already-acquired generation until cancellation or a terminal
    /// native error, then synchronously fence the endpoint and drain sessions.
    pub async fn run(
        self,
        mdns: Option<Arc<MdnsCore>>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            self.inner.run(mdns, cancel).await
        }
        #[cfg(windows)]
        {
            self.inner.run(mdns, cancel).await
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (self, mdns, cancel);
            anyhow::bail!("local IPC is unsupported on this platform")
        }
    }
}

async fn run_session<R, W>(
    mdns: Option<Arc<MdnsCore>>,
    reader: R,
    writer: W,
    access: Option<LocalDaemonAccess>,
    info: LocalDaemonInfo,
    cancel: CancellationToken,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(()),
        result = handle_connection(mdns, reader, writer, access, info) => result,
    }
}

fn observe_session_result(result: Option<Result<anyhow::Result<()>, tokio::task::JoinError>>) {
    match result {
        Some(Ok(Err(error))) => {
            tracing::debug!(%error, "Local-control connection closed with an error");
        }
        Some(Err(error)) if !error.is_cancelled() => {
            tracing::warn!(%error, "Local-control connection task failed");
        }
        _ => {}
    }
}

/// Reap every accepted session. Dropping a timed-out JoinSet would abort the
/// tasks but would not acknowledge their completion, so stragglers are
/// explicitly aborted and joined before the listener owner returns.
async fn drain_sessions(sessions: &mut JoinSet<anyhow::Result<()>>) {
    let deadline = tokio::time::Instant::now() + SESSION_DRAIN_TIMEOUT;
    while !sessions.is_empty() {
        match tokio::time::timeout_at(deadline, sessions.join_next()).await {
            Ok(result) => observe_session_result(result),
            Err(_) => break,
        }
    }

    if !sessions.is_empty() {
        tracing::warn!(
            sessions = sessions.len(),
            timeout_ms = SESSION_DRAIN_TIMEOUT.as_millis(),
            "Local-control sessions exceeded the shutdown deadline"
        );
        sessions.abort_all();
        while let Some(result) = sessions.join_next().await {
            observe_session_result(Some(result));
        }
    }
}

async fn handle_connection<R, W>(
    mdns: Option<Arc<MdnsCore>>,
    reader: R,
    mut writer: W,
    access: Option<LocalDaemonAccess>,
    info: LocalDaemonInfo,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // The guard is created by the domain and therefore survives every return
    // path through this transport, including writer failures.
    let session = mdns.as_ref().map(|core| core.open_registration_session());
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Ok(request) = serde_json::from_str::<LocalControlRequest>(line) {
            let response = match request {
                LocalControlRequest::Access { version } if version != LOCAL_CONTROL_VERSION => {
                    LocalControlResponse::unsupported_version(version)
                }
                LocalControlRequest::Info { version } if version != LOCAL_CONTROL_VERSION => {
                    LocalControlResponse::unsupported_version(version)
                }
                LocalControlRequest::Access { .. } => match &access {
                    Some(access) => LocalControlResponse::Access(access.clone()),
                    None => LocalControlResponse::Error {
                        code: "http_disabled".to_string(),
                        message: "the local daemon is not serving HTTP".to_string(),
                    },
                },
                LocalControlRequest::Info { .. } => LocalControlResponse::Info(info.clone()),
            };
            write_json_line(&mut writer, &response).await?;
            continue;
        }

        match (&mdns, &session) {
            (Some(core), Some(session)) => {
                dispatch::handle_line(core, session.id(), line, SESSION_GRACE, &mut writer).await?;
            }
            _ => {
                write_json_line(
                    &mut writer,
                    &serde_json::json!({
                        "error": "capability_disabled",
                        "message": "mDNS is disabled for this daemon"
                    }),
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn write_json_line<W, T>(writer: &mut W, value: &T) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let encoded = serde_json::to_vec(value)?;
    writer.write_all(&encoded).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

fn split_stream<S>(stream: S) -> (BufReader<tokio::io::ReadHalf<S>>, tokio::io::WriteHalf<S>)
where
    S: tokio::io::AsyncRead + AsyncWrite,
{
    let (reader, writer) = tokio::io::split(stream);
    (BufReader::new(reader), writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn info_is_available_when_http_access_is_disabled() {
        let info = LocalDaemonInfo {
            version: LOCAL_CONTROL_VERSION,
            data_root: "/var/lib/koi".to_string(),
            config_path: "/etc/koi/config.toml".to_string(),
        };
        let (client, server) = tokio::io::duplex(4096);
        let (server_reader, server_writer) = tokio::io::split(server);
        let task = tokio::spawn(handle_connection(
            None,
            BufReader::new(server_reader),
            server_writer,
            None,
            info.clone(),
        ));

        let (client_reader, mut client_writer) = tokio::io::split(client);
        client_writer
            .write_all(b"{\"request\":\"info\",\"version\":1}\n")
            .await
            .unwrap();
        client_writer.flush().await.unwrap();
        let mut line = String::new();
        BufReader::new(client_reader)
            .read_line(&mut line)
            .await
            .unwrap();
        drop(client_writer);

        let response: LocalControlResponse = serde_json::from_str(line.trim()).unwrap();
        assert!(response == LocalControlResponse::Info(info));
        task.await.unwrap().unwrap();
    }
}
