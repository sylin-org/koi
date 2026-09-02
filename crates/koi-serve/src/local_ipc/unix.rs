use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use koi_config::local_access::LocalOperator;
use koi_mdns::MdnsCore;
use tokio_util::sync::CancellationToken;

use super::{split_stream, LocalControlConfig};

pub(super) async fn start(
    mdns: Option<Arc<MdnsCore>>,
    config: LocalControlConfig,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let expected_uid = match config.operator {
        LocalOperator::UnixUid { uid } => uid,
        LocalOperator::WindowsSid { .. } => {
            anyhow::bail!("Windows SID cannot authorize a Unix local-control socket")
        }
    };

    remove_stale_socket(&config.path)?;
    let listener = tokio::net::UnixListener::bind(&config.path)?;
    std::fs::set_permissions(&config.path, std::fs::Permissions::from_mode(0o600))?;
    chown_socket(&config.path, expected_uid)?;

    tracing::info!(
        path = %config.path.display(),
        operator_uid = expected_uid,
        "Local control listening (Unix socket)"
    );

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let peer_uid = stream.peer_cred()?.uid();
                if !peer_is_authorized(peer_uid, expected_uid) {
                    tracing::warn!(peer_uid, expected_uid, "Rejected unauthorized local-control peer");
                    continue;
                }
                let mdns = mdns.clone();
                let access = config.access.clone();
                let info = config.info.clone();
                tokio::spawn(async move {
                    let (reader, writer) = split_stream(stream);
                    if let Err(error) =
                        super::handle_connection(mdns, reader, writer, access, info).await
                    {
                        tracing::debug!(%error, "Local-control connection closed with an error");
                    }
                });
            }
            _ = cancel.cancelled() => break,
        }
    }

    drop(listener);
    remove_owned_socket(&config.path);
    tracing::debug!("Local control stopped (Unix socket)");
    Ok(())
}

fn peer_is_authorized(peer_uid: u32, expected_uid: u32) -> bool {
    // Root already has read access to the owner-private breadcrumb and is the
    // Unix counterpart to SYSTEM/Administrators in the Windows pipe DACL.
    peer_uid == expected_uid || peer_uid == 0
}

fn remove_stale_socket(path: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => anyhow::bail!(
            "refusing to replace non-socket local-control path {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_owned_socket(path: &Path) {
    if std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
    {
        if let Err(error) = std::fs::remove_file(path) {
            tracing::warn!(%error, path = %path.display(), "Could not remove local-control socket");
        }
    }
}

fn chown_socket(path: &Path, uid: u32) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // Preserve the listener's group; the 0600 mode grants it no access.
    // SAFETY: `path` is a live NUL-terminated string and chown has no other
    // pointer preconditions.
    let result = unsafe { libc::chown(path.as_ptr(), uid, u32::MAX) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(test)]
mod tests {
    use super::peer_is_authorized;

    #[test]
    fn local_control_accepts_operator_and_root_only() {
        assert!(peer_is_authorized(1000, 1000));
        assert!(peer_is_authorized(0, 1000));
        assert!(!peer_is_authorized(65534, 1000));
    }
}
