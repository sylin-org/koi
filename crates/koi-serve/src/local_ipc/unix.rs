use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use koi_config::local_access::LocalOperator;
use koi_mdns::MdnsCore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::{
    drain_sessions, observe_session_result, run_session, split_stream, LocalControlConfig,
};

/// Stable, adjacent lock filename suffix. The file itself is deliberately
/// retained: unlinking a lock file can split waiters across two inodes.
const LOCK_SUFFIX: &str = ".lock";

/// One acquired Unix local-control generation.
pub(super) struct LocalControl {
    listener: tokio::net::UnixListener,
    socket_path: OwnedSocketPath,
    _generation_lock: GenerationLock,
    expected_uid: u32,
    access: Option<koi_common::local_control::LocalDaemonAccess>,
    info: koi_common::local_control::LocalDaemonInfo,
}

impl LocalControl {
    pub(super) fn acquire(config: LocalControlConfig) -> anyhow::Result<Self> {
        let expected_uid = match config.operator {
            LocalOperator::UnixUid { uid } => uid,
            LocalOperator::WindowsSid { .. } => {
                anyhow::bail!("Windows SID cannot authorize a Unix local-control socket")
            }
        };

        let generation_lock = GenerationLock::acquire(&config.path)?;
        remove_stale_socket(&config.path)?;
        let listener = tokio::net::UnixListener::bind(&config.path)?;
        let socket_path = OwnedSocketPath::observe(config.path.clone())?;

        std::fs::set_permissions(&config.path, std::fs::Permissions::from_mode(0o600))?;
        chown_socket(&config.path, expected_uid)?;
        socket_path.verify_current()?;

        Ok(Self {
            listener,
            socket_path,
            _generation_lock: generation_lock,
            expected_uid,
            access: config.access,
            info: config.info,
        })
    }

    pub(super) async fn run(
        mut self,
        mdns: Option<Arc<MdnsCore>>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let session_cancel = cancel.child_token();
        let mut sessions = JoinSet::new();

        tracing::info!(
            path = %self.socket_path.path.display(),
            operator_uid = self.expected_uid,
            "Local control listening (Unix socket)"
        );

        // Keep fallible accept/credential work inside a result boundary so
        // every terminal error still executes the exact cleanup below.
        let result: anyhow::Result<()> = async {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break Ok(()),
                    joined = sessions.join_next(), if !sessions.is_empty() => {
                        observe_session_result(joined);
                    }
                    accepted = self.listener.accept() => {
                        let (stream, _) = accepted?;
                        let peer_uid = stream.peer_cred()?.uid();
                        if !peer_is_authorized(peer_uid, self.expected_uid) {
                            tracing::warn!(peer_uid, expected_uid = self.expected_uid, "Rejected unauthorized local-control peer");
                            continue;
                        }
                        let (reader, writer) = split_stream(stream);
                        sessions.spawn(run_session(
                            mdns.clone(),
                            reader,
                            writer,
                            self.access.clone(),
                            self.info.clone(),
                            session_cancel.clone(),
                        ));
                    }
                }
            }
        }
        .await;

        // Fence new connections and the canonical path before retiring any
        // accepted work. The stable generation lock remains held until every
        // session is reaped and this function returns.
        drop(self.listener);
        let cleanup = self.socket_path.remove();
        session_cancel.cancel();
        drain_sessions(&mut sessions).await;
        tracing::debug!("Local control stopped (Unix socket)");

        match (result, cleanup) {
            (result, Ok(())) => result,
            (Ok(()), Err(cleanup)) => Err(cleanup),
            (Err(error), Err(cleanup)) => Err(error.context(format!(
                "local-control socket cleanup also failed: {cleanup}"
            ))),
        }
    }
}

fn peer_is_authorized(peer_uid: u32, expected_uid: u32) -> bool {
    // Root already has read access to the owner-private breadcrumb and is the
    // Unix counterpart to SYSTEM/Administrators in the Windows pipe DACL.
    peer_uid == expected_uid || peer_uid == 0
}

struct GenerationLock {
    _file: std::fs::File,
}

impl GenerationLock {
    fn acquire(socket_path: &Path) -> anyhow::Result<Self> {
        let mut lock_name = socket_path.as_os_str().to_os_string();
        lock_name.push(LOCK_SUFFIX);
        let lock_path = PathBuf::from(lock_name);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|error| {
                anyhow::anyhow!(
                    "could not open local-control generation lock {}: {error}",
                    lock_path.display()
                )
            })?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        use std::os::fd::AsRawFd as _;
        // SAFETY: `file` owns this descriptor for the full lock lifetime and
        // flock neither retains the integer nor accesses Rust memory.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            anyhow::bail!(
                "could not acquire local-control generation lock {} (another owner may be active): {error}",
                lock_path.display()
            );
        }
        Ok(Self { _file: file })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct OwnedSocketPath {
    path: PathBuf,
    identity: SocketIdentity,
    armed: bool,
}

impl OwnedSocketPath {
    fn observe(path: PathBuf) -> anyhow::Result<Self> {
        let identity = observe_socket(&path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "local-control socket disappeared immediately after bind: {}",
                path.display()
            )
        })?;
        Ok(Self {
            path,
            identity,
            armed: true,
        })
    }

    fn verify_current(&self) -> anyhow::Result<()> {
        match observe_socket(&self.path)? {
            Some(identity) if identity == self.identity => Ok(()),
            Some(identity) => anyhow::bail!(
                "local-control path {} changed generation during acquisition (expected device {} inode {}, found device {} inode {})",
                self.path.display(),
                self.identity.device,
                self.identity.inode,
                identity.device,
                identity.inode,
            ),
            None => anyhow::bail!(
                "local-control socket disappeared during acquisition: {}",
                self.path.display()
            ),
        }
    }

    fn remove(&mut self) -> anyhow::Result<()> {
        if !self.armed {
            return Ok(());
        }
        match observe_socket(&self.path)? {
            None => {
                self.armed = false;
                Ok(())
            }
            Some(identity) if identity == self.identity => {
                std::fs::remove_file(&self.path)?;
                self.armed = false;
                Ok(())
            }
            Some(identity) => {
                // This pathname now belongs to a different generation. Retain
                // the error as a terminal fact, but disarm Drop so it does not
                // repeatedly inspect (and can never delete) that successor.
                self.armed = false;
                Err(anyhow::anyhow!(
                    "refusing to remove replacement local-control socket {} (owned device {} inode {}, current device {} inode {})",
                    self.path.display(),
                    self.identity.device,
                    self.identity.inode,
                    identity.device,
                    identity.inode,
                ))
            }
        }
    }
}

impl Drop for OwnedSocketPath {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::warn!(
                %error,
                path = %self.path.display(),
                "Could not remove the owned local-control socket generation"
            );
        }
    }
}

fn observe_socket(path: &Path) -> anyhow::Result<Option<SocketIdentity>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            Ok(Some(SocketIdentity::from_metadata(&metadata)))
        }
        Ok(_) => anyhow::bail!("refusing non-socket local-control path {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn remove_stale_socket(path: &Path) -> anyhow::Result<()> {
    let Some(identity) = observe_socket(path)? else {
        return Ok(());
    };

    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => anyhow::bail!(
            "local-control socket {} already has a live owner",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            match observe_socket(path)? {
                None => Ok(()),
                Some(current) if current == identity => {
                    std::fs::remove_file(path)?;
                    Ok(())
                }
                Some(current) => anyhow::bail!(
                    "local-control socket {} changed while stale ownership was being verified (expected device {} inode {}, found device {} inode {})",
                    path.display(),
                    identity.device,
                    identity.inode,
                    current.device,
                    current.inode,
                ),
            }
        }
        Err(error) => Err(anyhow::anyhow!(
            "could not verify ownership of local-control socket {}: {error}",
            path.display()
        )),
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
    use super::*;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "koi-local-ipc-{label}-{}",
            koi_common::id::generate_short_id()
        ))
    }

    fn test_config(root: &Path) -> LocalControlConfig {
        LocalControlConfig {
            path: root.join("koi.sock"),
            operator: LocalOperator::UnixUid {
                uid: std::fs::metadata(root)
                    .expect("IPC test root metadata")
                    .uid(),
            },
            access: None,
            info: koi_common::local_control::LocalDaemonInfo {
                version: koi_common::local_control::LOCAL_CONTROL_VERSION,
                data_root: root.to_string_lossy().into_owned(),
                config_path: root.join("config.toml").to_string_lossy().into_owned(),
            },
        }
    }

    #[test]
    fn local_control_accepts_operator_and_root_only() {
        assert!(peer_is_authorized(1000, 1000));
        assert!(peer_is_authorized(0, 1000));
        assert!(!peer_is_authorized(65534, 1000));
    }

    #[tokio::test]
    async fn acquisition_and_shutdown_fence_the_real_socket_and_sessions() {
        let root = test_root("lifecycle");
        std::fs::create_dir_all(&root).expect("create IPC test root");
        let path = root.join("koi.sock");
        let owner = LocalControl::acquire(test_config(&root)).expect("acquire local control");
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("acquired socket path")
                .file_type()
                .is_socket(),
            "successful acquisition is the native readiness fence"
        );

        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let server = tokio::spawn(async move { owner.run(None, server_cancel).await });

        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect to ready socket");
        let mut client = tokio::io::BufReader::new(stream);
        client
            .get_mut()
            .write_all(b"{\"request\":\"info\",\"version\":1}\n")
            .await
            .expect("write info request");
        client.get_mut().flush().await.expect("flush request");
        let mut response = String::new();
        client
            .read_line(&mut response)
            .await
            .expect("read info response");
        assert!(response.contains("\"response\":\"info\""));

        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(3), server)
            .await
            .expect("listener shutdown timeout")
            .expect("listener task")
            .expect("listener result");
        assert!(
            std::fs::symlink_metadata(&path)
                .is_err_and(|error| { error.kind() == std::io::ErrorKind::NotFound }),
            "owned socket path must be removed before shutdown returns"
        );

        let mut tail = Vec::new();
        let bytes = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.read_to_end(&mut tail),
        )
        .await
        .expect("accepted session remained detached")
        .expect("read session EOF");
        assert_eq!(bytes, 0, "shutdown must close the accepted session");
        std::fs::remove_dir_all(root).expect("remove IPC test root");
    }

    #[tokio::test]
    async fn second_generation_cannot_replace_a_live_owner() {
        let root = test_root("exclusive");
        std::fs::create_dir_all(&root).expect("create IPC test root");
        let first = LocalControl::acquire(test_config(&root)).expect("first owner");
        let first_identity = observe_socket(&root.join("koi.sock"))
            .unwrap()
            .expect("first socket identity");

        let error = LocalControl::acquire(test_config(&root))
            .err()
            .expect("second owner must fail");
        assert!(error.to_string().contains("another owner may be active"));
        assert_eq!(
            observe_socket(&root.join("koi.sock")).unwrap(),
            Some(first_identity),
            "failed acquisition must not replace the live socket"
        );

        drop(first);
        assert!(observe_socket(&root.join("koi.sock")).unwrap().is_none());
        std::fs::remove_dir_all(root).expect("remove IPC test root");
    }

    #[tokio::test]
    async fn refused_stale_generation_is_recovered_and_owned() {
        let root = test_root("stale");
        std::fs::create_dir_all(&root).expect("create IPC test root");
        let path = root.join("koi.sock");
        let stale = std::os::unix::net::UnixListener::bind(&path).expect("bind stale socket");
        assert!(observe_socket(&path).unwrap().is_some());
        drop(stale);

        let owner = LocalControl::acquire(test_config(&root)).expect("recover stale socket");
        let current_identity = observe_socket(&path).unwrap().expect("current identity");
        assert_eq!(owner.socket_path.identity, current_identity);
        std::os::unix::net::UnixStream::connect(&path).expect("replacement socket is live");

        drop(owner);
        assert!(observe_socket(&path).unwrap().is_none());
        std::fs::remove_dir_all(root).expect("remove IPC test root");
    }

    #[tokio::test]
    async fn retiring_generation_never_deletes_a_replacement_socket() {
        let root = test_root("replacement");
        std::fs::create_dir_all(&root).expect("create IPC test root");
        let path = root.join("koi.sock");
        let owner = LocalControl::acquire(test_config(&root)).expect("acquire owner");

        std::fs::remove_file(&path).expect("unlink owned pathname");
        let replacement =
            std::os::unix::net::UnixListener::bind(&path).expect("bind replacement socket");
        let replacement_identity = observe_socket(&path)
            .unwrap()
            .expect("replacement identity");
        let cancel = CancellationToken::new();
        cancel.cancel();

        let error = owner
            .run(None, cancel)
            .await
            .expect_err("identity mismatch must be reported");
        assert!(error.to_string().contains("refusing to remove replacement"));
        assert_eq!(
            observe_socket(&path).unwrap(),
            Some(replacement_identity),
            "retiring owner must leave the replacement generation intact"
        );

        drop(replacement);
        std::fs::remove_file(&path).expect("remove replacement path");
        std::fs::remove_dir_all(root).expect("remove IPC test root");
    }
}
