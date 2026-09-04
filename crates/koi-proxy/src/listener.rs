//! TLS-terminating TCP passthrough listener.
//!
//! Each entry owns one listener task: it binds a `TcpListener`, terminates TLS with
//! the entry's (hot-reloadable) certificate, opens a plain `TcpStream` to the backend,
//! and pumps bytes both ways with [`copy_bidirectional`]. Because forwarding is at the
//! byte level, WebSockets and any other bidirectional/upgraded protocol work by
//! construction — there is no HTTP layer to misunderstand them.
//!
//! Liveness is reported through a [`watch`] channel: the real bind/accept outcome
//! (including the error detail on failure) is observable, never guessed. Listener
//! shutdown releases the listening socket immediately, gives already accepted
//! connections a bounded drain window, then aborts and reaps stragglers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use koi_common::integration::TlsIdentitySource;

use crate::config::ProxyEntry;
use crate::safety::parse_backend;
use crate::tls::{self, CertSelectionStatus, CertSource};

const TLS_TASK_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) type ListenerObserver = Arc<dyn Fn(ListenerStatus) + Send + Sync>;

/// Real liveness of a listener task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerState {
    Starting,
    Running,
    Error,
    Stopped,
}

impl ListenerState {
    pub fn as_str(self) -> &'static str {
        match self {
            ListenerState::Starting => "starting",
            ListenerState::Running => "running",
            ListenerState::Error => "error",
            ListenerState::Stopped => "stopped",
        }
    }
}

/// A snapshot of a listener's state, carried over a [`watch`] channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerStatus {
    pub state: ListenerState,
    pub error: Option<String>,
    pub cert_source: CertSource,
    pub cert_revision: u64,
}

impl ListenerStatus {
    pub(crate) fn starting() -> Self {
        Self {
            state: ListenerState::Starting,
            error: None,
            cert_source: CertSource::SelfSigned,
            cert_revision: 0,
        }
    }

    fn error(message: String, cert_source: CertSource, cert_revision: u64) -> Self {
        Self {
            state: ListenerState::Error,
            error: Some(message),
            cert_source,
            cert_revision,
        }
    }
}

/// Ownership handle for one listener task.
///
/// Shutdown acknowledges release of the listening socket and reaping of all
/// listener-owned TLS and connection tasks.
pub(crate) struct ListenerHandle {
    #[cfg(test)]
    pub(crate) status: watch::Receiver<ListenerStatus>,
    cancel: CancellationToken,
    completion: Option<JoinHandle<ConnectionTasks>>,
    connections: Option<ConnectionTasks>,
}

/// Explicit ownership of connections admitted before a listener stopped.
/// Restartable reconciliation may retain this value while streams drain;
/// terminal shutdown aborts and reaps any remaining tasks.
#[derive(Default)]
pub(crate) struct ConnectionTasks {
    tasks: Vec<JoinHandle<()>>,
}

impl ConnectionTasks {
    pub(crate) fn prune_finished(&mut self) {
        self.tasks.retain(|task| !task.is_finished());
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(crate) async fn shutdown_until(&mut self, deadline: tokio::time::Instant) {
        for task in &mut self.tasks {
            if task.is_finished() {
                let _ = (&mut *task).await;
                continue;
            }
            if tokio::time::timeout_at(deadline, &mut *task).await.is_err() {
                task.abort();
                let _ = (&mut *task).await;
            }
        }
        self.tasks.clear();
    }
}

impl Drop for ConnectionTasks {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl ListenerHandle {
    #[cfg(test)]
    pub(crate) fn watch_status(&self) -> watch::Receiver<ListenerStatus> {
        self.status.clone()
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.completion
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }

    /// Cancel and reap this listener without moving its owned task handle.
    /// Keeping the handle in place makes caller cancellation retry-safe.
    pub(crate) async fn shutdown_until(&mut self, deadline: tokio::time::Instant) {
        self.cancel.cancel();
        let Some(completion) = self.completion.as_mut() else {
            return;
        };
        let result = if completion.is_finished() {
            (&mut *completion).await
        } else {
            match tokio::time::timeout_at(deadline, &mut *completion).await {
                Ok(result) => result,
                Err(_) => {
                    completion.abort();
                    (&mut *completion).await
                }
            }
        };
        match result {
            Ok(connections) => self.connections = Some(connections),
            Err(error) if !error.is_cancelled() => {
                tracing::warn!(%error, "Proxy listener task failed during shutdown");
            }
            Err(_) => {}
        }
        self.completion = None;
    }

    pub(crate) fn take_connections(&mut self) -> ConnectionTasks {
        self.connections.take().unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) async fn shutdown(mut self) -> ConnectionTasks {
        self.shutdown_until(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        self.take_connections()
    }
}

impl Drop for ListenerHandle {
    fn drop(&mut self) {
        // Drop cannot acknowledge completion, but cancellation prevents an
        // accidentally abandoned owner from leaving a listener armed forever.
        self.cancel.cancel();
        if let Some(completion) = &self.completion {
            completion.abort();
        }
    }
}

/// Spawn a listener with explicitly composed TLS inputs. The Proxy-owned
/// override directory and the trust-domain identity port remain distinct.
#[cfg(test)]
pub(crate) fn spawn_listener_with_tls(
    entry: ProxyEntry,
    certificate_overrides_dir: std::path::PathBuf,
    tls_identity: Option<std::sync::Arc<dyn TlsIdentitySource>>,
) -> ListenerHandle {
    spawn_listener_with_tls_observer(entry, certificate_overrides_dir, tls_identity, None)
}

pub(crate) fn spawn_listener_with_tls_observer(
    entry: ProxyEntry,
    certificate_overrides_dir: std::path::PathBuf,
    tls_identity: Option<std::sync::Arc<dyn TlsIdentitySource>>,
    observer: Option<ListenerObserver>,
) -> ListenerHandle {
    let (tx, rx) = watch::channel(ListenerStatus::starting());
    #[cfg(not(test))]
    drop(rx);
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let completion = tokio::spawn(async move {
        run_listener(
            entry,
            task_cancel,
            certificate_overrides_dir,
            tls_identity,
            tx,
            observer,
        )
        .await
    });
    ListenerHandle {
        #[cfg(test)]
        status: rx,
        cancel,
        completion: Some(completion),
        connections: None,
    }
}

async fn run_listener(
    entry: ProxyEntry,
    cancel: CancellationToken,
    certificate_overrides_dir: std::path::PathBuf,
    tls_identity: Option<std::sync::Arc<dyn TlsIdentitySource>>,
    tx: watch::Sender<ListenerStatus>,
    observer: Option<ListenerObserver>,
) -> ConnectionTasks {
    // 1. TLS setup (cert resolution + self-signed fallback).
    let setup = match tls::build_tls(
        &entry,
        &certificate_overrides_dir,
        tls_identity,
        cancel.clone(),
    ) {
        Ok(setup) => setup,
        Err(e) => {
            publish_status(
                &tx,
                observer.as_ref(),
                ListenerStatus::error(format!("tls setup: {e}"), CertSource::SelfSigned, 0),
            );
            tracing::warn!(name = %entry.name, error = %e, "Proxy TLS setup failed");
            return ConnectionTasks::default();
        }
    };
    let tls::TlsSetup {
        config,
        mut cert_status,
        override_watcher: _override_watcher,
        mut background,
    } = setup;
    let mut certificate = *cert_status.borrow_and_update();
    let acceptor = TlsAcceptor::from(config);

    // 2. Keep the Proxy-owned override watcher alive for the listener's
    // lifetime. Certmesh changes arrive through its typed status port.
    let mut cert_status = Some(cert_status);

    // 3. Bind. A bind failure (e.g. port in use) is a real, observable Error state.
    let addr = SocketAddr::from(([0, 0, 0, 0], entry.listen_port));
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            publish_status(
                &tx,
                observer.as_ref(),
                ListenerStatus::error(
                    bind_error_message(&e),
                    certificate.source,
                    certificate.revision,
                ),
            );
            tracing::warn!(
                name = %entry.name, port = entry.listen_port, error = %e,
                "Proxy listener bind failed"
            );
            return ConnectionTasks::default();
        }
    };

    publish_status(
        &tx,
        observer.as_ref(),
        ListenerStatus {
            state: ListenerState::Running,
            error: None,
            cert_source: certificate.source,
            cert_revision: certificate.revision,
        },
    );
    tracing::info!(
        name = %entry.name, port = entry.listen_port, backend = %entry.backend,
        cert = certificate.source.as_str(), "Proxy listener running"
    );

    // 4. Accept loop. The listener task owns every admitted connection and
    // reaps it on shutdown; no data-plane work is detached.
    let mut connections = ConnectionTasks::default();
    loop {
        connections.prune_finished();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            next = next_cert_status(&mut cert_status) => {
                if let Some(next) = next {
                    certificate = next;
                    publish_status(&tx, observer.as_ref(), ListenerStatus {
                        state: ListenerState::Running,
                        error: None,
                        cert_source: certificate.source,
                        cert_revision: certificate.revision,
                    });
                    tracing::info!(
                        name = %entry.name,
                        cert = certificate.source.as_str(),
                        revision = certificate.revision,
                        "Proxy TLS selection changed"
                    );
                }
            }
            accept = listener.accept() => match accept {
                Ok((tcp, peer)) => {
                    let acceptor = acceptor.clone();
                    let backend = entry.backend.clone();
                    let name = entry.name.clone();
                    connections.tasks.push(tokio::spawn(async move {
                        handle_conn(acceptor, tcp, peer, &backend, &name).await;
                    }));
                }
                Err(e) => {
                    tracing::warn!(name = %entry.name, error = %e, "Proxy accept error");
                }
            },
        }
    }

    // Release admission first. Previously accepted streams are returned to the
    // runtime as an explicit owner so restartable reconciliation can let them
    // drain without detaching them.
    drop(listener);
    publish_status(
        &tx,
        observer.as_ref(),
        ListenerStatus {
            state: ListenerState::Stopped,
            error: None,
            cert_source: certificate.source,
            cert_revision: certificate.revision,
        },
    );

    let deadline = tokio::time::Instant::now() + TLS_TASK_DRAIN_TIMEOUT;
    background.shutdown_until(deadline).await;
    connections.prune_finished();
    connections
}

fn publish_status(
    tx: &watch::Sender<ListenerStatus>,
    observer: Option<&ListenerObserver>,
    status: ListenerStatus,
) {
    tx.send_replace(status.clone());
    if let Some(observer) = observer {
        observer(status);
    }
}

/// A closed optional source retires its select arm instead of busy-spinning.
async fn next_cert_status(
    receiver: &mut Option<watch::Receiver<CertSelectionStatus>>,
) -> Option<CertSelectionStatus> {
    let result = match receiver.as_mut() {
        Some(receiver) => match receiver.changed().await {
            Ok(()) => Ok(*receiver.borrow_and_update()),
            Err(_) => Err(()),
        },
        None => std::future::pending().await,
    };
    match result {
        Ok(source) => Some(source),
        Err(()) => {
            *receiver = None;
            None
        }
    }
}

/// Terminate TLS, connect to the backend, and pump bytes both ways.
async fn handle_conn(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    peer: SocketAddr,
    backend: &str,
    name: &str,
) {
    let mut tls = match acceptor.accept(tcp).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::debug!(name, %peer, error = %e, "Proxy TLS handshake failed");
            return;
        }
    };

    let (host, port) = match parse_backend(backend) {
        Ok(hostport) => hostport,
        Err(e) => {
            tracing::warn!(name, backend, error = %e, "Proxy backend parse failed");
            return;
        }
    };

    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(name, backend, error = %e, "Proxy backend connect failed");
            return;
        }
    };

    if let Err(e) = copy_bidirectional(&mut tls, &mut upstream).await {
        tracing::debug!(name, %peer, error = %e, "Proxy passthrough ended");
    }
}

/// Map a bind error to a concise, human-friendly message for the status surface.
fn bind_error_message(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::AddrInUse => "address in use".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        std::io::ErrorKind::AddrNotAvailable => "address not available".to_string(),
        _ => e.to_string(),
    }
}
