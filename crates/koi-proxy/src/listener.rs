//! TLS-terminating TCP passthrough listener.
//!
//! Each entry owns one listener task: it binds a `TcpListener`, terminates TLS with
//! the entry's (hot-reloadable) certificate, opens a plain `TcpStream` to the backend,
//! and pumps bytes both ways with [`copy_bidirectional`]. Because forwarding is at the
//! byte level, WebSockets and any other bidirectional/upgraded protocol work by
//! construction — there is no HTTP layer to misunderstand them.
//!
//! Liveness is reported through a [`watch`] channel: the real bind/accept outcome
//! (including the error detail on failure) is observable, never guessed.

use std::net::SocketAddr;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::ProxyEntry;
use crate::safety::parse_backend;
use crate::tls::{self, CertSource};

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
#[derive(Debug, Clone)]
pub struct ListenerStatus {
    pub state: ListenerState,
    pub error: Option<String>,
    pub cert_source: CertSource,
}

impl ListenerStatus {
    fn starting() -> Self {
        Self {
            state: ListenerState::Starting,
            error: None,
            cert_source: CertSource::SelfSigned,
        }
    }

    fn error(message: String, cert_source: CertSource) -> Self {
        Self {
            state: ListenerState::Error,
            error: Some(message),
            cert_source,
        }
    }
}

/// Spawn a passthrough TLS listener for an entry.
///
/// Returns immediately with a [`watch::Receiver`] reflecting the listener's real
/// liveness. The listener stops when `cancel` fires.
pub fn spawn_listener(
    entry: ProxyEntry,
    cancel: CancellationToken,
) -> watch::Receiver<ListenerStatus> {
    let (tx, rx) = watch::channel(ListenerStatus::starting());
    tokio::spawn(async move {
        run_listener(entry, cancel, tx).await;
    });
    rx
}

async fn run_listener(
    entry: ProxyEntry,
    cancel: CancellationToken,
    tx: watch::Sender<ListenerStatus>,
) {
    // 1. TLS setup (cert resolution + self-signed fallback).
    let setup = match tls::build_tls(&entry) {
        Ok(setup) => setup,
        Err(e) => {
            let _ = tx.send(ListenerStatus::error(
                format!("tls setup: {e}"),
                CertSource::SelfSigned,
            ));
            tracing::warn!(name = %entry.name, error = %e, "Proxy TLS setup failed");
            return;
        }
    };
    let cert_source = setup.cert_source;
    let acceptor = TlsAcceptor::from(setup.config);

    // 2. Cert hot-reload watcher (best-effort). Kept alive for the listener's
    //    lifetime; dropped when the accept loop exits.
    let _watcher = tls::spawn_cert_watcher(entry.clone(), setup.resolver, cancel.clone());

    // 3. Bind. A bind failure (e.g. port in use) is a real, observable Error state.
    let addr = SocketAddr::from(([0, 0, 0, 0], entry.listen_port));
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            let _ = tx.send(ListenerStatus::error(bind_error_message(&e), cert_source));
            tracing::warn!(
                name = %entry.name, port = entry.listen_port, error = %e,
                "Proxy listener bind failed"
            );
            return;
        }
    };

    let _ = tx.send(ListenerStatus {
        state: ListenerState::Running,
        error: None,
        cert_source,
    });
    tracing::info!(
        name = %entry.name, port = entry.listen_port, backend = %entry.backend,
        cert = cert_source.as_str(), "Proxy listener running"
    );

    // 4. Accept loop — one passthrough task per connection.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accept = listener.accept() => match accept {
                Ok((tcp, peer)) => {
                    let acceptor = acceptor.clone();
                    let backend = entry.backend.clone();
                    let name = entry.name.clone();
                    tokio::spawn(async move {
                        handle_conn(acceptor, tcp, peer, &backend, &name).await;
                    });
                }
                Err(e) => {
                    tracing::warn!(name = %entry.name, error = %e, "Proxy accept error");
                }
            }
        }
    }

    let _ = tx.send(ListenerStatus {
        state: ListenerState::Stopped,
        error: None,
        cert_source,
    });
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
