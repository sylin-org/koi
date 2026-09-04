//! ACME (RFC 8555) server-auth TLS listener.
//!
//! A near-clone of [`crate::mtls`] MINUS the client-cert verifier: ACME clients
//! (Caddy, Traefik, lego, certbot) have no Koi certificate yet — they are trying
//! to *get* one — so the listener authenticates only the server side
//! (`with_no_client_auth`). The server certificate is a daemon self-issued leaf
//! from the certmesh CA (SAN = daemon FQDN + IP), so the chain validates against
//! the CA root the operator distributes once for bootstrap.
//!
//! The router (`koi_certmesh::acme::routes`) is mounted under `/acme`. The
//! listener only starts when the certmesh CA is initialized + unlocked AND
//! `--no-acme` / `KOI_NO_ACME` is not set (gated in `daemon.rs`).

use std::sync::Arc;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use koi_certmesh::acme::AcmeState;

/// Default ACME server port (server-auth TLS). 5643 sits next to the daemon HTTP
/// port (5641) and the mTLS port (5642).
pub const DEFAULT_ACME_PORT: u16 = 5643;

/// Start the ACME server-auth TLS listener on the given port.
///
/// The server leaf is resolved from the shared hot-swappable `resolver` (the daemon's
/// self-issued leaf, the same one the mTLS listener presents), so a renewed leaf is
/// picked up without a restart; `acme_state` carries the CA access, account/order
/// stores, zone, and dns-01 solver. No client certificate is required or verified.
pub async fn start(
    listener: TcpListener,
    acme_state: Arc<AcmeState>,
    resolver: Arc<koi_certmesh::mtls::ReloadableServerCert>,
    cancel: CancellationToken,
    ready: oneshot::Sender<()>,
) -> anyhow::Result<()> {
    let address = listener.local_addr()?;
    let tls_config = koi_certmesh::mtls::build_server_auth_config_with_resolver(resolver)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let app = Router::new().nest("/acme", koi_certmesh::acme::routes(acme_state));

    let _ = ready.send(());
    tracing::info!(%address, "ACME (RFC 8555) adapter listening");
    let session_cancel = cancel.child_token();
    let mut sessions = JoinSet::new();

    loop {
        let (tcp, addr) = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => {
                observe_session(joined);
                continue;
            }
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "ACME accept error");
                    continue;
                }
            }
        };

        let acceptor = tls_acceptor.clone();
        let app = app.clone();
        let cancel = session_cancel.clone();

        sessions.spawn(async move {
            let tls_stream = match tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                result = acceptor.accept(tcp) => result,
            } {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(%addr, error = %e, "ACME TLS handshake failed");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let builder = Builder::new(TokioExecutor::new());
            let hyper_svc = hyper_util::service::TowerToHyperService::new(app);

            tokio::select! {
                res = builder.serve_connection_with_upgrades(io, hyper_svc) => {
                    if let Err(e) = res {
                        tracing::debug!(%addr, error = %e, "ACME connection error");
                    }
                }
                _ = cancel.cancelled() => {}
            }
        });
    }

    session_cancel.cancel();
    drain_sessions(&mut sessions).await;
    tracing::debug!("ACME adapter stopped");
    Ok(())
}

fn observe_session(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(error)) = result {
        if !error.is_cancelled() {
            tracing::warn!(%error, "ACME connection task failed");
        }
    }
}

async fn drain_sessions(sessions: &mut JoinSet<()>) {
    const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
    while !sessions.is_empty() {
        match tokio::time::timeout_at(deadline, sessions.join_next()).await {
            Ok(result) => observe_session(result),
            Err(_) => {
                sessions.abort_all();
                while let Some(result) = sessions.join_next().await {
                    if let Err(error) = result {
                        if !error.is_cancelled() {
                            tracing::warn!(%error, "aborted ACME connection task failed");
                        }
                    }
                }
                break;
            }
        }
    }
}

// The server-auth TLS config (and its explicit crypto-provider resolution) now lives
// in `koi_certmesh::mtls::build_server_auth_config_with_resolver`, shared with the
// mTLS listener so a single leaf-renewal reload refreshes both listeners.
