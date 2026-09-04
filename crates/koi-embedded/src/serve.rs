//! The posture-adaptive same-port listener supervisor (ADR-020 §5).
//!
//! [`run_adaptive_listener`] owns one already-bound TCP socket and **never rebinds it**.
//! Socket acquisition belongs to the public embedded boundary in
//! [`crate::KoiHandle::serve`], so a successful call is the readiness fence rather
//! than merely the admission of a task that might fail later. Each accepted
//! connection's first byte is peeked and dispatched against the node's posture *at
//! accept time*: a TLS ClientHello is served mTLS when this node is secure;
//! plaintext is served when Open. Because the socket is never closed, a posture
//! flip (plain↔mTLS) only changes how *new* connections are handled — an in-flight
//! connection is never dropped. This is Istio PERMISSIVE done safely (ADR-020 §13).
//!
//! Refusals are loud, not silent: a plaintext dial to a secure node is refused
//! (secure-by-default), and a TLS dial to an Open node is refused (no identity to
//! terminate TLS with). The supervisor reacts to the Certmesh status and sensitive
//! TLS-identity feeds, so posture changes, rotations, and withdrawals affect new
//! connections without a restart — which also makes the consumer's single `serve`
//! call mode-transparent.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use koi_certmesh::serve::{
    serve_mtls, serve_plain, AdaptiveServerConfig, TLS_HANDSHAKE_FIRST_BYTE,
};
use koi_certmesh::CertmeshCore;
use koi_common::integration::TlsIdentitySnapshot;
use koi_common::posture::Posture;

/// How long to wait for a connection's first byte before giving up. Bounds a
/// stalled/slow-loris dial so a single connection cannot pin a task forever.
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// Run a posture-adaptive, already-bound listener until `cancel` fires (ADR-020 §5).
///
/// The caller owns acquisition and readiness. This worker serves plaintext when
/// this node is Open and mTLS when it is secure, flipping per *new* connection on
/// a posture change without dropping in-flight ones. Per-connection and
/// posture-rebuild errors are logged rather than terminating the listener.
pub(crate) async fn run_adaptive_listener(
    core: Arc<CertmeshCore>,
    router: Router,
    listener: TcpListener,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let addr = listener.local_addr()?;
    let mut status_rx = core.watch_status();
    let mut identity_rx = core.watch_tls_identity();
    let initial = status_rx.borrow_and_update().clone();
    let mut posture = initial.posture;
    let mut authentication_required = initial.role.requires_authentication();
    let initial_identity = identity_rx.borrow_and_update().clone();
    let mut tls_config = build_tls_config(posture, &initial_identity);
    let session_cancel = cancel.child_token();
    let mut sessions = JoinSet::new();
    tracing::info!(%addr, ?posture, "same-port dial: listening");

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => {
                observe_session(joined);
            }
            changed = status_rx.changed() => {
                if changed.is_err() {
                    break; // the certmesh core was dropped
                }
                let status = status_rx.borrow_and_update().clone();
                posture = status.posture;
                authentication_required = status.role.requires_authentication();
                let identity = identity_rx.borrow_and_update().clone();
                tls_config = build_tls_config(posture, &identity);
                tracing::info!(
                    ?posture,
                    "same-port dial: posture changed — new connections use the updated protocol"
                );
            }
            changed = identity_rx.changed() => {
                if changed.is_err() {
                    break; // the certmesh identity authority was dropped
                }
                // Certmesh publishes sensitive material before its primary status
                // causal fence. Re-read both projections: withdrawal fails closed
                // immediately; a replacement becomes live no later than the status
                // revision that describes it.
                let status = status_rx.borrow_and_update().clone();
                posture = status.posture;
                authentication_required = status.role.requires_authentication();
                let identity = identity_rx.borrow_and_update().clone();
                tls_config = build_tls_config(posture, &identity);
                tracing::info!(
                    ?posture,
                    identity_revision = identity.revision,
                    "same-port dial: TLS identity changed — new connections use the updated material"
                );
            }
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "same-port dial: accept error");
                        continue;
                    }
                };
                let router = router.clone();
                let cancel_conn = session_cancel.clone();
                let secure = posture.signed;
                let authentication_required = authentication_required;
                let cfg = tls_config.clone();
                sessions.spawn(async move {
                    dispatch_connection(
                        tcp,
                        peer,
                        authentication_required,
                        secure,
                        cfg,
                        router,
                        cancel_conn,
                    )
                    .await;
                });
            }
        }
    }

    session_cancel.cancel();
    drain_sessions(&mut sessions).await;
    Ok(())
}

fn observe_session(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(error)) = result {
        if !error.is_cancelled() {
            tracing::warn!(%error, "same-port connection task failed");
        }
    }
}

async fn drain_sessions(sessions: &mut JoinSet<()>) {
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
    while !sessions.is_empty() {
        match tokio::time::timeout_at(deadline, sessions.join_next()).await {
            Ok(result) => observe_session(result),
            Err(_) => {
                sessions.abort_all();
                while let Some(result) = sessions.join_next().await {
                    if let Err(error) = result {
                        if !error.is_cancelled() {
                            tracing::warn!(%error, "aborted same-port connection task failed");
                        }
                    }
                }
                break;
            }
        }
    }
}

/// Build the mTLS server config from Certmesh's already-validated, immutable
/// identity projection. This boundary performs no persistence read. A secure
/// posture without material yields `None`, so connections are refused rather
/// than silently downgraded.
fn build_tls_config(
    posture: Posture,
    identity: &TlsIdentitySnapshot,
) -> Option<AdaptiveServerConfig> {
    if !posture.signed {
        return None;
    }
    let Some(material) = identity.material.as_ref() else {
        tracing::error!(
            identity_revision = identity.revision,
            "same-port dial: secure posture but Certmesh withdrew its TLS identity — \
             secure connections will be refused"
        );
        return None;
    };
    match AdaptiveServerConfig::from_identity(
        &material.certificate_chain_pem,
        &material.private_key_pem,
        &material.trust_anchor_pem,
    ) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::error!(
                error = %e,
                "same-port dial: secure posture but could not build mTLS config — \
                 secure connections will be refused"
            );
            None
        }
    }
}

/// Peek one byte to classify the connection, then dispatch by `(secure, is_tls)`.
async fn dispatch_connection(
    tcp: TcpStream,
    peer: SocketAddr,
    authentication_required: bool,
    secure: bool,
    cfg: Option<AdaptiveServerConfig>,
    router: Router,
    cancel: CancellationToken,
) {
    let mut first = [0u8; 1];
    let n = match tokio::time::timeout(PEEK_TIMEOUT, tcp.peek(&mut first)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!(%peer, error = %e, "same-port dial: peek failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "same-port dial: peek timed out");
            return;
        }
    };
    if n == 0 {
        return; // the client closed before sending anything
    }
    let is_tls = first[0] == TLS_HANDSHAKE_FIRST_BYTE;

    if authentication_required && !secure {
        tracing::warn!(
            %peer,
            "same-port dial: refusing connection because this mesh member's identity is unusable"
        );
        return;
    }

    match (secure, is_tls) {
        (true, true) => match cfg {
            Some(cfg) => serve_mtls(tcp, cfg, router, cancel).await,
            None => tracing::warn!(
                %peer,
                "same-port dial: secure posture but no mTLS config available — dropping TLS connection"
            ),
        },
        (true, false) => {
            // Secure node, plaintext client → refuse (secure-by-default). Dropping
            // `tcp` closes it; the refusal is logged, never a silent downgrade.
            tracing::warn!(
                %peer,
                "same-port dial: refused a plaintext connection to a secure node (mTLS required)"
            );
        }
        (false, false) => serve_plain(tcp, router, cancel).await,
        (false, true) => {
            tracing::warn!(
                %peer,
                "same-port dial: refused a TLS connection to an Open node (no identity to terminate TLS)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Extension;
    use axum::routing::{get, post};
    use koi_certmesh::http::ClientCn;
    use koi_certmesh::{protocol, CertmeshCore, CertmeshPaths};

    /// An isolated, wiped data dir per test (NOT the process-wide `ensure_data_dir`,
    /// which would clobber sibling tests' CA state).
    fn isolated_paths(tag: &str) -> CertmeshPaths {
        let dir = std::env::temp_dir().join(format!("koi-emb-serve-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        CertmeshPaths::with_data_dir(dir)
    }

    fn open_core(tag: &str) -> Arc<CertmeshCore> {
        Arc::new(
            CertmeshCore::uninitialized_with_paths(isolated_paths(tag))
                .with_local_hostname("embedded-serve-test-host")
                .expect("configure test host identity"),
        )
    }

    /// A secure (Authenticated) core: a CA + a self-enrolled leaf on disk.
    async fn secure_core(tag: &str) -> Arc<CertmeshCore> {
        std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
        let paths = isolated_paths(tag);
        let core = CertmeshCore::uninitialized_with_paths(paths)
            .with_local_hostname("embedded-serve-test-host")
            .expect("configure test host identity");
        core.create(protocol::CreateCaRequest {
            passphrase: "test-pass".into(),
            entropy_hex: koi_common::encoding::hex_encode(&[3_u8; 32]),
            operator: None,
            enrollment_open: false,
            requires_approval: false,
            auto_unlock: false,
            totp_secret_hex: None,
        })
        .await
        .expect("create managed test CA");
        core.self_enroll().await.expect("self-enroll");
        assert!(core.posture().signed, "core should be secure");
        Arc::new(core)
    }

    fn plain_router() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    fn cn_router() -> Router {
        Router::new().route(
            "/echo",
            post(|Extension(ClientCn(cn)): Extension<ClientCn>| async move { cn }),
        )
    }

    /// Both a plain GET route and an mTLS-CN POST route, so one running listener can
    /// be probed before and after a posture flip.
    fn combined_router() -> Router {
        Router::new()
            .route("/ping", get(|| async { "pong" }))
            .route(
                "/echo",
                post(|Extension(ClientCn(cn)): Extension<ClientCn>| async move { cn }),
            )
    }

    async fn bound_listener() -> TcpListener {
        TcpListener::bind(("127.0.0.1", 0)).await.unwrap()
    }

    #[tokio::test]
    async fn open_node_serves_plaintext() {
        let core = open_core("open-plain");
        let listener = bound_listener().await;
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(run_adaptive_listener(
            core,
            plain_router(),
            listener,
            cancel.clone(),
        ));

        let (status, body) = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping")
            .await
            .expect("plain GET to Open node");
        assert_eq!(status, 200);
        assert_eq!(body, "pong");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn secure_node_serves_mtls() {
        let core = secure_core("secure-mtls").await;
        let id = core.local_identity().await.expect("identity");
        let listener = bound_listener().await;
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(run_adaptive_listener(
            Arc::clone(&core),
            cn_router(),
            listener,
            cancel.clone(),
        ));

        // Dial mTLS with our own CA-signed leaf as the client identity.
        let (status, body) = koi_certmesh::mtls::post_json(
            &addr.ip().to_string(),
            addr.port(),
            "/echo",
            "{}",
            &id.cert_pem,
            &id.key_pem,
            &id.ca_cert_pem,
        )
        .await
        .expect("mTLS POST to secure node");
        assert_eq!(status, 200);
        assert_eq!(body, id.hostname, "the server authenticated our leaf CN");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn secure_node_refuses_plaintext() {
        let core = secure_core("secure-refuse-plain").await;
        let listener = bound_listener().await;
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(run_adaptive_listener(
            core,
            plain_router(),
            listener,
            cancel.clone(),
        ));

        // A plaintext GET to a secure node must not succeed.
        let result = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping").await;
        assert!(
            result.is_err() || result.as_ref().unwrap().0 != 200,
            "secure node must refuse plaintext; got {result:?}"
        );

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn open_node_refuses_tls() {
        let core = open_core("open-refuse-tls");
        // Build a throwaway client identity from a standalone CA to attempt a TLS dial.
        let client = secure_core("open-refuse-tls-client").await;
        let id = client.local_identity().await.unwrap();
        let listener = bound_listener().await;
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(run_adaptive_listener(
            core,
            cn_router(),
            listener,
            cancel.clone(),
        ));

        // A TLS dial to an Open node (no server cert) must fail at the handshake.
        let result = koi_certmesh::mtls::post_json(
            &addr.ip().to_string(),
            addr.port(),
            "/echo",
            "{}",
            &id.cert_pem,
            &id.key_pem,
            &id.ca_cert_pem,
        )
        .await;
        assert!(result.is_err(), "Open node must refuse TLS; got {result:?}");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn live_flip_open_to_secure_without_restart() {
        std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
        let paths = isolated_paths("flip");
        let core = Arc::new(
            CertmeshCore::uninitialized_with_paths(paths)
                .with_local_hostname("embedded-serve-test-host")
                .expect("configure test host identity"),
        );
        let listener = bound_listener().await;
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(run_adaptive_listener(
            Arc::clone(&core),
            combined_router(),
            listener,
            cancel.clone(),
        ));

        // While Open: plaintext works.
        let (status, body) = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping")
            .await
            .expect("plain works while Open");
        assert_eq!(status, 200);
        assert_eq!(body, "pong");

        // Flip to secure on the LIVE core (create → self-enroll → posture watch).
        let req = koi_certmesh::protocol::CreateCaRequest {
            passphrase: "test-pass-strong".to_string(),
            entropy_hex: koi_common::encoding::hex_encode(&[8u8; 32]),
            operator: None,
            enrollment_open: false,
            requires_approval: false,
            auto_unlock: false,
            totp_secret_hex: None,
        };
        core.create(req).await.expect("create CA");
        // Let the supervisor observe the posture change and rebuild its config.
        tokio::time::sleep(Duration::from_millis(250)).await;

        // SAME port, no restart: plaintext is now refused…
        let plain = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping").await;
        assert!(
            plain.is_err() || plain.as_ref().unwrap().0 != 200,
            "plaintext must be refused after the flip; got {plain:?}"
        );

        // …and mTLS now works on that same port.
        let id = core.local_identity().await.expect("identity after create");
        let (status, body) = koi_certmesh::mtls::post_json(
            &addr.ip().to_string(),
            addr.port(),
            "/echo",
            "{}",
            &id.cert_pem,
            &id.key_pem,
            &id.ca_cert_pem,
        )
        .await
        .expect("mTLS works after the flip");
        assert_eq!(status, 200);
        assert_eq!(body, id.hostname);

        cancel.cancel();
        let _ = server.await;
    }
}
