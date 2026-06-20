//! Per-connection serving primitives for the same-port posture dial (ADR-020 §5).
//!
//! koi-embedded's listener supervisor binds one socket, sniffs each accepted
//! connection's first byte, and routes it here — plaintext to [`serve_plain`], a
//! TLS ClientHello to [`serve_mtls`]. Because the socket is never rebound, a
//! posture flip (plain↔mTLS) is decided per *new* connection and never drops an
//! in-flight one — the Istio-PERMISSIVE property the ADR demands without its
//! footguns.
//!
//! These are the single-connection counterparts of [`mtls::serve`](crate::mtls::serve)
//! (which owns its own accept loop for the daemon's fixed mTLS port). The TLS
//! handshake + CN-injection path is intentionally the same shape; it is kept
//! separate so the proven daemon listener is untouched by the same-port dial.

use axum::extract::Extension;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::error::CertmeshError;
use crate::http::ClientCn;
use crate::mtls;

/// First byte of a TLS record whose ContentType is `handshake` (a ClientHello).
/// HTTP/1.x and h2c plaintext both begin with a printable ASCII byte (a method
/// char or `P` of the h2c preface), never `0x16`, so peeking this one byte
/// reliably distinguishes a TLS dial from a plaintext one (ADR-020 §5).
pub const TLS_HANDSHAKE_FIRST_BYTE: u8 = 0x16;

/// An opaque, cheaply-cloneable mTLS server config (this node's leaf + a CA client
/// verifier) for the same-port dial. Built from an identity and held by the
/// supervisor, rebuilt when the posture or the leaf changes. Wraps the rustls type
/// so koi-embedded never needs a direct rustls dependency.
#[derive(Clone)]
pub struct AdaptiveServerConfig(Arc<rustls::ServerConfig>);

impl AdaptiveServerConfig {
    /// Build from this node's PEM material: its CA-signed `cert_pem`/`key_pem`
    /// (presented as the server cert) and the `ca_cert_pem` clients must chain to.
    pub fn from_identity(
        cert_pem: &str,
        key_pem: &str,
        ca_cert_pem: &str,
    ) -> Result<Self, CertmeshError> {
        Ok(Self(Arc::new(mtls::build_server_config(
            cert_pem,
            key_pem,
            ca_cert_pem,
        )?)))
    }
}

impl std::fmt::Debug for AdaptiveServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdaptiveServerConfig(<rustls::ServerConfig>)")
    }
}

/// Serve one plaintext HTTP/1.1+2 connection with `router` until it closes or
/// `cancel` fires. The Open-posture path of the same-port dial.
pub async fn serve_plain(tcp: TcpStream, router: Router, cancel: CancellationToken) {
    let io = TokioIo::new(tcp);
    let svc = hyper_util::service::TowerToHyperService::new(router);
    let builder = Builder::new(TokioExecutor::new());
    tokio::select! {
        res = builder.serve_connection_with_upgrades(io, svc) => {
            if let Err(e) = res {
                tracing::debug!(error = %e, "plain connection error");
            }
        }
        _ = cancel.cancelled() => {}
    }
}

/// Serve one mTLS connection: complete the TLS handshake (requiring a client cert
/// chaining to the CA, per `config`), inject the peer's CN as
/// `Extension(`[`ClientCn`]`)`, and serve `router` until it closes or `cancel`
/// fires. A connection that presents no usable client CN is dropped. The
/// secure-posture path of the same-port dial.
pub async fn serve_mtls(
    tcp: TcpStream,
    config: AdaptiveServerConfig,
    router: Router,
    cancel: CancellationToken,
) {
    let acceptor = TlsAcceptor::from(config.0);
    let tls = match acceptor.accept(tcp).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "mTLS handshake failed");
            return;
        }
    };
    let cn = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| mtls::extract_cn(cert.as_ref()));
    let cn = match cn {
        Some(cn) => cn,
        None => {
            tracing::warn!("no CN in client certificate; dropping connection");
            return;
        }
    };
    let svc = router.layer(Extension(ClientCn(cn)));
    let io = TokioIo::new(tls);
    let hyper_svc = hyper_util::service::TowerToHyperService::new(svc);
    let builder = Builder::new(TokioExecutor::new());
    tokio::select! {
        res = builder.serve_connection_with_upgrades(io, hyper_svc) => {
            if let Err(e) = res {
                tracing::debug!(error = %e, "mTLS connection error");
            }
        }
        _ = cancel.cancelled() => {}
    }
}
