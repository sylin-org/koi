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

use std::sync::{Arc, OnceLock};

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use koi_certmesh::acme::AcmeState;

/// Default ACME server port (server-auth TLS). 5643 sits next to the daemon HTTP
/// port (5641) and the mTLS port (5642).
pub const DEFAULT_ACME_PORT: u16 = 5643;

/// Start the ACME server-auth TLS listener on the given port.
///
/// `cert_pem`/`key_pem` are the daemon's self-issued leaf (server identity);
/// `acme_state` carries the CA access, account/order stores, zone, and dns-01
/// solver. No client certificate is required or verified.
pub async fn start(
    port: u16,
    acme_state: Arc<AcmeState>,
    cert_pem: &str,
    key_pem: &str,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let tls_config = build_tls_config(cert_pem, key_pem)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let app = Router::new().nest("/acme", koi_certmesh::acme::routes(acme_state));

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "ACME (RFC 8555) adapter listening");

    loop {
        let (tcp, addr) = tokio::select! {
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "ACME accept error");
                    continue;
                }
            },
            _ = cancel.cancelled() => {
                tracing::debug!("ACME adapter stopped");
                return Ok(());
            }
        };

        let acceptor = tls_acceptor.clone();
        let app = app.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
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
}

/// The rustls crypto provider (aws-lc-rs, the workspace default), built **explicitly**
/// so this module never depends on a global `install_default` ordering — both
/// `aws-lc-rs` (via rustls) and `ring` (via koi-crypto) are linked, so a bare
/// `builder()` would panic at "could not determine the process-level CryptoProvider".
/// Mirrors [`koi_certmesh::mtls`] and koi-proxy's deliberate choice.
fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}

/// Build a server-auth-only rustls `ServerConfig` (no client cert verification).
fn build_tls_config(cert_pem: &str, key_pem: &str) -> anyhow::Result<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in ACME server cert PEM");
    }
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;

    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use std::net::{IpAddr, Ipv4Addr};

    /// Regression guard: `build_tls_config` must resolve the crypto provider
    /// explicitly. With both aws-lc-rs (rustls) and ring (koi-crypto) linked, a bare
    /// `ServerConfig::builder()` panics at "could not determine the process-level
    /// CryptoProvider" — which would silently kill the ACME listener's spawned task.
    /// This asserts the server-auth config builds from a self-signed leaf without
    /// panicking.
    #[test]
    fn build_tls_config_resolves_provider() {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        params
            .distinguished_name
            .push(DnType::CommonName, "test-acme-server");
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        let config = build_tls_config(&cert.pem(), &key.serialize_pem());
        assert!(
            config.is_ok(),
            "build_tls_config failed: {:?}",
            config.err()
        );
    }
}
