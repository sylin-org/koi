//! mTLS adapter — accepts client certificates and injects the CN as an axum Extension.
//!
//! Uses a manual `tokio-rustls` accept loop instead of `axum-server` so we can
//! extract the peer certificate's Common Name (CN) before handing the connection
//! to axum/hyper. The CN is attached as `Extension(ClientCn(cn))` per-connection,
//! making it available to handlers for authorization decisions.

use std::io::BufReader;
use std::sync::Arc;

use axum::extract::Extension;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::*;

use koi_certmesh::http::ClientCn;

/// Default mTLS port for inter-node certmesh traffic.
pub const DEFAULT_MTLS_PORT: u16 = 5642;

/// Start the mTLS adapter on the given port.
///
/// Accepts TLS connections that present a valid client certificate signed by `ca_cert_pem`,
/// extracts the CN, and routes requests through the certmesh inter-node router.
pub async fn start(
    port: u16,
    certmesh_core: Arc<koi_certmesh::CertmeshCore>,
    cert_pem: &str,
    key_pem: &str,
    ca_cert_pem: &str,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let tls_config = build_tls_config(cert_pem, key_pem, ca_cert_pem)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let app = Router::new().nest("/v1/certmesh", certmesh_core.inter_node_routes());

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "mTLS adapter listening");

    loop {
        let (tcp, addr) = tokio::select! {
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "mTLS accept error");
                    continue;
                }
            },
            _ = cancel.cancelled() => {
                tracing::debug!("mTLS adapter stopped");
                return Ok(());
            }
        };

        let acceptor = tls_acceptor.clone();
        let app = app.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            // TLS handshake
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(%addr, error = %e, "mTLS handshake failed");
                    return;
                }
            };

            // Extract client CN from the peer certificate
            let cn = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| extract_cn(cert.as_ref()));

            let cn = match cn {
                Some(cn) => cn,
                None => {
                    tracing::warn!(%addr, "no CN in client certificate");
                    return;
                }
            };

            tracing::debug!(%addr, %cn, "mTLS authenticated");

            // Inject CN into per-connection router so handlers can extract it
            let svc = app.layer(Extension(ClientCn(cn)));

            let io = TokioIo::new(tls_stream);
            let builder = Builder::new(TokioExecutor::new());
            let hyper_svc = hyper_util::service::TowerToHyperService::new(svc);

            tokio::select! {
                res = builder.serve_connection_with_upgrades(io, hyper_svc) => {
                    if let Err(e) = res {
                        tracing::debug!(%addr, error = %e, "mTLS connection error");
                    }
                }
                _ = cancel.cancelled() => {}
            }
        });
    }
}

/// Extract the Common Name (CN) from a DER-encoded X.509 certificate.
fn extract_cn(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(String::from);
    cn
}

/// Build a rustls `ServerConfig` that requires client certificates signed by the given CA.
fn build_tls_config(
    cert_pem: &str,
    key_pem: &str,
    ca_cert_pem: &str,
) -> anyhow::Result<rustls::ServerConfig> {
    // Parse server certificate chain
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        anyhow::bail!("no certificates found in server cert PEM");
    }

    // Parse server private key
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))?
            .ok_or_else(|| anyhow::anyhow!("no private key found in key PEM"))?;

    // Build a root cert store from the CA certificate for client verification
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(ca_cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
    for ca_cert in ca_certs {
        root_store.add(ca_cert)?;
    }

    let client_verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cn_from_self_signed() {
        // Generate a self-signed cert with CN="test-host" using rcgen
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-host");

        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let cert = params.self_signed(&key_pair).expect("self-sign");
        let der = cert.der();

        let cn = extract_cn(der.as_ref());
        assert_eq!(cn, Some("test-host".to_string()));
    }

    #[test]
    fn extract_cn_returns_none_for_garbage() {
        let cn = extract_cn(b"not a certificate");
        assert_eq!(cn, None);
    }
}
