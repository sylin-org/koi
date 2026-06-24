//! mTLS server primitive for the certificate mesh.
//!
//! A server that **requires** client certificates signed by the certmesh CA,
//! extracts the peer certificate's Common Name (CN), and injects it as
//! `Extension(`[`ClientCn`](crate::http::ClientCn)`(cn))` into the per-connection
//! router so handlers can authorize on the caller's identity.
//!
//! The TLS + CA-verification wiring lives here, in the crate that owns the CA, so
//! it is written once and shared — koi's own inter-node adapter and any consumer
//! that needs a certmesh-authenticated HTTPS listener call this rather than
//! re-implementing the rustls verifier and trust wiring. The API is generic over
//! the caller's `axum::Router`; it assumes no particular route set.

use std::sync::{Arc, OnceLock, RwLock};

use axum::extract::Extension;
use axum::Router;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::*;

use crate::error::CertmeshError;
use crate::http::ClientCn;

/// The rustls crypto provider (aws-lc-rs, the workspace default), built **explicitly**
/// so this module never depends on a global `install_default` ordering — both
/// `aws-lc-rs` (via rustls) and `ring` (via koi-crypto) are linked, so a bare
/// `builder()` would panic at "could not determine the process-level CryptoProvider".
/// Mirrors koi-proxy's deliberate choice.
fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}

fn cert_err(what: &str, e: String) -> CertmeshError {
    CertmeshError::Certificate(format!("{what}: {e}"))
}

/// Build the CA-pinned `WebPkiClientVerifier` shared by every certmesh mTLS server
/// config (static or [resolver-backed](build_server_config_with_resolver)). A
/// connection whose client cert does not chain to `ca_cert_pem` is rejected at the
/// handshake. Factored out so the static and hot-reloadable paths build it identically.
fn build_client_verifier(
    ca_cert_pem: &str,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, CertmeshError> {
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(ca_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| cert_err("CA cert PEM", e.to_string()))?;
    for ca_cert in ca_certs {
        root_store
            .add(ca_cert)
            .map_err(|e| cert_err("add CA to root store", e.to_string()))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store),
        provider(),
    )
    .build()
    .map_err(|e| cert_err("client verifier", e.to_string()))?;
    Ok(verifier as Arc<dyn rustls::server::danger::ClientCertVerifier>)
}

/// Build a rustls [`ServerConfig`](rustls::ServerConfig) that **requires** client
/// certificates signed by `ca_cert_pem` (a `WebPkiClientVerifier` over the CA),
/// terminating TLS with the server's own `(server_cert_pem, server_key_pem)`.
///
/// Connections that do not present a certificate chaining to the CA are rejected
/// at the TLS handshake. The server leaf is fixed for this config's lifetime; for a
/// listener that must pick up a renewed leaf without a restart, build with
/// [`build_server_config_with_resolver`] instead.
pub fn build_server_config(
    server_cert_pem: &str,
    server_key_pem: &str,
    ca_cert_pem: &str,
) -> Result<rustls::ServerConfig, CertmeshError> {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(server_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| cert_err("server cert PEM", e.to_string()))?;
    if certs.is_empty() {
        return Err(CertmeshError::Certificate(
            "no certificates found in server cert PEM".to_string(),
        ));
    }

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes())
        .map_err(|e| cert_err("server key PEM", e.to_string()))?;

    let client_verifier = build_client_verifier(ca_cert_pem)?;

    rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| cert_err("tls versions", e.to_string()))?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| cert_err("server config", e.to_string()))
}

/// A [`ResolvesServerCert`] whose server leaf can be **hot-swapped** at runtime.
///
/// One resolver backs both the inter-node mTLS listener (5642) and the ACME
/// server-auth listener (5643) — they present the *same* daemon self leaf. When that
/// leaf is renewed on disk (CA self-renewal via `renew_ca_self_leaf_if_due`, or a
/// member pull-renewal), [`reload`](Self::reload) swaps the in-memory
/// [`CertifiedKey`]; every subsequent TLS handshake on either listener then presents
/// the fresh cert with **no listener restart and no dropped connections** (the bound
/// socket and `ServerConfig` are never rebuilt — only the resolved cert changes).
/// This closes the "restart is the reload point" limitation noted in `self_enroll`.
#[derive(Debug)]
pub struct ReloadableServerCert {
    current: RwLock<Arc<CertifiedKey>>,
}

impl ReloadableServerCert {
    /// Build from the initial server leaf PEM (cert chain + private key).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Arc<Self>, CertmeshError> {
        let certified = build_certified_key(cert_pem, key_pem)?;
        Ok(Arc::new(Self {
            current: RwLock::new(certified),
        }))
    }

    /// Swap in a freshly-read leaf. On a parse error the previous (good) cert is kept
    /// and the error is returned for the caller to log — a bad write never drops the
    /// listener to a broken cert.
    pub fn reload(&self, cert_pem: &str, key_pem: &str) -> Result<(), CertmeshError> {
        let certified = build_certified_key(cert_pem, key_pem)?;
        if let Ok(mut guard) = self.current.write() {
            *guard = certified;
        }
        Ok(())
    }
}

impl ResolvesServerCert for ReloadableServerCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().ok().map(|guard| Arc::clone(&guard))
    }
}

/// Parse a PEM cert chain + private key into a rustls [`CertifiedKey`].
fn build_certified_key(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>, CertmeshError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| cert_err("server cert PEM", e.to_string()))?;
    if certs.is_empty() {
        return Err(CertmeshError::Certificate(
            "no certificates found in server cert PEM".to_string(),
        ));
    }
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| cert_err("server key PEM", e.to_string()))?;
    let signing_key = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| cert_err("load private key", e.to_string()))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Like [`build_server_config`] but the server leaf is resolved from a
/// hot-swappable [`ReloadableServerCert`], so a renewed leaf is picked up on the next
/// handshake without restarting the listener. The CA client-verifier is fixed (the CA
/// root does not change on a leaf renewal). Used by the inter-node mTLS listener.
pub fn build_server_config_with_resolver(
    resolver: Arc<ReloadableServerCert>,
    ca_cert_pem: &str,
) -> Result<rustls::ServerConfig, CertmeshError> {
    let client_verifier = build_client_verifier(ca_cert_pem)?;
    Ok(rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| cert_err("tls versions", e.to_string()))?
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(resolver as Arc<dyn ResolvesServerCert>))
}

/// A **server-auth-only** rustls config (no client-cert verification) whose leaf is
/// resolved from a hot-swappable [`ReloadableServerCert`]. Used by the ACME listener,
/// whose clients have no certificate yet (they are enrolling to *get* one). Shares the
/// resolver with the mTLS listener so a single renewal reload refreshes both.
pub fn build_server_auth_config_with_resolver(
    resolver: Arc<ReloadableServerCert>,
) -> Result<rustls::ServerConfig, CertmeshError> {
    Ok(rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| cert_err("tls versions", e.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(resolver as Arc<dyn ResolvesServerCert>))
}

/// Serve `router` over mTLS on an already-bound `listener` until `cancel` fires.
///
/// Each accepted connection completes the TLS handshake (rejecting any client
/// without a CA-signed certificate, per `config`), has its peer-certificate CN
/// extracted and injected as `Extension(`[`ClientCn`](crate::http::ClientCn)`(cn))`,
/// and is then served by a clone of `router`. A connection whose client certificate
/// yields no usable CN is dropped. Returns `Ok(())` on cancellation; transient
/// per-connection errors are logged, not propagated.
pub async fn serve(
    router: Router,
    listener: TcpListener,
    config: rustls::ServerConfig,
    cancel: CancellationToken,
) -> Result<(), CertmeshError> {
    let acceptor = TlsAcceptor::from(Arc::new(config));

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
                tracing::debug!("mTLS server stopped");
                return Ok(());
            }
        };

        let acceptor = acceptor.clone();
        let router = router.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            // TLS handshake — fails here if the client presents no / an untrusted cert.
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(%addr, error = %e, "mTLS handshake failed");
                    return;
                }
            };

            // Extract the caller's identity (CN) from the peer certificate.
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

            // Inject the CN so handlers can authorize on the caller.
            let svc = router.layer(Extension(ClientCn(cn)));
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

/// Upper bound on a client response body (renewal leaf / trust bundle). Both are
/// small in practice; the cap stops an unbounded buffer on a compromised or
/// MITM'd channel from amplifying memory use.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

// ── mTLS CLIENT primitive (ADR-017 F6 member-pull renewal) ──────────

/// A rustls server-cert verifier that **pins the CA** but does not require the
/// dialed name to match a certificate SAN.
///
/// On a LAN a member may legitimately reach its CA by IP, `.local`, or hostname —
/// trust is established by the *pinned CA* (the only root in the store), not by
/// DNS. The chain, signature, and validity window are still fully enforced by the
/// inner [`rustls::client::WebPkiServerVerifier`]; we only relax the name check by
/// substituting a name taken from the peer certificate itself. The pinned
/// `ca_fingerprint` is additionally re-checked at the application layer
/// (`renew_self_if_due`) against the returned CA cert.
#[derive(Debug)]
struct PinnedCaServerVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedCaServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Substitute a name the certificate actually carries so the inner
        // verifier's name check passes; chain-to-pinned-CA + validity still run.
        let name: ServerName<'static> = first_dns_san(end_entity.as_ref())
            .and_then(|s| ServerName::try_from(s).ok())
            .unwrap_or_else(|| server_name.to_owned());
        self.inner
            .verify_server_cert(end_entity, intermediates, &name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Extract the first DNS SAN from a DER-encoded X.509 certificate.
fn first_dns_san(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|gn| match gn {
        GeneralName::DNSName(dns) => Some(dns.to_string()),
        _ => None,
    })
}

/// Build a rustls [`ClientConfig`](rustls::ClientConfig) that presents
/// `(client_cert_pem, client_key_pem)` and verifies the server against the pinned
/// `ca_cert_pem` (chain + signature + validity), tolerating any SAN name (see
/// [`PinnedCaServerVerifier`]).
pub fn build_client_config(
    client_cert_pem: &str,
    client_key_pem: &str,
    ca_cert_pem: &str,
) -> Result<rustls::ClientConfig, CertmeshError> {
    let cert_err = |what: &str, e: String| CertmeshError::Certificate(format!("{what}: {e}"));

    let client_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(client_cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| cert_err("client cert PEM", e.to_string()))?;
    if client_certs.is_empty() {
        return Err(CertmeshError::Certificate(
            "no certificates found in client cert PEM".to_string(),
        ));
    }
    let client_key: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_slice(client_key_pem.as_bytes())
            .map_err(|e| cert_err("client key PEM", e.to_string()))?;

    let mut root_store = rustls::RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(ca_cert_pem.as_bytes()) {
        let ca = ca.map_err(|e| cert_err("CA cert PEM", e.to_string()))?;
        root_store
            .add(ca)
            .map_err(|e| cert_err("add CA to root store", e.to_string()))?;
    }

    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_store),
        provider(),
    )
    .build()
    .map_err(|e| cert_err("server verifier", e.to_string()))?;
    let verifier = Arc::new(PinnedCaServerVerifier { inner });

    rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| cert_err("tls versions", e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| cert_err("client config", e.to_string()))
}

// ── shared request driver (plain + mTLS) ────────────────────────────

/// Drive a single one-shot HTTP/1.1 request/response over an established byte
/// stream — plain [`TcpStream`] **or** an mTLS [`tokio_rustls`] stream — and
/// return `(status, body)`.
///
/// Generic over the stream so the plain and mTLS request paths share exactly one
/// implementation (no copy-pasted hyper plumbing): a `Connection: close` exchange
/// with the response body capped at [`MAX_RESPONSE_BYTES`]. The connection driver
/// is spawned so `send_request` can proceed; its errors are logged (they resurface
/// as a body-read failure if fatal). `json_body` present ⇒ POST-style body with a
/// JSON content type; absent ⇒ empty body (e.g. a GET).
async fn drive_request<S>(
    stream: S,
    method: hyper::Method,
    host: &str,
    port: u16,
    path: &str,
    json_body: Option<&str>,
) -> Result<(u16, String), CertmeshError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| CertmeshError::Internal(format!("http handshake: {e}")))?;
    // Drive the one-shot connection concurrently so `send_request` can proceed.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "client connection driver error");
        }
    });

    let builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::HOST, format!("{host}:{port}"))
        // One-shot client: ask the server to close after the response so the body
        // read always terminates.
        .header(hyper::header::CONNECTION, "close");
    let req = match json_body {
        Some(body) => builder
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_owned()))),
        None => builder.body(Full::new(Bytes::new())),
    }
    .map_err(|e| CertmeshError::Internal(format!("build request: {e}")))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| CertmeshError::Internal(format!("send request: {e}")))?;
    let status = resp.status().as_u16();
    let body = http_body_util::Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map_err(|e| CertmeshError::Internal(format!("read body: {e}")))?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// Open a plain TCP connection to `host:port` and drive one request over it.
pub(crate) async fn request_plain(
    host: &str,
    port: u16,
    method: hyper::Method,
    path: &str,
    json_body: Option<&str>,
) -> Result<(u16, String), CertmeshError> {
    let tcp = TcpStream::connect((host, port)).await?;
    drive_request(tcp, method, host, port, path, json_body).await
}

/// Open an mTLS connection to `host:port` with a prebuilt client `config` and
/// drive one request over it. SNI is advisory (the verifier tolerates the dialed
/// name — see [`PinnedCaServerVerifier`]); a placeholder name is substituted when
/// `host` is not a valid DNS name (e.g. an IP literal).
pub(crate) async fn request_tls(
    config: Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
    method: hyper::Method,
    path: &str,
    json_body: Option<&str>,
) -> Result<(u16, String), CertmeshError> {
    let connector = TlsConnector::from(config);
    let tcp = TcpStream::connect((host, port)).await?;
    let server_name = ServerName::try_from(host.to_string())
        .or_else(|_| ServerName::try_from("certmesh-peer.invalid".to_string()))
        .map_err(|e| CertmeshError::Internal(format!("server name: {e}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| CertmeshError::Internal(format!("mTLS handshake to {host}:{port}: {e}")))?;
    drive_request(tls, method, host, port, path, json_body).await
}

/// POST a JSON body to `host:port`+`path` over mTLS, presenting the client cert.
///
/// Returns `(status_code, response_body)`. The member-pull renewal loop uses this
/// to call the CA's mTLS `/v1/certmesh/renew` with its current leaf as the client
/// identity. A single request/response over a one-shot HTTP/1.1 connection.
#[allow(clippy::too_many_arguments)]
pub async fn post_json(
    host: &str,
    port: u16,
    path: &str,
    json_body: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
    ca_cert_pem: &str,
) -> Result<(u16, String), CertmeshError> {
    let config = Arc::new(build_client_config(
        client_cert_pem,
        client_key_pem,
        ca_cert_pem,
    )?);
    request_tls(
        config,
        host,
        port,
        hyper::Method::POST,
        path,
        Some(json_body),
    )
    .await
}

/// Plain-HTTP GET of `host:port`+`path` (no TLS) — the companion to [`post_json`]
/// used to pull the **self-verifying** trust bundle (ADR-017 P1).
///
/// The bundle is integrity-protected by its own CA signature, so it needs no
/// transport security; a plain GET (which the daemon's DAT middleware exempts)
/// keeps the pull simple. Returns `(status_code, body)`.
pub async fn get(host: &str, port: u16, path: &str) -> Result<(u16, String), CertmeshError> {
    request_plain(host, port, hyper::Method::GET, path, None).await
}

/// Extract the Common Name (CN) from a DER-encoded X.509 certificate.
pub fn extract_cn(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    // Bind to a local so the borrowing iterator drops before `cert`.
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(String::from);
    cn
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn extract_cn_from_self_signed() {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test-host");
        let key_pair = KeyPair::generate().expect("keygen");
        let cert = params.self_signed(&key_pair).expect("self-sign");
        assert_eq!(
            extract_cn(cert.der().as_ref()),
            Some("test-host".to_string())
        );
    }

    #[test]
    fn extract_cn_returns_none_for_garbage() {
        assert_eq!(extract_cn(b"not a certificate"), None);
    }

    /// A CA plus a CA-signed server cert (SAN `localhost` + 127.0.0.1) and a
    /// CA-signed client cert (CN `test-client`), as PEM.
    struct TestPki {
        ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
    }

    fn test_pki() -> TestPki {
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut s_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        s_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        s_params
            .distinguished_name
            .push(DnType::CommonName, "test-server");
        let s_key = KeyPair::generate().unwrap();
        let s_cert = s_params.signed_by(&s_key, &ca_cert, &ca_key).unwrap();

        let mut c_params = CertificateParams::new(vec![]).unwrap();
        c_params
            .distinguished_name
            .push(DnType::CommonName, "test-client");
        let c_key = KeyPair::generate().unwrap();
        let c_cert = c_params.signed_by(&c_key, &ca_cert, &ca_key).unwrap();

        TestPki {
            ca_pem: ca_cert.pem(),
            server_cert_pem: s_cert.pem(),
            server_key_pem: s_key.serialize_pem(),
            client_cert_pem: c_cert.pem(),
            client_key_pem: c_key.serialize_pem(),
        }
    }

    fn cn_router() -> Router {
        Router::new().route(
            "/cn",
            get(|Extension(ClientCn(cn)): Extension<ClientCn>| async move { cn }),
        )
    }

    fn cn_post_router() -> Router {
        Router::new().route(
            "/echo",
            post(|Extension(ClientCn(cn)): Extension<ClientCn>| async move { cn }),
        )
    }

    /// Client config trusting `ca_pem`, optionally presenting a client cert.
    fn client_config(ca_pem: &str, client: Option<(&str, &str)>) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        for ca in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(ca.unwrap()).unwrap();
        }
        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        match client {
            Some((cert_pem, key_pem)) => {
                let certs: Vec<CertificateDer<'static>> =
                    CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                        .collect::<Result<_, _>>()
                        .unwrap();
                let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
                builder.with_client_auth_cert(certs, key).unwrap()
            }
            None => builder.with_no_client_auth(),
        }
    }

    /// Connect, send a GET /cn over the TLS stream, and return the raw response.
    async fn try_request(addr: SocketAddr, cfg: rustls::ClientConfig) -> Result<String, String> {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| e.to_string())?;
        let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector
            .connect(domain, tcp)
            .await
            .map_err(|e| e.to_string())?;
        tls.write_all(b"GET /cn HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Complete an mTLS handshake (presenting `client`) and return the **server's**
    /// presented leaf CN — used to prove which cert the resolver served.
    async fn served_server_cn(
        addr: SocketAddr,
        ca_pem: &str,
        client: (&str, &str),
    ) -> Result<String, String> {
        let cfg = client_config(ca_pem, Some(client));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| e.to_string())?;
        let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = connector
            .connect(domain, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let server_cert = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or_else(|| "no server cert".to_string())?;
        extract_cn(server_cert.as_ref()).ok_or_else(|| "no CN in server cert".to_string())
    }

    #[tokio::test]
    async fn reloadable_resolver_hot_swaps_served_leaf() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};

        // A CA, two CA-signed server leaves (CN server-A / server-B), one client leaf.
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Reload CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        let server_leaf = |cn: &str| {
            let mut p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            p.subject_alt_names
                .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
            p.distinguished_name.push(DnType::CommonName, cn);
            let k = KeyPair::generate().unwrap();
            let c = p.signed_by(&k, &ca_cert, &ca_key).unwrap();
            (c.pem(), k.serialize_pem())
        };
        let (cert_a, key_a) = server_leaf("server-A");
        let (cert_b, key_b) = server_leaf("server-B");

        let mut c_params = CertificateParams::new(vec![]).unwrap();
        c_params
            .distinguished_name
            .push(DnType::CommonName, "test-client");
        let c_key = KeyPair::generate().unwrap();
        let c_cert = c_params.signed_by(&c_key, &ca_cert, &ca_key).unwrap();
        let client = (c_cert.pem(), c_key.serialize_pem());

        // Serve with a resolver-backed config presenting leaf A.
        let resolver = ReloadableServerCert::from_pem(&cert_a, &key_a).unwrap();
        let config = build_server_config_with_resolver(resolver.clone(), &ca_pem).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve(cn_router(), listener, config, cancel.clone()));

        // The client sees leaf A.
        let before = served_server_cn(addr, &ca_pem, (&client.0, &client.1))
            .await
            .expect("handshake A");
        assert_eq!(before, "server-A");

        // Hot-swap to leaf B with NO listener restart.
        resolver.reload(&cert_b, &key_b).expect("reload");

        // The next handshake presents leaf B — same socket, same ServerConfig.
        let after = served_server_cn(addr, &ca_pem, (&client.0, &client.1))
            .await
            .expect("handshake B");
        assert_eq!(
            after, "server-B",
            "hot-reload must swap the served server leaf without a restart"
        );

        // A bad reload is rejected and the previous good cert is kept.
        assert!(resolver.reload("not-a-cert", "not-a-key").is_err());
        let still = served_server_cn(addr, &ca_pem, (&client.0, &client.1))
            .await
            .expect("handshake after bad reload");
        assert_eq!(still, "server-B", "a bad reload must not drop the good cert");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn mtls_requires_client_cert_and_surfaces_cn() {
        let pki = test_pki();
        let config =
            build_server_config(&pki.server_cert_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve(cn_router(), listener, config, cancel.clone()));

        // A CA-signed client cert is accepted and its CN reaches the handler.
        let body = try_request(
            addr,
            client_config(
                &pki.ca_pem,
                Some((&pki.client_cert_pem, &pki.client_key_pem)),
            ),
        )
        .await
        .expect("authenticated client should connect");
        assert!(body.contains("200"), "expected HTTP 200; got: {body}");
        assert!(
            body.trim_end().ends_with("test-client"),
            "response body should be the client CN; got: {body}"
        );

        // No client cert -> rejected at the handshake.
        let no_cert = try_request(addr, client_config(&pki.ca_pem, None)).await;
        assert!(
            no_cert.is_err() || !no_cert.as_ref().unwrap().contains("200"),
            "a no-cert client must be rejected; got: {no_cert:?}"
        );

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn mtls_client_post_json_authenticates_and_reads_cn() {
        let pki = test_pki();
        let config =
            build_server_config(&pki.server_cert_pem, &pki.server_key_pem, &pki.ca_pem).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve(cn_post_router(), listener, config, cancel.clone()));

        let (status, body) = post_json(
            &addr.ip().to_string(),
            addr.port(),
            "/echo",
            "{}",
            &pki.client_cert_pem,
            &pki.client_key_pem,
            &pki.ca_pem,
        )
        .await
        .expect("authenticated client should POST");
        assert_eq!(status, 200);
        assert_eq!(body, "test-client", "the server saw the client CN");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn mtls_client_rejects_server_not_signed_by_pinned_ca() {
        // The server is signed by PKI A; the client presents a valid PKI-A client
        // cert (so the server accepts it) but PINS a different CA (PKI B) as the
        // server root → the client must reject the server cert.
        let server_pki = test_pki();
        let other_pki = test_pki();
        let config = build_server_config(
            &server_pki.server_cert_pem,
            &server_pki.server_key_pem,
            &server_pki.ca_pem,
        )
        .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve(cn_post_router(), listener, config, cancel.clone()));

        let result = post_json(
            &addr.ip().to_string(),
            addr.port(),
            "/echo",
            "{}",
            &server_pki.client_cert_pem,
            &server_pki.client_key_pem,
            &other_pki.ca_pem, // pin the WRONG CA
        )
        .await;
        assert!(
            result.is_err(),
            "client must reject a server not signed by its pinned CA"
        );

        cancel.cancel();
        let _ = server.await;
    }
}
