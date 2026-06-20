//! `client_for` — the posture-keyed peer client (ADR-020 §6).
//!
//! One call returns a [`PeerClient`] that speaks the right protocol to a
//! discovered peer: **plain HTTP** to an Open peer, **mTLS** to a secure peer —
//! keyed off the peer's advertised posture plus the mesh CA pin. The caller never
//! chooses http/https and never attaches a certificate, so the *same* consumer
//! code path works against both kinds of peer (the mode-transparency contract,
//! ADR-020 §2).
//!
//! The protocol decision is made loudly, not silently: a peer that requires
//! authentication while this node is Open, or a peer anchored to a *different*
//! mesh, returns a descriptive error instead of a connection that mysteriously
//! fails at the TLS layer (ADR-020 §13: "the category's defining failure is
//! silence").

use std::sync::Arc;

use koi_common::peer::Peer;

use crate::error::CertmeshError;
use crate::mtls;
use crate::{CertmeshCore, Identity};

/// A ready-to-use client to one peer, with the transport already resolved from
/// the peer's posture (ADR-020 §6).
///
/// Built by [`CertmeshCore::client_for`]. `get`/`post_json` dispatch to plain HTTP
/// or mTLS transparently; [`is_secure`](PeerClient::is_secure) reports which, so a
/// consumer can *observe* per-connection trust state (the "padlock on the wire")
/// without choosing it.
pub struct PeerClient {
    host: String,
    port: u16,
    transport: Transport,
}

enum Transport {
    /// Plain HTTP to an Open peer.
    Plain,
    /// mTLS to a secure peer, with the client config (our leaf + the pinned CA)
    /// built once at construction.
    Mtls(Arc<rustls::ClientConfig>),
}

impl std::fmt::Debug for PeerClient {
    /// Reports the dial target and resolved trust state; never the TLS config.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("secure", &self.is_secure())
            .finish()
    }
}

impl PeerClient {
    /// Whether this client speaks mTLS (the peer is secure and we authenticated to
    /// it) rather than plain HTTP. The observable per-connection trust state.
    pub fn is_secure(&self) -> bool {
        matches!(self.transport, Transport::Mtls(_))
    }

    /// The resolved target host this client dials.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The resolved target port this client dials.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// GET `path` from the peer, returning `(status, body)`. Plain or mTLS per the
    /// resolved transport.
    pub async fn get(&self, path: &str) -> Result<(u16, String), CertmeshError> {
        match &self.transport {
            Transport::Plain => {
                mtls::request_plain(&self.host, self.port, hyper::Method::GET, path, None).await
            }
            Transport::Mtls(config) => {
                mtls::request_tls(
                    Arc::clone(config),
                    &self.host,
                    self.port,
                    hyper::Method::GET,
                    path,
                    None,
                )
                .await
            }
        }
    }

    /// POST a JSON `body` to `path`, returning `(status, body)`. Plain or mTLS per
    /// the resolved transport.
    pub async fn post_json(&self, path: &str, body: &str) -> Result<(u16, String), CertmeshError> {
        match &self.transport {
            Transport::Plain => {
                mtls::request_plain(&self.host, self.port, hyper::Method::POST, path, Some(body))
                    .await
            }
            Transport::Mtls(config) => {
                mtls::request_tls(
                    Arc::clone(config),
                    &self.host,
                    self.port,
                    hyper::Method::POST,
                    path,
                    Some(body),
                )
                .await
            }
        }
    }
}

impl CertmeshCore {
    /// Build a [`PeerClient`] for a discovered [`Peer`] (ADR-020 §6).
    ///
    /// Mode-transparent: an Open peer yields a plain-HTTP client; a secure peer
    /// yields an mTLS client presenting **this node's** identity and pinning the
    /// mesh CA. The caller writes one code path.
    ///
    /// Errors (loudly, not via a silent handshake failure):
    /// - the peer advertises no dialable address/port;
    /// - the peer requires authentication but this node is Open (no identity);
    /// - the peer anchors to a *different* mesh (its `fp=` ≠ our CA fingerprint).
    pub async fn client_for(&self, peer: &Peer) -> Result<PeerClient, CertmeshError> {
        let (host, port) = peer.addr().ok_or_else(|| {
            CertmeshError::Internal(format!(
                "peer '{}' has no dialable address:port",
                peer.record.name
            ))
        })?;
        let identity = self.local_identity().await;
        select_client(peer, identity.as_ref(), host, port)
    }
}

/// Resolve the transport for a peer given our (optional) local identity. Pure —
/// no I/O, no `self` — so the policy is unit-testable without a live CA. Building
/// the rustls client config is the only non-trivial step (validates our PEMs).
fn select_client(
    peer: &Peer,
    identity: Option<&Identity>,
    host: String,
    port: u16,
) -> Result<PeerClient, CertmeshError> {
    // Open peer → plain HTTP. No identity required on either side.
    if !peer.posture.signed {
        return Ok(PeerClient {
            host,
            port,
            transport: Transport::Plain,
        });
    }

    // Secure peer → we must present a client certificate, so we need an identity.
    let id = identity.ok_or_else(|| {
        CertmeshError::Internal(format!(
            "peer '{}' requires authentication but this node is Open (no identity) — \
             run `koi certmesh join` (or call ensure_identity()) first",
            peer.record.name
        ))
    })?;

    // Same-mesh check: an mTLS handshake can only succeed if the peer anchors to
    // the CA we trust. Catch the mismatch here with a clear message rather than
    // letting it surface as an opaque TLS error.
    if let Some(peer_fp) = peer.fp.as_deref() {
        if !peer_fp.eq_ignore_ascii_case(&id.ca_fingerprint) {
            return Err(CertmeshError::Internal(format!(
                "peer '{}' anchors to a different mesh (peer CA fp {} ≠ our CA fp {}) — \
                 cannot establish mTLS",
                peer.record.name, peer_fp, id.ca_fingerprint
            )));
        }
    }

    let config = mtls::build_client_config(&id.cert_pem, &id.key_pem, &id.ca_cert_pem)?;
    Ok(PeerClient {
        host,
        port,
        transport: Transport::Mtls(Arc::new(config)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::posture::Posture;
    use koi_common::types::ServiceRecord;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    /// A CA, a CA-signed leaf (our identity cert/key), the CA fp, and a CA-signed
    /// server cert (for live mTLS round-trips).
    struct TestId {
        identity: Identity,
        ca_fp: String,
        server_cert_pem: String,
        server_key_pem: String,
    }

    fn test_identity() -> TestId {
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();
        let ca_fp =
            koi_crypto::pinning::fingerprint_sha256(pem::parse(&ca_pem).unwrap().contents());

        let mut leaf_params = CertificateParams::new(vec!["me.local".to_string()]).unwrap();
        leaf_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "me");
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        // A server cert (SAN localhost + 127.0.0.1) for the listener side.
        let mut s_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        s_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        s_params
            .distinguished_name
            .push(DnType::CommonName, "test-server");
        let s_key = KeyPair::generate().unwrap();
        let s_cert = s_params.signed_by(&s_key, &ca_cert, &ca_key).unwrap();

        let identity = Identity {
            hostname: "me".to_string(),
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
            ca_cert_pem: ca_pem,
            ca_fingerprint: ca_fp.clone(),
            renewal: crate::RenewalHealth {
                expires_at: chrono::Utc::now() + chrono::Duration::days(30),
                next_renewal_at: chrono::Utc::now() + chrono::Duration::days(20),
                expires_in_days: 30,
                renew_overdue: false,
                expired: false,
            },
        };
        TestId {
            identity,
            ca_fp,
            server_cert_pem: s_cert.pem(),
            server_key_pem: s_key.serialize_pem(),
        }
    }

    fn peer_with(posture: Posture, fp: Option<&str>) -> Peer {
        let mut txt = HashMap::new();
        if let Some(fp) = fp {
            txt.insert("fp".to_string(), fp.to_string());
        }
        koi_common::peer::stamp(&mut txt, posture, fp, None);
        Peer::from_record(ServiceRecord {
            name: "peer-01".to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some("peer-01.local".to_string()),
            ip: Some("127.0.0.1".to_string()),
            port: Some(8443),
            txt,
        })
    }

    #[test]
    fn open_peer_yields_plain_client_without_identity() {
        let peer = peer_with(Posture::OPEN, None);
        let client = select_client(&peer, None, "127.0.0.1".into(), 8080).unwrap();
        assert!(!client.is_secure());
        assert_eq!(client.host(), "127.0.0.1");
        assert_eq!(client.port(), 8080);
    }

    #[test]
    fn open_peer_is_plain_even_when_we_have_identity() {
        let id = test_identity();
        let peer = peer_with(Posture::OPEN, None);
        let client = select_client(&peer, Some(&id.identity), "127.0.0.1".into(), 8080).unwrap();
        assert!(!client.is_secure(), "an Open peer is dialed in plaintext");
    }

    #[test]
    fn secure_peer_without_local_identity_errors_loudly() {
        let peer = peer_with(Posture::new(true, false), Some("SOMEFP"));
        let err = select_client(&peer, None, "127.0.0.1".into(), 8443).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("requires authentication"), "got: {msg}");
        assert!(
            msg.contains("ensure_identity") || msg.contains("join"),
            "got: {msg}"
        );
    }

    #[test]
    fn secure_peer_in_different_mesh_errors_loudly() {
        let id = test_identity();
        // Peer advertises a fingerprint that is not our CA.
        let peer = peer_with(Posture::new(true, false), Some("DIFFERENT-MESH-FP"));
        let err = select_client(&peer, Some(&id.identity), "127.0.0.1".into(), 8443).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("different mesh"), "got: {msg}");
    }

    #[test]
    fn secure_peer_same_mesh_yields_mtls_client() {
        let id = test_identity();
        let peer = peer_with(Posture::new(true, false), Some(&id.ca_fp));
        let client = select_client(&peer, Some(&id.identity), "127.0.0.1".into(), 8443).unwrap();
        assert!(client.is_secure(), "same-mesh secure peer → mTLS");
    }

    #[test]
    fn secure_peer_fp_match_is_case_insensitive() {
        let id = test_identity();
        let upper = id.ca_fp.to_uppercase();
        // Only meaningful if the fp has hex letters; still must not falsely reject.
        let peer = peer_with(Posture::new(true, false), Some(&upper));
        let client = select_client(&peer, Some(&id.identity), "127.0.0.1".into(), 8443);
        assert!(client.is_ok(), "fp comparison must be case-insensitive");
    }

    #[test]
    fn secure_peer_without_advertised_fp_still_builds_mtls() {
        // No fp= advertised but posture=authenticated → trust our own pin and try.
        let id = test_identity();
        let mut txt = HashMap::new();
        txt.insert("posture".to_string(), "authenticated".to_string());
        let peer = Peer::from_record(ServiceRecord {
            name: "peer-02".to_string(),
            service_type: "_http._tcp".to_string(),
            host: None,
            ip: Some("127.0.0.1".to_string()),
            port: Some(8443),
            txt,
        });
        let client = select_client(&peer, Some(&id.identity), "127.0.0.1".into(), 8443);
        assert!(client.unwrap().is_secure());
    }

    // ── live round-trips: the dispatch actually works over the wire ──────

    #[tokio::test]
    async fn live_mtls_round_trip_surfaces_our_cn() {
        use crate::http::ClientCn;
        use axum::extract::Extension;
        use axum::routing::get as axum_get;
        use axum::Router;
        use tokio::net::TcpListener;
        use tokio_util::sync::CancellationToken;

        let id = test_identity();
        let server_config = mtls::build_server_config(
            &id.server_cert_pem,
            &id.server_key_pem,
            &id.identity.ca_cert_pem,
        )
        .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route(
            "/cn",
            axum_get(|Extension(ClientCn(cn)): Extension<ClientCn>| async move { cn }),
        );
        let cancel = CancellationToken::new();
        let server = tokio::spawn(mtls::serve(router, listener, server_config, cancel.clone()));

        let mut txt = HashMap::new();
        koi_common::peer::stamp(&mut txt, Posture::new(true, false), Some(&id.ca_fp), None);
        let peer = Peer::from_record(ServiceRecord {
            name: "peer-01".into(),
            service_type: "_http._tcp".into(),
            host: None,
            ip: Some("127.0.0.1".into()),
            port: Some(addr.port()),
            txt,
        });

        let client =
            select_client(&peer, Some(&id.identity), "127.0.0.1".into(), addr.port()).unwrap();
        assert!(client.is_secure(), "secure peer dialed over mTLS");
        let (status, body) = client.get("/cn").await.expect("mTLS GET should succeed");
        assert_eq!(status, 200);
        assert_eq!(body, "me", "the server authenticated our leaf CN");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn live_plain_round_trip_to_open_peer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A minimal one-shot HTTP/1.1 server (a plain peer); the client makes one
        // `Connection: close` request, so a single accept suffices.
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong",
                    )
                    .await;
                let _ = sock.flush().await;
            }
        });

        let peer = peer_with(Posture::OPEN, None);
        let client = select_client(&peer, None, "127.0.0.1".into(), addr.port()).unwrap();
        assert!(!client.is_secure(), "open peer dialed in plaintext");
        let (status, body) = client.get("/ping").await.expect("plain GET should succeed");
        assert_eq!(status, 200);
        assert_eq!(body, "pong");

        let _ = server.await;
    }
}
