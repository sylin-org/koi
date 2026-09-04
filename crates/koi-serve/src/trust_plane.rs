//! The daemon's trust-plane presence — posture-reactive (ADR-020 P4c / ADR-016 §2).
//!
//! One supervisor owns the node's whole trust-plane presence: the inter-node mTLS
//! listener (5642), the ACME server-auth listener (5643), **and** the
//! `_certmesh._tcp` mDNS discovery record (ADR-017 F12). It brings them all up when
//! the certmesh CA becomes available and tears them all down when the CA is
//! destroyed — with no daemon restart. The foreground daemon (`daemon_mode`) and
//! the Windows service (`run_service`) both spawn the trust plane through this one
//! function, so the two boot paths cannot drift.
//!
//! The supervisor keys off Certmesh's authoritative status and sensitive
//! [`TlsIdentitySource`] feeds. The trust-plane presence is live only while this
//! node owns an unlocked CA and Certmesh supplies usable identity material. A
//! node that boots Open and later runs `koi certmesh create` brings the plane up
//! reactively; a locked CA recovers via a bounded retry once unlock succeeds.

use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use koi_common::integration::{TlsIdentitySnapshot, TlsIdentitySource};
use koi_compose::cores::RunningCores;

/// How often to re-attempt `start_listeners` while an unlocked authority wants
/// the listeners but identity preparation or binding has not yet succeeded.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Ports, zone, and immutable machine identity the trust-plane presence needs.
pub struct TrustPlaneConfig {
    pub host: koi_compose::host::HostIdentity,
    pub mtls_port: u16,
    pub acme_port: u16,
    pub no_acme: bool,
    pub dns_zone: String,
    /// HTTP port to advertise in the `_certmesh._tcp` discovery record, or `None`
    /// when HTTP is disabled (then no discovery record is published).
    pub announce_http_port: Option<u16>,
    /// Mount `/v1/mcp` on the mTLS listener behind CN → roster principal
    /// authorization (ADR-026 §5). Off when MCP is disabled entirely
    /// (`--no-mcp-http`): one switch owns the tool surface, two transports.
    pub mgmt_mcp: bool,
}

/// Spawn the posture-reactive trust-plane supervisor (no-op when certmesh is
/// disabled). The supervisor is admitted immediately to the composition owner;
/// the listeners it owns are stopped and drained when the CA is destroyed or
/// `cancel` fires.
pub fn spawn(cores: &RunningCores, cfg: TrustPlaneConfig, cancel: CancellationToken) {
    let Some(certmesh) = cores.certmesh.clone() else {
        return;
    };
    let tls_identity: Arc<dyn TlsIdentitySource> =
        koi_compose::bridges::CertmeshTlsIdentityBridge::new(Arc::clone(&certmesh));
    let dns = cores.dns.clone();
    let mdns = cores.mdns.clone();
    // The management plane mounts the MCP tool surface on the mTLS listener
    // (ADR-026 §5); it needs the full cores, captured once here.
    let mgmt_mcp = cfg.mgmt_mcp.then(|| crate::mtls::MgmtMcp {
        cores: cores.cores().clone(),
        started_at: std::time::Instant::now(),
    });

    cores.own_task(tokio::spawn(async move {
        let mut status_rx = certmesh.watch_status();
        let mut identity_rx = tls_identity.watch_tls_identity();
        // `live` holds the trust-plane presence (listener cancel token + owned
        // tasks + the mDNS announce id) while up; `None` while the node is Open.
        let mut live: Option<Live> = None;

        loop {
            // Authenticated members are clients of this plane, not CA servers.
            // `signed` alone also covers them, so keep listener ownership keyed
            // to the local CA role as well as usable identity.
            let current = status_rx.borrow_and_update().clone();
            let authority_ready = current
                .authority
                .as_ref()
                .is_some_and(|authority| !authority.locked);
            let identity_ready = current.identity.condition
                == koi_certmesh::IdentityCondition::Healthy
                && identity_rx.borrow_and_update().material.is_some();

            // A live listener must never outlive the identity status that made it
            // safe. Keep the previous good certificate only across an unsuccessful
            // reload, not across a domain-declared invalid/expired/revoked identity.
            if live.is_some() && (!authority_ready || !identity_ready) {
                stop_listeners(live.take(), &mdns).await;
                tracing::info!("trust-plane presence stopped (identity unavailable)");
            }

            match (authority_ready, live.is_some()) {
                // An unlocked CA can self-enroll/repair its identity and start.
                (true, false) => {
                    if let Some(started) = start_listeners(
                        &certmesh,
                        &tls_identity,
                        &dns,
                        &mdns,
                        &mgmt_mcp,
                        &cfg,
                        &cancel,
                    )
                    .await
                    {
                        tracing::info!("trust-plane presence started (CA available)");
                        live = Some(started);
                    }
                    // If self-enroll is not ready yet (e.g. the CA exists but is locked
                    // at boot), the retry timer below re-attempts — a `koi certmesh
                    // unlock` does not change the posture watch, so a posture-change wake
                    // alone would never recover it.
                }
                // CA locked/destroyed → take the trust plane down (drain first).
                (false, true) => {
                    stop_listeners(live.take(), &mdns).await;
                    tracing::info!("trust-plane presence stopped (CA unavailable)");
                }
                _ => {}
            }

            // Re-attempt only while we want the listeners up but they are not — the
            // timer is inert once they are live or while the node is Open.
            let want_retry = authority_ready && live.is_none();

            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    stop_listeners(live.take(), &mdns).await;
                    break;
                }
                ended = next_live_task(&mut live) => {
                    observe_live_task(ended);
                    stop_listeners(live.take(), &mdns).await;
                    tracing::warn!("trust-plane presence stopped after an owned task exited; retrying while authority remains available");
                }
                changed = status_rx.changed() => {
                    if changed.is_err() {
                        // The certmesh core was dropped — tear down and exit.
                        stop_listeners(live.take(), &mdns).await;
                        break;
                    }
                }
                changed = identity_rx.changed() => {
                    if changed.is_err() {
                        // Losing the identity authority is fail-closed.
                        stop_listeners(live.take(), &mdns).await;
                        break;
                    }
                }
                _ = tokio::time::sleep(RETRY_INTERVAL), if want_retry => {
                    // Fall through to re-run start_listeners at the top of the loop.
                }
            }
        }
    }));
}

/// The trust-plane presence while a CA is available: the listeners' shared child
/// cancel token + their task handles, plus the `_certmesh._tcp` mDNS announce id (if
/// it was published). Dropped/torn down when the CA goes away.
struct Live {
    cancel: CancellationToken,
    handles: JoinSet<()>,
    announce_id: Option<String>,
    /// Fail-safe ownership for the lifecycle-scoped announcement. If explicit
    /// withdrawal cannot be acknowledged during provider churn, dropping this
    /// session moves the registration into mDNS's retrying reaper instead of
    /// leaving a permanent desired record behind.
    _announce_session: Option<koi_mdns::RegistrationSession>,
    resolver: Arc<koi_certmesh::mtls::ReloadableServerCert>,
}

/// Native resources acquired as one trust-plane generation before any task is
/// spawned or discovery record is published.
struct BoundListeners {
    mtls: tokio::net::TcpListener,
    mtls_port: u16,
    acme: Option<(tokio::net::TcpListener, u16)>,
}

impl Drop for Live {
    fn drop(&mut self) {
        // A cancelled supervisor must not detach its listener generation. Native
        // registration release remains the mDNS domain's responsibility during
        // its own terminal shutdown, but serving and identity use fail closed now.
        self.resolver.withdraw();
        self.cancel.cancel();
        self.handles.abort_all();
    }
}

/// Withdraw the mDNS announce, cancel the listeners' token and await their tasks
/// (graceful drain). No-op when the trust plane is already down.
async fn stop_listeners(live: Option<Live>, mdns: &Option<Arc<koi_mdns::MdnsCore>>) {
    if let Some(mut live) = live {
        // Fail closed before awaiting any graceful teardown work. Even a TCP
        // connection accepted in the drain window can no longer obtain the
        // withdrawn identity.
        live.resolver.withdraw();
        live.cancel.cancel();
        if let (Some(id), Some(mdns)) = (live.announce_id.as_deref(), mdns) {
            if let Err(e) = mdns.unregister(id).await {
                tracing::debug!(error = %e, "failed to withdraw _certmesh._tcp announce");
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !live.handles.is_empty() {
            match tokio::time::timeout_at(deadline, live.handles.join_next()).await {
                Ok(result) => observe_live_task(result),
                Err(_) => {
                    live.handles.abort_all();
                    while let Some(result) = live.handles.join_next().await {
                        observe_live_task(Some(result));
                    }
                }
            }
        }
    }
}

fn observe_live_task(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(error)) = result {
        if !error.is_cancelled() {
            tracing::warn!(%error, "trust-plane task failed");
        }
    }
}

async fn next_live_task(live: &mut Option<Live>) -> Option<Result<(), tokio::task::JoinError>> {
    match live {
        Some(live) if !live.handles.is_empty() => live.handles.join_next().await,
        _ => pending().await,
    }
}

/// Self-enroll the local leaf and spawn the mTLS (and ACME, when enabled) listeners
/// under a fresh child token. `None` when the CA is not yet ready to self-enroll
/// (e.g. locked at boot); the supervisor then re-attempts on the next posture change
/// or after [`RETRY_INTERVAL`], whichever comes first.
async fn start_listeners(
    certmesh: &Arc<koi_certmesh::CertmeshCore>,
    tls_identity: &Arc<dyn TlsIdentitySource>,
    dns: &Option<Arc<koi_dns::DnsRuntime>>,
    mdns: &Option<Arc<koi_mdns::MdnsCore>>,
    mgmt_mcp: &Option<crate::mtls::MgmtMcp>,
    cfg: &TrustPlaneConfig,
    parent_cancel: &CancellationToken,
) -> Option<Live> {
    // Subscribe before self-enrollment so a rotation racing startup is either
    // used as the seed or remains pending on this same latest-value receiver.
    let mut identity_updates = tls_identity.watch_tls_identity();
    if let Err(e) = certmesh.self_enroll().await {
        tracing::info!(reason = %e, "trust-plane: CA not ready for self-enroll yet");
        return None;
    }
    let identity = identity_updates.borrow_and_update().clone();
    let Some(material) = identity.material.as_ref() else {
        tracing::info!("trust-plane: Certmesh has no usable local TLS identity yet");
        return None;
    };

    // One hot-swappable resolver backs BOTH listeners. Certmesh owns the identity
    // material and its trust anchor; this adapter consumes one coherent boundary
    // snapshot instead of watching or rereading Certmesh's private storage.
    let resolver = match koi_certmesh::mtls::ReloadableServerCert::from_pem(
        &material.certificate_chain_pem,
        &material.private_key_pem,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "trust-plane: self leaf unusable for TLS; listeners not started");
            return None;
        }
    };

    // Acquire every configured native listener before spawning or advertising
    // the generation. A partial acquisition is rolled back by ordinary Drop.
    let BoundListeners {
        mtls: mtls_listener,
        mtls_port,
        acme: acme_listener,
    } = match acquire_listeners(cfg, dns.is_some()).await {
        Ok(listeners) => listeners,
        Err(error) => {
            tracing::warn!(%error, "trust-plane: native listener acquisition failed");
            return None;
        }
    };

    let token = parent_cancel.child_token();
    let mut handles = JoinSet::new();
    handles.spawn(run_cert_reload_task(
        identity_updates,
        resolver.clone(),
        token.clone(),
    ));
    let mut readiness = Vec::new();

    // ── mTLS inter-node + management listener (always, when secure) ──
    {
        let cm = certmesh.clone();
        let token = token.clone();
        let resolver = resolver.clone();
        let trust_anchor_pem = Arc::clone(&material.trust_anchor_pem);
        // Fresh per listener start: the MCP change pump binds to this attempt's
        // child token, so teardown fully drains it.
        let mgmt = mgmt_mcp.as_ref().map(|m| crate::mtls::MgmtMcp {
            cores: m.cores.clone(),
            started_at: m.started_at,
        });
        let (ready_tx, ready_rx) = oneshot::channel();
        readiness.push(("mTLS", ready_rx));
        handles.spawn(async move {
            if let Err(e) = crate::mtls::start(
                mtls_listener,
                cm,
                resolver,
                trust_anchor_pem.as_ref(),
                token,
                mgmt,
                ready_tx,
            )
            .await
            {
                tracing::error!(error = %e, "mTLS adapter failed");
            }
        });
    }

    // ── ACME server-auth listener (needs the DNS core for dns-01; gated by --no-acme) ──
    if !cfg.no_acme {
        if let (Some(dns), Some((listener, acme_port))) = (dns, acme_listener) {
            let base_url = format!("https://{}:{acme_port}", cfg.host.local_fqdn());
            let dns_solver: Arc<dyn koi_common::integration::AcmeDnsResolver> =
                koi_compose::bridges::AcmeDnsBridge::new(dns.clone());
            let acme_state = certmesh.acme_state(koi_certmesh::acme::AcmeStateConfig {
                base_url,
                zone: cfg.dns_zone.clone(),
                dns: dns_solver,
            });
            let token = token.clone();
            let resolver = resolver.clone();
            let (ready_tx, ready_rx) = oneshot::channel();
            readiness.push(("ACME", ready_rx));
            handles.spawn(async move {
                if let Err(e) =
                    crate::acme::start(listener, acme_state, resolver, token, ready_tx).await
                {
                    tracing::error!(error = %e, "ACME adapter failed");
                }
            });
        } else {
            tracing::info!(
                "ACME adapter: skipped (DNS capability disabled; dns-01 needs the DNS core)"
            );
        }
    }

    let mut live = Live {
        cancel: token,
        handles,
        announce_id: None,
        _announce_session: None,
        resolver,
    };
    for (adapter, ready) in readiness {
        let readiness = tokio::select! {
            biased;
            _ = parent_cancel.cancelled() => {
                stop_listeners(Some(live), mdns).await;
                return None;
            }
            readiness = ready => readiness,
        };
        if readiness.is_err() {
            tracing::warn!(
                adapter,
                "trust-plane adapter ended before reporting readiness"
            );
            stop_listeners(Some(live), mdns).await;
            return None;
        }
    }

    // ── `_certmesh._tcp` discovery announce (ADR-017 F12, on the HTTP port) ──
    // Reactive: published now that the CA exists; withdrawn in `stop_listeners`.
    // No-op when HTTP or mDNS is disabled (no port / no core to register on).
    let current_status = certmesh.status();
    if let (Some(mdns), Some(http_port)) = (mdns, cfg.announce_http_port) {
        let session = mdns.open_registration_session();
        let Some(id) = register_certmesh_record(
            current_status.as_ref(),
            mdns,
            &session,
            cfg.host.hostname(),
            http_port,
        )
        .await
        else {
            stop_listeners(Some(live), &Some(Arc::clone(mdns))).await;
            return None;
        };
        live.announce_id = Some(id);
        live._announce_session = Some(session);
    }

    tracing::info!(mtls_port, "trust-plane listeners crossed readiness fence");
    Some(live)
}

async fn acquire_listeners(
    cfg: &TrustPlaneConfig,
    dns_available: bool,
) -> anyhow::Result<BoundListeners> {
    use anyhow::Context as _;

    let mtls = tokio::net::TcpListener::bind(("0.0.0.0", cfg.mtls_port))
        .await
        .with_context(|| format!("could not bind mTLS port {}", cfg.mtls_port))?;
    let mtls_port = mtls
        .local_addr()
        .context("could not inspect bound mTLS listener")?
        .port();

    let acme = if !cfg.no_acme && dns_available {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", cfg.acme_port))
            .await
            .with_context(|| format!("could not bind ACME port {}", cfg.acme_port))?;
        let port = listener
            .local_addr()
            .context("could not inspect bound ACME listener")?
            .port();
        Some((listener, port))
    } else {
        None
    };

    Ok(BoundListeners {
        mtls,
        mtls_port,
        acme,
    })
}

/// Apply Certmesh's latest-value identity feed to the shared listener resolver.
/// `None` is an authoritative withdrawal and clears the resolver immediately;
/// the outer supervisor concurrently drains the listeners.
async fn run_cert_reload_task(
    mut identity: tokio::sync::watch::Receiver<Arc<TlsIdentitySnapshot>>,
    resolver: Arc<koi_certmesh::mtls::ReloadableServerCert>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = identity.changed() => {
                if changed.is_err() {
                    break;
                }
                let snapshot = identity.borrow_and_update().clone();
                apply_listener_identity(snapshot.as_ref(), &resolver);
            }
        }
    }
}

fn apply_listener_identity(
    snapshot: &TlsIdentitySnapshot,
    resolver: &Arc<koi_certmesh::mtls::ReloadableServerCert>,
) {
    let Some(identity) = snapshot.material.as_ref() else {
        resolver.withdraw();
        tracing::info!("trust-plane: listener identity withdrawn");
        return;
    };
    match resolver.reload(&identity.certificate_chain_pem, &identity.private_key_pem) {
        Ok(()) => tracing::info!("trust-plane: listeners reloaded the renewed self leaf"),
        Err(e) => {
            tracing::warn!(error = %e, "trust-plane: renewed leaf unusable; keeping the previous cert")
        }
    }
}

/// Advertise the certmesh CA on the LAN with its fingerprint in TXT (ADR-017 F12).
///
/// Publishes EXACTLY ONE `_certmesh._tcp` mDNS record (on the HTTP port, where the CA
/// serves `/status` and `/trust-bundle`) carrying `fp=<ca_fingerprint>` plus the ADR-020
/// posture stamp. A joiner cross-checks `fp=` against its invite pin — a convenience hint,
/// never a trust source (the authoritative check is the joiner's pinned-fingerprint
/// preflight). Returns `None` when no CA is initialized yet. Reactive: published when the
/// CA appears (here) and withdrawn in [`stop_listeners`]; the mDNS goodbye also withdraws
/// it on shutdown. (Moved from the binary's `infra` so the trust plane owns it end-to-end.)
async fn register_certmesh_record(
    status: &koi_certmesh::CertmeshStatus,
    mdns: &Arc<koi_mdns::MdnsCore>,
    session: &koi_mdns::RegistrationSession,
    hostname: &str,
    http_port: u16,
) -> Option<String> {
    // Only advertise once a CA exists — the fingerprint is the whole point of the record.
    let fingerprint = status
        .authority
        .as_ref()
        .and_then(|authority| authority.ca_fingerprint.clone())?;

    let mut txt = std::collections::HashMap::new();
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt.insert("name".to_string(), format!("Koi CA ({hostname})"));
    // Stamp the node's trust state (posture/fp/expires) so discoverers read the mesh's
    // trust map directly (ADR-020 §8). `fp=` stays the joiner's disambiguation hint
    // (ADR-017 F12); all advisory — the pinned-fingerprint preflight + `verify` remain
    // the authority (ADR-016 §2 "ask Koi, don't trust the wire").
    let expires_at = status
        .identity
        .info
        .as_ref()
        .map(|identity| identity.renewal.expires_at);
    koi_common::peer::stamp(&mut txt, status.posture, Some(&fingerprint), expires_at);
    let payload = koi_mdns::protocol::RegisterPayload {
        name: format!("Koi CA ({hostname})"),
        service_type: koi_certmesh::CERTMESH_SERVICE_TYPE.to_string(),
        port: http_port,
        ip: None,
        lease_secs: None,
        txt,
    };
    match mdns
        .register_with_policy(
            payload,
            koi_mdns::LeasePolicy::Session {
                grace: Duration::ZERO,
            },
            Some(session.id().clone()),
        )
        .await
    {
        Ok(result) => {
            tracing::info!(id = %result.id, port = http_port, fp = %fingerprint, "Certmesh CA announced via mDNS (_certmesh._tcp)");
            Some(result.id)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to announce certmesh CA via mDNS");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::integration::TlsIdentityMaterial;
    use koi_common::status::StatusFeed;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;

    #[derive(Clone)]
    struct MutableIdentitySource {
        feed: StatusFeed<TlsIdentitySnapshot>,
    }

    impl MutableIdentitySource {
        fn new(initial: TlsIdentitySnapshot) -> Self {
            Self {
                feed: StatusFeed::new(initial),
            }
        }

        fn publish(&self, next: TlsIdentitySnapshot) {
            self.feed.publish(next);
        }
    }

    impl TlsIdentitySource for MutableIdentitySource {
        fn tls_identity(&self) -> Arc<TlsIdentitySnapshot> {
            self.feed.current()
        }

        fn watch_tls_identity(&self) -> watch::Receiver<Arc<TlsIdentitySnapshot>> {
            self.feed.subscribe()
        }
    }

    fn generated_identity() -> (TlsIdentityMaterial, Vec<u8>) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate identity");
        let certificate_pem = generated.cert.pem();
        let certificate_der = generated.cert.der().as_ref().to_vec();
        (
            TlsIdentityMaterial {
                hostname: "localhost".to_string(),
                certificate_chain_pem: Arc::from(certificate_pem.clone()),
                private_key_pem: Arc::from(generated.key_pair.serialize_pem()),
                trust_anchor_pem: Arc::from(certificate_pem),
            },
            certificate_der,
        )
    }

    async fn served_certificate(
        resolver: Arc<koi_certmesh::mtls::ReloadableServerCert>,
    ) -> Option<Vec<u8>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("server TLS versions")
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test TLS listener");
        let address = listener.local_addr().expect("test TLS address");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept test TLS client");
            acceptor.accept(socket).await
        });

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let socket = TcpStream::connect(address).await.ok()?;
        let client = connector
            .connect(
                ServerName::try_from("localhost").expect("server name"),
                socket,
            )
            .await
            .ok();
        let _ = server.await;
        let client = client?;
        let (_, connection) = client.get_ref();
        connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|certificate| certificate.as_ref().to_vec())
    }

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            use SignatureScheme::*;
            vec![
                ECDSA_NISTP256_SHA256,
                ECDSA_NISTP384_SHA384,
                ED25519,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
            ]
        }
    }

    fn listener_config(mtls_port: u16, acme_port: u16) -> TrustPlaneConfig {
        TrustPlaneConfig {
            host: koi_compose::host::HostIdentity::from_hostname("test-host").unwrap(),
            mtls_port,
            acme_port,
            no_acme: false,
            dns_zone: "internal".to_string(),
            announce_http_port: Some(5641),
            mgmt_mcp: false,
        }
    }

    #[tokio::test]
    async fn occupied_mtls_port_rejects_the_generation_before_startup() {
        let occupied = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("occupy mTLS port");
        let port = occupied.local_addr().expect("occupied address").port();

        let error = acquire_listeners(&listener_config(port, 0), true)
            .await
            .err()
            .expect("occupied mTLS port must reject startup");
        assert!(error.to_string().contains("mTLS"));
    }

    #[tokio::test]
    async fn failed_acme_acquisition_releases_the_provisional_mtls_socket() {
        let provisional = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("choose provisional mTLS port");
        let mtls_port = provisional
            .local_addr()
            .expect("provisional address")
            .port();
        drop(provisional);

        let occupied = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("occupy ACME port");
        let acme_port = occupied.local_addr().expect("occupied address").port();

        let error = acquire_listeners(&listener_config(mtls_port, acme_port), true)
            .await
            .err()
            .expect("occupied ACME port must reject the whole generation");
        assert!(error.to_string().contains("ACME"));

        TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, mtls_port))
            .await
            .expect("failed generation must release provisional mTLS ownership");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_feed_rotates_then_withdraws_the_actual_served_certificate() {
        let (material_a, certificate_a) = generated_identity();
        let source = MutableIdentitySource::new(TlsIdentitySnapshot {
            revision: 1,
            material: Some(material_a.clone()),
        });
        let resolver = koi_certmesh::mtls::ReloadableServerCert::from_pem(
            &material_a.certificate_chain_pem,
            &material_a.private_key_pem,
        )
        .expect("initial resolver");
        let cancel = CancellationToken::new();
        let reload = tokio::spawn(run_cert_reload_task(
            source.watch_tls_identity(),
            Arc::clone(&resolver),
            cancel.clone(),
        ));

        assert_eq!(
            served_certificate(Arc::clone(&resolver)).await.as_deref(),
            Some(certificate_a.as_slice())
        );

        let (material_b, certificate_b) = generated_identity();
        source.publish(TlsIdentitySnapshot {
            revision: 2,
            material: Some(material_b),
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if served_certificate(Arc::clone(&resolver)).await.as_deref()
                    == Some(certificate_b.as_slice())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("rotated certificate becomes live");

        source.publish(TlsIdentitySnapshot {
            revision: 3,
            material: None,
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while served_certificate(Arc::clone(&resolver)).await.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("withdrawn identity rejects new handshakes");

        cancel.cancel();
        reload.await.expect("reload task exits cleanly");
    }
}
