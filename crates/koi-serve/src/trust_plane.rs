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
//! The supervisor keys off
//! [`CertmeshCore::watch_posture`](koi_certmesh::CertmeshCore::watch_posture) so the
//! whole trust-plane presence is live whenever the CA exists. A node that boots Open
//! and later runs `koi certmesh create` brings the trust plane up reactively, and a
//! node whose CA is **locked at boot** recovers via a bounded retry timer
//! ([`RETRY_INTERVAL`]) once `koi certmesh unlock` makes the CA usable.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_compose::cores::Cores;

/// How often to re-attempt `start_listeners` while the posture is secure but the
/// listeners are not yet live. Covers the case where a CA exists but is **locked at
/// boot**: the posture watch stays `signed: true`, so `koi certmesh unlock` does not
/// fire a posture change to wake the supervisor — the retry timer does instead, so
/// the trust plane recovers without a daemon restart.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Ports + zone the trust-plane presence needs. Host-agnostic — the ACME base
/// FQDN is derived from the local hostname inside the supervisor.
pub struct TrustPlaneConfig {
    pub mtls_port: u16,
    pub acme_port: u16,
    pub no_acme: bool,
    pub dns_zone: String,
    /// HTTP port to advertise in the `_certmesh._tcp` discovery record, or `None`
    /// when HTTP is disabled (then no discovery record is published).
    pub announce_http_port: Option<u16>,
}

/// Spawn the posture-reactive trust-plane supervisor (no-op when certmesh is
/// disabled). The supervisor task is pushed to `tasks` (so it is awaited on
/// ordered shutdown); the listeners it owns are stopped and drained when the CA is
/// destroyed or `cancel` fires.
pub fn spawn(
    cores: &Cores,
    cfg: TrustPlaneConfig,
    cancel: CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    let Some(certmesh) = cores.certmesh.clone() else {
        return;
    };
    let dns = cores.dns.clone();
    let mdns = cores.mdns.clone();

    tasks.push(tokio::spawn(async move {
        let mut posture_rx = certmesh.watch_posture();
        // `live` holds the trust-plane presence (listener cancel token + their
        // JoinHandles + the mDNS announce id) while up; `None` while the node is Open.
        let mut live: Option<Live> = None;

        loop {
            let secure = posture_rx.borrow_and_update().signed;
            match (secure, live.is_some()) {
                // CA appeared → bring the trust plane up.
                (true, false) => {
                    if let Some(started) =
                        start_listeners(&certmesh, &dns, &mdns, &cfg, &cancel).await
                    {
                        tracing::info!("trust-plane presence started (CA available)");
                        live = Some(started);
                    }
                    // If self-enroll is not ready yet (e.g. the CA exists but is locked
                    // at boot), the retry timer below re-attempts — a `koi certmesh
                    // unlock` does not change the posture watch, so a posture-change wake
                    // alone would never recover it.
                }
                // CA destroyed → take the trust plane down (drain in-flight first).
                (false, true) => {
                    stop_listeners(live.take(), &mdns).await;
                    tracing::info!("trust-plane presence stopped (CA unavailable)");
                }
                _ => {}
            }

            // Re-attempt only while we want the listeners up but they are not — the
            // timer is inert once they are live or while the node is Open.
            let want_retry = secure && live.is_none();

            tokio::select! {
                _ = cancel.cancelled() => {
                    stop_listeners(live.take(), &mdns).await;
                    break;
                }
                changed = posture_rx.changed() => {
                    if changed.is_err() {
                        // The certmesh core was dropped — tear down and exit.
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
    handles: Vec<JoinHandle<()>>,
    announce_id: Option<String>,
}

/// Withdraw the mDNS announce, cancel the listeners' token and await their tasks
/// (graceful drain). No-op when the trust plane is already down.
async fn stop_listeners(live: Option<Live>, mdns: &Option<Arc<koi_mdns::MdnsCore>>) {
    if let Some(live) = live {
        if let (Some(id), Some(mdns)) = (live.announce_id.as_deref(), mdns) {
            if let Err(e) = mdns.unregister(id) {
                tracing::debug!(error = %e, "failed to withdraw _certmesh._tcp announce");
            }
        }
        live.cancel.cancel();
        for h in live.handles {
            let _ = h.await;
        }
    }
}

/// Self-enroll the local leaf and spawn the mTLS (and ACME, when enabled) listeners
/// under a fresh child token. `None` when the CA is not yet ready to self-enroll
/// (e.g. locked at boot); the supervisor then re-attempts on the next posture change
/// or after [`RETRY_INTERVAL`], whichever comes first.
async fn start_listeners(
    certmesh: &Arc<koi_certmesh::CertmeshCore>,
    dns: &Option<Arc<koi_dns::DnsRuntime>>,
    mdns: &Option<Arc<koi_mdns::MdnsCore>>,
    cfg: &TrustPlaneConfig,
    parent_cancel: &CancellationToken,
) -> Option<Live> {
    // The mTLS and ACME listeners both present this self-issued leaf; issue it once.
    let enrollment = match certmesh.self_enroll().await {
        Ok(e) => e,
        Err(e) => {
            tracing::info!(reason = %e, "trust-plane: CA not ready for self-enroll yet");
            return None;
        }
    };

    let token = parent_cancel.child_token();
    let mut handles = Vec::new();

    // ── mTLS inter-node listener (always, when secure) ──
    {
        let cm = certmesh.clone();
        let port = cfg.mtls_port;
        let token = token.clone();
        let enr = enrollment.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = crate::mtls::start(
                port,
                cm,
                &enr.cert_pem,
                &enr.key_pem,
                &enr.ca_cert_pem,
                token,
            )
            .await
            {
                tracing::error!(error = %e, "mTLS adapter failed");
            }
        }));
    }

    // ── ACME server-auth listener (needs the DNS core for dns-01; gated by --no-acme) ──
    if !cfg.no_acme {
        if let Some(dns) = dns {
            let base_url = format!("https://{}:{}", local_fqdn(), cfg.acme_port);
            let dns_solver: Arc<dyn koi_common::integration::AcmeDnsSolver> =
                koi_compose::bridges::AcmeDnsBridge::new(dns.clone());
            let acme_state = certmesh.acme_state(koi_certmesh::acme::AcmeStateConfig {
                base_url,
                zone: cfg.dns_zone.clone(),
                dns: dns_solver,
            });
            let port = cfg.acme_port;
            let token = token.clone();
            let enr = enrollment.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) =
                    crate::acme::start(port, acme_state, &enr.cert_pem, &enr.key_pem, token).await
                {
                    tracing::error!(error = %e, "ACME adapter failed");
                }
            }));
        } else {
            tracing::info!(
                "ACME adapter: skipped (DNS capability disabled; dns-01 needs the DNS core)"
            );
        }
    }

    // ── `_certmesh._tcp` discovery announce (ADR-017 F12, on the HTTP port) ──
    // Reactive: published now that the CA exists; withdrawn in `stop_listeners`.
    // No-op when HTTP or mDNS is disabled (no port / no core to register on).
    let announce_id = match (mdns, cfg.announce_http_port) {
        (Some(mdns), Some(http_port)) => register_certmesh_record(certmesh, mdns, http_port).await,
        _ => None,
    };

    Some(Live {
        cancel: token,
        handles,
        announce_id,
    })
}

/// Best-effort local hostname for the ACME base URL. ACME clients reach the
/// listener at this name; the daemon leaf's SAN covers
/// `<hostname>`/`<hostname>.local`/`localhost`, so any of those resolves.
fn local_fqdn() -> String {
    hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
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
    certmesh: &Arc<koi_certmesh::CertmeshCore>,
    mdns: &Arc<koi_mdns::MdnsCore>,
    http_port: u16,
) -> Option<String> {
    // Only advertise once a CA exists — the fingerprint is the whole point of the record.
    let fingerprint = certmesh.ca_fingerprint().await?;

    let hostname = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let mut txt = std::collections::HashMap::new();
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt.insert("name".to_string(), format!("Koi CA ({hostname})"));
    // Stamp the node's trust state (posture/fp/expires) so discoverers read the mesh's
    // trust map directly (ADR-020 §8). `fp=` stays the joiner's disambiguation hint
    // (ADR-017 F12); all advisory — the pinned-fingerprint preflight + `verify` remain
    // the authority (ADR-016 §2 "ask Koi, don't trust the wire").
    let expires_at = certmesh
        .local_identity()
        .await
        .map(|id| id.renewal.expires_at);
    koi_common::peer::stamp(&mut txt, certmesh.posture(), Some(&fingerprint), expires_at);
    let payload = koi_mdns::protocol::RegisterPayload {
        name: format!("Koi CA ({hostname})"),
        service_type: koi_certmesh::CERTMESH_SERVICE_TYPE.to_string(),
        port: http_port,
        ip: None,
        lease_secs: None,
        txt,
    };
    match mdns.register(payload) {
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
