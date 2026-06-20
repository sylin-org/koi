//! The daemon's trust-plane TLS listeners — posture-reactive (ADR-020 P4c / ADR-016 §2).
//!
//! One supervisor owns **both** the inter-node mTLS listener (5642) and the ACME
//! server-auth listener (5643): it brings them up when the certmesh CA becomes
//! available and tears them down when the CA is destroyed — with no daemon
//! restart. The foreground daemon (`daemon_mode`) and the Windows service
//! (`run_service`) both spawn the trust plane through this one function, so the two
//! boot paths cannot drift. (Previously each inlined the wiring and the Windows
//! path had already silently dropped ACME — the exact class of parity defect the
//! `koi-compose` layer exists to prevent.)
//!
//! Before ADR-020 these listeners were gated **once at boot** on a CA already
//! existing (`self_enroll` at startup). A node that booted Open and later ran
//! `koi certmesh create` then had a dead trust plane until restart — ADR-016 §2's
//! "startup-gated mTLS/ACME listeners" bug. The supervisor keys off
//! [`CertmeshCore::watch_posture`](koi_certmesh::CertmeshCore::watch_posture) so
//! the trust plane is live whenever the CA exists.

use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_compose::cores::Cores;

/// Ports + zone the trust-plane listeners need. Host-agnostic — the ACME base
/// FQDN is derived from the local hostname inside the supervisor.
pub struct TrustPlaneConfig {
    pub mtls_port: u16,
    pub acme_port: u16,
    pub no_acme: bool,
    pub dns_zone: String,
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

    tasks.push(tokio::spawn(async move {
        let mut posture_rx = certmesh.watch_posture();
        // `live` holds the listeners' shared cancel token + their JoinHandles while
        // the trust plane is up; `None` while the node is Open.
        let mut live: Option<(CancellationToken, Vec<JoinHandle<()>>)> = None;

        loop {
            let secure = posture_rx.borrow_and_update().signed;
            match (secure, live.is_some()) {
                // CA appeared → bring the trust plane up.
                (true, false) => {
                    if let Some(started) = start_listeners(&certmesh, &dns, &cfg, &cancel).await {
                        tracing::info!("trust-plane listeners started (CA available)");
                        live = Some(started);
                    }
                    // If self-enroll is not ready yet, retry on the next posture change.
                }
                // CA destroyed → take the trust plane down (drain in-flight first).
                (false, true) => {
                    stop_listeners(live.take()).await;
                    tracing::info!("trust-plane listeners stopped (CA unavailable)");
                }
                _ => {}
            }

            tokio::select! {
                _ = cancel.cancelled() => {
                    stop_listeners(live.take()).await;
                    break;
                }
                changed = posture_rx.changed() => {
                    if changed.is_err() {
                        // The certmesh core was dropped — tear down and exit.
                        stop_listeners(live.take()).await;
                        break;
                    }
                }
            }
        }
    }));
}

/// Cancel the listeners' token and await their tasks (graceful drain). No-op when
/// the trust plane is already down.
async fn stop_listeners(live: Option<(CancellationToken, Vec<JoinHandle<()>>)>) {
    if let Some((token, handles)) = live {
        token.cancel();
        for h in handles {
            let _ = h.await;
        }
    }
}

/// Self-enroll the local leaf and spawn the mTLS (and ACME, when enabled) listeners
/// under a fresh child token. `None` when the CA is not yet ready to self-enroll
/// (the supervisor retries on the next posture change).
async fn start_listeners(
    certmesh: &Arc<koi_certmesh::CertmeshCore>,
    dns: &Option<Arc<koi_dns::DnsRuntime>>,
    cfg: &TrustPlaneConfig,
    parent_cancel: &CancellationToken,
) -> Option<(CancellationToken, Vec<JoinHandle<()>>)> {
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
            if let Err(e) = crate::adapters::mtls::start(
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
                if let Err(e) = crate::adapters::acme::start(
                    port,
                    acme_state,
                    &enr.cert_pem,
                    &enr.key_pem,
                    token,
                )
                .await
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

    Some((token, handles))
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
