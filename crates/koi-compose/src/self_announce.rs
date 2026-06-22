//! Posture-reactive self-announce supervisor for this host's own service records.
//!
//! One task owns the host's `_http._tcp` self-announcement (with the ADR-020 posture stamp)
//! and the `_mcp._tcp` transport descriptor. It **re-stamps `_http._tcp` on every
//! Open↔Authenticated posture flip** — so a node that boots Open and later runs `koi certmesh
//! create` (or `destroy`) updates its advertised `posture=`/`fp=`/`expires=` without a restart,
//! mirroring how the trust-plane supervisor manages `_certmesh._tcp`. Both records (and the
//! in-zone `_mcp` DNS TXT) are withdrawn on shutdown. The foreground daemon, the Windows
//! service, and `koi-embedded` all spawn it through this one function, so the three boot paths
//! cannot drift.
//!
//! Two ways it differs from the trust-plane supervisor:
//! - These records are advertised **regardless of posture** (they are transport-discovery, not
//!   CA-gated); only the `_http` posture stamp varies, and `_mcp` (which carries no stamp) is
//!   published once and simply held until shutdown.
//! - It needs **no lock-at-boot retry**: the `_http` stamp is read from on-disk cert info
//!   (`local_identity`/`posture`), which is available whether or not the CA key is unlocked —
//!   unlike the trust plane, whose `self_enroll` needs the unlocked key. So reacting to posture
//!   changes alone is sufficient.

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::cores::Cores;

/// Ports, gates, and zone the self-announce supervisor needs.
pub struct SelfAnnounceConfig {
    /// The local HTTP/MCP port advertised in both records.
    pub http_port: u16,
    /// The dashboard hint advertised in the `_http._tcp` TXT (what the caller actually serves).
    pub dashboard_enabled: bool,
    /// Publish `_http._tcp` (folds the caller's `--announce-http` + HTTP-on gate).
    pub announce_http: bool,
    /// Publish `_mcp._tcp` (folds the caller's MCP-transport + HTTP-on gate).
    pub announce_mcp: bool,
    /// DNS zone for the in-zone `_mcp.<host>.<zone>` TXT descriptor.
    pub dns_zone: String,
}

/// Spawn the posture-reactive self-announce supervisor. No-op when mDNS is disabled or both
/// records are gated off. The task is pushed to `tasks` (so it is awaited on ordered
/// shutdown); it withdraws its records when `cancel` fires.
pub fn spawn(
    cores: &Cores,
    cfg: SelfAnnounceConfig,
    cancel: CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    if cores.mdns.is_none() || (!cfg.announce_http && !cfg.announce_mcp) {
        return;
    }
    let cores = cores.clone();
    tasks.push(tokio::spawn(async move {
        // Capture the hostname once so the `_mcp` withdrawal targets exactly the in-zone DNS
        // TXT name that was registered, even if the OS hostname changes mid-run.
        let hostname = crate::announce::local_hostname();

        // Subscribe BEFORE the first announce so a posture flip during startup is not missed.
        // No retry timer is needed (unlike trust_plane): the `_http` stamp comes from on-disk
        // cert info (`local_identity`/`posture`), readable whether or not the CA key is
        // unlocked, so the boot stamp is already correct and only real posture changes re-stamp.
        let mut posture_rx = cores.certmesh.as_ref().map(|c| c.watch_posture());

        // `_http._tcp` carries the posture stamp → re-announced on each posture flip.
        let mut http_id = crate::announce::http_record(
            &cores,
            cfg.http_port,
            cfg.dashboard_enabled,
            cfg.announce_http,
        )
        .await;
        // `_mcp._tcp` is transport-discovery only (no posture stamp) → published once, held
        // until shutdown. (This also gives it a real withdrawal, which the prior one-shot
        // announce lacked — its id was dropped and the record leaked until the mDNS goodbye.)
        let mcp_id = crate::announce::mcp_record(
            &cores,
            &hostname,
            cfg.http_port,
            &cfg.dns_zone,
            cfg.announce_mcp,
        )
        .await;

        // React to posture flips only when there is a CA to watch and we publish `_http`;
        // otherwise just hold the records until shutdown.
        match posture_rx.as_mut() {
            Some(rx) if cfg.announce_http => loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    changed = rx.changed() => {
                        if changed.is_err() {
                            // The certmesh core was dropped before shutdown (unreachable while a
                            // boot path holds the `Cores` Arc). Warn so a future refactor that
                            // clears certmesh at runtime is observable, then withdraw + exit.
                            tracing::warn!(
                                "self-announce: certmesh posture watch closed before shutdown; \
                                 withdrawing records and stopping re-announce"
                            );
                            break;
                        }
                        // Posture flipped → re-announce `_http` so its stamp is current
                        // (re-reads posture/fp/expires fresh — never the cached boot TXT).
                        if let (Some(old), Some(mdns)) = (http_id.take(), cores.mdns.as_ref()) {
                            let _ = mdns.unregister(&old);
                        }
                        http_id = crate::announce::http_record(
                            &cores,
                            cfg.http_port,
                            cfg.dashboard_enabled,
                            cfg.announce_http,
                        )
                        .await;
                    }
                }
            },
            _ => {
                cancel.cancelled().await;
            }
        }

        // Withdraw both records (and the in-zone `_mcp` DNS TXT) on shutdown.
        if let (Some(id), Some(mdns)) = (http_id, cores.mdns.as_ref()) {
            let _ = mdns.unregister(&id);
        }
        crate::announce::withdraw_mcp(&cores, &hostname, &cfg.dns_zone, mcp_id.as_deref());
    }));
}
