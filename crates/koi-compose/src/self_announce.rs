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
//! - It needs **no lock-at-boot retry**: the `_http` stamp is read from Certmesh's
//!   accepted status projection, which is available whether or not the CA key is unlocked —
//!   unlike the trust plane, whose `self_enroll` needs the unlocked key. So reacting to posture
//!   changes alone is sufficient.

use tokio_util::sync::CancellationToken;

use crate::cores::{Cores, RunningCores};

const ANNOUNCE_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

/// Ports, gates, and zone the self-announce supervisor needs.
pub struct SelfAnnounceConfig {
    /// Immutable machine identity captured by the application composition.
    pub host: crate::host::HostIdentity,
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
/// records are gated off. The task is transferred directly to the graph's lifecycle
/// owner; it withdraws its records when `cancel` fires.
pub fn spawn(cores: &RunningCores, cfg: SelfAnnounceConfig, cancel: CancellationToken) {
    if cores.mdns.is_none() || (!cfg.announce_http && !cfg.announce_mcp) {
        return;
    }
    let task_cores: Cores = cores.cores().clone();
    cores.own_task(tokio::spawn(async move {
        let Some(mdns) = task_cores.mdns.as_ref() else {
            return;
        };
        // These are process-scoped derived records, not permanent operator
        // intent. Session ownership gives every exit path a retrying mDNS
        // cleanup fallback when explicit provider withdrawal cannot settle.
        let registration_session = mdns.open_registration_session();

        let hostname = cfg.host.hostname().to_string();

        // The DNS descriptor is a process-local lease rather than durable DNS
        // configuration. Its synchronous Drop closes the task-abort path that
        // cannot run the graceful mDNS withdrawal below.
        let _mcp_txt = crate::announce::mcp_txt_lease(
            &task_cores,
            &hostname,
            &cfg.dns_zone,
            cfg.announce_mcp,
        );

        // Subscribe BEFORE the first announce so a posture flip during startup is not missed.
        // No retry timer is needed (unlike trust_plane): the `_http` stamp comes from
        // Certmesh status, readable whether or not the CA key is
        // unlocked, so the boot stamp is already correct and only real posture changes re-stamp.
        let mut status_rx = task_cores.certmesh.as_ref().map(|c| c.watch_status());

        // `_http._tcp` carries the posture stamp → re-announced on each posture flip.
        let mut http_id = crate::announce::http_record(
            &task_cores,
            &registration_session,
            &hostname,
            cfg.http_port,
            cfg.dashboard_enabled,
            cfg.announce_http,
        )
        .await;
        // `_mcp._tcp` is transport-discovery only (no posture stamp) → published once, held
        // until shutdown. (This also gives it a real withdrawal, which the prior one-shot
        // announce lacked — its id was dropped and the record leaked until the mDNS goodbye.)
        let mut mcp_id = crate::announce::mcp_record(
            &task_cores,
            &registration_session,
            &hostname,
            cfg.http_port,
            cfg.announce_mcp,
        )
        .await;

        // Initial provider churn is recoverable without a daemon restart. A
        // restamp is break-before-make: retain the old id until withdrawal is
        // acknowledged, so a transient failure cannot create duplicates.
        let mut http_dirty = cfg.announce_http && http_id.is_none();
        let mut mcp_dirty = cfg.announce_mcp && mcp_id.is_none();
        let mut retry = tokio::time::interval(ANNOUNCE_RETRY);
        retry.tick().await;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = async {
                    match status_rx.as_mut() {
                        Some(receiver) => receiver.changed().await,
                        None => std::future::pending().await,
                    }
                }, if cfg.announce_http => {
                    if changed.is_err() {
                        tracing::warn!(
                            "self-announce: certmesh status watch closed; retaining transport records until shutdown"
                        );
                        status_rx = None;
                    } else {
                        http_dirty = true;
                    }
                }
                _ = retry.tick(), if http_dirty || mcp_dirty => {}
            }

            if http_dirty {
                if let Some(old) = http_id.clone() {
                    match mdns.unregister(&old).await {
                        Ok(()) => http_id = None,
                        Err(error) => {
                            tracing::warn!(%error, id = %old, "self-announce restamp waiting for prior HTTP withdrawal");
                        }
                    }
                }
                if http_id.is_none() {
                    http_id = crate::announce::http_record(
                        &task_cores,
                        &registration_session,
                        &hostname,
                        cfg.http_port,
                        cfg.dashboard_enabled,
                        cfg.announce_http,
                    )
                    .await;
                }
                http_dirty = http_id.is_none();
            }

            if mcp_dirty {
                mcp_id = crate::announce::mcp_record(
                    &task_cores,
                    &registration_session,
                    &hostname,
                    cfg.http_port,
                    cfg.announce_mcp,
                )
                .await;
                mcp_dirty = mcp_id.is_none();
            }
        }

        // Withdraw both mDNS records. The in-zone `_mcp` TXT is synchronously
        // removed when `_mcp_txt` drops at task exit.
        if let (Some(id), Some(mdns)) = (http_id, task_cores.mdns.as_ref()) {
            let _ = mdns.unregister(&id).await;
        }
        crate::announce::withdraw_mcp(&task_cores, mcp_id.as_deref()).await;
    }));
}
