//! Certmesh CA → OS Trust desired-state bridge.
//!
//! Neither domain depends on the other. Composition subscribes to Certmesh's
//! sensitive in-process anchor projection before reading its seed, then drives
//! one idempotent Trust command for each latest value. The Trust domain owns
//! journaling, platform effects, status, retries, and events.

use std::sync::Arc;
use std::time::Duration;

use koi_certmesh::{CertmeshCaAnchorSnapshot, CertmeshCore};
use koi_trust::{InstallRoot, TrustCore, TrustError};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub const CERTMESH_ROOT_NAME: &str = "koi-certmesh-ca";
pub const CERTMESH_ROOT_SOURCE: &str = "certmesh";
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Arm Certmesh observation, reconcile the current desired anchor, and spawn
/// the single owned reactive/retry worker. When Certmesh is disabled, `None` is
/// still desired state and removes only the exactly tracked Certmesh-owned root.
///
/// Initial reconciliation is awaited before this returns, making the function a
/// startup causal fence. Failure is retained by `TrustStatus` and retried; it
/// does not make unrelated Koi capabilities unavailable.
pub async fn start_bridge(
    certmesh: Option<Arc<CertmeshCore>>,
    trust: Arc<TrustCore>,
    cancel: CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    // Subscribe first so a transition racing the seed cannot be lost.
    let mut anchor_rx = certmesh.as_ref().map(|core| core.watch_ca_anchor());
    let initial = anchor_rx
        .as_mut()
        .map(|receiver| receiver.borrow_and_update().as_ref().clone())
        .unwrap_or_else(|| CertmeshCaAnchorSnapshot::absent(0));
    reconcile_latest(&trust, &initial).await;

    tasks.push(tokio::spawn(run_bridge(anchor_rx, initial, trust, cancel)));
}

async fn run_bridge(
    mut anchor_rx: Option<tokio::sync::watch::Receiver<Arc<CertmeshCaAnchorSnapshot>>>,
    mut latest: CertmeshCaAnchorSnapshot,
    trust: Arc<TrustCore>,
    cancel: CancellationToken,
) {
    // Source availability is not desired state. If the Certmesh feed closes,
    // retain the last accepted anchor rather than translating a broken
    // observation channel into a destructive `anchor: None`.
    let mut retry = tokio::time::interval(RECONCILE_INTERVAL);
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Initial work was already fenced by `start_bridge`; consume the interval's
    // immediate tick.
    retry.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            change = changed_opt(&mut anchor_rx) => {
                match change {
                    AnchorSourceChange::Changed => {
                        if let Some(receiver) = anchor_rx.as_mut() {
                            latest = receiver.borrow_and_update().as_ref().clone();
                            reconcile_latest(&trust, &latest).await;
                        }
                    }
                    AnchorSourceChange::Closed => {
                        tracing::warn!(
                            revision = latest.revision,
                            "Certmesh CA-anchor source closed; preserving the last accepted Trust desire"
                        );
                        anchor_rx = None;
                    }
                }
            }
            _ = retry.tick() => {
                if let Err(error) = trust.reconcile().await {
                    tracing::warn!(%error, "OS trust-store recovery remains pending");
                }
                reconcile_latest(&trust, &latest).await;
            }
        }
    }
}

async fn changed_opt(
    receiver: &mut Option<tokio::sync::watch::Receiver<Arc<CertmeshCaAnchorSnapshot>>>,
) -> AnchorSourceChange {
    match receiver.as_mut() {
        Some(receiver) => match receiver.changed().await {
            Ok(()) => AnchorSourceChange::Changed,
            Err(_) => AnchorSourceChange::Closed,
        },
        None => std::future::pending().await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorSourceChange {
    Changed,
    Closed,
}

async fn reconcile_latest(trust: &TrustCore, snapshot: &CertmeshCaAnchorSnapshot) {
    if let Err(error) = apply_anchor(trust, snapshot).await {
        tracing::warn!(
            %error,
            revision = snapshot.revision,
            "could not converge the Certmesh root in the OS trust store; it remains observable and will be retried"
        );
    }
}

async fn apply_anchor(
    trust: &TrustCore,
    snapshot: &CertmeshCaAnchorSnapshot,
) -> Result<(), AnchorApplyError> {
    match snapshot
        .anchor()
        .map_err(|reason| AnchorApplyError::Source(reason.to_string()))?
    {
        Some(anchor) => {
            trust
                .ensure_installed(InstallRoot {
                    name: CERTMESH_ROOT_NAME.to_string(),
                    source: CERTMESH_ROOT_SOURCE.to_string(),
                    certificate_pem: anchor.certificate_pem.clone(),
                })
                .await?;
        }
        None => {
            trust
                .ensure_removed(CERTMESH_ROOT_NAME, CERTMESH_ROOT_SOURCE)
                .await?;
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum AnchorApplyError {
    #[error("Certmesh CA-anchor observation failed: {0}")]
    Source(String),
    #[error(transparent)]
    Trust(#[from] TrustError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_certmesh::CertmeshCaAnchorState;

    fn test_dir(label: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "koi-compose-trust-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn anchor(name: &str, revision: u64) -> CertmeshCaAnchorSnapshot {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate_pem = params.self_signed(&key).unwrap().pem();
        let certificate = os_truststore::Cert::from_pem(&certificate_pem).unwrap();
        CertmeshCaAnchorSnapshot {
            revision,
            state: CertmeshCaAnchorState::Available(koi_certmesh::CertmeshCaAnchor {
                fingerprint: certificate.fingerprint_hex(),
                certificate_pem,
            }),
        }
    }

    #[tokio::test]
    async fn desired_anchor_and_absence_converge_through_real_domain_commands() {
        let dir = test_dir("converge");
        let (trust, _) = TrustCore::open_memory(dir.clone()).await.unwrap();
        apply_anchor(&trust, &anchor("mesh", 1)).await.unwrap();
        assert_eq!(trust.status().roots.len(), 1);
        assert_eq!(trust.status().roots[0].source, CERTMESH_ROOT_SOURCE);

        apply_anchor(
            &trust,
            &CertmeshCaAnchorSnapshot {
                revision: 2,
                state: CertmeshCaAnchorState::Absent,
            },
        )
        .await
        .unwrap();
        assert!(trust.status().roots.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failed_effect_is_journaled_and_retry_converges() {
        let dir = test_dir("retry");
        let (trust, control) = TrustCore::open_memory(dir.clone()).await.unwrap();
        control.fail_next_install();
        let desired = anchor("mesh", 1);
        assert!(apply_anchor(&trust, &desired).await.is_err());
        assert!(trust.status().pending.is_some());

        trust.reconcile().await.unwrap();
        apply_anchor(&trust, &desired).await.unwrap();
        assert!(trust.status().pending.is_none());
        assert_eq!(trust.status().roots.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn closed_anchor_source_does_not_mean_desired_absence() {
        let dir = test_dir("closed-source");
        let (trust, _) = TrustCore::open_memory(dir.clone()).await.unwrap();
        let desired = anchor("mesh", 1);
        apply_anchor(&trust, &desired).await.unwrap();

        let (anchor_tx, anchor_rx) = tokio::sync::watch::channel(Arc::new(desired.clone()));
        drop(anchor_tx);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_bridge(
            Some(anchor_rx),
            desired,
            Arc::new(trust.clone()),
            cancel.clone(),
        ));

        // A closed watch receiver is immediately ready. Give the bridge enough
        // scheduler turns to consume it without relying on wall-clock sleeps.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(trust.status().roots.len(), 1);
        assert_eq!(trust.status().roots[0].source, CERTMESH_ROOT_SOURCE);

        cancel.cancel();
        task.await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unavailable_anchor_observation_preserves_the_last_accepted_desire() {
        let dir = test_dir("unavailable-source");
        let (trust, _) = TrustCore::open_memory(dir.clone()).await.unwrap();
        apply_anchor(&trust, &anchor("mesh", 1)).await.unwrap();

        let error = apply_anchor(
            &trust,
            &CertmeshCaAnchorSnapshot {
                revision: 2,
                state: CertmeshCaAnchorState::Unavailable {
                    reason: "permission denied".to_string(),
                },
            },
        )
        .await
        .expect_err("unavailable source is not desired absence");

        assert!(error.to_string().contains("permission denied"));
        assert_eq!(trust.status().roots.len(), 1);
        assert_eq!(trust.status().roots[0].source, CERTMESH_ROOT_SOURCE);
        let _ = std::fs::remove_dir_all(dir);
    }
}
