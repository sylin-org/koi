//! Certmesh background orchestration — the member-pull renewal loop plus the
//! enrollment-approval pump.
//!
//! These are **cross-domain orchestration**, not certmesh domain logic: they tie the
//! certmesh state machine (which lives in `koi-certmesh`, with its own tests) to the
//! daemon lifecycle (the cancellation token, the background task set) and an
//! operator-approval decision. That is exactly what a composition crate is for.
//!
//! Relocating them here (out of the binary's `main.rs`) is what makes Windows-service and
//! embedded daemons reach parity with the foreground daemon by construction — all three
//! call [`spawn_certmesh_background_tasks`] and [`spawn_enrollment_approval`].

use std::sync::Arc;
use std::time::Duration;

use koi_certmesh::{ApprovalDecision, ApprovalRequest, CertmeshCore};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Decides one enrollment-approval request.
///
/// The `bool` is the mesh's `requires_approval` flag (whether an operator name must
/// accompany the approval).
///
/// Injected so the transport is the caller's choice: the foreground daemon supplies an
/// interactive stdin prompt; the Windows service and embedded daemons (no console) supply
/// [`deny_and_log_decider`], which never blocks and never silently approves.
///
/// Called inside `spawn_blocking`, so a blocking implementation (stdin) is fine.
pub type ApprovalDecider = Arc<dyn Fn(&str, bool) -> ApprovalDecision + Send + Sync>;

/// An [`ApprovalDecider`] that denies every request and logs it.
///
/// The safe default where there is no operator to ask (Windows service, embedded). The CA
/// is never weakened silently: an enrollment that cannot be approved is refused, visibly.
pub fn deny_and_log_decider() -> ApprovalDecider {
    Arc::new(|hostname: &str, _requires_approval: bool| {
        tracing::warn!(
            hostname,
            "Certmesh enrollment auto-denied (no interactive console to approve)"
        );
        ApprovalDecision::Denied
    })
}

/// Wire the certmesh approval channel to `decider` and pump requests until cancellation.
///
/// Each request is resolved on a blocking task (so a stdin decider is safe) and the
/// decision is sent back over the request's one-shot reply channel.
pub async fn spawn_enrollment_approval(
    certmesh: &Arc<CertmeshCore>,
    decider: ApprovalDecider,
    cancel: &CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    let (tx, mut rx) = mpsc::channel(8);
    certmesh.set_approval_channel(tx).await;

    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                request = rx.recv() => {
                    let Some(request) = request else {
                        break;
                    };
                    dispatch_approval(request, decider.clone()).await;
                }
            }
        }
    }));
}

/// Resolve a single approval request via the decider and reply over its one-shot channel.
///
/// Factored out of the pump loop so the routing is unit-testable without driving a real
/// enrollment through the certmesh state machine.
async fn dispatch_approval(request: ApprovalRequest, decider: ApprovalDecider) {
    let ApprovalRequest {
        hostname,
        requires_approval,
        respond_to,
    } = request;
    let decision = tokio::task::spawn_blocking(move || decider(&hostname, requires_approval))
        .await
        .unwrap_or(ApprovalDecision::Denied);
    let _ = respond_to.send(decision);
}

/// Spawn certmesh background tasks based on the node's role.
///
/// Spawns one loop: the **member-pull renewal** check (ADR-017 F6). On a node that
/// joined a mesh it periodically asks the certmesh core whether the local leaf is
/// within the CA policy's renewal threshold and, if so, performs a rotate-key pull
/// renewal over mTLS. It is a no-op on the CA itself and on unconfigured nodes
/// (the CA renews its own leaf at restart via `self_enroll`).
///
/// CA failover is **manual** (`koi certmesh promote`): there is no automatic
/// absence-watch or standby roster sync, so the loop needs neither mDNS nor the
/// HTTP port. It respects `CancellationToken` for orderly shutdown.
pub fn spawn_certmesh_background_tasks(
    certmesh: &Arc<CertmeshCore>,
    cancel: &CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    // ── Member-pull renewal loop ────────────────────────────────────
    // A joined member renews its own cert before expiry by generating a fresh
    // keypair + CSR and pulling a CA signature over mTLS (the key never leaves the
    // member). No-op on the CA / unconfigured nodes.
    let cm = Arc::clone(certmesh);
    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let interval = Duration::from_secs(koi_certmesh::lifecycle::RENEWAL_CHECK_INTERVAL_SECS);
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    match cm.renew_self_if_due().await {
                        Ok(koi_certmesh::RenewOutcome::Renewed { expires, hook }) => {
                            let hook_ok = hook.as_ref().map(|h| h.success).unwrap_or(true);
                            if hook_ok {
                                tracing::info!(%expires, "Certificate renewed (rotated key)");
                            } else {
                                tracing::warn!(%expires, "Certificate renewed but reload hook failed");
                            }
                        }
                        Ok(koi_certmesh::RenewOutcome::NotDue { .. })
                        | Ok(koi_certmesh::RenewOutcome::NotApplicable) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "Certificate renewal failed; will retry next cycle");
                        }
                    }
                }
            }
        }
    }));

    tracing::debug!("Certmesh background tasks spawned");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn deny_and_log_decider_denies_regardless_of_approval_flag() {
        let decider = deny_and_log_decider();
        for requires_approval in [false, true] {
            assert!(matches!(
                decider("host", requires_approval),
                ApprovalDecision::Denied
            ));
        }
    }

    #[tokio::test]
    async fn dispatch_approval_routes_decider_approval() {
        let decider: ApprovalDecider =
            Arc::new(|_hostname, _requires_approval| ApprovalDecision::Approved {
                operator: Some("alice".to_string()),
            });
        let (tx, rx) = oneshot::channel();
        let request = ApprovalRequest {
            hostname: "node-1".to_string(),
            requires_approval: true,
            respond_to: tx,
        };
        dispatch_approval(request, decider).await;
        match rx.await.expect("decision delivered") {
            ApprovalDecision::Approved { operator } => {
                assert_eq!(operator.as_deref(), Some("alice"))
            }
            ApprovalDecision::Denied => panic!("expected approval"),
        }
    }

    #[tokio::test]
    async fn dispatch_approval_routes_deny_decider() {
        let (tx, rx) = oneshot::channel();
        let request = ApprovalRequest {
            hostname: "node-2".to_string(),
            requires_approval: false,
            respond_to: tx,
        };
        dispatch_approval(request, deny_and_log_decider()).await;
        assert!(matches!(
            rx.await.expect("decision delivered"),
            ApprovalDecision::Denied
        ));
    }

    #[tokio::test]
    async fn spawn_enrollment_approval_pumps_until_cancel() {
        // A certmesh core with no CA still accepts an approval channel; the pump should
        // wire it and then exit cleanly on cancellation.
        let dir = std::env::temp_dir().join(format!("koi-compose-approval-{}", std::process::id()));
        let paths = koi_certmesh::CertmeshPaths::with_data_dir(dir);
        let certmesh = Arc::new(koi_certmesh::CertmeshCore::uninitialized_with_paths(paths));
        let cancel = CancellationToken::new();
        let mut tasks = Vec::new();

        spawn_enrollment_approval(&certmesh, deny_and_log_decider(), &cancel, &mut tasks).await;
        assert_eq!(tasks.len(), 1);

        cancel.cancel();
        for task in tasks {
            task.await.expect("pump task joins cleanly");
        }
    }
}
