//! Certmesh background orchestration — the role-driven loops that keep a CA mesh
//! converging (renewal, member heartbeat) plus the enrollment-approval pump.
//!
//! These loops are **cross-domain orchestration**, not certmesh domain logic: they tie
//! the certmesh state machine (which lives in `koi-certmesh`, with its own tests) to the
//! local daemon's HTTP surface (`koi-client` over the breadcrumb) and an operator-approval
//! decision. That is exactly what a composition crate is for — and it is why the loops
//! cannot live in `koi-certmesh` itself: a domain crate must not depend on `koi-client`
//! (the architecture guard forbids domain→domain edges).
//!
//! Relocating them here (out of the binary's `main.rs`) is what makes Windows-service and
//! embedded daemons reach parity with the foreground daemon by construction — all three
//! call [`spawn_certmesh_background_tasks`] and [`spawn_enrollment_approval`].

use std::sync::Arc;
use std::time::Duration;

use koi_certmesh::profiles::TrustProfile;
use koi_certmesh::{ApprovalDecision, ApprovalRequest, CertmeshCore};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Decides one enrollment-approval request.
///
/// Injected so the transport is the caller's choice: the foreground daemon supplies an
/// interactive stdin prompt; the Windows service and embedded daemons (no console) supply
/// [`deny_and_log_decider`], which never blocks and never silently approves.
///
/// Called inside `spawn_blocking`, so a blocking implementation (stdin) is fine.
pub type ApprovalDecider = Arc<dyn Fn(&str, TrustProfile) -> ApprovalDecision + Send + Sync>;

/// An [`ApprovalDecider`] that denies every request and logs it.
///
/// The safe default where there is no operator to ask (Windows service, embedded). The CA
/// is never weakened silently: an enrollment that cannot be approved is refused, visibly.
pub fn deny_and_log_decider() -> ApprovalDecider {
    Arc::new(|hostname: &str, _profile: TrustProfile| {
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
        profile,
        respond_to,
    } = request;
    let decision = tokio::task::spawn_blocking(move || decider(&hostname, profile))
        .await
        .unwrap_or(ApprovalDecision::Denied);
    let _ = respond_to.send(decision);
}

/// Spawn certmesh background tasks based on the node's role.
///
/// Spawns exactly two loops:
/// - **Primary (unlocked)**: hourly renewal check loop
/// - **Member**: periodic health heartbeat to CA
///
/// CA failover is **manual** (`koi certmesh promote`): there is no automatic absence-watch
/// or standby roster sync, so neither loop needs mDNS or the HTTP port.
///
/// All loops respect `CancellationToken` for orderly shutdown.
pub fn spawn_certmesh_background_tasks(
    certmesh: &Arc<CertmeshCore>,
    cancel: &CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    // ── Renewal check loop ──────────────────────────────────────────
    // Runs on the primary when the CA is unlocked. If the CA is still
    // locked at startup, the loop checks periodically and skips gracefully.
    let cm = Arc::clone(certmesh);
    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let interval = Duration::from_secs(koi_certmesh::lifecycle::RENEWAL_CHECK_INTERVAL_SECS);
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    let results = cm.renew_all_due().await;
                    for (hostname, result) in &results {
                        match result {
                            Ok(hook) => {
                                let hook_ok = hook.as_ref().map(|h| h.success).unwrap_or(true);
                                if hook_ok {
                                    tracing::info!(hostname, "Certificate renewed");
                                } else {
                                    tracing::warn!(hostname, "Certificate renewed but hook failed");
                                }
                            }
                            Err(e) => {
                                tracing::error!(hostname, error = %e, "Certificate renewal failed");
                            }
                        }
                    }
                    if !results.is_empty() {
                        tracing::info!(count = results.len(), "Renewal check complete");
                    }
                }
            }
        }
    }));

    // ── Member health heartbeat loop ────────────────────────────────
    // Members periodically POST their pinned CA fingerprint to the CA
    // endpoint. This validates the cert chain is still trusted.
    let cm = Arc::clone(certmesh);
    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let interval = Duration::from_secs(koi_certmesh::health::HEARTBEAT_INTERVAL_SECS);
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    // Only run if this node is a regular member (not primary/standby)
                    if cm.node_role().await != Some(koi_certmesh::roster::MemberRole::Member) {
                        continue;
                    }

                    let hostname = match koi_certmesh::CertmeshCore::local_hostname() {
                        Some(h) => h,
                        None => continue,
                    };

                    let pinned_fp = match cm.pinned_ca_fingerprint().await {
                        Some(fp) => fp,
                        None => {
                            tracing::debug!("Health heartbeat: no pinned CA fingerprint");
                            continue;
                        }
                    };

                    let bc = match koi_config::breadcrumb::read_breadcrumb() {
                        Some(bc) => bc,
                        None => {
                            tracing::debug!("Health heartbeat: no CA endpoint found");
                            continue;
                        }
                    };
                    let endpoint = bc.endpoint;
                    let token = bc.token;

                    let request = serde_json::json!({
                        "hostname": hostname,
                        "pinned_ca_fingerprint": pinned_fp,
                    });

                    // KoiClient is blocking (ureq) - run in a blocking task
                    let result = tokio::task::spawn_blocking(move || {
                        let c = koi_client::KoiClient::with_token(&endpoint, &token);
                        c.health_heartbeat(&request)
                    })
                    .await;

                    match result {
                        Ok(Ok(resp)) => {
                            let valid = resp.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
                            if valid {
                                tracing::debug!("Health heartbeat: valid");
                            } else {
                                tracing::warn!("Health heartbeat: CA fingerprint mismatch");
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "Health heartbeat: request failed");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Health heartbeat: blocking task panicked");
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
    async fn deny_and_log_decider_denies_every_profile() {
        let decider = deny_and_log_decider();
        for profile in [
            TrustProfile::JustMe,
            TrustProfile::MyTeam,
            TrustProfile::MyOrganization,
        ] {
            assert!(matches!(decider("host", profile), ApprovalDecision::Denied));
        }
    }

    #[tokio::test]
    async fn dispatch_approval_routes_decider_approval() {
        let decider: ApprovalDecider = Arc::new(|_hostname, _profile| ApprovalDecision::Approved {
            operator: Some("alice".to_string()),
        });
        let (tx, rx) = oneshot::channel();
        let request = ApprovalRequest {
            hostname: "node-1".to_string(),
            profile: TrustProfile::MyTeam,
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
            profile: TrustProfile::JustMe,
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
