//! Koi composition layer — the single place that constructs domain cores, installs the
//! cross-domain integration bridges, runs the container orchestrator, assembles
//! capability status, and tears everything down in order.
//!
//! Three consumers share it: the `koi` daemon (`daemon_mode`), the Windows service
//! (`run_service`), and `koi-embedded`. Building the composition once makes Windows and
//! embedded parity true *by construction* — the verified `koi install` defect (a weaker
//! Windows daemon missing the orchestrator + certmesh background loops) cannot recur,
//! because all three call the same code.
//!
//! This is a **composition crate**, not a domain crate: it depends on every domain it
//! wires. Nothing depends on it except the top-level consumers, so the `koi-common`
//! kernel and the domain crates keep clean dependency closures.

/// Per-host mDNS announce records (`_http._tcp` self-announcement with the ADR-020 trust
/// stamp, `_mcp._tcp` transport descriptor) shared by the daemon, the Windows service, and
/// embedded so the stamp is present by construction on every boot path.
pub mod announce;

/// Immutable machine identity captured once and injected into every adapter
/// that renders or publishes it.
pub mod host;

/// Platform mDNS catalog: the domain supervisor probes real adapters and owns
/// capability-aware runtime selection and transitions.
pub mod mdns;

/// The posture-reactive self-announce supervisor: keeps the `_http._tcp` posture stamp current
/// across Open↔Authenticated flips and owns the `_mcp._tcp` lifecycle. Spawned identically by
/// all three boot paths (mirrors the trust-plane's `_certmesh._tcp` reactivity).
pub mod self_announce;

/// The cross-domain integration-trait bridges (moved from the binary's `integrations.rs`).
pub mod bridges;

/// Certmesh role-driven background loops + the enrollment-approval pump (moved from the
/// binary's `main.rs`). Shared so Windows-service and embedded daemons reach parity.
pub mod certmesh;

/// Cross-domain Device/Service/Endpoint catalog and its owned observer.
pub mod catalog;

/// Reactive desired-state bridge from Certmesh's authoritative CA anchor to
/// the independently owned OS Trust domain.
pub mod trust;

/// The container-runtime orchestrator: translates runtime lifecycle events into
/// mDNS/DNS/health/proxy operations (moved from the binary's `orchestrator.rs`). Shared so
/// Windows-service and embedded daemons can spawn it too.
pub mod orchestrator;

/// Daemon core composition: `build_cores` (the one core+bridge construction graph the
/// daemon and the Windows service share), `init_certmesh_core`, and `ordered_shutdown`.
pub mod cores;

/// Outbound webhook fan-out (ADR-028): HMAC-signed delivery of the merged event
/// stream to operator-declared sinks. Composition-layer adapter, not a domain.
pub mod webhook;

/// Observable product status (`KoiStatus`) — the single capability ladder shared by
/// `/v1/status`, the dashboard snapshot, MCP, and the embedded facade.
pub mod status;

/// The rich dashboard snapshot (`build_dashboard_snapshot`) — the one detail projection of
/// an already-captured `KoiStatus` shared by the daemon and embedded dashboard adapters.
pub mod snapshot;

#[cfg(test)]
mod parity_tests {
    //! Acceptance proof for the `koi install` parity fix (P07).
    //!
    //! The Windows service (`run_service`) and the foreground daemon (`daemon_mode`) now
    //! spawn certmesh background tasks + the orchestrator through these exact composition
    //! functions. Asserting the spawned-task inventory here — with no SCM and no network —
    //! proves Windows gets the same task set the daemon does (the verified defect was a
    //! structurally weaker Windows daemon missing precisely these tasks).

    use std::sync::Arc;

    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    fn test_certmesh() -> Arc<koi_certmesh::CertmeshCore> {
        let dir = std::env::temp_dir().join(format!("koi-compose-parity-{}", std::process::id()));
        let paths = koi_certmesh::CertmeshPaths::with_data_dir(dir);
        Arc::new(
            koi_certmesh::CertmeshCore::uninitialized_with_paths(paths)
                .with_local_hostname("compose-parity-host")
                .expect("configure test host identity"),
        )
    }

    fn test_runtime() -> Arc<koi_runtime::RuntimeCore> {
        // Constructed but never `start_watching`'d — no backend connection, no network.
        Arc::new(koi_runtime::RuntimeCore::new(koi_runtime::RuntimeConfig {
            backend_kind: koi_runtime::RuntimeBackendKind::Auto,
            socket_path: None,
        }))
    }

    #[tokio::test]
    async fn certmesh_role_loops_spawn_owned_renewal_and_status_clocks() {
        // ADR-017 F6: one member-pull renewal loop. CA failover is manual
        // (`koi certmesh promote`) and the old broken health-heartbeat loop was
        // removed. ADR-043 adds Certmesh's own deadline-aware status clock.
        let certmesh = test_certmesh();
        let cancel = CancellationToken::new();
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        crate::certmesh::spawn_certmesh_background_tasks(&certmesh, &cancel, &mut tasks, true);
        assert_eq!(
            tasks.len(),
            2,
            "expected renewal and deadline-aware status loops"
        );

        cancel.cancel();
        for task in tasks {
            let _ = task.await;
        }
    }

    #[tokio::test]
    async fn self_managed_certmesh_still_runs_its_authoritative_status_clock() {
        let certmesh = test_certmesh();
        let cancel = CancellationToken::new();
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        crate::certmesh::spawn_certmesh_background_tasks(&certmesh, &cancel, &mut tasks, false);
        assert_eq!(
            tasks.len(),
            1,
            "manual renewal must disable maintenance, not deadline observation"
        );

        cancel.cancel();
        for task in tasks {
            let _ = task.await;
        }
    }

    #[tokio::test]
    async fn windows_parity_full_task_inventory() {
        // Mirror the exact spawn sequence windows.rs run_service now uses with certmesh +
        // runtime enabled: 1 approval pump + 2 certmesh loops + 1 orchestrator = 4.
        let certmesh = test_certmesh();
        let runtime = test_runtime();
        let cancel = CancellationToken::new();
        let owner = crate::cores::RunningCores::default();
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        crate::certmesh::spawn_enrollment_approval(
            &certmesh,
            crate::certmesh::deny_and_log_decider(),
            &cancel,
            &owner,
        )
        .await;
        crate::certmesh::spawn_certmesh_background_tasks(&certmesh, &cancel, &mut tasks, true);
        tasks.push(crate::orchestrator::spawn_orchestrator(
            &runtime,
            crate::orchestrator::OrchestrationTargets {
                mdns: None,
                dns: None,
                health: None,
                proxy: None,
            },
            None,
            cancel.clone(),
        ));
        owner.own_tasks(tasks);

        assert_eq!(
            owner.owned_task_count(),
            4,
            "Windows parity: 1 approval + 2 certmesh loops + 1 orchestrator"
        );

        crate::cores::ordered_shutdown(
            &cancel,
            &owner,
            std::time::Duration::from_secs(2),
            std::time::Duration::ZERO,
        )
        .await;
    }
}
