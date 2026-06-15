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

/// The cross-domain integration-trait bridges (moved from the binary's `integrations.rs`).
pub mod bridges;

/// Certmesh role-driven background loops + the enrollment-approval pump (moved from the
/// binary's `main.rs`). Shared so Windows-service and embedded daemons reach parity.
pub mod certmesh;

/// The container-runtime orchestrator: translates runtime lifecycle events into
/// mDNS/DNS/health/proxy operations (moved from the binary's `orchestrator.rs`). Shared so
/// Windows-service and embedded daemons can spawn it too.
pub mod orchestrator;

// Further modules are filled in across the remaining P07 checkpoint steps:
//   status      — assemble_capabilities (the single capability-status source)
//   cores       — init_cores + ordered_shutdown

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
        Arc::new(koi_certmesh::CertmeshCore::uninitialized_with_paths(paths))
    }

    fn test_runtime() -> Arc<koi_runtime::RuntimeCore> {
        // Constructed but never `start_watching`'d — no backend connection, no network.
        Arc::new(koi_runtime::RuntimeCore::new(koi_runtime::RuntimeConfig {
            backend_kind: koi_runtime::RuntimeBackendKind::Auto,
            socket_path: None,
        }))
    }

    #[tokio::test]
    async fn certmesh_role_loops_spawn_four_tasks_regardless_of_mdns() {
        // renewal + roster sync + heartbeat + failover = 4, whether or not mDNS is present
        // (failover is still spawned with mDNS=None; it exits early internally).
        let certmesh = test_certmesh();
        let cancel = CancellationToken::new();
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        crate::certmesh::spawn_certmesh_background_tasks(
            &certmesh, None, 5641, &cancel, &mut tasks,
        );
        assert_eq!(tasks.len(), 4, "expected the 4 certmesh role loops");

        cancel.cancel();
        for task in tasks {
            let _ = task.await;
        }
    }

    #[tokio::test]
    async fn windows_parity_full_task_inventory() {
        // Mirror the exact spawn sequence windows.rs run_service now uses with certmesh +
        // runtime enabled: 1 approval pump + 4 certmesh role loops + 1 orchestrator = 6.
        let certmesh = test_certmesh();
        let runtime = test_runtime();
        let cancel = CancellationToken::new();
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        crate::certmesh::spawn_enrollment_approval(
            &certmesh,
            crate::certmesh::deny_and_log_decider(),
            &cancel,
            &mut tasks,
        )
        .await;
        crate::certmesh::spawn_certmesh_background_tasks(
            &certmesh, None, 5641, &cancel, &mut tasks,
        );
        tasks.push(crate::orchestrator::spawn_orchestrator(
            &runtime,
            crate::orchestrator::OrchestrationTargets {
                mdns: None,
                dns: None,
                health: None,
                proxy: None,
            },
            cancel.clone(),
        ));

        assert_eq!(
            tasks.len(),
            6,
            "Windows parity: 1 approval + 4 certmesh loops + 1 orchestrator"
        );

        cancel.cancel();
        for task in tasks {
            let _ = task.await;
        }
    }
}
