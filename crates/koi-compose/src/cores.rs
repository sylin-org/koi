//! Daemon core composition — the single place that constructs every domain core, wires the
//! cross-domain integration bridges between them, spawns the domain background tasks
//! (orchestrator + certmesh role loops), and tears it all down in order.
//!
//! Before P07 this graph was hand-written twice — in the binary's `daemon_mode` and again
//! in the Windows service's `run_service` — and the two had already drifted into a verified
//! `koi install` defect. [`build_cores`] is now the one copy both call, so the daemon they
//! construct is identical by construction.
//!
//! The enrollment-approval pump is intentionally *not* spawned here: its decider differs by
//! host (the foreground daemon prompts on stdin; consoleless hosts deny). The caller spawns
//! it via [`crate::certmesh::spawn_enrollment_approval`].

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_common::integration::{
    AliasFeedback, CertmeshSnapshot, DnsProbe, MdnsSnapshot, ProxySnapshot,
};

/// The set of domain cores a daemon runs. Each is present only if its capability is enabled
/// (via the `no_*` flags in [`CoreSpec`]).
#[derive(Clone, Default)]
pub struct Cores {
    pub mdns: Option<Arc<koi_mdns::MdnsCore>>,
    pub certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    pub dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub health: Option<Arc<koi_health::HealthRuntime>>,
    pub proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    pub udp: Option<Arc<koi_udp::UdpRuntime>>,
    pub runtime: Option<Arc<koi_runtime::RuntimeCore>>,
    /// The shared mDNS cached-records snapshot bridge (same instance DNS/health
    /// consume). Exposed so presentation adapters (e.g. the Prometheus SD endpoint's
    /// `?include=discovered` slice) can read cached records without spawning a second
    /// meta-browse. `None` when mDNS is disabled.
    pub mdns_snapshot: Option<Arc<dyn MdnsSnapshot>>,
}

/// Capability flags + inputs needed to build the cores. A daemon-`Config` subset, kept here
/// (rather than depending on the binary's `Config`) so koi-compose stays standalone.
pub struct CoreSpec {
    pub no_mdns: bool,
    pub no_certmesh: bool,
    pub no_dns: bool,
    pub no_health: bool,
    pub no_proxy: bool,
    pub no_udp: bool,
    pub no_runtime: bool,
    /// Data directory for certmesh state (resolved by the caller).
    pub data_dir: std::path::PathBuf,
    /// DNS configuration (the caller's resolved `DnsConfig`).
    pub dns_config: koi_dns::DnsConfig,
    /// Runtime backend selector string ("auto", "docker", "podman", …).
    pub runtime: String,
    /// Daemon HTTP port (the local management/API port the daemon binds).
    pub http_port: u16,
}

/// Initialize the certmesh core, auto-unlocking from the vault when a key is present.
///
/// Always returns `Some` (so HTTP routes mount even before `koi certmesh create`):
/// - CA not initialized → an uninitialized core (routes reachable for `/create`);
/// - CA initialized + a vault auto-unlock key present → booted **already unlocked**,
///   collapsing the old "create locked → read key → unlock" three-step;
/// - CA initialized + no key (or decryption fails) → a locked core.
///
/// This is the converged single definition shared by the daemon, the Windows service, and
/// koi-embedded (the daemon path thereby gains the vault auto-unlock embedded already had).
pub fn init_certmesh_core(data_dir: Option<&Path>) -> Option<Arc<koi_certmesh::CertmeshCore>> {
    // Composition root: resolve the data dir once (Some -> injected dir, None -> the one
    // default) and thread it into every branch so a custom data_dir is honoured end-to-end,
    // including the early returns.
    let paths = koi_certmesh::CertmeshPaths::with_data_dir(
        koi_common::paths::koi_data_dir_with_override(data_dir),
    );
    if !paths.is_ca_initialized() {
        tracing::info!("Certmesh: CA not initialized - routes mounted for /create");
        return Some(Arc::new(
            koi_certmesh::CertmeshCore::uninitialized_with_paths(paths),
        ));
    }

    let roster_path = paths.roster_path();
    let roster = match koi_certmesh::roster::load_roster(&roster_path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to load certmesh roster - using uninitialized state");
            return Some(Arc::new(
                koi_certmesh::CertmeshCore::uninitialized_with_paths(paths),
            ));
        }
    };

    // ── F11 machine binding: refuse auto-unlock on a changed host ───────
    // Checked BEFORE reading the vault key so a VM clone / disk restore onto new
    // hardware (different machine-id) boots LOCKED instead of auto-unlocking with
    // the copied vault key. Fail-safe + audited; a legitimate migration recovers
    // with a one-time manual `koi certmesh unlock`.
    let machine_ok = koi_certmesh::machine_binding_ok(&paths);
    if !machine_ok {
        let _ = koi_certmesh::audit::append_entry_to(
            &paths.audit_log_path(),
            "auto_unlock_refused_machine_changed",
            &[],
        );
        tracing::error!(
            "Certmesh: machine fingerprint changed since CA creation (clone/restore?) — \
             booting LOCKED; run `koi certmesh unlock` to unlock manually on this host"
        );
    }

    // ── Auto-unlock at init: single source of truth ─────────────
    // The auto-unlock passphrase lives in the koi-crypto vault (written by
    // CertmeshCore::save_auto_unlock_key_at, which deletes any legacy plaintext file).
    // Retrieve it through the domain crate so this boot path can never drift from where the
    // key is actually stored. When a key is present, boot the core already unlocked.
    if machine_ok {
        if let Ok(Some(pp)) = koi_certmesh::CertmeshCore::read_auto_unlock_key(&paths) {
            match koi_certmesh::ca::load_ca(&pp, &paths) {
                Ok(ca_state) => {
                    // Reload roster (fresh copy for the new Arc)
                    if let Ok(fresh_roster) = koi_certmesh::roster::load_roster(&roster_path) {
                        let auth_path = paths.auth_path();
                        let auth = if auth_path.exists() {
                            std::fs::read_to_string(&auth_path)
                                .ok()
                                .and_then(|json| {
                                    serde_json::from_str::<koi_crypto::auth::StoredAuth>(&json).ok()
                                })
                                .and_then(|stored| stored.unlock(&pp).ok())
                        } else {
                            None
                        };

                        tracing::info!("Certmesh CA auto-unlocked at init from vault");
                        return Some(Arc::new(koi_certmesh::CertmeshCore::new_with_paths(
                            ca_state,
                            fresh_roster,
                            auth,
                            paths,
                        )));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Auto-unlock key exists in vault but CA decryption failed"
                    );
                }
            }
        }
    }

    // No auto-unlock key - boot locked
    tracing::info!("Certmesh: CA initialized (locked, use `koi certmesh unlock` to decrypt)");
    let core = koi_certmesh::CertmeshCore::locked_with_paths(roster, paths);
    Some(Arc::new(core))
}

/// Build all domain cores + cross-domain bridges, then spawn the caller-invariant domain
/// background tasks: the runtime orchestrator (when runtime is enabled) and the certmesh
/// role loops (when certmesh is enabled). Returns the assembled [`Cores`].
///
/// The bridges are wired in dependency order: DNS consumes the mDNS/certmesh/alias bridges;
/// health consumes the mDNS/DNS/certmesh/proxy bridges. Disabled capabilities pass `None`.
pub async fn build_cores(
    spec: &CoreSpec,
    cancel: &CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) -> Cores {
    // ── mDNS ──
    let mdns_core = if !spec.no_mdns {
        match koi_mdns::MdnsCore::with_cancel(cancel.clone()) {
            Ok(core) => Some(Arc::new(core)),
            Err(e) => {
                tracing::error!(error = %e, "Failed to initialize mDNS core");
                None
            }
        }
    } else {
        tracing::info!("mDNS capability: disabled");
        None
    };

    // ── Certmesh ──
    let certmesh_core = if !spec.no_certmesh {
        init_certmesh_core(Some(&spec.data_dir))
    } else {
        tracing::info!("Certmesh capability: disabled");
        None
    };

    // ── Integration bridges ──
    // These wrap domain cores and implement cross-domain traits from koi_common::integration.
    let mdns_bridge: Option<Arc<dyn MdnsSnapshot>> = if let Some(ref core) = mdns_core {
        Some(crate::bridges::MdnsBridge::spawn(core.clone()).await)
    } else {
        None
    };

    let certmesh_bridge: Option<Arc<dyn CertmeshSnapshot>> = certmesh_core
        .as_ref()
        .map(|core| crate::bridges::CertmeshBridge::new(core.clone()) as Arc<dyn CertmeshSnapshot>);

    let alias_feedback: Option<Arc<dyn AliasFeedback>> = certmesh_core.as_ref().map(|core| {
        crate::bridges::AliasFeedbackBridge::new(core.clone()) as Arc<dyn AliasFeedback>
    });

    // ── DNS (consumes mdns + certmesh + alias bridges) ──
    let dns_runtime = if !spec.no_dns {
        let core = koi_dns::DnsCore::new(
            spec.dns_config.clone(),
            mdns_bridge.clone(),
            certmesh_bridge.clone(),
            alias_feedback,
        )
        .await;
        match core {
            Ok(core) => {
                let runtime = Arc::new(koi_dns::DnsRuntime::new(core));
                if let Err(e) = runtime.start().await {
                    tracing::error!(error = %e, "Failed to start DNS server");
                }
                Some(runtime)
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to initialize DNS core");
                None
            }
        }
    } else {
        tracing::info!("DNS capability: disabled");
        None
    };

    // ── Proxy ──
    let proxy_runtime = if !spec.no_proxy {
        match koi_proxy::ProxyCore::new() {
            Ok(core) => {
                let runtime = Arc::new(koi_proxy::ProxyRuntime::new(Arc::new(core)));
                if let Err(e) = runtime.start_all().await {
                    tracing::error!(error = %e, "Failed to start proxy listeners");
                }
                Some(runtime)
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to initialize proxy core");
                None
            }
        }
    } else {
        tracing::info!("Proxy capability: disabled");
        None
    };

    let dns_bridge: Option<Arc<dyn DnsProbe>> = dns_runtime
        .as_ref()
        .map(|rt| crate::bridges::DnsBridge::new(rt.clone()) as Arc<dyn DnsProbe>);

    let proxy_bridge: Option<Arc<dyn ProxySnapshot>> = proxy_runtime
        .as_ref()
        .map(|rt| crate::bridges::ProxyBridge::new(rt.core()) as Arc<dyn ProxySnapshot>);

    // ── Health (consumes mdns + dns + certmesh + proxy bridges) ──
    let health_runtime = if !spec.no_health {
        let core = Arc::new(
            koi_health::HealthCore::new(
                mdns_bridge.clone(),
                dns_bridge,
                certmesh_bridge,
                proxy_bridge,
            )
            .await,
        );
        let runtime = Arc::new(koi_health::HealthRuntime::new(core));
        if let Err(e) = runtime.start().await {
            tracing::error!(error = %e, "Failed to start health checks");
        }
        Some(runtime)
    } else {
        tracing::info!("Health capability: disabled");
        None
    };

    // ── UDP ──
    let udp_runtime = if !spec.no_udp {
        Some(Arc::new(koi_udp::UdpRuntime::new(cancel.clone())))
    } else {
        tracing::info!("UDP capability: disabled");
        None
    };

    // ── Runtime adapter ──
    let runtime_core = if !spec.no_runtime {
        // No silent fallback: an unrecognized backend selector disables the
        // runtime adapter rather than quietly running Auto. The CLI rejects bad
        // values at parse time; this guards the service/env path.
        match koi_runtime::RuntimeBackendKind::from_str_loose(&spec.runtime) {
            Some(backend_kind) => {
                let rt_config = koi_runtime::RuntimeConfig {
                    backend_kind,
                    socket_path: None,
                };
                let core = Arc::new(koi_runtime::RuntimeCore::new(rt_config));
                match core.start_watching(cancel.clone()).await {
                    Ok(()) => Some(core),
                    Err(e) => {
                        tracing::warn!(error = %e, "Runtime adapter unavailable, continuing without it");
                        None
                    }
                }
            }
            None => {
                tracing::error!(
                    value = %spec.runtime,
                    accepted = ?koi_runtime::RuntimeBackendKind::ACCEPTED,
                    "Unknown runtime backend; disabling runtime adapter"
                );
                None
            }
        }
    } else {
        tracing::info!("Runtime capability: disabled");
        None
    };

    // ── Runtime orchestrator ──
    // Translates container lifecycle events into mDNS/DNS/health/proxy operations.
    if let Some(ref rt) = runtime_core {
        tasks.push(crate::orchestrator::spawn_orchestrator(
            rt,
            crate::orchestrator::OrchestrationTargets {
                mdns: mdns_core.clone(),
                dns: dns_runtime.clone(),
                health: health_runtime.clone(),
                proxy: proxy_runtime.clone(),
            },
            cancel.clone(),
        ));
    }

    let cores = Cores {
        mdns: mdns_core,
        certmesh: certmesh_core,
        dns: dns_runtime,
        health: health_runtime,
        proxy: proxy_runtime,
        udp: udp_runtime,
        runtime: runtime_core,
        mdns_snapshot: mdns_bridge,
    };

    // ── Certmesh role background loops (caller-invariant) ──
    // The approval pump is spawned by the caller (its decider differs by host).
    if let Some(ref certmesh) = cores.certmesh {
        crate::certmesh::spawn_certmesh_background_tasks(certmesh, cancel, tasks);
    }

    tracing::debug!("Domain cores built");
    cores
}

/// Ordered teardown: cancel → drain in-flight → join tasks → withdraw the HTTP mDNS
/// announcement → core goodbye (mDNS, DNS, health, proxy, UDP). Bounded by `timeout`.
pub async fn ordered_shutdown(
    cancel: &CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    cores: &Cores,
    http_announce_id: Option<String>,
    timeout: Duration,
    drain: Duration,
) {
    let shutdown = async {
        cancel.cancel();
        tokio::time::sleep(drain).await;
        for task in tasks {
            let _ = task.await;
        }
        if let Some(ref id) = http_announce_id {
            if let Some(ref core) = cores.mdns {
                if let Err(e) = core.unregister(id) {
                    tracing::warn!(error = %e, "Failed to withdraw HTTP mDNS announcement");
                }
            }
        }
        if let Some(ref core) = cores.mdns {
            if let Err(e) = core.shutdown().await {
                tracing::warn!(error = %e, "Error during mDNS shutdown");
            }
        }
        if let Some(ref dns) = cores.dns {
            dns.stop().await;
        }
        if let Some(ref health) = cores.health {
            let _ = health.stop().await;
        }
        if let Some(ref proxy) = cores.proxy {
            let _ = proxy.stop_all().await;
        }
        if let Some(ref udp) = cores.udp {
            udp.shutdown().await;
        }
    };
    if tokio::time::timeout(timeout, shutdown).await.is_err() {
        tracing::warn!("Shutdown timed out after {:?} - forcing exit", timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_certmesh::{CertmeshCore, CertmeshPaths};

    /// Regression guard for ADR-017 F11: the **real boot path** (`init_certmesh_core`,
    /// not the unused `try_auto_unlock`) must refuse to auto-unlock when the machine
    /// fingerprint changed since CA creation (a VM clone / disk restore). The fix
    /// that wires `machine_binding_ok` into this path is exactly what an earlier
    /// implementation missed — this test ensures it can't silently un-wire again.
    #[tokio::test]
    async fn init_certmesh_core_refuses_auto_unlock_on_machine_change() {
        let base = koi_common::test::ensure_data_dir("koi-compose-cores-tests").join("f11-boot");
        let _ = std::fs::remove_dir_all(&base);
        let paths = CertmeshPaths::with_data_dir(base.clone());

        // Create a CA with auto-unlock — records the vault key + machine.bind.
        let core = CertmeshCore::uninitialized_with_paths(paths.clone());
        core.create(koi_certmesh::protocol::CreateCaRequest {
            passphrase: "f11-boot-pass".into(),
            entropy_hex: "11".repeat(32),
            operator: None,
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: true,
            totp_secret_hex: None,
        })
        .await
        .expect("CA create");

        // Same host (machine.bind matches) → the boot path auto-unlocks.
        let booted = init_certmesh_core(Some(&base)).expect("core");
        assert!(
            !booted.certmesh_status().await.ca_locked,
            "matching machine binding should auto-unlock at boot"
        );

        // Simulate a clone/restore: overwrite the recorded fingerprint. The boot
        // path must now refuse auto-unlock and come up LOCKED.
        std::fs::write(paths.machine_bind_path(), b"not-this-host-fingerprint").unwrap();
        let booted_after = init_certmesh_core(Some(&base)).expect("core");
        assert!(
            booted_after.certmesh_status().await.ca_locked,
            "a changed machine fingerprint must refuse auto-unlock at boot (F11)"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
