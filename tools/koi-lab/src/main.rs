mod acme;
mod certmesh_lifecycle_windows_ca;
mod certmesh_recovery_windows;
mod derived;
mod evidence;
mod installed_service;
mod installed_service_openrc;
mod installed_service_process;
mod installed_service_systemd;
#[cfg(windows)]
mod installed_service_windows;
mod lab;
mod mgmt_principal;
mod model;
mod planner;
mod probe;
mod profile;
mod profile_journal;
mod putty;
mod runtime_reconnect;
mod service_lifecycle;
mod service_lifecycle_windows;
mod soak;
mod story;
mod webhook_fanout;
mod windows_acme;
mod windows_breadth;
mod windows_daemon;
mod windows_mdns;
mod windows_proxy;
mod windows_webhook;

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use crate::installed_service::{InstalledServiceOptions, ObserverKind};
use crate::lab::Lab;
use crate::model::{LabProfile, RunId, TrustRotation};
use crate::profile::ProfileOptions;

#[cfg(not(windows))]
const DEFAULT_INSTALLED_SERVICE_OBSERVER: &str = "systemd";
#[cfg(windows)]
const DEFAULT_INSTALLED_SERVICE_OBSERVER: &str = "windows-scm";
#[cfg(not(windows))]
const DEFAULT_INSTALLED_SERVICE_NAME: &str = "koi.service";
#[cfg(windows)]
const DEFAULT_INSTALLED_SERVICE_NAME: &str = "koi";
#[cfg(not(windows))]
const DEFAULT_INSTALLED_BINARY: &str = "/usr/local/bin/koi";
#[cfg(windows)]
const DEFAULT_INSTALLED_BINARY: &str = r"C:\Program Files\Koi\koi.exe";

#[derive(Debug, Parser)]
#[command(
    name = "koi-lab",
    about = "Run-scoped controller for Koi's dedicated physical test lab"
)]
struct Cli {
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,

    #[arg(long, default_value = "tools/koi-lab/lab.json")]
    config: PathBuf,

    #[command(subcommand)]
    command: LabCommand,
}

#[derive(Debug, Subcommand)]
enum LabCommand {
    /// Inventory every node without changing remote state.
    Preflight,
    /// Build Windows and static Linux releases locally (Linux via cross + Docker).
    Build,
    /// Lock both Linux nodes and stage one verified artifact in a run directory.
    Deploy {
        /// Reuse this local artifact instead of the configured release path.
        #[arg(long)]
        artifact: Option<PathBuf>,
    },
    /// Run a non-privileged role-based certmesh smoke from Windows.
    CertmeshSmoke {
        #[arg(long)]
        run_id: String,
        #[arg(long, value_enum, default_value = "linux-forward")]
        rotation: TrustRotation,
    },
    /// Exercise role-based native trust install, TLS verification, and exact removal.
    CertmeshNativeTrust {
        #[arg(long)]
        run_id: String,
        /// Acknowledge temporary mutation of a dedicated node's system trust store.
        #[arg(long)]
        allow_system_mutation: bool,
        #[arg(long, value_enum, default_value = "linux-forward")]
        rotation: TrustRotation,
    },
    /// Exercise member custody, renewal, restart, pinning, and revocation boundaries.
    CertmeshLifecycle {
        #[arg(long)]
        run_id: String,
        #[arg(long, value_enum, default_value = "linux-forward")]
        rotation: TrustRotation,
    },
    /// Exercise encrypted backup, run-scoped data loss, restore, restart, and renewal.
    CertmeshRecovery {
        #[arg(long)]
        run_id: String,
        #[arg(long, value_enum, default_value = "linux-forward")]
        rotation: TrustRotation,
    },
    /// Exercise physical DNS, mDNS, Docker orchestration, health, UDP, and aggregation.
    CapabilityStory {
        #[arg(long)]
        run_id: String,
        /// Acknowledge temporary mutation of the native client's system trust store.
        #[arg(long)]
        allow_system_mutation: bool,
        #[arg(long, value_enum, default_value = "linux-forward")]
        rotation: TrustRotation,
    },
    /// Interrupt only Koi's run-owned Docker API relay and prove exact reconnect deltas.
    RuntimeReconnect {
        #[arg(long)]
        run_id: String,
        #[arg(long, value_enum, default_value = "linux-forward")]
        rotation: TrustRotation,
    },
    /// Prove cross-host webhook fan-out: signed delivery to a run-owned sink fixture.
    WebhookFanout {
        #[arg(long)]
        run_id: String,
        #[arg(long, value_enum, default_value = "linux-forward")]
        rotation: TrustRotation,
    },
    /// Prove principal identity end-to-end over the physical management plane (ADR-026).
    MgmtPrincipal {
        #[arg(long)]
        run_id: String,
        #[arg(long, value_enum, default_value = "linux-forward")]
        rotation: TrustRotation,
        /// Explicit catalog assignment overriding the rotation mapping:
        /// machine to enroll FROM (runs the CA-side daemon).
        #[arg(long)]
        primary: Option<String>,
        /// Explicit catalog assignment: machine that plays the principal's
        /// probe (stages the identity and dials the management plane).
        #[arg(long)]
        probe: Option<String>,
    },
    /// W4 (ADR-032): Windows-hosted CA rotation — a physical Linux member
    /// enrolls, renews, and is revoked against a CA daemon on this workstation.
    CertmeshLifecycleWindowsCa {
        #[arg(long)]
        run_id: String,
        /// Member node id (must be a physical Linux node with the member role).
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// W6+W9 (ADR-032): Windows-hosted serving lane — DNS on the standard
    /// port plus cross-host health checks in both directions.
    WindowsBreadth {
        #[arg(long)]
        run_id: String,
        /// Member node id (physical Linux verifier and health target).
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// W5 (ADR-032): mDNS announce/browse from Windows over the real LAN.
    WindowsMdns {
        #[arg(long)]
        run_id: String,
        /// Member node id (physical Linux discoverer/announcer).
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// W7 (ADR-032): TLS proxy serving ON Windows, verified by Schannel AND
    /// openssl from Linux over the real LAN.
    WindowsProxy {
        #[arg(long)]
        run_id: String,
        /// CA host node id (physical Linux ca-role host).
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// W8 (ADR-032): webhook origin ON Windows, sink on the Linux member,
    /// HMAC verified at receive.
    WindowsWebhook {
        #[arg(long)]
        run_id: String,
        /// Sink host node id (physical Linux node).
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// W12 (ADR-032): ACME dns-01 with the Windows daemon as the RFC 8555
    /// server, TXT served through its own DNS runtime.
    WindowsAcme {
        #[arg(long)]
        run_id: String,
        /// Observer node id (physical Linux node).
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// Exercise encrypted backup, exact Windows-side data loss, restore, and
    /// identity continuity with the CA hosted on the workstation (ADR-032 W10).
    CertmeshRecoveryWindows {
        #[arg(long)]
        run_id: String,
        /// Member node id (physical Linux node).
        #[arg(long)]
        member: Option<String>,
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// Prove SCM service supervision on this Windows workstation (ADR-032 W1).
    ServiceLifecycleWindows {
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// List every two-role assignment the catalog planner generates.
    Pairings {
        /// Role played by the first machine (e.g. "ca", "principal").
        #[arg(long)]
        primary_role: String,
        /// Role played by the second machine (e.g. "member", "sink").
        #[arg(long)]
        secondary_role: String,
    },
    /// Prove run-owned systemd readiness, supervision, reconstruction, and removal on Brook.
    ServiceLifecycle {
        #[arg(long)]
        run_id: String,
        /// Acknowledge the temporary run-owned transient systemd unit.
        #[arg(long)]
        allow_system_mutation: bool,
    },
    /// Repeat container derivation/reversal with periodic daemon restarts under hard bounds.
    BoundedSoak {
        #[arg(long)]
        run_id: String,
        #[arg(long, default_value_t = 20)]
        iterations: u32,
        #[arg(long, default_value_t = 15)]
        max_minutes: u32,
        /// Restart Koi with a live container every N iterations; zero disables restarts.
        #[arg(long, default_value_t = 5)]
        restart_every: u32,
    },
    /// Sample one real installed service and a semantic physical-peer Koi surface.
    InstalledServiceCollect {
        #[arg(long)]
        run_id: String,
        /// Native installed-service observer for the service manager under test.
        #[arg(long, value_enum, default_value = DEFAULT_INSTALLED_SERVICE_OBSERVER)]
        observer: ObserverKind,
        #[arg(long, default_value = DEFAULT_INSTALLED_SERVICE_NAME)]
        service: String,
        #[arg(long, default_value = DEFAULT_INSTALLED_BINARY)]
        binary: PathBuf,
        #[arg(long, default_value_t = 30)]
        duration_seconds: u64,
        #[arg(long, default_value_t = 5)]
        sample_interval_seconds: u64,
        /// Maximum expected system-service restart delta during this collection.
        #[arg(long, default_value_t = 0)]
        max_service_restarts: u64,
        /// Maximum samples whose essential service/product observation may be unavailable.
        #[arg(long, default_value_t = 0)]
        max_unavailable_samples: u64,
        /// Maximum consecutive unavailable essential observations.
        #[arg(long, default_value_t = 0)]
        max_consecutive_unavailable_samples: u64,
        #[arg(long, default_value_t = 67_108_864)]
        max_rss_growth_bytes: u64,
        #[arg(long, default_value_t = 16)]
        max_descriptor_growth: u64,
        #[arg(long, default_value_t = 8)]
        max_thread_growth: u64,
        #[arg(long, default_value_t = 8)]
        max_task_growth: u64,
        /// Human-readable provenance label for the independently installed Koi peer.
        #[arg(long)]
        peer_label: String,
        /// Root URL returned by an independently installed peer's Koi Pond surface.
        #[arg(long)]
        peer_surface: String,
    },
    /// Run an unattended deploy/scenario/cleanup policy with aggregate evidence.
    RunProfile {
        #[arg(value_enum)]
        profile: LabProfile,
        /// Reuse this local artifact for every fresh deployment in the profile.
        #[arg(long)]
        artifact: Option<PathBuf>,
        /// Acknowledge native trust and transient service mutations in the full profile.
        #[arg(long)]
        allow_system_mutation: bool,
        /// Override the soak profile's iteration count.
        #[arg(long)]
        iterations: Option<u32>,
        /// Override the soak profile's time bound.
        #[arg(long)]
        max_minutes: Option<u32>,
        /// Override the soak profile's live-container restart cadence; zero disables it.
        #[arg(long)]
        restart_every: Option<u32>,
    },
    /// Recover a stale interrupted profile using exact journal-owned run IDs.
    RecoverProfile,
    /// Show exactly what cleanup would remove; never changes state.
    PlanCleanup {
        #[arg(long)]
        run_id: String,
    },
    /// Remove only state owned by this exact run, then release both locks.
    Cleanup {
        #[arg(long)]
        run_id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let lab = Lab::load(&cli.repo_root, &cli.config)?;
    match cli.command {
        LabCommand::Preflight => {
            let report = lab.preflight()?;
            let path = lab.write_preflight(&report)?;
            print_json(&report)?;
            eprintln!("preflight report: {}", path.display());
        }
        LabCommand::Build => {
            print_json(&lab.build_release()?)?;
        }
        LabCommand::Deploy { artifact } => {
            let manifest = lab.deploy(artifact.as_deref())?;
            print_json(&manifest)?;
            eprintln!(
                "run {} owns both remote lab locks until cleanup",
                manifest.run_id.as_str()
            );
        }
        LabCommand::CertmeshSmoke { run_id, rotation } => {
            print_json(&lab.certmesh_smoke(&RunId::parse(&run_id)?, rotation)?)?;
        }
        LabCommand::CertmeshNativeTrust {
            run_id,
            allow_system_mutation,
            rotation,
        } => {
            print_json(&lab.certmesh_native_trust(
                &RunId::parse(&run_id)?,
                allow_system_mutation,
                rotation,
            )?)?;
        }
        LabCommand::CertmeshLifecycle { run_id, rotation } => {
            print_json(&lab.certmesh_lifecycle(&RunId::parse(&run_id)?, rotation)?)?;
        }
        LabCommand::CertmeshRecovery { run_id, rotation } => {
            print_json(&lab.certmesh_recovery(&RunId::parse(&run_id)?, rotation)?)?;
        }
        LabCommand::CapabilityStory {
            run_id,
            allow_system_mutation,
            rotation,
        } => {
            print_json(&lab.capability_story(
                &RunId::parse(&run_id)?,
                allow_system_mutation,
                rotation,
            )?)?;
        }
        LabCommand::RuntimeReconnect { run_id, rotation } => {
            print_json(&lab.runtime_reconnect(&RunId::parse(&run_id)?, rotation)?)?;
        }
        LabCommand::WebhookFanout { run_id, rotation } => {
            print_json(&lab.webhook_fanout(&RunId::parse(&run_id)?, rotation)?)?;
        }
        LabCommand::MgmtPrincipal {
            run_id,
            rotation,
            primary,
            probe,
        } => {
            if (primary.is_some()) != (probe.is_some()) {
                anyhow::bail!("--primary and --probe must be supplied together");
            }
            print_json(&lab.mgmt_principal(
                &RunId::parse(&run_id)?,
                rotation,
                primary.as_deref(),
                probe.as_deref(),
            )?)?;
        }
        LabCommand::CertmeshLifecycleWindowsCa {
            run_id,
            member,
            allow_system_mutation,
        } => {
            print_json(&lab.certmesh_lifecycle_windows_ca(
                &RunId::parse(&run_id)?,
                member.as_deref(),
                allow_system_mutation,
            )?)?;
        }
        LabCommand::WindowsBreadth {
            run_id,
            member,
            allow_system_mutation,
        } => {
            print_json(&lab.windows_breadth(
                &RunId::parse(&run_id)?,
                member.as_deref(),
                allow_system_mutation,
            )?)?;
        }
        LabCommand::WindowsMdns {
            run_id,
            member,
            allow_system_mutation,
        } => {
            print_json(&lab.windows_mdns(
                &RunId::parse(&run_id)?,
                member.as_deref(),
                allow_system_mutation,
            )?)?;
        }
        LabCommand::WindowsProxy {
            run_id,
            member,
            allow_system_mutation,
        } => {
            print_json(&lab.windows_proxy(
                &RunId::parse(&run_id)?,
                member.as_deref(),
                allow_system_mutation,
            )?)?;
        }
        LabCommand::WindowsWebhook {
            run_id,
            member,
            allow_system_mutation,
        } => {
            print_json(&lab.windows_webhook(
                &RunId::parse(&run_id)?,
                member.as_deref(),
                allow_system_mutation,
            )?)?;
        }
        LabCommand::WindowsAcme {
            run_id,
            member,
            allow_system_mutation,
        } => {
            print_json(&lab.windows_acme(
                &RunId::parse(&run_id)?,
                member.as_deref(),
                allow_system_mutation,
            )?)?;
        }
        LabCommand::CertmeshRecoveryWindows {
            run_id,
            member,
            allow_system_mutation,
        } => {
            print_json(&lab.certmesh_recovery_windows(
                &RunId::parse(&run_id)?,
                member.as_deref(),
                allow_system_mutation,
            )?)?;
        }
        LabCommand::ServiceLifecycleWindows {
            run_id,
            allow_system_mutation,
        } => {
            print_json(
                &lab.service_lifecycle_windows(&RunId::parse(&run_id)?, allow_system_mutation)?,
            )?;
        }
        LabCommand::Pairings {
            primary_role,
            secondary_role,
        } => {
            print_json(&crate::planner::pairings(
                lab.config(),
                &primary_role,
                &secondary_role,
            ))?;
        }
        LabCommand::ServiceLifecycle {
            run_id,
            allow_system_mutation,
        } => {
            print_json(&lab.service_lifecycle(&RunId::parse(&run_id)?, allow_system_mutation)?)?;
        }
        LabCommand::BoundedSoak {
            run_id,
            iterations,
            max_minutes,
            restart_every,
        } => {
            print_json(&lab.bounded_soak(
                &RunId::parse(&run_id)?,
                iterations,
                max_minutes,
                restart_every,
            )?)?;
        }
        LabCommand::InstalledServiceCollect {
            run_id,
            observer,
            service,
            binary,
            duration_seconds,
            sample_interval_seconds,
            max_service_restarts,
            max_unavailable_samples,
            max_consecutive_unavailable_samples,
            max_rss_growth_bytes,
            max_descriptor_growth,
            max_thread_growth,
            max_task_growth,
            peer_label,
            peer_surface,
        } => {
            let report = lab.installed_service_collect(
                &RunId::parse(&run_id)?,
                &InstalledServiceOptions {
                    observer,
                    service_name: service,
                    binary_path: binary,
                    duration_seconds,
                    sample_interval_seconds,
                    max_service_restarts,
                    max_unavailable_samples,
                    max_consecutive_unavailable_samples,
                    max_rss_growth_bytes,
                    max_descriptor_growth,
                    max_thread_growth,
                    max_task_growth,
                    peer_label,
                    peer_surface,
                },
            )?;
            let passed = report.checks.iter().all(|check| check.passed);
            print_json(&report)?;
            if !passed {
                bail!("installed-service collection produced a red verdict");
            }
        }
        LabCommand::RunProfile {
            profile,
            artifact,
            allow_system_mutation,
            iterations,
            max_minutes,
            restart_every,
        } => {
            let execution = lab.run_profile(
                profile,
                ProfileOptions {
                    artifact,
                    allow_system_mutation,
                    soak_iterations: iterations,
                    soak_max_minutes: max_minutes,
                    soak_restart_every: restart_every,
                },
            )?;
            print_json(&execution.report)?;
            eprintln!("profile evidence: {}", execution.evidence_path.display());
            if !execution.succeeded {
                bail!(
                    "{} profile failed; exact evidence was preserved",
                    profile.as_str()
                );
            }
        }
        LabCommand::RecoverProfile => {
            let execution = lab.recover_profile()?;
            print_json(&execution.report)?;
            if let Some(path) = execution.evidence_path {
                eprintln!("profile recovery evidence: {}", path.display());
            }
            if !execution.succeeded {
                bail!("interrupted profile recovery refused or failed");
            }
        }
        LabCommand::PlanCleanup { run_id } => {
            print_json(&lab.cleanup_plan(&RunId::parse(&run_id)?)?)?;
        }
        LabCommand::Cleanup { run_id } => {
            print_json(&lab.cleanup(&RunId::parse(&run_id)?)?)?;
        }
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
