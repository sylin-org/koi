mod acme;
mod derived;
mod evidence;
mod lab;
mod model;
mod probe;
mod profile;
mod profile_journal;
mod putty;
mod runtime_reconnect;
mod service_lifecycle;
mod soak;
mod story;
mod webhook_fanout;

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use crate::lab::Lab;
use crate::model::{LabProfile, RunId, TrustRotation};
use crate::profile::ProfileOptions;

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
