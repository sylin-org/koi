mod acme;
mod lab;
mod model;
mod putty;
mod story;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::lab::Lab;
use crate::model::{RunId, TrustRotation};

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
