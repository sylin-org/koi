use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{bail, Result};
use chrono::Utc;

use crate::lab::Lab;
use crate::model::{
    output_path, CheckResult, LabProfile, NodeSnapshot, PreflightReport, ProfileCaseReport,
    ProfileReport, RunId, TrustRotation,
};
use crate::soak::validate_soak_bounds;

const DEFAULT_SOAK_ITERATIONS: u32 = 20;
const DEFAULT_SOAK_MINUTES: u32 = 15;
const DEFAULT_SOAK_RESTART_EVERY: u32 = 5;

pub struct ProfileOptions {
    pub artifact: Option<PathBuf>,
    pub allow_system_mutation: bool,
    pub soak_iterations: Option<u32>,
    pub soak_max_minutes: Option<u32>,
    pub soak_restart_every: Option<u32>,
}

pub struct ProfileExecution {
    pub report: ProfileReport,
    pub evidence_path: PathBuf,
    pub succeeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileCase {
    CertmeshSmoke(TrustRotation),
    CertmeshNativeTrust(TrustRotation),
    CertmeshLifecycle(TrustRotation),
    CertmeshRecovery(TrustRotation),
    CapabilityStory(TrustRotation),
    RuntimeReconnect(TrustRotation),
    ServiceLifecycle,
    BoundedSoak,
}

impl ProfileCase {
    fn name(self) -> String {
        match self {
            Self::CertmeshSmoke(rotation) => {
                format!("certmesh-smoke-{}", rotation.as_str())
            }
            Self::CertmeshNativeTrust(rotation) => {
                format!("certmesh-native-trust-{}", rotation.as_str())
            }
            Self::CertmeshLifecycle(rotation) => {
                format!("certmesh-lifecycle-{}", rotation.as_str())
            }
            Self::CertmeshRecovery(rotation) => {
                format!("certmesh-recovery-{}", rotation.as_str())
            }
            Self::CapabilityStory(rotation) => {
                format!("capability-story-{}", rotation.as_str())
            }
            Self::RuntimeReconnect(rotation) => {
                format!("runtime-reconnect-{}", rotation.as_str())
            }
            Self::ServiceLifecycle => "service-lifecycle-linux".to_owned(),
            Self::BoundedSoak => "bounded-soak-linux".to_owned(),
        }
    }

    fn requires_system_mutation(self) -> bool {
        matches!(
            self,
            Self::CertmeshNativeTrust(_) | Self::CapabilityStory(_) | Self::ServiceLifecycle
        )
    }
}

impl Lab {
    pub fn run_profile(
        &self,
        profile: LabProfile,
        options: ProfileOptions,
    ) -> Result<ProfileExecution> {
        let cases = profile_cases(profile);
        if cases.iter().any(|case| case.requires_system_mutation())
            && !options.allow_system_mutation
        {
            bail!(
                "{} profile requires --allow-system-mutation for native trust and transient service cases",
                profile.as_str()
            );
        }
        let soak = resolve_soak_options(profile, &options)?;
        let execution_id = RunId::generate();
        let created_at = Utc::now();
        let output_dir = output_path(execution_id.as_str());

        let initial = self.preflight()?;
        self.write_json(&output_dir.join("preflight-before.json"), &initial)?;
        let mut checks = vec![phase_check(
            "preflight-before",
            initial.deploy_ready,
            "all nodes are deployment-ready",
            "initial preflight reported deployment blockers",
        )];
        let mut case_reports = Vec::new();
        let mut failed = !initial.deploy_ready;

        if !failed {
            for case in cases {
                let case_name = case.name();
                let manifest = match self.deploy(options.artifact.as_deref()) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        eprintln!("profile case {case_name} deployment failed: {error:#}");
                        checks.push(phase_check(
                            &format!("{case_name}.deploy"),
                            false,
                            "run-owned artifact deployed",
                            "deployment failed; partial deployment rollback was requested",
                        ));
                        case_reports.push(ProfileCaseReport {
                            name: case_name,
                            run_id: None,
                            deployment_passed: false,
                            scenario_passed: false,
                            cleanup_passed: false,
                        });
                        failed = true;
                        break;
                    }
                };
                let run_id = manifest.run_id.clone();
                checks.push(phase_check(
                    &format!("{case_name}.deploy"),
                    true,
                    "run-owned artifact deployed and verified on both Linux nodes",
                    "deployment failed",
                ));

                let scenario = self.execute_profile_case(case, &run_id, soak);
                let scenario_passed = scenario.is_ok();
                if let Err(error) = &scenario {
                    eprintln!("profile case {case_name} scenario failed: {error:#}");
                }
                checks.push(phase_check(
                    &format!("{case_name}.scenario"),
                    scenario_passed,
                    "existing scenario evaluator passed",
                    "scenario evaluator failed; see controller stderr and run diagnostics",
                ));

                let cleanup = self.cleanup(&run_id);
                let cleanup_passed = cleanup.is_ok();
                if let Err(error) = &cleanup {
                    eprintln!("profile case {case_name} cleanup failed: {error:#}");
                }
                checks.push(phase_check(
                    &format!("{case_name}.cleanup"),
                    cleanup_passed,
                    "exact run-owned cleanup removed both run directories and locks",
                    "exact cleanup failed; release gate remains red",
                ));
                case_reports.push(ProfileCaseReport {
                    name: case_name,
                    run_id: Some(run_id),
                    deployment_passed: true,
                    scenario_passed,
                    cleanup_passed,
                });

                if !scenario_passed || !cleanup_passed {
                    failed = true;
                    break;
                }
            }
        }

        let final_preflight = self.preflight();
        let baseline_restored = match final_preflight {
            Ok(report) => {
                self.write_json(&output_dir.join("preflight-after.json"), &report)?;
                stable_baseline_matches(&initial, &report)
            }
            Err(error) => {
                eprintln!("profile final preflight failed: {error:#}");
                false
            }
        };
        checks.push(phase_check(
            "preflight-after-baseline",
            baseline_restored,
            "stable node, service, fixed-artifact, and listening-socket baselines were restored",
            "final preflight failed or the stable lab baseline changed",
        ));
        failed |= !baseline_restored;

        let report = ProfileReport {
            schema: 1,
            execution_id: execution_id.clone(),
            created_at,
            git_commit: initial.git_commit,
            profile,
            cases: case_reports,
            checks,
            secrets_redacted: true,
        };
        let evidence_path = self.write_evidence(
            &output_dir.join(format!("profile-{}.json", profile.as_str())),
            &report,
        )?;
        Ok(ProfileExecution {
            report,
            evidence_path,
            succeeded: !failed,
        })
    }

    fn execute_profile_case(
        &self,
        case: ProfileCase,
        run_id: &RunId,
        soak: SoakOptions,
    ) -> Result<()> {
        match case {
            ProfileCase::CertmeshSmoke(rotation) => {
                self.certmesh_smoke(run_id, rotation)?;
            }
            ProfileCase::CertmeshNativeTrust(rotation) => {
                self.certmesh_native_trust(run_id, true, rotation)?;
            }
            ProfileCase::CertmeshLifecycle(rotation) => {
                self.certmesh_lifecycle(run_id, rotation)?;
            }
            ProfileCase::CertmeshRecovery(rotation) => {
                self.certmesh_recovery(run_id, rotation)?;
            }
            ProfileCase::CapabilityStory(rotation) => {
                self.capability_story(run_id, true, rotation)?;
            }
            ProfileCase::RuntimeReconnect(rotation) => {
                self.runtime_reconnect(run_id, rotation)?;
            }
            ProfileCase::ServiceLifecycle => {
                self.service_lifecycle(run_id, true)?;
            }
            ProfileCase::BoundedSoak => {
                self.bounded_soak(
                    run_id,
                    soak.iterations,
                    soak.max_minutes,
                    soak.restart_every,
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SoakOptions {
    iterations: u32,
    max_minutes: u32,
    restart_every: u32,
}

fn resolve_soak_options(profile: LabProfile, options: &ProfileOptions) -> Result<SoakOptions> {
    let customized = options.soak_iterations.is_some()
        || options.soak_max_minutes.is_some()
        || options.soak_restart_every.is_some();
    if profile != LabProfile::Soak && customized {
        bail!("soak bounds may only be supplied with the soak profile");
    }
    let resolved = SoakOptions {
        iterations: options.soak_iterations.unwrap_or(DEFAULT_SOAK_ITERATIONS),
        max_minutes: options.soak_max_minutes.unwrap_or(DEFAULT_SOAK_MINUTES),
        restart_every: options
            .soak_restart_every
            .unwrap_or(DEFAULT_SOAK_RESTART_EVERY),
    };
    if profile == LabProfile::Soak {
        validate_soak_bounds(
            resolved.iterations,
            resolved.max_minutes,
            resolved.restart_every,
        )?;
    }
    Ok(resolved)
}

fn profile_cases(profile: LabProfile) -> Vec<ProfileCase> {
    use ProfileCase::*;
    use TrustRotation::{LinuxForward, LinuxReverse};

    match profile {
        LabProfile::Smoke => vec![CertmeshSmoke(LinuxForward), CertmeshSmoke(LinuxReverse)],
        LabProfile::Certmesh => certmesh_cases(),
        LabProfile::Full => {
            let mut cases = certmesh_cases();
            cases.extend([
                RuntimeReconnect(LinuxForward),
                RuntimeReconnect(LinuxReverse),
                CapabilityStory(LinuxForward),
                CapabilityStory(LinuxReverse),
                ServiceLifecycle,
            ]);
            cases
        }
        LabProfile::Soak => vec![BoundedSoak],
    }
}

fn certmesh_cases() -> Vec<ProfileCase> {
    use ProfileCase::*;
    use TrustRotation::{LinuxForward, LinuxReverse, WindowsClient};

    vec![
        CertmeshLifecycle(LinuxForward),
        CertmeshLifecycle(LinuxReverse),
        CertmeshRecovery(LinuxForward),
        CertmeshRecovery(LinuxReverse),
        CertmeshNativeTrust(LinuxForward),
        CertmeshNativeTrust(LinuxReverse),
        CertmeshNativeTrust(WindowsClient),
    ]
}

fn phase_check(name: &str, passed: bool, success: &str, failure: &str) -> CheckResult {
    CheckResult {
        name: name.to_owned(),
        passed,
        detail: if passed { success } else { failure }.to_owned(),
    }
}

fn stable_baseline_matches(before: &PreflightReport, after: &PreflightReport) -> bool {
    stable_node_matches(&before.local, &after.local)
        && stable_nodes_by_id(&before.remotes) == stable_nodes_by_id(&after.remotes)
}

fn stable_nodes_by_id(nodes: &[NodeSnapshot]) -> BTreeMap<&str, StableNode<'_>> {
    nodes
        .iter()
        .map(|node| (node.id.as_str(), StableNode::from(node)))
        .collect()
}

fn stable_node_matches(before: &NodeSnapshot, after: &NodeSnapshot) -> bool {
    StableNode::from(before) == StableNode::from(after)
}

#[derive(Eq, PartialEq)]
struct StableNode<'a> {
    expected_hostname: &'a str,
    observed_hostname: &'a str,
    services: &'a BTreeMap<String, crate::model::ServiceSnapshot>,
    listening_sockets: BTreeSet<&'a str>,
    remote_root_present: bool,
    existing_artifact_sha256: Option<&'a str>,
    existing_artifact_version: Option<&'a str>,
    deploy_ready: bool,
    scenario_ready: bool,
}

impl<'a> From<&'a NodeSnapshot> for StableNode<'a> {
    fn from(node: &'a NodeSnapshot) -> Self {
        Self {
            expected_hostname: &node.expected_hostname,
            observed_hostname: &node.observed_hostname,
            services: &node.services,
            listening_sockets: node.listening_sockets.iter().map(String::as_str).collect(),
            remote_root_present: node.remote_root_present,
            existing_artifact_sha256: node.existing_artifact_sha256.as_deref(),
            existing_artifact_version: node.existing_artifact_version.as_deref(),
            deploy_ready: node.deploy_ready,
            scenario_ready: node.scenario_ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ServiceSnapshot;

    #[test]
    fn profiles_are_one_policy_list_over_existing_scenarios() {
        let smoke = profile_cases(LabProfile::Smoke);
        assert_eq!(smoke.len(), 2);
        assert!(smoke.iter().all(|case| !case.requires_system_mutation()));

        let certmesh = profile_cases(LabProfile::Certmesh);
        assert_eq!(certmesh.len(), 7);
        assert_eq!(
            certmesh
                .iter()
                .filter(|case| case.requires_system_mutation())
                .count(),
            3
        );

        let full = profile_cases(LabProfile::Full);
        assert_eq!(full.len(), 12);
        assert_eq!(&full[..certmesh.len()], certmesh.as_slice());
        assert_eq!(
            full.iter()
                .filter(|case| case.requires_system_mutation())
                .count(),
            6
        );
        assert_eq!(
            profile_cases(LabProfile::Soak),
            vec![ProfileCase::BoundedSoak]
        );
    }

    #[test]
    fn non_soak_profiles_refuse_soak_tuning() {
        let options = ProfileOptions {
            artifact: None,
            allow_system_mutation: false,
            soak_iterations: Some(1),
            soak_max_minutes: None,
            soak_restart_every: None,
        };
        assert!(resolve_soak_options(LabProfile::Smoke, &options).is_err());
    }

    #[test]
    fn baseline_ignores_clock_but_detects_service_and_socket_changes() {
        let before = preflight();
        let mut after = preflight();
        after.local.utc_epoch += 60;
        after.remotes[0].clock_skew_seconds += 1;
        assert!(stable_baseline_matches(&before, &after));

        after.remotes[0].services.get_mut("koi").unwrap().active = "active".into();
        assert!(!stable_baseline_matches(&before, &after));
        after.remotes[0].services.get_mut("koi").unwrap().active = "inactive".into();
        after.remotes[0]
            .listening_sockets
            .push("tcp LISTEN 0 128 0.0.0.0:16541".into());
        assert!(!stable_baseline_matches(&before, &after));
    }

    fn preflight() -> PreflightReport {
        let local = node("windows");
        PreflightReport {
            schema: 1,
            created_at: Utc::now(),
            git_commit: "deadbeef".into(),
            local,
            remotes: vec![node("brook"), node("granite")],
            deploy_ready: true,
            scenario_ready: true,
        }
    }

    fn node(id: &str) -> NodeSnapshot {
        NodeSnapshot {
            id: id.into(),
            expected_hostname: id.into(),
            observed_hostname: id.into(),
            address: "127.0.0.1".into(),
            operating_system: "test".into(),
            architecture: "x86_64".into(),
            utc_epoch: 1,
            clock_skew_seconds: 0,
            clock_probe_span_seconds: 0,
            sudo_non_interactive: true,
            tools: BTreeMap::new(),
            services: BTreeMap::from([(
                "koi".into(),
                ServiceSnapshot {
                    active: "inactive".into(),
                    enabled: "not-found".into(),
                    exec_start: None,
                },
            )]),
            listening_sockets: vec!["udp UNCONN 0 0 0.0.0.0:5353".into()],
            remote_root_present: true,
            existing_artifact_sha256: Some("abc".into()),
            existing_artifact_version: Some("koi 0.7.0".into()),
            deploy_ready: true,
            scenario_ready: true,
            blockers: Vec::new(),
            warnings: Vec::new(),
        }
    }
}
