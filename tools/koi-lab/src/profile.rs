use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use chrono::Utc;

use crate::lab::Lab;
use crate::model::{
    output_path, CheckResult, LabProfile, NodeSnapshot, PreflightReport, ProfileCaseReport,
    ProfileReport, RunId, TrustRotation,
};
use crate::profile_journal::ProfileJournal;
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
    WebhookFanout(TrustRotation),
    MgmtPrincipal(TrustRotation),
    ServiceLifecycle,
    BoundedSoak,
    ServiceLifecycleWindows,
    WindowsPipeIpc,
    WindowsCaLifecycle,
    WindowsMdns,
    WindowsBreadth,
    WindowsProxy,
    WindowsWebhook,
    WindowsRecovery,
    WindowsAcme,
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
            Self::WebhookFanout(rotation) => {
                format!("webhook-fanout-{}", rotation.as_str())
            }
            Self::MgmtPrincipal(rotation) => {
                format!("mgmt-principal-{}", rotation.as_str())
            }
            Self::ServiceLifecycle => "service-lifecycle-linux".to_owned(),
            Self::BoundedSoak => "bounded-soak-linux".to_owned(),
            Self::ServiceLifecycleWindows => "service-lifecycle-windows".to_owned(),
            Self::WindowsPipeIpc => "windows-pipe-ipc".to_owned(),
            Self::WindowsCaLifecycle => "certmesh-lifecycle-windows-ca".to_owned(),
            Self::WindowsMdns => "windows-mdns".to_owned(),
            Self::WindowsBreadth => "windows-breadth".to_owned(),
            Self::WindowsProxy => "windows-proxy".to_owned(),
            Self::WindowsWebhook => "windows-webhook".to_owned(),
            Self::WindowsRecovery => "windows-recovery".to_owned(),
            Self::WindowsAcme => "windows-acme".to_owned(),
        }
    }

    fn requires_system_mutation(self) -> bool {
        matches!(
            self,
            Self::CertmeshNativeTrust(_)
                | Self::CapabilityStory(_)
                | Self::ServiceLifecycle
                | Self::ServiceLifecycleWindows
                | Self::WindowsCaLifecycle
                | Self::WindowsMdns
                | Self::WindowsBreadth
                | Self::WindowsProxy
                | Self::WindowsWebhook
                | Self::WindowsRecovery
                | Self::WindowsAcme
        )
    }

    /// Lanes that run ON the Windows workstation and need its elevation:
    /// the `linux` profile is `full` minus exactly these.
    fn windows_workstation_lane(self) -> bool {
        matches!(
            self,
            Self::CertmeshNativeTrust(TrustRotation::WindowsClient)
                | Self::ServiceLifecycleWindows
                | Self::WindowsPipeIpc
                | Self::WindowsCaLifecycle
                | Self::WindowsMdns
                | Self::WindowsBreadth
                | Self::WindowsProxy
                | Self::WindowsWebhook
                | Self::WindowsRecovery
                | Self::WindowsAcme
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
        let mut journal = ProfileJournal::start(
            self.repo_root(),
            execution_id.clone(),
            profile,
            initial.git_commit.clone(),
        )?;
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
                let run_id = RunId::generate();
                journal.prepare_case(&case_name, &run_id)?;
                let manifest = match self
                    .deploy_with_run_id(options.artifact.as_deref(), run_id.clone())
                {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        eprintln!("profile case {case_name} deployment failed: {error:#}");
                        let cleanup_passed = match self.cleanup(&run_id) {
                            Ok(_) => {
                                journal.case_cleaned(&run_id)?;
                                true
                            }
                            Err(cleanup_error) => {
                                eprintln!(
                                    "profile case {case_name} deployment rollback verification failed: {cleanup_error:#}"
                                );
                                false
                            }
                        };
                        checks.push(phase_check(
                            &format!("{case_name}.deploy"),
                            false,
                            "run-owned artifact deployed",
                            "deployment failed; partial deployment rollback was requested",
                        ));
                        case_reports.push(ProfileCaseReport {
                            name: case_name,
                            run_id: Some(run_id),
                            deployment_passed: false,
                            scenario_passed: false,
                            cleanup_passed,
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
                if cleanup_passed {
                    journal.case_cleaned(&run_id)?;
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
        if !journal.has_pending_run() {
            journal.finish(false)?;
        } else {
            failed = true;
        }
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
            ProfileCase::WebhookFanout(rotation) => {
                self.webhook_fanout(run_id, rotation)?;
            }
            ProfileCase::MgmtPrincipal(rotation) => {
                self.mgmt_principal(run_id, rotation, None, None)?;
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
            ProfileCase::ServiceLifecycleWindows => {
                self.service_lifecycle_windows(run_id, true)?;
            }
            ProfileCase::WindowsPipeIpc => {
                self.windows_pipe_ipc_test()?;
            }
            ProfileCase::WindowsCaLifecycle => {
                self.certmesh_lifecycle_windows_ca(run_id, None, true)?;
            }
            ProfileCase::WindowsMdns => {
                self.windows_mdns(run_id, None, true)?;
            }
            ProfileCase::WindowsBreadth => {
                self.windows_breadth(run_id, None, true)?;
            }
            ProfileCase::WindowsProxy => {
                self.windows_proxy(run_id, None, true)?;
            }
            ProfileCase::WindowsWebhook => {
                self.windows_webhook(run_id, None, true)?;
            }
            ProfileCase::WindowsRecovery => {
                self.certmesh_recovery_windows(run_id, None, true)?;
            }
            ProfileCase::WindowsAcme => {
                self.windows_acme(run_id, None, true)?;
            }
        }
        Ok(())
    }

    /// W2 (ADR-032): the named-pipe IPC lane is a product integration test
    /// (crates/koi/tests/named_pipe_ipc.rs) that spawns its own per-run
    /// daemon on ephemeral ports and drives read-only probes — the profile
    /// case is the invocation, not a re-implementation.
    fn windows_pipe_ipc_test(&self) -> Result<()> {
        let output = std::process::Command::new("cargo")
            .args([
                "test",
                "--locked",
                "-p",
                "koi-net",
                "--test",
                "named_pipe_ipc",
            ])
            .current_dir(&self.repo_root)
            .output()
            .context("failed to start cargo for the named-pipe IPC test")?;
        if !output.status.success() {
            bail!(
                "named-pipe IPC test failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            );
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
        LabProfile::Full | LabProfile::Linux => {
            let mut cases = certmesh_cases();
            cases.extend([
                RuntimeReconnect(LinuxForward),
                RuntimeReconnect(LinuxReverse),
                WebhookFanout(LinuxForward),
                WebhookFanout(LinuxReverse),
                MgmtPrincipal(LinuxForward),
                MgmtPrincipal(LinuxReverse),
                CapabilityStory(LinuxForward),
                CapabilityStory(LinuxReverse),
                ServiceLifecycle,
                ServiceLifecycleWindows,
                WindowsPipeIpc,
                WindowsCaLifecycle,
                WindowsMdns,
                WindowsBreadth,
                WindowsProxy,
                WindowsWebhook,
                WindowsRecovery,
                WindowsAcme,
            ]);
            // The linux profile is `full` minus exactly the Windows
            // workstation's lanes: identical breadth otherwise, runnable from
            // an unelevated controller session (ADR-026-era working choice —
            // privilege lanes are separated, never silently skipped inside a
            // transaction).
            if profile == LabProfile::Linux {
                cases.retain(|case| !case.windows_workstation_lane());
            }
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

pub(crate) fn stable_baseline_matches(before: &PreflightReport, after: &PreflightReport) -> bool {
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
    use crate::TrustRotation::{LinuxForward, LinuxReverse};

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
        assert_eq!(full.len(), 25);
        assert_eq!(&full[..certmesh.len()], certmesh.as_slice());
        // The webhook + principal cases ride the same non-privileged lane as reconnect.
        assert_eq!(
            &full[certmesh.len() + 2..certmesh.len() + 6],
            [
                ProfileCase::WebhookFanout(LinuxForward),
                ProfileCase::WebhookFanout(LinuxReverse),
                ProfileCase::MgmtPrincipal(LinuxForward),
                ProfileCase::MgmtPrincipal(LinuxReverse),
            ]
        );
        assert_eq!(
            full.iter()
                .filter(|case| case.requires_system_mutation())
                .count(),
            14
        );
        // The Windows workstation's lanes ride the tail of `full`, in matrix
        // order; the pipe lane is the one that needs no system mutation.
        assert_eq!(
            &full[16..],
            [
                ProfileCase::ServiceLifecycleWindows,
                ProfileCase::WindowsPipeIpc,
                ProfileCase::WindowsCaLifecycle,
                ProfileCase::WindowsMdns,
                ProfileCase::WindowsBreadth,
                ProfileCase::WindowsProxy,
                ProfileCase::WindowsWebhook,
                ProfileCase::WindowsRecovery,
                ProfileCase::WindowsAcme,
            ]
        );
        assert!(!ProfileCase::WindowsPipeIpc.requires_system_mutation());

        // The linux profile is `full` minus exactly the Windows workstation's
        // lanes — same order, runnable unelevated.
        let linux = profile_cases(LabProfile::Linux);
        assert_eq!(linux.len(), 15);
        assert!(
            !linux.iter().any(|case| case.windows_workstation_lane()),
            "the linux profile must not contain Windows workstation lanes"
        );
        for (full_case, linux_case) in full
            .iter()
            .filter(|c| !c.windows_workstation_lane())
            .zip(linux.iter())
        {
            assert_eq!(full_case, linux_case, "linux preserves full's ordering");
        }
        // The Linux native-trust rotations stay in: they mutate only the two
        // dedicated test hosts' trust stores (the flagged privilege lane).
        assert_eq!(
            linux
                .iter()
                .filter(|case| case.requires_system_mutation())
                .count(),
            5
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
            catalog_roles: Vec::new(),
            catalog_mutations: Vec::new(),
            catalog_privilege: "dedicated-box".into(),
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
