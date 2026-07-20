use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::model::{
    output_path, ArtifactIdentity, BuildReport, CertmeshLifecycleReport, CertmeshRecoveryReport,
    CertmeshSmokeReport, CheckResult, CleanupPlan, DeployedNode, DeploymentManifest, LabConfig,
    NativeTrustReport, NodeCleanupPlan, NodeSnapshot, NodeSpec, PreflightReport, RunId,
    ServiceSnapshot, TrustRotation,
};
use crate::putty::PuttyTransport;

const REQUIRED_LOCAL_TOOLS: &[&str] = &["cross", "docker", "git", "plink", "pscp"];
const REQUIRED_REMOTE_TOOLS: &[&str] = &["sha256sum", "systemctl", "ss", "realpath", "readlink"];
const SCENARIO_REMOTE_TOOLS: &[&str] = &[
    "curl",
    "jq",
    "dig",
    "nc",
    "docker",
    "openssl",
    "python3",
    "setsid",
    "systemd-run",
];
const TEST_PORTS: &[u16] = &[5641, 5642, 5643];
const MAX_CLOCK_SKEW_SECONDS: i64 = 5;

pub struct Lab {
    repo_root: PathBuf,
    config: LabConfig,
    transport: PuttyTransport,
}

pub(crate) struct InstalledTrust {
    pub(crate) name: String,
    pub(crate) fingerprint: String,
    pub(crate) source: String,
    pub(crate) state: String,
}

pub(crate) struct MemberIdentityEvidence {
    pub(crate) key_sha256: String,
    pub(crate) cert_sha256: String,
    pub(crate) cert_fingerprint: String,
}

pub(crate) struct CertmeshProvisioning {
    pub(crate) ca_fingerprint: String,
    pub(crate) member_posture: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeFaultRole {
    Unchanged,
    Stopped,
    Updated,
    Started,
}

impl RuntimeFaultRole {
    pub(crate) const ALL: [Self; 4] =
        [Self::Unchanged, Self::Stopped, Self::Updated, Self::Started];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Stopped => "stopped",
            Self::Updated => "updated",
            Self::Started => "started",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonProfile {
    Certmesh,
    CapabilityStory,
    RuntimeReconnect,
}

impl Lab {
    pub fn load(repo_root: &Path, config_path: &Path) -> Result<Self> {
        let repo_root = repo_root
            .canonicalize()
            .with_context(|| format!("could not resolve repo root {}", repo_root.display()))?;
        let config_path = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            repo_root.join(config_path)
        };
        let config = LabConfig::load(&config_path)?;
        let transport = PuttyTransport::from_environment();
        Ok(Self {
            repo_root,
            config,
            transport,
        })
    }

    pub fn preflight(&self) -> Result<PreflightReport> {
        let local = self.probe_local(current_epoch()?)?;
        let remotes = self
            .config
            .remotes()
            .map(|node| self.probe_remote(node))
            .collect::<Result<Vec<_>>>()?;
        let deploy_ready = local.deploy_ready && remotes.iter().all(|node| node.deploy_ready);
        let scenario_ready =
            local.scenario_ready && remotes.iter().all(|node| node.scenario_ready) && deploy_ready;
        Ok(PreflightReport {
            schema: 1,
            created_at: Utc::now(),
            git_commit: self.git_commit()?,
            local,
            remotes,
            deploy_ready,
            scenario_ready,
        })
    }

    pub fn write_preflight(&self, report: &PreflightReport) -> Result<PathBuf> {
        let name = format!(
            "preflight-{}.json",
            report.created_at.format("%Y%m%dT%H%M%SZ")
        );
        self.write_json(&output_path(&name), report)
    }

    pub fn build_release(&self) -> Result<BuildReport> {
        let windows_status = Command::new("cargo")
            .current_dir(&self.repo_root)
            .args(["build", "--release", "--locked", "-p", "koi-net"])
            .status()
            .context("failed to start the local Windows release build")?;
        if !windows_status.success() {
            bail!("local Windows release build failed with exit {windows_status}");
        }
        let status = Command::new("cross")
            .current_dir(&self.repo_root)
            .args([
                "build",
                "--release",
                "--locked",
                "--target",
                &self.config.artifact.target,
                "-p",
                &self.config.artifact.package,
            ])
            .status()
            .context("failed to start the local cross build")?;
        if !status.success() {
            bail!("local cross build failed with exit {status}");
        }
        Ok(BuildReport {
            linux: self.artifact_identity(None)?,
            windows: ArtifactIdentity::from_path(&self.repo_root.join("target/release/koi.exe"))?,
        })
    }

    pub fn artifact_identity(&self, override_path: Option<&Path>) -> Result<ArtifactIdentity> {
        let path = override_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.repo_root.join(&self.config.artifact.relative_path));
        ArtifactIdentity::from_path(&path)
    }

    pub fn deploy(&self, artifact_path: Option<&Path>) -> Result<DeploymentManifest> {
        let preflight = self.preflight()?;
        if !preflight.deploy_ready {
            bail!("deployment refused: preflight has deployment blockers");
        }
        let artifact = self.artifact_identity(artifact_path)?;
        let run_id = RunId::generate();
        let remotes: Vec<&NodeSpec> = self.config.remotes().collect();
        let mut acquired: Vec<&NodeSpec> = Vec::new();

        for node in &remotes {
            if let Err(error) = self.acquire_lock(node, &run_id) {
                self.rollback_partial(&acquired, &run_id);
                return Err(error).with_context(|| format!("could not lock node {}", node.id()));
            }
            acquired.push(node);
        }

        let deployed = self.deploy_locked(&remotes, &run_id, &artifact);
        let nodes = match deployed {
            Ok(nodes) => nodes,
            Err(error) => {
                self.rollback_partial(&acquired, &run_id);
                return Err(error).context("deployment rolled back after a node failed");
            }
        };

        let manifest = DeploymentManifest {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            git_commit: self.git_commit()?,
            artifact,
            nodes,
        };
        let path = output_path(run_id.as_str()).join("manifest.json");
        self.write_json(&path, &manifest)?;
        Ok(manifest)
    }

    pub fn cleanup_plan(&self, run_id: &RunId) -> Result<CleanupPlan> {
        let nodes = self
            .config
            .remotes()
            .map(|node| self.node_cleanup_plan(node, run_id))
            .collect::<Result<Vec<_>>>()?;
        Ok(CleanupPlan {
            run_id: run_id.clone(),
            nodes,
        })
    }

    pub fn certmesh_smoke(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
    ) -> Result<CertmeshSmokeReport> {
        let plan = self.cleanup_plan(run_id)?;
        if plan
            .nodes
            .iter()
            .any(|node| !node.owner_matches || !node.run_dir_present)
        {
            bail!("certmesh smoke refused: run does not own both staged node directories");
        }
        let roles = rotation.roles();
        let ca = self.remote_by_id(roles.ca)?;
        let member = self.remote_by_id(roles.service)?;
        let trust_before_ca = self.system_trust_fingerprint(ca)?;
        let trust_before_member = self.system_trust_fingerprint(member)?;

        self.start_run_daemon(ca, run_id)?;
        self.start_run_daemon(member, run_id)?;
        let ca_url = self.node_url(ca)?;
        let member_url = self.node_url(member)?;
        wait_for_http(&format!("{ca_url}/healthz"))?;
        wait_for_http(&format!("{member_url}/healthz"))?;
        let provisioned = self.provision_certmesh(run_id, ca, member)?;
        let ca_fingerprint = provisioned.ca_fingerprint;
        let member_posture = provisioned.member_posture;
        let trust_after_ca = self.system_trust_fingerprint(ca)?;
        let trust_after_member = self.system_trust_fingerprint(member)?;
        if trust_before_ca != trust_after_ca || trust_before_member != trust_after_member {
            bail!("non-privileged certmesh smoke changed a Linux system trust store");
        }

        let report = CertmeshSmokeReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            rotation,
            ca_node: ca.id().to_owned(),
            member_node: member.id().to_owned(),
            checks: vec![
                CheckResult {
                    name: "controller_to_ca_health".into(),
                    passed: true,
                    detail: format!("{ca_url}/healthz returned OK"),
                },
                CheckResult {
                    name: "controller_to_service_health".into(),
                    passed: true,
                    detail: format!("{member_url}/healthz returned OK"),
                },
                CheckResult {
                    name: "invite_pin".into(),
                    passed: true,
                    detail: format!(
                        "invite pinned CA {}…",
                        ca_fingerprint.get(..16).unwrap_or(&ca_fingerprint)
                    ),
                },
                CheckResult {
                    name: "invite_pin_mismatch_refused".into(),
                    passed: true,
                    detail: "member rejected the wrong CA fingerprint before generating a key"
                        .into(),
                },
                CheckResult {
                    name: "service_joined_ca".into(),
                    passed: true,
                    detail: format!(
                        "CA roster contains {}; posture={member_posture}",
                        member.hostname()
                    ),
                },
                CheckResult {
                    name: "system_trust_unchanged".into(),
                    passed: true,
                    detail: "system trust fingerprints unchanged on both Linux nodes".into(),
                },
            ],
            secrets_redacted: true,
        };
        let path =
            output_path(run_id.as_str()).join(format!("certmesh-smoke-{}.json", rotation.as_str()));
        self.write_json(&path, &report)?;
        Ok(report)
    }

    /// Establish one run-owned CA/member relationship through the public
    /// create/invite/join boundaries. Daemon lifecycle and system trust remain
    /// the caller's responsibility so smoke, lifecycle, and whole-story lanes
    /// share one enrollment chokepoint.
    pub(crate) fn provision_certmesh(
        &self,
        run_id: &RunId,
        ca: &NodeSpec,
        member: &NodeSpec,
    ) -> Result<CertmeshProvisioning> {
        let ca_url = self.node_url(ca)?;
        let ca_token = self.daemon_token(ca, run_id)?;
        let entropy = format!("{:x}", Sha256::digest(run_id.as_str().as_bytes()));
        let create = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/create"),
            Some(&ca_token),
            Some(&json!({
                "passphrase": format!("koi-lab-{}", run_id.as_str()),
                "entropy_hex": entropy,
                "operator": "koi-lab",
                "enrollment_open": true,
                "requires_approval": false,
                "auto_unlock": false
            })),
        )?;
        let ca_fingerprint = required_json_string(&create, "ca_fingerprint")?;

        let invite = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/invite"),
            Some(&ca_token),
            Some(&json!({
                "hostname": member.hostname(),
                "ttl_mins": 30
            })),
        )?;
        let invite_token = required_json_string(&invite, "token")?;
        if !invite_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            bail!("CA returned an invite token unsafe for the remote CLI boundary");
        }
        let invite_fingerprint = required_json_string(&invite, "ca_fingerprint")?;
        if invite_fingerprint != ca_fingerprint {
            bail!("invite fingerprint does not match the created CA");
        }

        let member_run_dir = member.run_dir(run_id)?;
        let mismatched_invite = mismatch_invite_fingerprint(&invite_token, &ca_fingerprint)?;
        let mismatch_command = format!(
            "env KOI_DATA_DIR={member_run_dir}/data XDG_RUNTIME_DIR={member_run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1 {member_run_dir}/koi certmesh join {ca_url} --invite {mismatched_invite} --ca-mtls-port {} --json",
            ca.lab_ports()?.mtls
        );
        let mismatch = self.transport.run(member, &mismatch_command)?;
        if mismatch.status.success()
            || !String::from_utf8_lossy(&mismatch.stderr)
                .to_ascii_lowercase()
                .contains("fingerprint")
        {
            bail!("member did not reject the deliberately mismatched invite pin");
        }
        self.transport.run_checked(
            member,
            &format!(
                "test ! -e {member_run_dir}/data/certs/{}/key.pem",
                member.hostname()
            ),
        )?;

        let join_command = format!(
            "set -eu; test \"$(cat {member_run_dir}/owner)\" = {}; env KOI_DATA_DIR={member_run_dir}/data XDG_RUNTIME_DIR={member_run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1 {member_run_dir}/koi certmesh join {ca_url} --invite {invite_token} --ca-mtls-port {} --json",
            run_id.as_str(),
            ca.lab_ports()?.mtls
        );
        self.transport.run_checked(member, &join_command)?;

        let status = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
        let members = status
            .get("members")
            .and_then(Value::as_array)
            .context("CA status did not contain a members array")?;
        if !members
            .iter()
            .any(|value| value.get("hostname").and_then(Value::as_str) == Some(member.hostname()))
        {
            bail!(
                "CA roster does not contain {} after join",
                member.hostname()
            );
        }

        let diagnosis_command = format!(
            "env KOI_DATA_DIR={member_run_dir}/data KOI_DNS_ZONE=internal KOI_NO_CREDENTIAL_STORE=1 {member_run_dir}/koi trust diagnose --json"
        );
        let diagnosis_output = self.transport.run_checked(member, &diagnosis_command)?;
        let diagnosis: Value = serde_json::from_str(diagnosis_output.trim())
            .context("member trust diagnosis returned invalid JSON")?;
        if diagnosis.get("overall").and_then(Value::as_str) != Some("healthy") {
            bail!("member trust diagnosis is not healthy");
        }
        let member_posture = diagnosis
            .get("checks")
            .and_then(Value::as_array)
            .and_then(|checks| {
                checks
                    .iter()
                    .find(|check| check.get("name").and_then(Value::as_str) == Some("posture"))
            })
            .and_then(|check| check.get("detail"))
            .and_then(Value::as_str)
            .context("member trust diagnosis has no posture detail")?
            .to_owned();

        Ok(CertmeshProvisioning {
            ca_fingerprint,
            member_posture,
        })
    }

    pub fn certmesh_native_trust(
        &self,
        run_id: &RunId,
        allow_system_mutation: bool,
        rotation: TrustRotation,
    ) -> Result<NativeTrustReport> {
        require_system_mutation(allow_system_mutation)?;
        let roles = rotation.roles();
        let ca = self.remote_by_id(roles.ca)?;
        let service = self.remote_by_id(roles.service)?;
        let client = self.config.node(roles.client)?;
        self.require_native_client_privilege(client)?;

        // This establishes certmesh and proves its non-privileged invariants first.
        // It does not alter either system trust store.
        self.certmesh_smoke(run_id, rotation)?;

        let service_url = self.node_url(service)?;
        let service_token = self.daemon_token(service, run_id)?;
        let service_ports = service.lab_ports()?;
        curl_json(
            "POST",
            &format!("{service_url}/v1/proxy/add"),
            Some(&service_token),
            Some(&json!({
                "name": service.hostname(),
                "listen_port": service_ports.proxy,
                "backend": format!("127.0.0.1:{}", service_ports.http),
                "allow_remote": false
            })),
        )?;
        wait_for_proxy(
            &format!("{service_url}/v1/proxy/status"),
            service.hostname(),
            service_ports.proxy,
        )?;

        let trust_before = self.native_trust_fingerprint(client)?;
        if self
            .native_tls_curl(client, service, service.hostname())?
            .status
            .success()
        {
            bail!("native trust precondition failed: the fresh CA was already trusted");
        }

        let installed = self.install_native_trust(client, ca, run_id)?;

        let exercise_result = (|| -> Result<Vec<CheckResult>> {
            let native_curl = self.native_tls_curl(client, service, service.hostname())?;
            if !native_curl.status.success()
                || String::from_utf8_lossy(&native_curl.stdout).trim() != "OK"
            {
                bail!(
                    "native curl did not trust the Koi proxy after install: {}",
                    String::from_utf8_lossy(&native_curl.stderr).trim()
                );
            }

            let secondary =
                self.native_tls_secondary(client, service, service.hostname(), run_id)?;
            if !secondary.status.success() {
                bail!(
                    "secondary native client did not verify the Koi proxy after install: {}",
                    String::from_utf8_lossy(&secondary.stderr).trim()
                );
            }

            let wrong_hostname = format!("wrong-{}", service.hostname());
            if self
                .native_tls_curl(client, service, &wrong_hostname)?
                .status
                .success()
            {
                bail!("native curl accepted the service certificate for a wrong hostname");
            }

            if !self.native_trust_is_tracked(client, run_id, &installed)? {
                bail!("Koi trust state did not track the installed fingerprint");
            }

            let windows_lifecycle = if matches!(client, NodeSpec::LocalWindows { .. }) {
                Some(self.exercise_windows_member_custody(ca, run_id)?)
            } else {
                None
            };

            let mut checks = vec![
                CheckResult {
                    name: "native_tls_fails_before_install".into(),
                    passed: true,
                    detail: format!(
                        "{} curl rejected {}'s fresh CA before installation",
                        client.id(),
                        service.id()
                    ),
                },
                CheckResult {
                    name: "koi_proxy_uses_certmesh_leaf".into(),
                    passed: true,
                    detail: format!(
                        "{}:{} serves the certmesh member certificate",
                        service.hostname(),
                        service_ports.proxy
                    ),
                },
                CheckResult {
                    name: "native_tls_succeeds_after_install".into(),
                    passed: true,
                    detail: format!(
                        "{} native clients verified {} without a custom CA",
                        client.id(),
                        service.id()
                    ),
                },
                CheckResult {
                    name: "wrong_hostname_rejected".into(),
                    passed: true,
                    detail: "native curl rejected the same endpoint under a non-SAN hostname"
                        .into(),
                },
                CheckResult {
                    name: "tracked_fingerprint_matches".into(),
                    passed: true,
                    detail: format!("Koi tracked sha256 {}", installed.fingerprint),
                },
            ];
            if let Some(lifecycle) = windows_lifecycle {
                checks.extend([
                    CheckResult {
                        name: "local_machine_root_exact_fingerprint".into(),
                        passed: true,
                        detail: format!(
                            "LocalMachine\\Root contained exactly one certificate with sha256 {}",
                            installed.fingerprint
                        ),
                    },
                    CheckResult {
                        name: "schannel_curl_succeeds_after_install".into(),
                        passed: true,
                        detail: "curl.exe used Schannel with CA and hostname verification; revocation remained best-effort only for the private CA's missing CRL distribution point".into(),
                    },
                    CheckResult {
                        name: "invoke_web_request_succeeds_and_hosts_restored".into(),
                        passed: true,
                        detail: "Invoke-WebRequest verified the proxy and its temporary mapping restored the exact original hosts-file bytes".into(),
                    },
                ]);
                checks.extend(lifecycle);
            }
            Ok(checks)
        })();

        // The removal path runs even when any post-install assertion fails.
        let removal_result = self.remove_native_trust(client, run_id, &installed);
        let trust_after = self.native_trust_fingerprint(client)?;
        if let Err(error) = removal_result {
            bail!(
                "native trust cleanup failed for {} (manual source retained at {}): {error:#}",
                installed.fingerprint,
                installed.source
            );
        }
        if trust_after != trust_before {
            bail!(
                "native trust cleanup did not restore {}'s captured system-store fingerprint",
                client.id()
            );
        }
        if self
            .native_tls_curl(client, service, service.hostname())?
            .status
            .success()
        {
            bail!("native curl still trusts the service after exact root removal");
        }
        let mut checks = exercise_result?;
        checks.push(CheckResult {
            name: "native_tls_fails_after_remove".into(),
            passed: true,
            detail: format!(
                "{} curl rejected {} after the root was removed",
                client.id(),
                service.id()
            ),
        });
        checks.push(CheckResult {
            name: "system_trust_restored".into(),
            passed: true,
            detail: format!(
                "{}'s complete trust-store fingerprint matches the captured baseline",
                client.id()
            ),
        });

        let report = NativeTrustReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            rotation,
            ca_node: ca.id().to_owned(),
            service_node: service.id().to_owned(),
            client_node: client.id().to_owned(),
            ca_fingerprint: installed.fingerprint,
            checks,
            system_trust_restored: true,
            secrets_redacted: true,
        };
        let path =
            output_path(run_id.as_str()).join(format!("native-trust-{}.json", rotation.as_str()));
        self.write_json(&path, &report)?;
        Ok(report)
    }

    pub fn certmesh_lifecycle(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
    ) -> Result<CertmeshLifecycleReport> {
        // Establish membership through the public join path, including the pin
        // mismatch preflight. This remains a non-system-mutating scenario.
        self.certmesh_smoke(run_id, rotation)?;

        let roles = rotation.roles();
        let ca = self.remote_by_id(roles.ca)?;
        let member = self.remote_by_id(roles.service)?;
        let ca_url = self.node_url(ca)?;
        let member_url = self.node_url(member)?;
        let member_run_dir = member.run_dir(run_id)?;
        let member_ports = member.lab_ports()?;

        let before = self.member_identity_evidence(member, run_id)?;
        let ca_token = self.daemon_token(ca, run_id)?;
        let member_token = self.daemon_token(member, run_id)?;
        curl_json(
            "POST",
            &format!("{member_url}/v1/proxy/add"),
            Some(&member_token),
            Some(&json!({
                "name": member.hostname(),
                "listen_port": member_ports.proxy,
                "backend": format!("127.0.0.1:{}", member_ports.http),
                "allow_remote": false
            })),
        )?;
        wait_for_proxy(
            &format!("{member_url}/v1/proxy/status"),
            member.hostname(),
            member_ports.proxy,
        )?;
        self.require_tls_with_run_ca(ca, member, run_id)?;

        let renew_command = format!(
            "set -eu; test \"$(cat {member_run_dir}/owner)\" = {}; env KOI_DATA_DIR={member_run_dir}/data XDG_RUNTIME_DIR={member_run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1 {member_run_dir}/koi certmesh renew --json",
            run_id.as_str()
        );
        let renew_output = self.transport.run_checked(member, &renew_command)?;
        let renewed: Value = serde_json::from_str(renew_output.trim())
            .context("operator renewal returned invalid JSON")?;
        if renewed.get("renewed").and_then(Value::as_bool) != Some(true) {
            bail!("operator renewal did not report a completed rotation");
        }

        let rotated = self.member_identity_evidence(member, run_id)?;
        if rotated.key_sha256 == before.key_sha256 {
            bail!("operator renewal did not rotate the member private key");
        }
        if rotated.cert_sha256 == before.cert_sha256 {
            bail!("operator renewal did not replace the member leaf certificate");
        }
        let status = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
        let roster_fingerprint = status
            .get("members")
            .and_then(Value::as_array)
            .and_then(|members| {
                members.iter().find(|entry| {
                    entry.get("hostname").and_then(Value::as_str) == Some(member.hostname())
                })
            })
            .and_then(|entry| entry.get("cert_fingerprint"))
            .and_then(Value::as_str)
            .context("CA roster omitted the renewed member fingerprint")?;
        if !roster_fingerprint.eq_ignore_ascii_case(&rotated.cert_fingerprint) {
            bail!("CA roster fingerprint does not match the rotated member leaf");
        }

        self.restart_run_daemon(member, run_id)?;
        wait_for_http(&format!("{member_url}/healthz"))?;
        wait_for_proxy(
            &format!("{member_url}/v1/proxy/status"),
            member.hostname(),
            member_ports.proxy,
        )?;
        let after_restart = self.member_identity_evidence(member, run_id)?;
        if after_restart.key_sha256 != rotated.key_sha256
            || after_restart.cert_sha256 != rotated.cert_sha256
        {
            bail!("member identity changed unexpectedly across daemon restart");
        }
        let diagnosis = self.member_diagnosis(member, run_id)?;
        if diagnosis.get("overall").and_then(Value::as_str) != Some("healthy") {
            bail!("member diagnosis was not healthy after restart");
        }

        let revoked = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/revoke"),
            Some(&ca_token),
            Some(&json!({
                "hostname": member.hostname(),
                "reason": "koi-lab-v1-lifecycle",
                "operator": "koi-lab"
            })),
        )?;
        if revoked.get("revoked").and_then(Value::as_bool) != Some(true) {
            bail!("CA did not report the member as revoked");
        }

        // A restart drives the member's immediate trust-bundle pass. The
        // resulting RED diagnosis is authoritative; generic TLS remains valid
        // until leaf expiry because certmesh intentionally has no CRL/OCSP layer.
        self.restart_run_daemon(member, run_id)?;
        wait_for_http(&format!("{member_url}/healthz"))?;
        wait_for_proxy(
            &format!("{member_url}/v1/proxy/status"),
            member.hostname(),
            member_ports.proxy,
        )?;
        let red = self.wait_for_red_member_diagnosis(member, run_id)?;
        let self_revocation_red =
            red.get("checks")
                .and_then(Value::as_array)
                .is_some_and(|checks| {
                    checks.iter().any(|check| {
                        check.get("name").and_then(Value::as_str) == Some("self_revocation")
                            && check.get("status").and_then(Value::as_str) == Some("red")
                    })
                });
        if !self_revocation_red {
            bail!("RED diagnosis did not identify self revocation");
        }

        let denied_renewal = self.transport.run(member, &renew_command)?;
        if denied_renewal.status.success()
            || !String::from_utf8_lossy(&denied_renewal.stderr)
                .to_ascii_lowercase()
                .contains("revoked")
        {
            bail!("revoked member renewal was not refused at the CA boundary");
        }
        let after_denial = self.member_identity_evidence(member, run_id)?;
        if after_denial.key_sha256 != rotated.key_sha256
            || after_denial.cert_sha256 != rotated.cert_sha256
        {
            bail!("failed revoked renewal changed the member's working identity");
        }
        self.require_tls_with_run_ca(ca, member, run_id)?;

        let report = CertmeshLifecycleReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            rotation,
            ca_node: ca.id().to_owned(),
            member_node: member.id().to_owned(),
            checks: vec![
                CheckResult {
                    name: "local_key_custody".into(),
                    passed: true,
                    detail: "member key and state are mode 0600; key matches the issued leaf"
                        .into(),
                },
                CheckResult {
                    name: "chain_and_configured_zone_sans".into(),
                    passed: true,
                    detail: format!(
                        "leaf chains to the run CA and covers {} plus {}.internal",
                        member.hostname(),
                        member.hostname()
                    ),
                },
                CheckResult {
                    name: "operator_renewal_rotates_key".into(),
                    passed: true,
                    detail: format!(
                        "key {}… → {}… and CA roster tracks the new leaf",
                        &before.key_sha256[..16],
                        &rotated.key_sha256[..16]
                    ),
                },
                CheckResult {
                    name: "restart_preserves_identity".into(),
                    passed: true,
                    detail: "daemon restart preserved the rotated identity and restored the proxy"
                        .into(),
                },
                CheckResult {
                    name: "revocation_boundary".into(),
                    passed: true,
                    detail: "member pulled revocation, diagnosed RED, and CA refused renewal without changing local identity".into(),
                },
                CheckResult {
                    name: "generic_tls_revocation_limit".into(),
                    passed: true,
                    detail: "documented limitation confirmed: the unexpired revoked leaf still validates under the CA without CRL/OCSP".into(),
                },
            ],
            secrets_redacted: true,
        };
        let path = output_path(run_id.as_str())
            .join(format!("certmesh-lifecycle-{}.json", rotation.as_str()));
        self.write_json(&path, &report)?;
        Ok(report)
    }

    pub fn certmesh_recovery(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
    ) -> Result<CertmeshRecoveryReport> {
        self.certmesh_smoke(run_id, rotation)?;

        let roles = rotation.roles();
        let ca = self.remote_by_id(roles.ca)?;
        let member = self.remote_by_id(roles.service)?;
        let ca_url = self.node_url(ca)?;
        let ca_token = self.daemon_token(ca, run_id)?;
        let ca_passphrase = format!("koi-lab-{}", run_id.as_str());
        let backup_passphrase = format!("koi-lab-backup-{}", run_id.as_str());
        let restored_passphrase = format!("koi-lab-restored-{}", run_id.as_str());

        let before = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
        let ca_fingerprint = required_json_string(&before, "ca_fingerprint")?;
        let member_was_active = status_has_active_member(&before, member.hostname());
        if !member_was_active {
            bail!("backup precondition failed: member is not active in the CA roster");
        }
        let backup = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/backup"),
            Some(&ca_token),
            Some(&json!({
                "ca_passphrase": ca_passphrase,
                "backup_passphrase": backup_passphrase
            })),
        )?;
        let backup_hex = required_json_string(&backup, "backup_hex")?;
        if backup.get("format").and_then(Value::as_str) != Some("koi-backup-v1")
            || backup.get("version").and_then(Value::as_u64) != Some(2)
        {
            bail!("CA returned an unexpected backup format/version");
        }

        let wrong_restore = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/restore"),
            Some(&ca_token),
            Some(&json!({
                "backup_hex": backup_hex,
                "backup_passphrase": "deliberately-wrong-passphrase",
                "new_passphrase": restored_passphrase
            })),
        );
        if wrong_restore.is_ok() {
            bail!("restore accepted a deliberately wrong backup passphrase");
        }
        let after_wrong = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
        if required_json_string(&after_wrong, "ca_fingerprint")? != ca_fingerprint
            || !status_has_active_member(&after_wrong, member.hostname())
        {
            bail!("failed restore changed the live CA before validation completed");
        }

        self.stop_run_daemon(ca, run_id)?;
        self.wipe_run_daemon_state(ca, run_id)?;
        self.start_run_daemon(ca, run_id)?;
        wait_for_http(&format!("{ca_url}/healthz"))?;
        let empty = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
        if empty.get("ca_initialized").and_then(Value::as_bool) != Some(false) {
            bail!("run-scoped data-loss simulation did not produce a fresh CA state");
        }
        let recovery_token = self.daemon_token(ca, run_id)?;
        let restored = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/restore"),
            Some(&recovery_token),
            Some(&json!({
                "backup_hex": backup_hex,
                "backup_passphrase": backup_passphrase,
                "new_passphrase": restored_passphrase
            })),
        )?;
        if restored.get("restored").and_then(Value::as_bool) != Some(true) {
            bail!("restore did not report success");
        }
        let restored_status =
            curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
        if restored_status.get("ca_locked").and_then(Value::as_bool) != Some(false)
            || required_json_string(&restored_status, "ca_fingerprint")? != ca_fingerprint
            || !status_has_active_member(&restored_status, member.hostname())
        {
            bail!("restored CA did not recover its identity and active roster");
        }
        self.require_recovery_binding(ca, run_id)?;
        self.wait_for_member_operator_renewal(member, run_id)?;

        self.restart_run_daemon(ca, run_id)?;
        wait_for_http(&format!("{ca_url}/healthz"))?;
        let locked = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
        if locked.get("ca_locked").and_then(Value::as_bool) != Some(true)
            || required_json_string(&locked, "ca_fingerprint")? != ca_fingerprint
        {
            bail!("restored CA did not restart locked with the same public identity");
        }
        let locked_identity = self.member_identity_evidence(member, run_id)?;
        if self
            .transport
            .run(member, &self.member_renew_command(member, run_id)?)?
            .status
            .success()
        {
            bail!("member renewal succeeded while the restored CA was locked");
        }
        let after_locked_denial = self.member_identity_evidence(member, run_id)?;
        if after_locked_denial.key_sha256 != locked_identity.key_sha256
            || after_locked_denial.cert_sha256 != locked_identity.cert_sha256
        {
            bail!("failed renewal against the locked CA changed member identity");
        }

        let restarted_token = self.daemon_token(ca, run_id)?;
        if curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/unlock"),
            Some(&restarted_token),
            Some(&json!({ "passphrase": ca_passphrase })),
        )
        .is_ok()
        {
            bail!("the pre-restore CA passphrase unlocked the recovered key");
        }
        let unlocked = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/unlock"),
            Some(&restarted_token),
            Some(&json!({ "passphrase": restored_passphrase })),
        )?;
        if unlocked.get("success").and_then(Value::as_bool) != Some(true) {
            bail!("the restored passphrase did not unlock the recovered CA");
        }
        self.wait_for_member_operator_renewal(member, run_id)?;
        let ca_run_dir = ca.run_dir(run_id)?;
        self.transport.run_checked(
            ca,
            &format!(
                "set -eu; test \"$(cat {ca_run_dir}/owner)\" = {}; grep -q ' | backup_restored' {ca_run_dir}/data/logs/certmesh-audit.log",
                run_id.as_str()
            ),
        )?;

        let report = CertmeshRecoveryReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            rotation,
            ca_node: ca.id().to_owned(),
            member_node: member.id().to_owned(),
            ca_fingerprint,
            checks: vec![
                CheckResult {
                    name: "encrypted_backup_and_prevalidation".into(),
                    passed: true,
                    detail: "v2 encrypted backup created; wrong passphrase was rejected without changing live state".into(),
                },
                CheckResult {
                    name: "run_scoped_data_loss".into(),
                    passed: true,
                    detail: "only the owned CA data/runtime roots were erased; the replacement daemon started uninitialized".into(),
                },
                CheckResult {
                    name: "ca_identity_and_roster_restored".into(),
                    passed: true,
                    detail: "CA fingerprint and active member roster survived recovery".into(),
                },
                CheckResult {
                    name: "recovery_host_bound_and_online".into(),
                    passed: true,
                    detail: "recovery wrote a mode-0600 machine binding and member renewal succeeded over restored mTLS".into(),
                },
                CheckResult {
                    name: "restart_locks_recovered_key".into(),
                    passed: true,
                    detail: "restart locked the CA; renewal failed without changing the member identity".into(),
                },
                CheckResult {
                    name: "new_passphrase_restores_continuity".into(),
                    passed: true,
                    detail: "old CA passphrase failed; restored passphrase unlocked; a second key-rotating renewal succeeded".into(),
                },
            ],
            secrets_redacted: true,
        };
        let path = output_path(run_id.as_str())
            .join(format!("certmesh-recovery-{}.json", rotation.as_str()));
        self.write_json(&path, &report)?;
        Ok(report)
    }

    pub fn cleanup(&self, run_id: &RunId) -> Result<CleanupPlan> {
        let before = self.cleanup_plan(run_id)?;
        if before.nodes.iter().any(|node| !node.owner_matches) {
            bail!("cleanup refused: at least one node lock is absent or owned by another run");
        }
        for node in self.config.remotes() {
            self.cleanup_node(node, run_id)?;
        }
        let after = self.cleanup_plan(run_id)?;
        if after
            .nodes
            .iter()
            .any(|node| node.owner_matches || node.run_dir_present)
        {
            bail!("cleanup verification failed: run state remains on at least one node");
        }
        Ok(after)
    }

    fn probe_local(&self, now_epoch: i64) -> Result<NodeSnapshot> {
        let node = self.config.local()?;
        let local_ports = node.lab_ports()?.all();
        let observed_hostname = command_stdout("hostname", &[])?;
        let mut tools = BTreeMap::new();
        for tool in REQUIRED_LOCAL_TOOLS {
            tools.insert((*tool).to_owned(), command_exists(tool));
        }
        let mut blockers = Vec::new();
        if !observed_hostname.eq_ignore_ascii_case(node.hostname()) {
            blockers.push(format!(
                "hostname mismatch: expected {}, observed {observed_hostname}",
                node.hostname()
            ));
        }
        for (tool, present) in &tools {
            if !present {
                blockers.push(format!("required local tool {tool} is missing"));
            }
        }

        let sockets = command_stdout("netstat", &["-ano", "-p", "tcp"])
            .unwrap_or_default()
            .lines()
            .filter(|line| {
                line.contains("LISTENING")
                    && TEST_PORTS
                        .iter()
                        .chain(local_ports.iter())
                        .any(|port| line.contains(&format!(":{port}")))
            })
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut services = BTreeMap::new();
        let koi_service = Command::new("sc.exe").args(["query", "koi"]).output();
        if let Ok(output) = koi_service {
            let text = String::from_utf8_lossy(&output.stdout);
            services.insert(
                "koi".to_owned(),
                ServiceSnapshot {
                    active: if text.contains("RUNNING") {
                        "active".to_owned()
                    } else if output.status.success() {
                        "inactive".to_owned()
                    } else {
                        "not-found".to_owned()
                    },
                    enabled: "unknown".to_owned(),
                    exec_start: None,
                },
            );
        }
        let scenario_ready = blockers.is_empty()
            && sockets.is_empty()
            && services.values().all(|service| service.active != "active");
        let warnings = if sockets.is_empty() {
            Vec::new()
        } else {
            vec!["one or more Koi test ports are already in use locally".to_owned()]
        };
        let artifact = self.artifact_identity(None).ok();
        Ok(NodeSnapshot {
            id: node.id().to_owned(),
            expected_hostname: node.hostname().to_owned(),
            observed_hostname,
            address: node.address().to_owned(),
            operating_system: "windows".to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            utc_epoch: now_epoch,
            clock_skew_seconds: 0,
            clock_probe_span_seconds: 0,
            sudo_non_interactive: false,
            tools,
            services,
            listening_sockets: sockets,
            remote_root_present: true,
            existing_artifact_sha256: artifact.as_ref().map(|item| item.sha256.clone()),
            existing_artifact_version: None,
            deploy_ready: blockers.is_empty(),
            scenario_ready,
            blockers,
            warnings,
        })
    }

    pub(crate) fn remote_by_id(&self, id: &str) -> Result<&NodeSpec> {
        self.config
            .remotes()
            .find(|node| node.id() == id)
            .with_context(|| format!("lab config has no remote node {id}"))
    }

    pub(crate) fn node_url(&self, node: &NodeSpec) -> Result<String> {
        Ok(format!(
            "http://{}:{}",
            node.address(),
            node.lab_ports()?.http
        ))
    }

    fn start_run_daemon(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.launch_run_daemon(node, run_id, false, DaemonProfile::Certmesh)
    }

    pub(crate) fn start_story_daemon(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.launch_run_daemon(node, run_id, false, DaemonProfile::CapabilityStory)
    }

    pub(crate) fn start_runtime_reconnect_daemon(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
    ) -> Result<()> {
        self.launch_run_daemon(node, run_id, false, DaemonProfile::RuntimeReconnect)
    }

    pub(crate) fn restart_story_daemon(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.stop_run_daemon(node, run_id)?;
        self.launch_run_daemon(node, run_id, true, DaemonProfile::CapabilityStory)
    }

    pub(crate) fn stop_story_daemon(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.stop_run_daemon(node, run_id)
    }

    fn restart_run_daemon(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.stop_run_daemon(node, run_id)?;
        self.launch_run_daemon(node, run_id, true, DaemonProfile::Certmesh)
    }

    fn launch_run_daemon(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
        preserve_state: bool,
        profile: DaemonProfile,
    ) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let ports = node.lab_ports()?;
        let http_port = ports.http;
        let mtls_port = ports.mtls;
        let acme_port = ports.acme;
        let proxy_port = ports.proxy;
        let dns_port = ports.dns;
        let fixture_port = ports.fixture;
        let prepare = if preserve_state {
            format!(
                "test -d {run_dir}/data; mkdir -p {run_dir}/runtime; rm -f {run_dir}/runtime/koi.endpoint"
            )
        } else {
            format!(
                "test ! -e {run_dir}/data; test ! -e {run_dir}/runtime; mkdir {run_dir}/data {run_dir}/runtime"
            )
        };
        let profile_args = match profile {
            DaemonProfile::Certmesh => {
                "--no-ipc --no-mdns --no-dns --no-health --no-udp --no-runtime --no-acme --no-mcp-http"
                    .to_owned()
            }
            DaemonProfile::CapabilityStory | DaemonProfile::RuntimeReconnect => format!(
                "--dns-port {dns_port} --dns-public --announce-http --runtime docker"
            ),
        };
        let guarded_ports = match profile {
            DaemonProfile::Certmesh => {
                format!("{http_port}|{mtls_port}|{acme_port}|{proxy_port}")
            }
            DaemonProfile::CapabilityStory | DaemonProfile::RuntimeReconnect => format!(
                "{http_port}|{mtls_port}|{acme_port}|{proxy_port}|{dns_port}|{fixture_port}|{}",
                ports.container
            ),
        };
        let runtime_env = match profile {
            DaemonProfile::RuntimeReconnect => {
                format!(" DOCKER_HOST=unix://{run_dir}/docker-proxy.sock")
            }
            DaemonProfile::Certmesh | DaemonProfile::CapabilityStory => String::new(),
        };
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test ! -e {run_dir}/daemon.pid; ! ss -H -lntup | grep -Eq ':({guarded_ports}) '; {prepare}; setsid -f sh -c 'echo $$ > {run_dir}/daemon.pid; exec env KOI_DATA_DIR={run_dir}/data KOI_DNS_ZONE=internal XDG_RUNTIME_DIR={run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1{runtime_env} {run_dir}/koi --daemon --port {http_port} --http-bind 0.0.0.0 --mtls-port {mtls_port} --acme-port {acme_port} {profile_args} >>{run_dir}/daemon.log 2>&1'",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    fn stop_run_daemon(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test -f {run_dir}/daemon.pid; pid=$(cat {run_dir}/daemon.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; kill -0 \"$pid\"; exe=$(readlink -f /proc/\"$pid\"/exe); test \"$exe\" = {run_dir}/koi; kill \"$pid\"; i=0; while kill -0 \"$pid\" 2>/dev/null && test \"$i\" -lt 100; do sleep .1; i=$((i+1)); done; ! kill -0 \"$pid\" 2>/dev/null; rm -f {run_dir}/daemon.pid",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    pub(crate) fn start_story_fixture(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let port = node.lab_ports()?.fixture;
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test ! -e {run_dir}/fixture.pid; ! ss -H -lnt | grep -Eq ':{port} '; nc_exe=$(realpath \"$(command -v nc)\"); printf '%s' \"$nc_exe\" > {run_dir}/fixture.exe; setsid -f sh -c 'echo $$ > {run_dir}/fixture.pid; exec nc -lk 127.0.0.1 {port} >>{run_dir}/fixture.log 2>&1'; i=0; while ! ss -H -lnt | grep -Eq ':{port} ' && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; ss -H -lnt | grep -Eq ':{port} '",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    pub(crate) fn stop_story_fixture(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test -f {run_dir}/fixture.pid; test -f {run_dir}/fixture.exe; pid=$(cat {run_dir}/fixture.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; expected=$(cat {run_dir}/fixture.exe); test \"$(readlink -f /proc/\"$pid\"/exe)\" = \"$expected\"; kill \"$pid\"; i=0; while kill -0 \"$pid\" 2>/dev/null && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; ! kill -0 \"$pid\" 2>/dev/null; rm -f {run_dir}/fixture.pid",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    pub(crate) fn start_story_dns_blocker(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let port = node.lab_ports()?.dns;
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test ! -e {run_dir}/dns-blocker.pid; i=0; while ss -H -lnu | grep -Eq ':{port} ' && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; ! ss -H -lnu | grep -Eq ':{port} '; nc_exe=$(realpath \"$(command -v nc)\"); printf '%s' \"$nc_exe\" > {run_dir}/dns-blocker.exe; setsid -f sh -c 'echo $$ > {run_dir}/dns-blocker.pid; exec nc -u -lk 0.0.0.0 {port} >>{run_dir}/dns-blocker.log 2>&1'; i=0; while ! ss -H -lnu | grep -Eq ':{port} ' && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; ss -H -lnu | grep -Eq ':{port} '",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    pub(crate) fn stop_story_dns_blocker(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let port = node.lab_ports()?.dns;
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test -f {run_dir}/dns-blocker.pid; test -f {run_dir}/dns-blocker.exe; pid=$(cat {run_dir}/dns-blocker.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; expected=$(cat {run_dir}/dns-blocker.exe); test \"$(readlink -f /proc/\"$pid\"/exe)\" = \"$expected\"; kill \"$pid\"; i=0; while kill -0 \"$pid\" 2>/dev/null && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; ! kill -0 \"$pid\" 2>/dev/null; i=0; while ss -H -lnu | grep -Eq ':{port} ' && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; ! ss -H -lnu | grep -Eq ':{port} '; rm -f {run_dir}/dns-blocker.pid",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    pub(crate) fn stage_runtime_proxy(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let remote_script = format!("{run_dir}/docker_socket_proxy.py");
        let local_script = self
            .repo_root
            .join("tools/koi-lab/fixtures/docker_socket_proxy.py");
        self.transport.run_checked(
            node,
            &format!(
                "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test ! -e {remote_script}; test ! -e {run_dir}/docker-proxy.exe",
                run_id.as_str(),
                run_id.as_str()
            ),
        )?;
        self.transport
            .copy_to(node, &local_script, &remote_script)?;
        self.transport.run_checked(
            node,
            &format!(
                "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; chmod 700 {remote_script}; python=$(realpath \"$(command -v python3)\"); test -x \"$python\"; printf '%s' \"$python\" > {run_dir}/docker-proxy.exe",
                run_id.as_str(),
                run_id.as_str()
            ),
        )?;
        Ok(())
    }

    pub(crate) fn start_runtime_proxy(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test -x {run_dir}/docker_socket_proxy.py; test -f {run_dir}/docker-proxy.exe; test ! -e {run_dir}/docker-proxy.pid; test ! -e {run_dir}/docker-proxy.sock; setsid -f sh -c 'echo $$ > {run_dir}/docker-proxy.pid; exec \"$(cat {run_dir}/docker-proxy.exe)\" {run_dir}/docker_socket_proxy.py --listen {run_dir}/docker-proxy.sock --upstream /var/run/docker.sock >>{run_dir}/docker-proxy.log 2>&1'; i=0; while ! test -S {run_dir}/docker-proxy.sock && test \"$i\" -lt 100; do sleep .1; i=$((i+1)); done; test -S {run_dir}/docker-proxy.sock; test \"$(stat -c %a {run_dir}/docker-proxy.sock)\" = 600; pid=$(cat {run_dir}/docker-proxy.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; test \"$(readlink -f /proc/\"$pid\"/exe)\" = \"$(cat {run_dir}/docker-proxy.exe)\"; tr '\\000' ' ' </proc/\"$pid\"/cmdline | grep -F -- '{run_dir}/docker_socket_proxy.py --listen {run_dir}/docker-proxy.sock --upstream /var/run/docker.sock' >/dev/null",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    pub(crate) fn stop_runtime_proxy(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.transport
            .run_checked(node, &runtime_proxy_stop_script(node, run_id, true)?)?;
        Ok(())
    }

    pub(crate) fn remove_runtime_proxy_files(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        self.transport.run_checked(
            node,
            &format!(
                "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test ! -e {run_dir}/docker-proxy.pid; test ! -e {run_dir}/docker-proxy.sock; rm -f {run_dir}/docker-proxy.log {run_dir}/docker-proxy.exe {run_dir}/docker_socket_proxy.py",
                run_id.as_str(),
                run_id.as_str()
            ),
        )?;
        Ok(())
    }

    pub(crate) fn start_runtime_fault_container(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
        role: RuntimeFaultRole,
    ) -> Result<String> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let image_ref = story_image_ref(run_id);
        let container_name = runtime_fault_container_name(run_id, role);
        let marker = runtime_fault_container_marker(&run_dir, role);
        let common_labels = format!(
            "--label org.sylin.koi.lab.owner=koi-lab --label org.sylin.koi.lab.run={} --label org.sylin.koi.lab.role={}",
            run_id.as_str(),
            role.as_str()
        );
        let ports = node.lab_ports()?;
        let managed = if role == RuntimeFaultRole::Unchanged {
            format!(
                "--label koi.enable=true --label koi.name=koi-reconnect-{} --label koi.type=_http._tcp --label koi.dns.name=reconnect-{} --label koi.health.path=/healthz --label koi.health.kind=http --label koi.health.interval=1 --label koi.health.timeout=1 --label koi.proxy.port={} --label koi.proxy.remote=true --label koi.txt.run={} --publish {}:{}:5641",
                runtime_fault_suffix(run_id),
                runtime_fault_suffix(run_id),
                ports.proxy,
                run_id.as_str(),
                node.address(),
                ports.container
            )
        } else {
            "--label koi.enable=false".to_owned()
        };
        let readiness = if role == RuntimeFaultRole::Unchanged {
            format!(
                "i=0; while ! curl --silent --fail --max-time 1 http://{}:{}/healthz >/dev/null && test \"$i\" -lt 100; do sleep .1; i=$((i+1)); done; curl --silent --fail --max-time 2 http://{}:{}/healthz >/dev/null;",
                node.address(),
                ports.container,
                node.address(),
                ports.container
            )
        } else {
            "test \"$(docker container inspect \"$cid\" | jq -r '.[0].State.Running')\" = true;"
                .to_owned()
        };
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test \"$(cat {run_dir}/image.ref)\" = {image_ref}; test ! -e {marker}; ! docker container inspect {container_name} >/dev/null 2>&1; cid=$(docker create --name {container_name} {common_labels} {managed} {image_ref} --daemon --port 5641 --http-bind 0.0.0.0 --no-ipc --no-mdns --no-dns --no-health --no-proxy --no-udp --no-runtime --no-acme --no-mcp-http); case \"$cid\" in ''|*[!0-9a-f]*) exit 76;; esac; printf '%s' \"$cid\" > {marker}; docker start \"$cid\" >/dev/null; {readiness} printf '%s' \"$cid\"",
            run_id.as_str(),
            run_id.as_str()
        );
        Ok(self
            .transport
            .run_checked(node, &command)?
            .trim()
            .to_owned())
    }

    pub(crate) fn stop_runtime_fault_container(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
        role: RuntimeFaultRole,
    ) -> Result<()> {
        self.transport.run_checked(
            node,
            &runtime_fault_container_remove_script(node, run_id, role, true)?,
        )?;
        Ok(())
    }

    pub(crate) fn connect_runtime_fault_network(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
        role: RuntimeFaultRole,
    ) -> Result<String> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let marker = runtime_fault_container_marker(&run_dir, role);
        let network_name = runtime_fault_network_name(run_id);
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test -f {marker}; test ! -e {run_dir}/runtime-fault-network.id; ! docker network inspect {network_name} >/dev/null 2>&1; nid=$(docker network create --label org.sylin.koi.lab.owner=koi-lab --label org.sylin.koi.lab.run={} {network_name}); case \"$nid\" in ''|*[!0-9a-f]*) exit 76;; esac; printf '%s' \"$nid\" > {run_dir}/runtime-fault-network.id; docker network connect {network_name} \"$(cat {marker})\"; printf '%s' \"$nid\"",
            run_id.as_str(),
            run_id.as_str(),
            run_id.as_str()
        );
        Ok(self
            .transport
            .run_checked(node, &command)?
            .trim()
            .to_owned())
    }

    pub(crate) fn remove_runtime_fault_network(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
    ) -> Result<()> {
        self.transport
            .run_checked(node, &runtime_fault_network_remove_script(node, run_id)?)?;
        Ok(())
    }

    pub(crate) fn stage_story_container_image(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
    ) -> Result<()> {
        let local_root = self.repo_root.join(output_path(run_id.as_str()));
        fs::create_dir_all(&local_root).with_context(|| {
            format!(
                "could not create story output directory {}",
                local_root.display()
            )
        })?;
        let context_dir = local_root.join("story-image-context");
        let archive = local_root.join("story-image.tar");
        if context_dir.exists() || archive.exists() {
            bail!("story image staging paths already exist for {run_id:?}");
        }
        fs::create_dir(&context_dir)
            .with_context(|| format!("could not create image context {}", context_dir.display()))?;

        let image_ref = story_image_ref(run_id);
        let remote_run_dir = node.run_dir(run_id)?;
        let remote_archive = format!("{remote_run_dir}/story-image.tar");
        let local_binary = context_dir.join("koi");
        let dockerfile = context_dir.join("Dockerfile");
        let mut local_image_created = false;

        let result = (|| -> Result<()> {
            let inspect = Command::new("docker")
                .args(["image", "inspect", &image_ref])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .context("failed to inspect the local story image tag")?;
            if inspect.success() {
                bail!("local story image tag already exists: {image_ref}");
            }

            self.transport
                .copy_from(node, &format!("{remote_run_dir}/koi"), &local_binary)?;
            let copied = ArtifactIdentity::from_path(&local_binary)?;
            let expected =
                self.remote_line(node, &format!("cat {remote_run_dir}/artifact.sha256"))?;
            if copied.sha256 != expected {
                bail!(
                    "copied container fixture binary has SHA-256 {}, expected {expected}",
                    copied.sha256
                );
            }

            fs::write(
                &dockerfile,
                format!(
                    "FROM scratch\nCOPY koi /koi\nLABEL org.sylin.koi.lab.run=\"{}\"\nENTRYPOINT [\"/koi\"]\n",
                    run_id.as_str()
                ),
            )
            .with_context(|| format!("could not write {}", dockerfile.display()))?;

            let build = Command::new("docker")
                .args([
                    "build",
                    "--network=none",
                    "--platform=linux/amd64",
                    "--tag",
                    &image_ref,
                ])
                .arg(&context_dir)
                .status()
                .context("failed to start the local story image build")?;
            if !build.success() {
                bail!("local story image build failed with exit {build}");
            }
            local_image_created = true;

            let save = Command::new("docker")
                .args(["image", "save", "--output"])
                .arg(&archive)
                .arg(&image_ref)
                .status()
                .context("failed to start the local story image save")?;
            if !save.success() {
                bail!("local story image save failed with exit {save}");
            }
            self.transport.copy_to(node, &archive, &remote_archive)?;

            let lock_dir = node.lock_dir()?;
            let command = format!(
                "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {remote_run_dir}/owner)\" = {}; test -f {remote_archive}; test ! -e {remote_run_dir}/image.ref; test ! -e {remote_run_dir}/image.id; ! docker image inspect {image_ref} >/dev/null 2>&1; printf '%s' {image_ref} > {remote_run_dir}/image.ref; docker image load --input {remote_archive} >/dev/null; test \"$(docker image inspect {image_ref} | jq -r '.[0].Config.Labels[\"org.sylin.koi.lab.run\"]')\" = {}; docker image inspect {image_ref} | jq -r '.[0].Id' > {remote_run_dir}/image.id; rm -f {remote_archive}",
                run_id.as_str(),
                run_id.as_str(),
                run_id.as_str()
            );
            self.transport.run_checked(node, &command)?;
            Ok(())
        })();

        let mut cleanup_failures = Vec::new();
        if local_image_created {
            match Command::new("docker")
                .args(["image", "rm", &image_ref])
                .status()
            {
                Ok(status) if status.success() => {}
                Ok(status) => cleanup_failures.push(format!(
                    "local image tag {image_ref} removal exited {status}"
                )),
                Err(error) => cleanup_failures.push(format!(
                    "could not start local image tag {image_ref} removal: {error}"
                )),
            }
        }
        if archive.exists() {
            if let Err(error) = fs::remove_file(&archive) {
                cleanup_failures.push(format!("could not remove {}: {error}", archive.display()));
            }
        }
        if context_dir.exists() {
            if let Err(error) = fs::remove_dir_all(&context_dir) {
                cleanup_failures.push(format!(
                    "could not remove {}: {error}",
                    context_dir.display()
                ));
            }
        }

        match (result, cleanup_failures.is_empty()) {
            (Ok(()), true) => Ok(()),
            (Err(error), true) => Err(error),
            (Ok(()), false) => bail!("{}", cleanup_failures.join("; ")),
            (Err(error), false) => Err(error).context(cleanup_failures.join("; ")),
        }
    }

    pub(crate) fn start_story_container(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
        service_name: &str,
        dns_name: &str,
    ) -> Result<String> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let ports = node.lab_ports()?;
        let image_ref = story_image_ref(run_id);
        let container_name = story_container_name(run_id);
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test \"$(cat {run_dir}/image.ref)\" = {image_ref}; test ! -e {run_dir}/container.id; ! docker container inspect {container_name} >/dev/null 2>&1; ! ss -H -lnt | grep -Eq ':{} '; cid=$(docker create --name {container_name} --label org.sylin.koi.lab.owner=koi-lab --label org.sylin.koi.lab.run={} --label koi.enable=true --label koi.name={service_name} --label koi.type=_http._tcp --label koi.dns.name={dns_name} --label koi.health.path=/healthz --label koi.health.kind=http --label koi.health.interval=1 --label koi.health.timeout=1 --label koi.proxy.port={} --label koi.proxy.remote=true --label koi.txt.run={} --publish {}:{}:5641 {image_ref} --daemon --port 5641 --http-bind 0.0.0.0 --no-ipc --no-mdns --no-dns --no-health --no-proxy --no-udp --no-runtime --no-acme --no-mcp-http); case \"$cid\" in ''|*[!0-9a-f]*) exit 76;; esac; printf '%s' \"$cid\" > {run_dir}/container.id; docker start \"$cid\" >/dev/null; i=0; while ! curl --silent --fail --max-time 1 http://{}:{}/healthz >/dev/null && test \"$i\" -lt 100; do sleep .1; i=$((i+1)); done; curl --silent --fail --max-time 2 http://{}:{}/healthz >/dev/null; printf '%s' \"$cid\"",
            run_id.as_str(),
            run_id.as_str(),
            ports.container,
            run_id.as_str(),
            ports.proxy,
            run_id.as_str(),
            node.address(),
            ports.container,
            node.address(),
            ports.container,
            node.address(),
            ports.container,
        );
        Ok(self
            .transport
            .run_checked(node, &command)?
            .trim()
            .to_owned())
    }

    pub(crate) fn stop_story_container(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.transport
            .run_checked(node, &story_container_remove_script(node, run_id, true)?)?;
        Ok(())
    }

    pub(crate) fn cleanup_story_container(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.transport
            .run_checked(node, &story_container_remove_script(node, run_id, false)?)?;
        Ok(())
    }

    pub(crate) fn remove_story_container_image(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
    ) -> Result<()> {
        self.transport
            .run_checked(node, &story_image_remove_script(node, run_id, true)?)?;
        Ok(())
    }

    pub(crate) fn cleanup_story_container_image(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
    ) -> Result<()> {
        self.transport
            .run_checked(node, &story_image_remove_script(node, run_id, false)?)?;
        Ok(())
    }

    pub(crate) fn run_remote(
        &self,
        node: &NodeSpec,
        command: &str,
    ) -> Result<std::process::Output> {
        self.transport.run(node, command)
    }

    pub(crate) fn run_remote_checked(&self, node: &NodeSpec, command: &str) -> Result<String> {
        self.transport.run_checked(node, command)
    }

    pub(crate) fn copy_from_remote(
        &self,
        node: &NodeSpec,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<()> {
        self.transport.copy_from(node, remote_path, local_path)
    }

    fn wipe_run_daemon_state(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let data = format!("{run_dir}/data");
        let runtime = format!("{run_dir}/runtime");
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test ! -e {run_dir}/daemon.pid; test -d {data}; test -d {runtime}; test \"$(realpath {data})\" = {data}; test \"$(realpath {runtime})\" = {runtime}; rm -rf -- {data} {runtime}; test ! -e {data}; test ! -e {runtime}",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    pub(crate) fn member_renew_command(&self, member: &NodeSpec, run_id: &RunId) -> Result<String> {
        let run_dir = member.run_dir(run_id)?;
        Ok(format!(
            "set -eu; test \"$(cat {run_dir}/owner)\" = {}; env KOI_DATA_DIR={run_dir}/data XDG_RUNTIME_DIR={run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1 {run_dir}/koi certmesh renew --json",
            run_id.as_str()
        ))
    }

    fn wait_for_member_operator_renewal(&self, member: &NodeSpec, run_id: &RunId) -> Result<()> {
        let before = self.member_identity_evidence(member, run_id)?;
        let command = self.member_renew_command(member, run_id)?;
        let mut last = String::new();
        for _ in 0..40 {
            let output = self.transport.run(member, &command)?;
            if output.status.success() {
                let renewed: Value = serde_json::from_slice(&output.stdout)
                    .context("operator renewal returned invalid JSON")?;
                if renewed.get("renewed").and_then(Value::as_bool) == Some(true) {
                    let after = self.member_identity_evidence(member, run_id)?;
                    if after.key_sha256 == before.key_sha256
                        || after.cert_sha256 == before.cert_sha256
                    {
                        bail!("operator renewal did not rotate member identity material");
                    }
                    return Ok(());
                }
                last = renewed.to_string();
            } else {
                last = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            }
            thread::sleep(Duration::from_millis(250));
        }
        bail!("member renewal did not recover after CA activation: {last}")
    }

    fn require_recovery_binding(&self, ca: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = ca.run_dir(run_id)?;
        self.transport.run_checked(
            ca,
            &format!(
                "set -eu; test \"$(cat {run_dir}/owner)\" = {}; bind={run_dir}/data/certmesh/ca/machine.bind; test -f \"$bind\"; test \"$(stat -c %a \"$bind\")\" = 600; machine_id=$(tr -d '\\r\\n' </etc/machine-id); expected=$(printf 'koi-machine-bind:%s' \"$machine_id\" | sha256sum | cut -d' ' -f1); test \"$(cat \"$bind\")\" = \"$expected\"",
                run_id.as_str()
            ),
        )?;
        Ok(())
    }

    pub(crate) fn member_identity_evidence(
        &self,
        member: &NodeSpec,
        run_id: &RunId,
    ) -> Result<MemberIdentityEvidence> {
        let run_dir = member.run_dir(run_id)?;
        let hostname = member.hostname();
        let cert_dir = format!("{run_dir}/data/certs/{hostname}");
        let key = format!("{cert_dir}/key.pem");
        let cert = format!("{cert_dir}/cert.pem");
        let ca = format!("{cert_dir}/ca.pem");
        let fullchain = format!("{cert_dir}/fullchain.pem");
        let member_state = format!("{run_dir}/data/certmesh/member.json");

        let metadata = self.remote_line(
            member,
            &format!(
                "set -eu; test \"$(cat {run_dir}/owner)\" = {}; test \"$(stat -c %a {key})\" = 600; test \"$(stat -c %a {member_state})\" = 600; test \"$(grep -c 'BEGIN CERTIFICATE' {fullchain})\" = 2; key_pub=$(openssl pkey -in {key} -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1); cert_pub=$(openssl x509 -in {cert} -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1); test \"$key_pub\" = \"$cert_pub\"; openssl verify -CAfile {ca} {cert} >/dev/null; key_sha=$(sha256sum {key} | cut -d' ' -f1); cert_sha=$(sha256sum {cert} | cut -d' ' -f1); cert_fp=$(openssl x509 -in {cert} -outform DER | sha256sum | cut -d' ' -f1); printf '%s|%s|%s' \"$key_sha\" \"$cert_sha\" \"$cert_fp\"",
                run_id.as_str()
            ),
        )?;
        let mut fields = metadata.split('|');
        let key_sha256 = fields.next().unwrap_or_default().to_owned();
        let cert_sha256 = fields.next().unwrap_or_default().to_owned();
        let cert_fingerprint = fields.next().unwrap_or_default().to_owned();
        if fields.next().is_some()
            || !is_sha256(&key_sha256)
            || !is_sha256(&cert_sha256)
            || !is_sha256(&cert_fingerprint)
        {
            bail!("member identity evidence returned malformed fingerprints");
        }

        let sans = self.remote_line(
            member,
            &format!("openssl x509 -in {cert} -noout -ext subjectAltName"),
        )?;
        let sans = sans.to_ascii_lowercase();
        let host = hostname.to_ascii_lowercase();
        if !sans.contains(&format!("dns:{host}")) || !sans.contains(&format!("dns:{host}.internal"))
        {
            bail!("member leaf does not cover hostname plus configured-zone FQDN");
        }

        Ok(MemberIdentityEvidence {
            key_sha256,
            cert_sha256,
            cert_fingerprint,
        })
    }

    fn member_diagnosis(&self, member: &NodeSpec, run_id: &RunId) -> Result<Value> {
        let run_dir = member.run_dir(run_id)?;
        let output = self.transport.run(
            member,
            &format!(
                "env KOI_DATA_DIR={run_dir}/data KOI_DNS_ZONE=internal KOI_NO_CREDENTIAL_STORE=1 {run_dir}/koi trust diagnose --json"
            ),
        )?;
        serde_json::from_slice(&output.stdout)
            .context("member trust diagnosis returned invalid JSON")
    }

    fn wait_for_red_member_diagnosis(&self, member: &NodeSpec, run_id: &RunId) -> Result<Value> {
        let mut last = Value::Null;
        for _ in 0..30 {
            let diagnosis = self.member_diagnosis(member, run_id)?;
            if diagnosis.get("overall").and_then(Value::as_str) == Some("red") {
                return Ok(diagnosis);
            }
            last = diagnosis;
            thread::sleep(Duration::from_millis(250));
        }
        bail!("member diagnosis did not become RED after revocation: {last}")
    }

    fn require_tls_with_run_ca(
        &self,
        client: &NodeSpec,
        service: &NodeSpec,
        run_id: &RunId,
    ) -> Result<()> {
        let service_port = service.lab_ports()?.proxy;
        let ca_run_dir = client.run_dir(run_id)?;
        let ca_pem = format!("{ca_run_dir}/data/certmesh/ca/ca-cert.pem");
        let output = self.transport.run(
            client,
            &format!(
                "curl --silent --show-error --fail --max-time 10 --resolve {}:{service_port}:{} --cacert {ca_pem} https://{}:{service_port}/healthz",
                service.hostname(),
                service.address(),
                service.hostname()
            ),
        )?;
        if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "OK" {
            bail!(
                "run-CA TLS verification failed from {} to {}: {}",
                client.id(),
                service.id(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    pub(crate) fn daemon_token(&self, node: &NodeSpec, run_id: &RunId) -> Result<String> {
        let run_dir = node.run_dir(run_id)?;
        for _ in 0..50 {
            let token = self.remote_line(
                node,
                &format!(
                    "test -f {run_dir}/runtime/koi.endpoint && sed -n '2s/^dat://p' {run_dir}/runtime/koi.endpoint || true"
                ),
            )?;
            if !token.is_empty() {
                return Ok(token);
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("node {} did not produce a daemon token", node.id())
    }

    pub(crate) fn require_native_client_privilege(&self, client: &NodeSpec) -> Result<()> {
        match client {
            NodeSpec::LocalWindows { .. } => ensure_windows_elevated(),
            NodeSpec::PuttyLinux { .. } => {
                if self.transport.run(client, "sudo -n true")?.status.success() {
                    Ok(())
                } else {
                    bail!(
                        "native trust refused: {} lacks passwordless sudo",
                        client.id()
                    )
                }
            }
        }
    }

    pub(crate) fn native_trust_fingerprint(&self, client: &NodeSpec) -> Result<String> {
        match client {
            NodeSpec::LocalWindows { .. } => windows_trust_fingerprint(),
            NodeSpec::PuttyLinux { .. } => self.system_trust_fingerprint(client),
        }
    }

    fn system_trust_fingerprint(&self, node: &NodeSpec) -> Result<String> {
        self.remote_line(
            node,
            "find /usr/local/share/ca-certificates /etc/ssl/certs -maxdepth 2 -printf '%p|%y|%s|%l\\n' 2>/dev/null | sort | sha256sum | cut -d' ' -f1",
        )
    }

    pub(crate) fn native_tls_curl(
        &self,
        client: &NodeSpec,
        service: &NodeSpec,
        hostname: &str,
    ) -> Result<std::process::Output> {
        let port = service.lab_ports()?.proxy;
        match client {
            NodeSpec::PuttyLinux { .. } => self.transport.run(
                client,
                &format!(
                    "curl --noproxy '*' --silent --show-error --fail --max-time 10 --resolve {hostname}:{port}:{} https://{hostname}:{port}/healthz",
                    service.address()
                ),
            ),
            NodeSpec::LocalWindows { .. } => Command::new("curl.exe")
                .args(windows_curl_args(
                    service.address(),
                    hostname,
                    port,
                ))
                .output()
                .context("failed to start Windows curl.exe"),
        }
    }

    pub(crate) fn native_tls_secondary(
        &self,
        client: &NodeSpec,
        service: &NodeSpec,
        hostname: &str,
        run_id: &RunId,
    ) -> Result<std::process::Output> {
        let port = service.lab_ports()?.proxy;
        match client {
            NodeSpec::PuttyLinux { .. } => self.transport.run(
                client,
                &format!(
                    "openssl s_client -connect {}:{port} -servername {hostname} -verify_return_error -verify_hostname {hostname} </dev/null >/dev/null 2>&1",
                    service.address()
                ),
            ),
            NodeSpec::LocalWindows { .. } => windows_invoke_web_request(
                service.address(),
                hostname,
                port,
                run_id,
            ),
        }
    }

    pub(crate) fn install_native_trust(
        &self,
        client: &NodeSpec,
        ca: &NodeSpec,
        run_id: &RunId,
    ) -> Result<InstalledTrust> {
        let ca_run_dir = ca.run_dir(run_id)?;
        let remote_ca_pem = format!("{ca_run_dir}/data/certmesh/ca/ca-cert.pem");
        let (source, state, output) = match client {
            NodeSpec::PuttyLinux { .. } => {
                if client.id() != ca.id() {
                    bail!(
                        "Linux rotations require the native client to hold the run-owned CA root"
                    );
                }
                let state = format!("{ca_run_dir}/trust-state");
                let command = native_trust_install_command(client, run_id, &remote_ca_pem, &state)?;
                let output = self.transport.run_checked(client, &command)?;
                (remote_ca_pem, state, output)
            }
            NodeSpec::LocalWindows { .. } => {
                let root = self.prepare_windows_trust_dir(run_id)?;
                let source_path = root.join("ca-cert.pem");
                let state_path = root.join("state");
                self.transport.copy_from(ca, &remote_ca_pem, &source_path)?;
                let output = self.run_windows_koi(
                    &state_path,
                    &["--json", "trust", "install"],
                    Some(&source_path),
                )?;
                if !output.status.success() {
                    bail!(
                        "Windows trust install failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
                (
                    source_path.display().to_string(),
                    state_path.display().to_string(),
                    String::from_utf8(output.stdout)
                        .context("Windows trust install returned non-UTF-8 output")?,
                )
            }
        };

        let identity = parse_installed_trust(&output).or_else(|parse_error| {
            // The OS store may already have changed even when stdout is malformed.
            // Recover the one identity from this fresh run state and compensate.
            let recovery = self.single_tracked_trust(client, run_id, &state, &source)?;
            match self.remove_native_trust(client, run_id, &recovery) {
                Ok(()) => Err(parse_error.context("native trust install was rolled back")),
                Err(cleanup_error) => Err(parse_error.context(format!(
                    "native trust install output was invalid and rollback failed: {cleanup_error:#}"
                ))),
            }
        })?;
        let installed = InstalledTrust {
            name: identity.0,
            fingerprint: identity.1,
            source,
            state,
        };
        if matches!(client, NodeSpec::LocalWindows { .. }) {
            let store_check = windows_store_contains(&installed.fingerprint);
            if !matches!(store_check, Ok(true)) {
                self.remove_native_trust(client, run_id, &installed)
                    .context("Windows store verification failed and rollback also failed")?;
                match store_check {
                    Ok(false) => bail!(
                        "Windows LocalMachine\\Root does not contain the installed fingerprint"
                    ),
                    Err(error) => {
                        return Err(error)
                            .context("Windows store verification failed after install")
                    }
                    Ok(true) => unreachable!(),
                }
            }
        }
        Ok(installed)
    }

    pub(crate) fn native_trust_is_tracked(
        &self,
        client: &NodeSpec,
        run_id: &RunId,
        installed: &InstalledTrust,
    ) -> Result<bool> {
        let list = self.native_trust_list(client, run_id, &installed.state)?;
        Ok(list
            .get("roots")
            .and_then(Value::as_array)
            .is_some_and(|roots| {
                roots.iter().any(|root| {
                    root.get("name").and_then(Value::as_str) == Some(&installed.name)
                        && root.get("fingerprint").and_then(Value::as_str)
                            == Some(&installed.fingerprint)
                })
            }))
    }

    fn native_trust_list(&self, client: &NodeSpec, run_id: &RunId, state: &str) -> Result<Value> {
        let output = match client {
            NodeSpec::PuttyLinux { .. } => {
                let run_dir = client.run_dir(run_id)?;
                let command = format!(
                    "sudo -n env KOI_DATA_DIR={} {run_dir}/koi --json trust list",
                    state
                );
                self.transport.run_checked(client, &command)?
            }
            NodeSpec::LocalWindows { .. } => {
                let output =
                    self.run_windows_koi(Path::new(state), &["--json", "trust", "list"], None)?;
                if !output.status.success() {
                    bail!("Windows trust list failed");
                }
                String::from_utf8(output.stdout)
                    .context("Windows trust list returned non-UTF-8 output")?
            }
        };
        serde_json::from_str(output.trim()).context("native trust list returned invalid JSON")
    }

    fn single_tracked_trust(
        &self,
        client: &NodeSpec,
        run_id: &RunId,
        state: &str,
        source: &str,
    ) -> Result<InstalledTrust> {
        let list = self.native_trust_list(client, run_id, state)?;
        let roots = list
            .get("roots")
            .and_then(Value::as_array)
            .context("native trust state omitted roots")?;
        if roots.len() != 1 {
            bail!("fresh native trust state did not contain exactly one recovery identity");
        }
        let name = required_json_string(&roots[0], "name")?;
        let fingerprint = required_json_string(&roots[0], "fingerprint")?;
        if name != "koi-ca-cert" || !is_sha256(&fingerprint) {
            bail!("native trust recovery identity is unsafe");
        }
        Ok(InstalledTrust {
            name,
            fingerprint,
            source: source.to_string(),
            state: state.to_string(),
        })
    }

    pub(crate) fn remove_native_trust(
        &self,
        client: &NodeSpec,
        run_id: &RunId,
        installed: &InstalledTrust,
    ) -> Result<()> {
        match client {
            NodeSpec::PuttyLinux { .. } => {
                let command = native_trust_remove_command(
                    client,
                    run_id,
                    &installed.name,
                    &installed.fingerprint,
                    &installed.state,
                )?;
                self.transport.run_checked(client, &command)?;
            }
            NodeSpec::LocalWindows { .. } => {
                let root = self.windows_trust_dir(run_id);
                let expected_source = root.join("ca-cert.pem");
                let expected_state = root.join("state");
                if Path::new(&installed.source) != expected_source
                    || Path::new(&installed.state) != expected_state
                    || !is_sha256(&installed.fingerprint)
                {
                    bail!("Windows trust cleanup identity is not exact");
                }
                let output = self.run_windows_koi(
                    &expected_state,
                    &["--json", "trust", "remove", &installed.name],
                    None,
                )?;
                if !output.status.success() {
                    bail!(
                        "Windows trust remove failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
                if windows_store_contains(&installed.fingerprint)? {
                    bail!("Windows LocalMachine\\Root still contains the removed fingerprint");
                }
                self.cleanup_windows_trust_dir(run_id, &expected_source, &expected_state)?;
            }
        }
        Ok(())
    }

    fn windows_trust_dir(&self, run_id: &RunId) -> PathBuf {
        self.repo_root
            .join(output_path(run_id.as_str()))
            .join("windows-trust")
    }

    fn prepare_windows_trust_dir(&self, run_id: &RunId) -> Result<PathBuf> {
        let root = self.windows_trust_dir(run_id);
        if root.exists() {
            bail!(
                "Windows trust run directory already exists: {}",
                root.display()
            );
        }
        fs::create_dir_all(&root)
            .with_context(|| format!("could not create {}", root.display()))?;
        fs::write(root.join("owner"), format!("{}\n", run_id.as_str()))?;
        Ok(root)
    }

    fn cleanup_windows_trust_dir(&self, run_id: &RunId, source: &Path, state: &Path) -> Result<()> {
        let root = self.windows_trust_dir(run_id);
        if source != root.join("ca-cert.pem") || state != root.join("state") {
            bail!("Windows cleanup paths escaped the exact run-owned directory");
        }
        let owner = fs::read_to_string(root.join("owner"))?;
        if owner.trim() != run_id.as_str() {
            bail!("Windows cleanup refused: run owner does not match");
        }
        if state.exists() {
            fs::remove_dir_all(state)?;
        }
        fs::remove_file(source)?;
        fs::remove_file(root.join("owner"))?;
        fs::remove_dir(&root)?;
        Ok(())
    }

    fn windows_member_dir(&self, run_id: &RunId) -> PathBuf {
        self.repo_root
            .join(output_path(run_id.as_str()))
            .join("windows-member")
    }

    fn exercise_windows_member_custody(
        &self,
        ca: &NodeSpec,
        run_id: &RunId,
    ) -> Result<Vec<CheckResult>> {
        let windows = self.config.local()?;
        let ports = windows.lab_ports()?;
        let root = self.prepare_windows_member_dir(run_id)?;
        let mut child = match self.start_windows_member_daemon(&root, &ports) {
            Ok(child) => child,
            Err(error) => {
                self.remove_windows_member_dir(run_id, &root)
                    .context("Windows member daemon failed to start and local cleanup failed")?;
                return Err(error);
            }
        };

        let exercise = (|| -> Result<Vec<CheckResult>> {
            let member_url = format!("http://127.0.0.1:{}", ports.http);
            wait_for_http(&format!("{member_url}/healthz"))?;
            let member_token = self.require_windows_breadcrumb(&root, &member_url)?;
            let initial_pid = child.id();

            let ca_url = self.node_url(ca)?;
            let ca_token = self.daemon_token(ca, run_id)?;
            let invite = curl_json(
                "POST",
                &format!("{ca_url}/v1/certmesh/invite"),
                Some(&ca_token),
                Some(&json!({
                    "hostname": windows.hostname(),
                    "ttl_mins": 30
                })),
            )?;
            let invite_token = required_json_string(&invite, "token")?;
            let ca_fingerprint = required_json_string(&invite, "ca_fingerprint")?;
            let mismatched_invite = mismatch_invite_fingerprint(&invite_token, &ca_fingerprint)?;

            let mismatch = self.run_windows_member_koi(
                &root,
                &[
                    "certmesh".into(),
                    "join".into(),
                    ca_url.clone(),
                    "--invite".into(),
                    mismatched_invite,
                    "--ca-mtls-port".into(),
                    ca.lab_ports()?.mtls.to_string(),
                    "--json".into(),
                ],
            )?;
            if mismatch.status.success()
                || !String::from_utf8_lossy(&mismatch.stderr)
                    .to_ascii_lowercase()
                    .contains("fingerprint")
            {
                bail!("Windows member did not reject the deliberately mismatched invite pin");
            }
            let key_path = root
                .join("data")
                .join("certs")
                .join(windows.hostname())
                .join("key.pem");
            if key_path.exists() {
                bail!("Windows wrong-pin attempt generated a member private key");
            }

            let joined = self.run_windows_member_koi(
                &root,
                &[
                    "certmesh".into(),
                    "join".into(),
                    ca_url.clone(),
                    "--invite".into(),
                    invite_token,
                    "--ca-mtls-port".into(),
                    ca.lab_ports()?.mtls.to_string(),
                    "--json".into(),
                ],
            )?;
            if !joined.status.success() {
                bail!(
                    "Windows member join failed: {}",
                    String::from_utf8_lossy(&joined.stderr).trim()
                );
            }

            let diagnosis = self.run_windows_member_koi(
                &root,
                &["trust".into(), "diagnose".into(), "--json".into()],
            )?;
            if !diagnosis.status.success() {
                bail!(
                    "Windows member diagnosis failed: {}",
                    String::from_utf8_lossy(&diagnosis.stderr).trim()
                );
            }
            let diagnosis: Value = serde_json::from_slice(&diagnosis.stdout)
                .context("Windows member diagnosis returned invalid JSON")?;
            if diagnosis.get("overall").and_then(Value::as_str) != Some("healthy") {
                bail!("Windows member diagnosis was not healthy after enrollment");
            }

            let status = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
            if !status_has_active_member(&status, windows.hostname()) {
                bail!("CA roster did not contain the active Windows member");
            }

            let before = windows_member_identity_evidence(&root, windows.hostname())?;
            curl_json(
                "POST",
                &format!("{member_url}/v1/proxy/add"),
                Some(&member_token),
                Some(&json!({
                    "name": windows.hostname(),
                    "listen_port": ports.proxy,
                    "backend": format!("127.0.0.1:{}", ports.http),
                    "allow_remote": false
                })),
            )?;
            wait_for_proxy(
                &format!("{member_url}/v1/proxy/status"),
                windows.hostname(),
                ports.proxy,
            )?;
            require_windows_proxy_tls(windows.hostname(), ports.proxy)?;

            let renewal = self.run_windows_member_koi(
                &root,
                &["certmesh".into(), "renew".into(), "--json".into()],
            )?;
            if !renewal.status.success() {
                bail!(
                    "Windows member renewal failed: {}",
                    String::from_utf8_lossy(&renewal.stderr).trim()
                );
            }
            let renewal_json: Value = serde_json::from_slice(&renewal.stdout)
                .context("Windows member renewal returned invalid JSON")?;
            if renewal_json.get("renewed").and_then(Value::as_bool) != Some(true) {
                bail!("Windows member renewal did not report a completed rotation");
            }
            let rotated = windows_member_identity_evidence(&root, windows.hostname())?;
            if rotated.key_sha256 == before.key_sha256 {
                bail!("Windows renewal did not rotate the member private key");
            }
            if rotated.cert_sha256 == before.cert_sha256 {
                bail!("Windows renewal did not replace the member certificate");
            }
            let status = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
            let roster_fingerprint = status
                .get("members")
                .and_then(Value::as_array)
                .and_then(|members| {
                    members.iter().find(|entry| {
                        entry.get("hostname").and_then(Value::as_str) == Some(windows.hostname())
                    })
                })
                .and_then(|entry| entry.get("cert_fingerprint"))
                .and_then(Value::as_str)
                .context("CA roster omitted the renewed Windows fingerprint")?;
            if !roster_fingerprint.eq_ignore_ascii_case(&rotated.cert_fingerprint) {
                bail!("CA roster fingerprint does not match the rotated Windows leaf");
            }

            let restarted_pid = self.restart_windows_member_daemon(&root, &ports, &mut child)?;
            if restarted_pid == initial_pid {
                bail!("run-owned Windows daemon restart reused the original PID");
            }
            wait_for_http(&format!("{member_url}/healthz"))?;
            self.require_windows_breadcrumb(&root, &member_url)?;
            wait_for_proxy(
                &format!("{member_url}/v1/proxy/status"),
                windows.hostname(),
                ports.proxy,
            )?;
            require_windows_proxy_tls(windows.hostname(), ports.proxy)?;
            let after_restart = windows_member_identity_evidence(&root, windows.hostname())?;
            if after_restart.key_sha256 != rotated.key_sha256
                || after_restart.cert_sha256 != rotated.cert_sha256
            {
                bail!("Windows member identity changed across daemon restart");
            }
            let diagnosis = self.windows_member_diagnosis(&root)?;
            if diagnosis.get("overall").and_then(Value::as_str) != Some("healthy") {
                bail!("Windows member diagnosis was not healthy after restart");
            }

            let revoked = curl_json(
                "POST",
                &format!("{ca_url}/v1/certmesh/revoke"),
                Some(&ca_token),
                Some(&json!({
                    "hostname": windows.hostname(),
                    "reason": "koi-lab-v1-windows-lifecycle",
                    "operator": "koi-lab"
                })),
            )?;
            if revoked.get("revoked").and_then(Value::as_bool) != Some(true) {
                bail!("CA did not report the Windows member as revoked");
            }

            let revocation_pid = self.restart_windows_member_daemon(&root, &ports, &mut child)?;
            if revocation_pid == restarted_pid {
                bail!("Windows revocation restart reused the previous PID");
            }
            wait_for_http(&format!("{member_url}/healthz"))?;
            self.require_windows_breadcrumb(&root, &member_url)?;
            let red = self.wait_for_red_windows_member_diagnosis(&root)?;
            let self_revocation_red =
                red.get("checks")
                    .and_then(Value::as_array)
                    .is_some_and(|checks| {
                        checks.iter().any(|check| {
                            check.get("name").and_then(Value::as_str) == Some("self_revocation")
                                && check.get("status").and_then(Value::as_str) == Some("red")
                        })
                    });
            if !self_revocation_red {
                bail!("Windows RED diagnosis did not identify self revocation");
            }

            let denied_renewal = self.run_windows_member_koi(
                &root,
                &["certmesh".into(), "renew".into(), "--json".into()],
            )?;
            if denied_renewal.status.success() || !output_contains(&denied_renewal, "revoked") {
                bail!("revoked Windows member renewal was not refused at the CA boundary");
            }
            let after_renewal_denial = windows_member_identity_evidence(&root, windows.hostname())?;
            if after_renewal_denial.key_sha256 != rotated.key_sha256
                || after_renewal_denial.cert_sha256 != rotated.cert_sha256
            {
                bail!("failed Windows renewal changed the active local identity");
            }

            let rejoin_invite = curl_json(
                "POST",
                &format!("{ca_url}/v1/certmesh/invite"),
                Some(&ca_token),
                Some(&json!({
                    "hostname": windows.hostname(),
                    "ttl_mins": 30
                })),
            )?;
            let rejoin_token = required_json_string(&rejoin_invite, "token")?;
            let denied_rejoin = self.run_windows_member_koi(
                &root,
                &[
                    "certmesh".into(),
                    "join".into(),
                    ca_url,
                    "--invite".into(),
                    rejoin_token,
                    "--ca-mtls-port".into(),
                    ca.lab_ports()?.mtls.to_string(),
                    "--json".into(),
                ],
            )?;
            if denied_rejoin.status.success() || !output_contains(&denied_rejoin, "revoked") {
                bail!("revoked Windows member rejoin was not refused at the CA boundary");
            }
            let after_rejoin_denial = windows_member_identity_evidence(&root, windows.hostname())?;
            if after_rejoin_denial.key_sha256 != rotated.key_sha256
                || after_rejoin_denial.cert_sha256 != rotated.cert_sha256
            {
                bail!("failed Windows rejoin changed the active local identity");
            }

            windows_member_acl_evidence(&root, windows.hostname())?;
            Ok(vec![
                CheckResult {
                    name: "windows_member_acl_custody".into(),
                    passed: true,
                    detail: format!(
                        "{} rejected a wrong pin before key creation and restricts the data root, active member key, member state, and breadcrumb to SYSTEM, Administrators, and the current user",
                        windows.hostname()
                    ),
                },
                CheckResult {
                    name: "windows_member_renewal_rotates_identity".into(),
                    passed: true,
                    detail: format!(
                        "private key {}… → {}…; certificate {}… → {}…; production diagnosis verified correspondence and the CA roster converged to {}",
                        &before.key_sha256[..16],
                        &rotated.key_sha256[..16],
                        &before.cert_sha256[..16],
                        &rotated.cert_sha256[..16],
                        rotated.cert_fingerprint
                    ),
                },
                CheckResult {
                    name: "windows_member_restart_continuity".into(),
                    passed: true,
                    detail: format!(
                        "exact run-owned daemon PID {initial_pid} restarted as {restarted_pid}; identity, healthy diagnosis, and Schannel proxy continuity survived"
                    ),
                },
                CheckResult {
                    name: "windows_member_revocation_boundary".into(),
                    passed: true,
                    detail: format!(
                        "exact restart to PID {revocation_pid} pulled revocation; diagnosis became RED/self_revoked and renewal was refused"
                    ),
                },
                CheckResult {
                    name: "windows_member_rejoin_refused_without_identity_mutation".into(),
                    passed: true,
                    detail: "the CA refused a fresh-invite rejoin for the revoked hostname and the active private key and certificate remained byte-identical".into(),
                },
            ])
        })();

        if let Err(error) = &exercise {
            let path = output_path(run_id.as_str()).join("windows-member-failure.json");
            if let Err(write_error) = self.write_json(
                &path,
                &json!({
                    "schema": 1,
                    "run_id": run_id.as_str(),
                    "created_at": Utc::now(),
                    "stage": "windows_member_lifecycle",
                    "error": format!("{error:#}"),
                    "secrets_redacted": true
                }),
            ) {
                eprintln!(
                    "could not preserve redacted Windows member failure evidence: {write_error:#}"
                );
            }
        }

        let cleanup = self.cleanup_windows_member_dir(run_id, &root, &mut child);
        match (exercise, cleanup) {
            (Ok(checks), Ok(())) => Ok(checks),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Err(error), Err(cleanup_error)) => {
                Err(error).context(format!("Windows member cleanup failed: {cleanup_error:#}"))
            }
        }
    }

    fn prepare_windows_member_dir(&self, run_id: &RunId) -> Result<PathBuf> {
        let root = self.windows_member_dir(run_id);
        if root.exists() {
            bail!(
                "Windows member run directory already exists: {}",
                root.display()
            );
        }
        fs::create_dir_all(root.join("program-data"))
            .with_context(|| format!("could not create {}", root.display()))?;
        fs::write(root.join("owner"), format!("{}\n", run_id.as_str()))?;
        Ok(root)
    }

    fn windows_member_command(&self, root: &Path) -> Result<Command> {
        let koi = self.repo_root.join("target/release/koi.exe");
        if !koi.is_file() {
            bail!(
                "Windows release binary is missing at {}; build it locally first",
                koi.display()
            );
        }
        let mut command = Command::new(koi);
        command
            .env("KOI_DATA_DIR", root.join("data"))
            .env("ProgramData", root.join("program-data"))
            .env("KOI_NO_CREDENTIAL_STORE", "1")
            .env("KOI_DNS_ZONE", "internal")
            .env("KOI_LOG", "warn");
        Ok(command)
    }

    fn start_windows_member_daemon(
        &self,
        root: &Path,
        ports: &crate::model::LabPorts,
    ) -> Result<std::process::Child> {
        let log = fs::File::create(root.join("daemon.log"))?;
        let stderr = log.try_clone()?;
        let mut command = self.windows_member_command(root)?;
        command
            .args(["--daemon", "--port"])
            .arg(ports.http.to_string())
            .args(["--http-bind", "127.0.0.1", "--mtls-port"])
            .arg(ports.mtls.to_string())
            .args(["--acme-port"])
            .arg(ports.acme.to_string())
            .args([
                "--no-ipc",
                "--no-mdns",
                "--no-dns",
                "--no-health",
                "--no-udp",
                "--no-runtime",
                "--no-acme",
                "--no-mcp-http",
            ])
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr));
        command
            .spawn()
            .context("failed to start the run-owned Windows member daemon")
    }

    fn restart_windows_member_daemon(
        &self,
        root: &Path,
        ports: &crate::model::LabPorts,
        child: &mut std::process::Child,
    ) -> Result<u32> {
        let old_pid = child.id();
        if child.try_wait()?.is_some() {
            bail!("run-owned Windows daemon PID {old_pid} exited before its exact restart");
        }
        child.kill()?;
        child.wait()?;
        let replacement = self.start_windows_member_daemon(root, ports)?;
        let new_pid = replacement.id();
        *child = replacement;
        Ok(new_pid)
    }

    fn run_windows_member_koi(&self, root: &Path, args: &[String]) -> Result<std::process::Output> {
        self.windows_member_command(root)?
            .args(args)
            .output()
            .context("failed to start the Windows member CLI")
    }

    fn require_windows_breadcrumb(&self, root: &Path, expected_endpoint: &str) -> Result<String> {
        let breadcrumb = root.join("program-data").join("koi").join("koi.endpoint");
        for _ in 0..50 {
            if let Ok(contents) = fs::read_to_string(&breadcrumb) {
                let mut lines = contents.lines();
                let endpoint = lines.next().unwrap_or_default();
                let token = lines
                    .next()
                    .unwrap_or_default()
                    .strip_prefix("dat:")
                    .unwrap_or_default();
                if endpoint == expected_endpoint && !token.is_empty() {
                    return Ok(token.to_owned());
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("run-owned Windows daemon did not write the expected breadcrumb")
    }

    fn windows_member_diagnosis(&self, root: &Path) -> Result<Value> {
        let output = self
            .run_windows_member_koi(root, &["trust".into(), "diagnose".into(), "--json".into()])?;
        serde_json::from_slice(&output.stdout)
            .context("Windows member trust diagnosis returned invalid JSON")
    }

    fn wait_for_red_windows_member_diagnosis(&self, root: &Path) -> Result<Value> {
        let mut last = Value::Null;
        for _ in 0..30 {
            let diagnosis = self.windows_member_diagnosis(root)?;
            if diagnosis.get("overall").and_then(Value::as_str) == Some("red") {
                return Ok(diagnosis);
            }
            last = diagnosis;
            thread::sleep(Duration::from_millis(250));
        }
        bail!("Windows member diagnosis did not become RED after revocation: {last}")
    }

    fn cleanup_windows_member_dir(
        &self,
        run_id: &RunId,
        root: &Path,
        child: &mut std::process::Child,
    ) -> Result<()> {
        if root != self.windows_member_dir(run_id) {
            bail!("Windows member cleanup path escaped the exact run-owned directory");
        }
        if child.try_wait()?.is_none() {
            child.kill()?;
            child.wait()?;
        }
        self.remove_windows_member_dir(run_id, root)
    }

    fn remove_windows_member_dir(&self, run_id: &RunId, root: &Path) -> Result<()> {
        if root != self.windows_member_dir(run_id) {
            bail!("Windows member cleanup path escaped the exact run-owned directory");
        }
        let owner = fs::read_to_string(root.join("owner"))?;
        if owner.trim() != run_id.as_str() {
            bail!("Windows member cleanup refused: run owner does not match");
        }
        fs::remove_dir_all(root)?;
        if root.exists() {
            bail!("Windows member cleanup did not remove the exact run directory");
        }
        Ok(())
    }

    fn run_windows_koi(
        &self,
        state: &Path,
        args: &[&str],
        trailing_path: Option<&Path>,
    ) -> Result<std::process::Output> {
        let koi = self.repo_root.join("target/release/koi.exe");
        if !koi.is_file() {
            bail!(
                "Windows release binary is missing at {}; build it locally first",
                koi.display()
            );
        }
        let mut command = Command::new(koi);
        command.env("KOI_DATA_DIR", state).args(args);
        if let Some(path) = trailing_path {
            command.arg(path);
        }
        command
            .output()
            .context("failed to start the Windows Koi CLI")
    }

    fn probe_remote(&self, node: &NodeSpec) -> Result<NodeSnapshot> {
        let expected_architecture = match node {
            NodeSpec::PuttyLinux { architecture, .. } => architecture,
            NodeSpec::LocalWindows { .. } => bail!("{} is not a remote node", node.id()),
        };
        let observed_hostname = self.remote_line(node, "hostname")?;
        let operating_system = self.remote_line(node, "uname -srm")?;
        let architecture = self.remote_line(node, "uname -m")?;
        let clock_probe_started = current_epoch()?;
        let utc_epoch = self
            .remote_line(node, "date -u +%s")?
            .parse::<i64>()
            .with_context(|| format!("node {} returned an invalid clock", node.id()))?;
        let clock_probe_finished = current_epoch()?;
        let clock_probe_span_seconds = clock_probe_finished - clock_probe_started;
        let clock_probe_midpoint = clock_probe_started + clock_probe_span_seconds / 2;
        let clock_skew_seconds = utc_epoch - clock_probe_midpoint;
        let sudo_non_interactive = self
            .transport
            .run(node, "sudo -n true")
            .is_ok_and(|out| out.status.success());

        let all_tools = REQUIRED_REMOTE_TOOLS
            .iter()
            .chain(SCENARIO_REMOTE_TOOLS.iter())
            .copied()
            .collect::<Vec<_>>();
        let tool_command = format!(
            "for x in {}; do command -v \"$x\" >/dev/null 2>&1 && echo \"$x=yes\" || echo \"$x=no\"; done",
            all_tools.join(" ")
        );
        let mut tools = parse_bool_map(&self.transport.run_checked(node, &tool_command)?);
        let nc_unix = self
            .transport
            .run(node, "nc -h 2>&1 | grep -q -- '-U'")
            .is_ok_and(|output| output.status.success());
        tools.insert("nc_unix".to_owned(), nc_unix);
        let docker_daemon = self
            .transport
            .run(node, "docker info >/dev/null 2>&1")
            .is_ok_and(|output| output.status.success());
        tools.insert("docker_daemon".to_owned(), docker_daemon);

        let services_output = self.transport.run_checked(
            node,
            "for s in koi garden-moss avahi-daemon; do a=$(systemctl is-active \"$s\" 2>/dev/null || true); e=$(systemctl is-enabled \"$s\" 2>/dev/null || true); echo \"$s|$a|$e\"; done",
        )?;
        let mut services = parse_services(&services_output);
        if let Some(koi) = services.get_mut("koi") {
            let exec = self.remote_line(
                node,
                "systemctl show koi --property=ExecStart --value 2>/dev/null || true",
            )?;
            if !exec.is_empty() {
                koi.exec_start = Some(exec);
            }
        }

        let listening_sockets = self
            .transport
            .run_checked(
                node,
                "ss -H -lntup 2>/dev/null | grep -E ':53 |:5353 |:5641 |:5642 |:5643 ' || true",
            )?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let root = node.remote_root()?;
        let remote_root_present =
            self.remote_line(node, &format!("test -d {root} && echo yes || echo no"))? == "yes";
        let existing_artifact_sha256 = optional_remote_line(
            &self.transport,
            node,
            &format!("test -f {root}/koi && sha256sum {root}/koi | cut -d' ' -f1 || true"),
        )?;
        let existing_artifact_version = optional_remote_line(
            &self.transport,
            node,
            &format!("test -x {root}/koi && {root}/koi version 2>/dev/null | head -1 || true"),
        )?;

        let mut blockers = Vec::new();
        let mut warnings = Vec::new();
        if observed_hostname != node.hostname() {
            blockers.push(format!(
                "hostname mismatch: expected {}, observed {observed_hostname}",
                node.hostname()
            ));
        }
        if architecture != *expected_architecture {
            blockers.push(format!(
                "architecture mismatch: expected {expected_architecture}, observed {architecture}"
            ));
        }
        if clock_skew_seconds.abs() > MAX_CLOCK_SKEW_SECONDS {
            blockers.push(format!("clock skew is {clock_skew_seconds} seconds"));
        }
        for tool in REQUIRED_REMOTE_TOOLS {
            if !tools.get(*tool).copied().unwrap_or(false) {
                blockers.push(format!("required staging tool {tool} is missing"));
            }
        }
        for tool in SCENARIO_REMOTE_TOOLS {
            if !tools.get(*tool).copied().unwrap_or(false) {
                warnings.push(format!("scenario tool {tool} is missing"));
            }
        }
        if !nc_unix {
            warnings.push("scenario tool nc lacks Unix-domain socket (-U) support".into());
        }
        if !docker_daemon {
            warnings.push("Docker CLI cannot reach the daemon as the lab user".into());
        }
        if !sudo_non_interactive {
            warnings
                .push("passwordless sudo is unavailable; privileged lanes will be blocked".into());
        }
        let active_services = services
            .iter()
            .filter(|(_, service)| service.active == "active")
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if !active_services.is_empty() {
            warnings.push(format!(
                "pre-existing active services must be preserved/restored: {}",
                active_services.join(", ")
            ));
        }
        let occupied_test_ports = listening_sockets
            .iter()
            .filter(|line| {
                TEST_PORTS
                    .iter()
                    .any(|port| line.contains(&format!(":{port} ")))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !occupied_test_ports.is_empty() {
            warnings.push("one or more Koi control ports are already occupied".into());
        }
        let deploy_ready = blockers.is_empty();
        let scenario_ready = deploy_ready
            && sudo_non_interactive
            && active_services.is_empty()
            && occupied_test_ports.is_empty()
            && SCENARIO_REMOTE_TOOLS
                .iter()
                .all(|tool| tools.get(*tool).copied().unwrap_or(false))
            && nc_unix
            && docker_daemon;
        Ok(NodeSnapshot {
            id: node.id().to_owned(),
            expected_hostname: node.hostname().to_owned(),
            observed_hostname,
            address: node.address().to_owned(),
            operating_system,
            architecture,
            utc_epoch,
            clock_skew_seconds,
            clock_probe_span_seconds,
            sudo_non_interactive,
            tools,
            services,
            listening_sockets,
            remote_root_present,
            existing_artifact_sha256,
            existing_artifact_version,
            deploy_ready,
            scenario_ready,
            blockers,
            warnings,
        })
    }

    fn deploy_locked(
        &self,
        nodes: &[&NodeSpec],
        run_id: &RunId,
        artifact: &ArtifactIdentity,
    ) -> Result<Vec<DeployedNode>> {
        let mut deployed = Vec::new();
        for node in nodes {
            let run_dir = node.run_dir(run_id)?;
            self.transport
                .run_checked(node, &prepare_run_script(node, run_id)?)?;
            let partial = format!("{run_dir}/koi.partial");
            self.transport.copy_to(node, &artifact.path, &partial)?;
            let verify = format!(
                "set -eu; actual=$(sha256sum {partial} | cut -d' ' -f1); test \"$actual\" = {}; mv {partial} {run_dir}/koi; chmod 700 {run_dir}/koi; printf '%s\\n' {} > {run_dir}/artifact.sha256; {run_dir}/koi version 2>/dev/null | head -1",
                artifact.sha256, artifact.sha256
            );
            let version = self.transport.run_checked(node, &verify)?.trim().to_owned();
            if version.is_empty() {
                bail!(
                    "deployed artifact on {} did not report a version",
                    node.id()
                );
            }
            deployed.push(DeployedNode {
                id: node.id().to_owned(),
                address: node.address().to_owned(),
                run_dir,
                artifact_sha256: artifact.sha256.clone(),
                version,
            });
        }
        Ok(deployed)
    }

    fn acquire_lock(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.transport
            .run_checked(node, &acquire_lock_script(node, run_id)?)?;
        Ok(())
    }

    fn cleanup_node(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        self.transport
            .run_checked(node, &cleanup_script(node, run_id)?)?;
        Ok(())
    }

    fn rollback_partial(&self, nodes: &[&NodeSpec], run_id: &RunId) {
        for node in nodes.iter().rev() {
            if let Err(error) = self.cleanup_node(node, run_id) {
                eprintln!(
                    "WARNING: rollback cleanup failed on {} for {}: {error:#}",
                    node.id(),
                    run_id.as_str()
                );
            }
        }
    }

    fn node_cleanup_plan(&self, node: &NodeSpec, run_id: &RunId) -> Result<NodeCleanupPlan> {
        let lock_dir = node.lock_dir()?;
        let run_dir = node.run_dir(run_id)?;
        let owner = self.remote_line(
            node,
            &format!("test -f {lock_dir}/owner && cat {lock_dir}/owner || true"),
        )?;
        let run_dir_present =
            self.remote_line(node, &format!("test -d {run_dir} && echo yes || echo no"))? == "yes";
        let files = if run_dir_present {
            self.transport
                .run_checked(
                    node,
                    &format!(
                        "find {run_dir} -maxdepth 1 -mindepth 1 -printf '%f\\n' 2>/dev/null | sort"
                    ),
                )?
                .lines()
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        };
        Ok(NodeCleanupPlan {
            id: node.id().to_owned(),
            lock_dir,
            run_dir,
            owner_matches: owner == run_id.as_str(),
            run_dir_present,
            files,
        })
    }

    pub(crate) fn remote_line(&self, node: &NodeSpec, command: &str) -> Result<String> {
        Ok(self.transport.run_checked(node, command)?.trim().to_owned())
    }

    fn git_commit(&self) -> Result<String> {
        command_stdout_in(&self.repo_root, "git", &["rev-parse", "HEAD"])
    }

    pub(crate) fn write_json<T: serde::Serialize>(
        &self,
        relative_path: &Path,
        value: &T,
    ) -> Result<PathBuf> {
        let path = if relative_path.is_absolute() {
            relative_path.to_path_buf()
        } else {
            self.repo_root.join(relative_path)
        };
        let parent = path
            .parent()
            .context("report path has no parent directory")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create report directory {}", parent.display()))?;
        let bytes = serde_json::to_vec_pretty(value)?;
        fs::write(&path, bytes)
            .with_context(|| format!("could not write report {}", path.display()))?;
        Ok(path)
    }
}

fn parse_bool_map(output: &str) -> BTreeMap<String, bool> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim() == "yes"))
        .collect()
}

fn parse_services(output: &str) -> BTreeMap<String, ServiceSnapshot> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '|');
            let name = parts.next()?.trim();
            let active = parts.next()?.trim();
            let enabled = parts.next()?.trim();
            Some((
                name.to_owned(),
                ServiceSnapshot {
                    active: active.to_owned(),
                    enabled: enabled.to_owned(),
                    exec_start: None,
                },
            ))
        })
        .collect()
}

fn optional_remote_line(
    transport: &PuttyTransport,
    node: &NodeSpec,
    command: &str,
) -> Result<Option<String>> {
    let value = transport.run_checked(node, command)?.trim().to_owned();
    Ok((!value.is_empty()).then_some(value))
}

fn acquire_lock_script(node: &NodeSpec, run_id: &RunId) -> Result<String> {
    let root = node.remote_root()?;
    let lock = node.lock_dir()?;
    Ok(format!(
        "set -eu; mkdir -p {root}; if mkdir {lock} 2>/dev/null; then printf '%s\\n' {} > {lock}/owner; else owner=$(cat {lock}/owner 2>/dev/null || echo unknown); echo \"lab lock held by $owner\" >&2; exit 73; fi",
        run_id.as_str()
    ))
}

fn prepare_run_script(node: &NodeSpec, run_id: &RunId) -> Result<String> {
    let root = node.remote_root()?;
    let lock = node.lock_dir()?;
    let run_dir = node.run_dir(run_id)?;
    Ok(format!(
        "set -eu; test \"$(cat {lock}/owner)\" = {}; mkdir -p {root}/runs; test ! -e {run_dir}; mkdir {run_dir}; printf '%s\\n' {} > {run_dir}/owner",
        run_id.as_str(),
        run_id.as_str()
    ))
}

pub(crate) fn require_system_mutation(allow_system_mutation: bool) -> Result<()> {
    if !allow_system_mutation {
        bail!("system mutation refused: pass --allow-system-mutation only for a dedicated lab run");
    }
    Ok(())
}

fn ensure_windows_elevated() -> Result<()> {
    #[cfg(windows)]
    {
        let status = Command::new("net.exe")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .context("failed to test Windows elevation")?;
        if status.success() {
            Ok(())
        } else {
            bail!(
                "Windows trust rotation refused before setup: run koi-lab from an elevated Administrator terminal"
            )
        }
    }
    #[cfg(not(windows))]
    {
        bail!("the Windows trust rotation must be controlled from the Windows lab node")
    }
}

fn windows_trust_fingerprint() -> Result<String> {
    let output = powershell_output(windows_trust_fingerprint_script())?;
    if !output.status.success() {
        bail!(
            "could not snapshot Windows LocalMachine\\Root: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(format!("{:x}", Sha256::digest(&output.stdout)))
}

fn windows_store_contains(fingerprint: &str) -> Result<bool> {
    if !is_sha256(fingerprint) {
        bail!("invalid Windows certificate fingerprint");
    }
    let output = powershell_output(&windows_store_contains_script(fingerprint))?;
    if !output.status.success() {
        bail!(
            "could not inspect Windows LocalMachine\\Root: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "yes")
}

fn windows_invoke_web_request(
    address: &str,
    hostname: &str,
    port: u16,
    run_id: &RunId,
) -> Result<std::process::Output> {
    powershell_output(&windows_iwr_script(address, hostname, port, run_id))
}

fn windows_iwr_script(address: &str, hostname: &str, port: u16, run_id: &RunId) -> String {
    format!(
        "$ErrorActionPreference='Stop'; $hosts=Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'; $before=[IO.File]::ReadAllBytes($hosts); try {{ [IO.File]::AppendAllText($hosts, \"`r`n{address}`t{hostname}`t# koi-lab-{}`r`n\", [Text.Encoding]::ASCII); $response=Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -Uri 'https://{hostname}:{port}/healthz'; if ($response.Content.Trim() -ne 'OK') {{ throw 'unexpected response body' }}; 'OK' }} finally {{ [IO.File]::WriteAllBytes($hosts, $before); $after=[IO.File]::ReadAllBytes($hosts); if ([Convert]::ToBase64String($after) -cne [Convert]::ToBase64String($before)) {{ throw 'hosts file bytes were not restored exactly' }} }}",
        run_id.as_str()
    )
}

fn windows_member_acl_evidence(root: &Path, hostname: &str) -> Result<()> {
    let script = windows_member_acl_script(root, hostname);
    let output = powershell_output(&script)?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "yes" {
        bail!(
            "Windows member ACL evidence failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn windows_member_identity_evidence(root: &Path, hostname: &str) -> Result<MemberIdentityEvidence> {
    let cert_dir = root.join("data").join("certs").join(hostname);
    let key = fs::read(cert_dir.join("key.pem"))
        .context("could not read the run-owned Windows member key")?;
    let cert = fs::read(cert_dir.join("cert.pem"))
        .context("could not read the run-owned Windows member certificate")?;
    let parsed = pem::parse(&cert).context("Windows member certificate was not valid PEM")?;
    let (_, leaf) = X509Certificate::from_der(parsed.contents())
        .map_err(|error| anyhow::anyhow!("Windows member leaf was not valid X.509: {error}"))?;
    if !leaf.validity().is_valid() {
        bail!(
            "run-owned Windows member leaf is outside its validity window (not before {}, not after {})",
            leaf.validity().not_before,
            leaf.validity().not_after
        );
    }
    let ca = fs::read(cert_dir.join("ca.pem"))
        .context("could not read the run-owned Windows member CA certificate")?;
    let parsed_ca = pem::parse(&ca).context("Windows member CA certificate was not valid PEM")?;
    let (_, ca_cert) = X509Certificate::from_der(parsed_ca.contents())
        .map_err(|error| anyhow::anyhow!("Windows member CA was not valid X.509: {error}"))?;
    if !ca_cert.validity().is_valid() {
        bail!(
            "run-owned Windows member CA is outside its validity window (not before {}, not after {})",
            ca_cert.validity().not_before,
            ca_cert.validity().not_after
        );
    }
    let key_sha256 = format!("{:x}", Sha256::digest(&key));
    let cert_sha256 = format!("{:x}", Sha256::digest(&cert));
    let cert_fingerprint = format!("{:x}", Sha256::digest(parsed.contents()));
    if !is_sha256(&key_sha256) || !is_sha256(&cert_sha256) || !is_sha256(&cert_fingerprint) {
        bail!("Windows member identity evidence returned malformed fingerprints");
    }
    Ok(MemberIdentityEvidence {
        key_sha256,
        cert_sha256,
        cert_fingerprint,
    })
}

fn require_windows_proxy_tls(hostname: &str, port: u16) -> Result<()> {
    let output = Command::new("curl.exe")
        .args(windows_curl_args("127.0.0.1", hostname, port))
        .output()
        .context("failed to start Schannel curl.exe for the Windows member proxy")?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "OK" {
        bail!(
            "Schannel curl.exe did not verify the Windows member proxy: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn output_contains(output: &std::process::Output, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    String::from_utf8_lossy(&output.stdout)
        .to_ascii_lowercase()
        .contains(&needle)
        || String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains(&needle)
}

fn windows_member_acl_script(root: &Path, hostname: &str) -> String {
    let data = powershell_path_literal(&root.join("data"));
    let key = powershell_path_literal(
        &root
            .join("data")
            .join("certs")
            .join(hostname)
            .join("key.pem"),
    );
    let state = powershell_path_literal(&root.join("data").join("certmesh").join("member.json"));
    let breadcrumb =
        powershell_path_literal(&root.join("program-data").join("koi").join("koi.endpoint"));
    format!(
        "$ErrorActionPreference='Stop'; $allowed=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value); function Assert-RestrictedAcl([string]$path,[bool]$requireProtected) {{ $item=Get-Item -LiteralPath $path; $acl=$item.GetAccessControl(); if ($requireProtected -and -not $acl.AreAccessRulesProtected) {{ throw \"ACL inheritance remains enabled on $path\" }}; $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {{ $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow }}); foreach ($rule in $rules) {{ if ($allowed -notcontains $rule.IdentityReference.Value) {{ throw \"unexpected allow ACE on $path\" }} }}; foreach ($sid in $allowed) {{ if (-not ($rules | Where-Object {{ $_.IdentityReference.Value -eq $sid }})) {{ throw \"missing required allow ACE on $path\" }} }} }}; Assert-RestrictedAcl {data} $true; Assert-RestrictedAcl {key} $false; Assert-RestrictedAcl {state} $false; Assert-RestrictedAcl {breadcrumb} $true; 'yes'"
    )
}

fn powershell_path_literal(path: &Path) -> String {
    let displayed = path.display().to_string();
    let displayed = displayed.strip_prefix(r"\\?\").unwrap_or(&displayed);
    format!("'{}'", displayed.replace('\'', "''"))
}

fn windows_curl_args(address: &str, hostname: &str, port: u16) -> Vec<String> {
    vec![
        "--noproxy".into(),
        "*".into(),
        "--silent".into(),
        "--show-error".into(),
        "--fail".into(),
        "--max-time".into(),
        "10".into(),
        "--ssl-revoke-best-effort".into(),
        "--resolve".into(),
        format!("{hostname}:{port}:{address}"),
        format!("https://{hostname}:{port}/healthz"),
    ]
}

fn powershell_output(script: &str) -> Result<std::process::Output> {
    Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .output()
        .context("failed to start Windows PowerShell")
}

fn windows_trust_fingerprint_script() -> &'static str {
    r#"$ErrorActionPreference='Stop'; $store=[Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine'); $sha=[Security.Cryptography.SHA256]::Create(); try { $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly); $store.Certificates | ForEach-Object { ($sha.ComputeHash($_.RawData) | ForEach-Object { $_.ToString('x2') }) -join '' } | Sort-Object } finally { $store.Close(); $sha.Dispose() }"#
}

fn windows_store_contains_script(fingerprint: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'; $wanted='{fingerprint}'; $store=[Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine'); $sha=[Security.Cryptography.SHA256]::Create(); try {{ $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly); $found=@($store.Certificates | Where-Object {{ (($sha.ComputeHash($_.RawData) | ForEach-Object {{ $_.ToString('x2') }}) -join '') -eq $wanted }}).Count; if ($found -eq 1) {{ 'yes' }} elseif ($found -eq 0) {{ 'no' }} else {{ throw \"duplicate certificate identity in LocalMachine Root\" }} }} finally {{ $store.Close(); $sha.Dispose() }}"
    )
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn mismatch_invite_fingerprint(invite: &str, expected_fingerprint: &str) -> Result<String> {
    if !is_sha256(expected_fingerprint) {
        bail!("expected invite fingerprint is not a full SHA-256 identity");
    }
    let (secret, fingerprint) = invite
        .rsplit_once('.')
        .context("invite does not carry a fingerprint pin")?;
    if secret.is_empty()
        || !fingerprint.eq_ignore_ascii_case(expected_fingerprint)
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invite does not match the expected safe pinned-code shape");
    }
    let replacement = if fingerprint.starts_with('0') {
        '1'
    } else {
        '0'
    };
    let mut mismatched = fingerprint.to_owned();
    mismatched.replace_range(..1, &replacement.to_string());
    Ok(format!("{secret}.{mismatched}"))
}

fn parse_installed_trust(output: &str) -> Result<(String, String)> {
    let value: Value = serde_json::from_str(output.trim())
        .context("native trust install returned invalid JSON")?;
    let installed = value
        .get("installed")
        .context("native trust install omitted installed result")?;
    let name = required_json_string(installed, "name")?;
    let fingerprint = required_json_string(installed, "fingerprint")?;
    if name != "koi-ca-cert" || !is_sha256(&fingerprint) {
        bail!("native trust install returned an unsafe identity");
    }
    Ok((name, fingerprint))
}

fn native_trust_install_command(
    node: &NodeSpec,
    run_id: &RunId,
    ca_pem: &str,
    trust_state: &str,
) -> Result<String> {
    let run_dir = node.run_dir(run_id)?;
    let lock_dir = node.lock_dir()?;
    let expected_ca = format!("{run_dir}/data/certmesh/ca/ca-cert.pem");
    let expected_state = format!("{run_dir}/trust-state");
    if ca_pem != expected_ca || trust_state != expected_state {
        bail!("native trust paths are not the exact run-owned paths");
    }
    Ok(format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test -f {ca_pem}; test \"$(realpath {ca_pem})\" = {ca_pem}; test ! -e {trust_state}; sudo -n env KOI_DATA_DIR={trust_state} {run_dir}/koi --json trust install {ca_pem}",
        run_id.as_str(),
        run_id.as_str()
    ))
}

fn native_trust_remove_command(
    node: &NodeSpec,
    run_id: &RunId,
    name: &str,
    fingerprint: &str,
    trust_state: &str,
) -> Result<String> {
    let run_dir = node.run_dir(run_id)?;
    let lock_dir = node.lock_dir()?;
    let expected_state = format!("{run_dir}/trust-state");
    if trust_state != expected_state
        || name != "koi-ca-cert"
        || fingerprint.len() != 64
        || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("native trust removal identity is not exact");
    }

    // os-truststore 0.0.2 removes Debian's anchor, but update-ca-certificates
    // can leave its two fingerprint-owned symlinks dangling. Match both the
    // full target and the short fingerprint before pruning only that residue.
    let marker = &fingerprint[..16];
    let anchor = format!("/usr/local/share/ca-certificates/{name}-{marker}.crt");
    let leaf = format!("/etc/ssl/certs/{name}-{marker}.pem");
    Ok(format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; sudo -n env KOI_DATA_DIR={trust_state} {run_dir}/koi --json trust remove {name}; if test -L {leaf}; then test ! -e {anchor}; test \"$(readlink {leaf})\" = {anchor}; for link in /etc/ssl/certs/*.[0-9]*; do if test -L \"$link\" && test \"$(readlink \"$link\")\" = {name}-{marker}.pem; then sudo -n rm -f -- \"$link\"; fi; done; sudo -n rm -f -- {leaf}; fi; test ! -e {anchor}; test ! -L {leaf}; resolved=$(sudo -n realpath {trust_state}); test \"$resolved\" = {trust_state}; sudo -n rm -rf -- \"$resolved\"",
        run_id.as_str(),
        run_id.as_str()
    ))
}

fn story_image_ref(run_id: &RunId) -> String {
    format!("koi-lab-story:{}", run_id.as_str().to_ascii_lowercase())
}

fn story_container_name(run_id: &RunId) -> String {
    format!("koi-lab-story-{}", run_id.as_str().to_ascii_lowercase())
}

fn runtime_fault_suffix(run_id: &RunId) -> String {
    run_id
        .as_str()
        .rsplit('-')
        .next()
        .unwrap_or("fault")
        .to_ascii_lowercase()
}

fn runtime_fault_container_name(run_id: &RunId, role: RuntimeFaultRole) -> String {
    format!(
        "koi-lab-runtime-{}-{}",
        role.as_str(),
        run_id.as_str().to_ascii_lowercase()
    )
}

fn runtime_fault_container_marker(run_dir: &str, role: RuntimeFaultRole) -> String {
    format!("{run_dir}/runtime-fault-{}.id", role.as_str())
}

fn runtime_fault_network_name(run_id: &RunId) -> String {
    format!(
        "koi-lab-runtime-net-{}",
        run_id.as_str().to_ascii_lowercase()
    )
}

fn runtime_fault_container_remove_script(
    node: &NodeSpec,
    run_id: &RunId,
    role: RuntimeFaultRole,
    require_present: bool,
) -> Result<String> {
    let lock_dir = node.lock_dir()?;
    let run_dir = node.run_dir(run_id)?;
    let marker = runtime_fault_container_marker(&run_dir, role);
    let container_name = runtime_fault_container_name(run_id, role);
    let required = if require_present { "true" } else { "false" };
    Ok(format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; required={required}; if test -f {marker}; then cid=$(cat {marker}); case \"$cid\" in ''|*[!0-9a-f]*) exit 76;; esac; if docker container inspect \"$cid\" >/dev/null 2>&1; then actual=$(docker container inspect \"$cid\" | jq -r '.[0].Name + \"|\" + .[0].Config.Labels[\"org.sylin.koi.lab.owner\"] + \"|\" + .[0].Config.Labels[\"org.sylin.koi.lab.run\"] + \"|\" + .[0].Config.Labels[\"org.sylin.koi.lab.role\"]'); test \"$actual\" = \"/{container_name}|koi-lab|{}|{}\"; docker container rm --force \"$cid\" >/dev/null; elif test \"$required\" = true; then exit 76; fi; rm -f {marker}; elif test \"$required\" = true; then exit 76; fi",
        run_id.as_str(),
        run_id.as_str(),
        run_id.as_str(),
        role.as_str()
    ))
}

fn runtime_fault_network_remove_script(node: &NodeSpec, run_id: &RunId) -> Result<String> {
    let lock_dir = node.lock_dir()?;
    let run_dir = node.run_dir(run_id)?;
    let network_name = runtime_fault_network_name(run_id);
    Ok(format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; if test -f {run_dir}/runtime-fault-network.id; then expected=$(cat {run_dir}/runtime-fault-network.id); case \"$expected\" in ''|*[!0-9a-f]*) exit 76;; esac; if docker network inspect {network_name} >/dev/null 2>&1; then actual=$(docker network inspect {network_name} | jq -r '.[0].Id + \"|\" + .[0].Labels[\"org.sylin.koi.lab.owner\"] + \"|\" + .[0].Labels[\"org.sylin.koi.lab.run\"]'); test \"$actual\" = \"$expected|koi-lab|{}\"; docker network rm {network_name} >/dev/null; fi; rm -f {run_dir}/runtime-fault-network.id; fi",
        run_id.as_str(),
        run_id.as_str(),
        run_id.as_str()
    ))
}

fn runtime_proxy_stop_script(
    node: &NodeSpec,
    run_id: &RunId,
    require_present: bool,
) -> Result<String> {
    let lock_dir = node.lock_dir()?;
    let run_dir = node.run_dir(run_id)?;
    let required = if require_present { "true" } else { "false" };
    Ok(format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; required={required}; if test -f {run_dir}/docker-proxy.pid; then test -f {run_dir}/docker-proxy.exe; pid=$(cat {run_dir}/docker-proxy.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; if kill -0 \"$pid\" 2>/dev/null; then test \"$(readlink -f /proc/\"$pid\"/exe)\" = \"$(cat {run_dir}/docker-proxy.exe)\"; tr '\\000' ' ' </proc/\"$pid\"/cmdline | grep -F -- '{run_dir}/docker_socket_proxy.py --listen {run_dir}/docker-proxy.sock --upstream /var/run/docker.sock' >/dev/null; kill \"$pid\"; i=0; while kill -0 \"$pid\" 2>/dev/null && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; ! kill -0 \"$pid\" 2>/dev/null; elif test \"$required\" = true; then exit 76; fi; rm -f {run_dir}/docker-proxy.pid; elif test \"$required\" = true; then exit 76; fi; i=0; while test -e {run_dir}/docker-proxy.sock && test \"$i\" -lt 20; do sleep .1; i=$((i+1)); done; if test -e {run_dir}/docker-proxy.sock; then test -S {run_dir}/docker-proxy.sock; rm -f {run_dir}/docker-proxy.sock; fi",
        run_id.as_str(),
        run_id.as_str()
    ))
}

fn story_container_remove_script(
    node: &NodeSpec,
    run_id: &RunId,
    require_present: bool,
) -> Result<String> {
    let lock_dir = node.lock_dir()?;
    let run_dir = node.run_dir(run_id)?;
    let container_name = story_container_name(run_id);
    let required = if require_present { "true" } else { "false" };
    Ok(format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; required={required}; if test -f {run_dir}/container.id; then cid=$(cat {run_dir}/container.id); case \"$cid\" in ''|*[!0-9a-f]*) exit 76;; esac; if docker container inspect \"$cid\" >/dev/null 2>&1; then actual=$(docker container inspect \"$cid\" | jq -r '.[0].Name + \"|\" + .[0].Config.Labels[\"org.sylin.koi.lab.owner\"] + \"|\" + .[0].Config.Labels[\"org.sylin.koi.lab.run\"]'); test \"$actual\" = \"/{container_name}|koi-lab|{}\"; docker container rm --force \"$cid\" >/dev/null; elif test \"$required\" = true; then exit 76; fi; rm -f {run_dir}/container.id; elif test \"$required\" = true; then exit 76; fi",
        run_id.as_str(),
        run_id.as_str(),
        run_id.as_str()
    ))
}

fn story_image_remove_script(
    node: &NodeSpec,
    run_id: &RunId,
    require_present: bool,
) -> Result<String> {
    let lock_dir = node.lock_dir()?;
    let run_dir = node.run_dir(run_id)?;
    let image_ref = story_image_ref(run_id);
    let required = if require_present { "true" } else { "false" };
    Ok(format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; required={required}; if test -f {run_dir}/image.ref; then test \"$(cat {run_dir}/image.ref)\" = {image_ref}; if docker image inspect {image_ref} >/dev/null 2>&1; then test -f {run_dir}/image.id; expected=$(cat {run_dir}/image.id); printf '%s' \"$expected\" | grep -Eq '^sha256:[0-9a-f]{{64}}$'; actual=$(docker image inspect {image_ref} | jq -r '.[0].Id'); test \"$actual\" = \"$expected\"; test \"$(docker image inspect {image_ref} | jq -r '.[0].Config.Labels[\"org.sylin.koi.lab.run\"]')\" = {}; docker image rm {image_ref} >/dev/null; elif test \"$required\" = true; then exit 76; fi; rm -f {run_dir}/image.ref {run_dir}/image.id; elif test \"$required\" = true; then exit 76; fi; rm -f {run_dir}/story-image.tar",
        run_id.as_str(),
        run_id.as_str(),
        run_id.as_str()
    ))
}

fn cleanup_script(node: &NodeSpec, run_id: &RunId) -> Result<String> {
    let root = node.remote_root()?;
    let lock = node.lock_dir()?;
    let run_dir = node.run_dir(run_id)?;
    let container_cleanup = story_container_remove_script(node, run_id, false)?;
    let runtime_container_cleanup = RuntimeFaultRole::ALL
        .into_iter()
        .map(|role| runtime_fault_container_remove_script(node, run_id, role, false))
        .collect::<Result<Vec<_>>>()?
        .join("; ");
    let runtime_network_cleanup = runtime_fault_network_remove_script(node, run_id)?;
    let image_cleanup = story_image_remove_script(node, run_id, false)?;
    let runtime_proxy_cleanup = runtime_proxy_stop_script(node, run_id, false)?;
    let systemd_cleanup =
        crate::service_lifecycle::transient_service_cleanup_script(node, run_id, false)?;
    Ok(format!(
        "set -eu; test -f {lock}/owner; test \"$(cat {lock}/owner)\" = {}; if test -d {run_dir}; then test -f {run_dir}/owner; test \"$(cat {run_dir}/owner)\" = {}; {systemd_cleanup}; {container_cleanup}; {runtime_container_cleanup}; {runtime_network_cleanup}; {image_cleanup}; if test -f {run_dir}/fixture.pid; then pid=$(cat {run_dir}/fixture.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; test -f {run_dir}/fixture.exe; if kill -0 \"$pid\" 2>/dev/null; then expected=$(cat {run_dir}/fixture.exe); test \"$(readlink -f /proc/\"$pid\"/exe)\" = \"$expected\"; kill \"$pid\"; i=0; while kill -0 \"$pid\" 2>/dev/null && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; if kill -0 \"$pid\" 2>/dev/null; then kill -KILL \"$pid\"; fi; fi; rm -f {run_dir}/fixture.pid; fi; if test -f {run_dir}/dns-blocker.pid; then pid=$(cat {run_dir}/dns-blocker.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; test -f {run_dir}/dns-blocker.exe; if kill -0 \"$pid\" 2>/dev/null; then expected=$(cat {run_dir}/dns-blocker.exe); test \"$(readlink -f /proc/\"$pid\"/exe)\" = \"$expected\"; kill \"$pid\"; i=0; while kill -0 \"$pid\" 2>/dev/null && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; if kill -0 \"$pid\" 2>/dev/null; then kill -KILL \"$pid\"; fi; fi; rm -f {run_dir}/dns-blocker.pid; fi; if test -f {run_dir}/daemon.pid; then pid=$(cat {run_dir}/daemon.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; if kill -0 \"$pid\" 2>/dev/null; then exe=$(readlink -f /proc/\"$pid\"/exe); test \"$exe\" = {run_dir}/koi; kill \"$pid\"; i=0; while kill -0 \"$pid\" 2>/dev/null && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; if kill -0 \"$pid\" 2>/dev/null; then kill -KILL \"$pid\"; fi; fi; rm -f {run_dir}/daemon.pid; fi; {runtime_proxy_cleanup}; rm -f {run_dir}/daemon.log {run_dir}/fixture.log {run_dir}/fixture.exe {run_dir}/dns-blocker.log {run_dir}/dns-blocker.exe {run_dir}/docker-proxy.log {run_dir}/docker-proxy.exe {run_dir}/docker_socket_proxy.py {run_dir}/koi.partial; for owned in {run_dir}/data {run_dir}/runtime; do if test -d \"$owned\"; then resolved=$(realpath \"$owned\"); test \"$resolved\" = \"$owned\"; rm -rf -- \"$resolved\"; fi; done; rm -f {run_dir}/koi {run_dir}/artifact.sha256 {run_dir}/owner; rmdir {run_dir}; fi; rmdir {root}/runs 2>/dev/null || true; rm -f {lock}/owner; rmdir {lock}",
        run_id.as_str(),
        run_id.as_str()
    ))
}

pub(crate) fn wait_for_http(url: &str) -> Result<()> {
    let mut last_error = String::new();
    for _ in 0..100 {
        match curl_text("GET", url, None, None) {
            Ok(body) if body.trim() == "OK" => return Ok(()),
            Ok(body) => last_error = format!("unexpected body {body:?}"),
            Err(error) => last_error = format!("{error:#}"),
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("endpoint {url} did not become healthy: {last_error}")
}

fn wait_for_proxy(url: &str, name: &str, port: u16) -> Result<()> {
    let mut last = String::new();
    for _ in 0..100 {
        match curl_json("GET", url, None, None) {
            Ok(status) => {
                let ready =
                    status
                        .get("proxies")
                        .and_then(Value::as_array)
                        .is_some_and(|proxies| {
                            proxies.iter().any(|proxy| {
                                proxy.get("name").and_then(Value::as_str) == Some(name)
                                    && proxy.get("listen_port").and_then(Value::as_u64)
                                        == Some(u64::from(port))
                                    && proxy.get("state").and_then(Value::as_str) == Some("running")
                                    && proxy.get("cert_source").and_then(Value::as_str)
                                        == Some("certmesh")
                            })
                        });
                if ready {
                    return Ok(());
                }
                last = status.to_string();
            }
            Err(error) => last = format!("{error:#}"),
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("proxy {name}:{port} did not reach running/certmesh state: {last}")
}

pub(crate) fn curl_json(
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<Value> {
    let serialized = body.map(serde_json::to_string).transpose()?;
    let text = curl_text(method, url, token, serialized.as_deref())?;
    serde_json::from_str(&text).with_context(|| format!("{url} returned invalid JSON"))
}

pub(crate) fn curl_text(
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Result<String> {
    let mut command = Command::new("curl.exe");
    command.args([
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--max-time",
        "10",
        "--request",
        method,
        url,
    ]);
    if let Some(token) = token {
        command.args(["--header", &format!("x-koi-token: {token}")]);
    }
    if let Some(body) = body {
        command.args([
            "--header",
            "content-type: application/json",
            "--data-binary",
            "@-",
        ]);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to start curl.exe for {url}"))?;
        child
            .stdin
            .take()
            .context("curl stdin was not piped")?
            .write_all(body.as_bytes())
            .context("could not stream the HTTP request body to curl")?;
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for curl.exe for {url}"))?;
        return curl_output(method, url, output);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to start curl.exe for {url}"))?;
    curl_output(method, url, output)
}

fn curl_output(method: &str, url: &str, output: std::process::Output) -> Result<String> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let response = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        bail!(
            "HTTP {method} {url} failed (exit {}): {stderr}; response={response}",
            output.status.code().unwrap_or(-1)
        );
    }
    String::from_utf8(output.stdout).with_context(|| format!("{url} returned non-UTF-8 data"))
}

fn required_json_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .with_context(|| format!("response is missing string field {field}"))
}

fn status_has_active_member(status: &Value, hostname: &str) -> bool {
    status
        .get("members")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|member| {
                member.get("hostname").and_then(Value::as_str) == Some(hostname)
                    && member.get("status").and_then(Value::as_str) == Some("active")
            })
        })
}

fn current_epoch() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("system clock does not fit in i64")
}

fn command_exists(program: &str) -> bool {
    Command::new("where.exe")
        .arg(program)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn command_stdout(program: &str, args: &[&str]) -> Result<String> {
    command_stdout_in(Path::new("."), program, args)
}

fn command_stdout_in(directory: &Path, program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .current_dir(directory)
        .args(args)
        .output()
        .with_context(|| format!("failed to start {program}"))?;
    if !output.status.success() {
        bail!("{program} failed with exit {}", output.status);
    }
    Ok(String::from_utf8(output.stdout)
        .with_context(|| format!("{program} returned non-UTF-8 output"))?
        .trim()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> NodeSpec {
        NodeSpec::PuttyLinux {
            id: "brook".into(),
            hostname: "stone-platinum-brook".into(),
            address: "192.168.1.44".into(),
            user: "stone".into(),
            host_key: "SHA256:abcdefghijklmnopqrstuvwxyz".into(),
            architecture: "x86_64".into(),
            remote_root: "/home/stone/koi-test".into(),
            http_port: 16541,
            mtls_port: 16542,
            acme_port: 16543,
            proxy_port: 16544,
            dns_port: 16553,
            fixture_port: 16554,
            container_port: 16555,
        }
    }

    #[test]
    fn cleanup_is_owner_checked_and_recurses_only_into_owned_data_roots() {
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        let script = cleanup_script(&node(), &run_id).unwrap();
        assert!(script.contains("cat /home/stone/koi-test/.koi-lab-lock/owner"));
        assert!(script.contains("cat /home/stone/koi-test/runs/v1-20260719T000000Z-deadbeef/owner"));
        assert!(script.contains("test \"$resolved\" = \"$owned\""));
        assert!(script.contains("rm -rf -- \"$resolved\""));
        assert!(!script.contains("pkill"));
        assert!(script.contains("systemd-unit"));
        assert!(script.contains("sudo -n systemctl stop koi-lab-v1-"));
        assert!(!script.contains("systemctl stop koi.service"));
        assert!(script.contains("readlink -f /proc/\"$pid\"/exe"));
        assert!(script.contains("test \"$exe\" = /home/stone/koi-test/runs/"));
        assert!(script.contains("fixture.exe"));
        assert!(script.contains("dns-blocker.exe"));
        assert!(script.contains("test \"$(readlink -f /proc/\"$pid\"/exe)\" = \"$expected\""));
        assert!(script.contains("org.sylin.koi.lab.owner"));
        assert!(script.contains("org.sylin.koi.lab.run"));
        assert!(script.contains("koi-lab-story:v1-20260719t000000z-deadbeef"));
        assert!(script.contains("docker container rm --force \"$cid\""));
        assert!(script.contains("docker image rm koi-lab-story:"));
    }

    #[test]
    fn story_container_cleanup_requires_the_exact_run_identity() {
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        let container = story_container_remove_script(&node(), &run_id, true).unwrap();
        assert!(container.contains("required=true"));
        assert!(container.contains(
            "/koi-lab-story-v1-20260719t000000z-deadbeef|koi-lab|v1-20260719T000000Z-deadbeef"
        ));

        let image = story_image_remove_script(&node(), &run_id, true).unwrap();
        assert!(image.contains("required=true"));
        assert!(image.contains("test \"$actual\" = \"$expected\""));
        assert!(image.contains("org.sylin.koi.lab.run"));
    }

    #[test]
    fn runtime_fault_cleanup_requires_role_run_and_engine_identity() {
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        for role in RuntimeFaultRole::ALL {
            let script =
                runtime_fault_container_remove_script(&node(), &run_id, role, true).unwrap();
            assert!(script.contains("required=true"));
            assert!(script.contains("org.sylin.koi.lab.owner"));
            assert!(script.contains("org.sylin.koi.lab.run"));
            assert!(script.contains("org.sylin.koi.lab.role"));
            assert!(script.contains(&format!("|{}\"", role.as_str())));
        }

        let network = runtime_fault_network_remove_script(&node(), &run_id).unwrap();
        assert!(network.contains("runtime-fault-network.id"));
        assert!(network.contains("test \"$actual\" = \"$expected|koi-lab|v1-"));
        assert!(network.contains("docker network rm koi-lab-runtime-net-"));
    }

    #[test]
    fn runtime_proxy_cleanup_is_pid_executable_and_command_line_scoped() {
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        let script = runtime_proxy_stop_script(&node(), &run_id, true).unwrap();
        assert!(script.contains("required=true"));
        assert!(script.contains("docker-proxy.pid"));
        assert!(script.contains("docker-proxy.exe"));
        assert!(script.contains("readlink -f /proc/\"$pid\"/exe"));
        assert!(script.contains("/proc/\"$pid\"/cmdline"));
        assert!(script.contains("--upstream /var/run/docker.sock"));
        assert!(!script.contains("pkill"));
        assert!(!script.contains("sudo"));
    }

    #[test]
    fn lock_acquisition_is_atomic_and_records_ownership() {
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        let script = acquire_lock_script(&node(), &run_id).unwrap();
        assert!(script.contains("mkdir /home/stone/koi-test/.koi-lab-lock"));
        assert!(script.contains("v1-20260719T000000Z-deadbeef"));
        assert!(script.contains("exit 73"));
    }

    #[test]
    fn privileged_lane_requires_an_explicit_gate() {
        assert!(require_system_mutation(false).is_err());
        assert!(require_system_mutation(true).is_ok());
    }

    #[test]
    fn windows_iwr_mapping_restores_the_exact_hosts_bytes() {
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        let script = windows_iwr_script("192.168.1.55", "stone-granite-spring", 17544, &run_id);
        assert!(script.contains("ReadAllBytes($hosts)"));
        assert!(script.contains("finally { [IO.File]::WriteAllBytes($hosts, $before)"));
        assert!(script.contains("$after=[IO.File]::ReadAllBytes($hosts)"));
        assert!(script.contains("hosts file bytes were not restored exactly"));
        assert!(script.contains("192.168.1.55`tstone-granite-spring"));
        assert!(script.contains("Invoke-WebRequest"));
    }

    #[test]
    fn windows_member_acl_evidence_is_sid_based_and_covers_secret_custody() {
        let root = Path::new(r"F:\repo\.lab-runs\v1-test\windows-member");
        let script = windows_member_acl_script(root, "stone-leaded-sparkle");
        assert!(script.contains("S-1-5-18"));
        assert!(script.contains("S-1-5-32-544"));
        assert!(script.contains("WindowsIdentity]::GetCurrent().User.Value"));
        assert!(script.contains(".GetAccessControl()"));
        assert!(script.contains("AreAccessRulesProtected"));
        assert!(script.contains(r"windows-member\data' $true"));
        assert!(script.contains(r"certs\stone-leaded-sparkle\key.pem' $false"));
        assert!(script.contains(r"certmesh\member.json' $false"));
        assert!(script.contains(r"program-data\koi\koi.endpoint' $true"));
        assert!(!script.contains("Get-Acl"));
        assert!(!script.contains("Everyone"));
        assert!(!script.contains("Authenticated Users"));
    }

    #[test]
    fn windows_curl_keeps_verification_with_private_ca_revocation_best_effort() {
        let args = windows_curl_args("192.168.1.55", "stone-granite-spring", 17544);
        assert!(args.iter().any(|arg| arg == "--ssl-revoke-best-effort"));
        assert!(args
            .iter()
            .any(|arg| { arg == "stone-granite-spring:17544:192.168.1.55" }));
        assert!(!args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-k" | "--insecure" | "--ssl-no-revoke")));
    }

    #[test]
    fn windows_certificate_store_scripts_use_x509_store_without_a_provider() {
        let fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let scripts = [
            windows_trust_fingerprint_script().to_owned(),
            windows_store_contains_script(fingerprint),
        ];
        for script in scripts {
            assert!(script.contains("X509Store]::new('Root','LocalMachine')"));
            assert!(script.contains("OpenFlags]::ReadOnly"));
            assert!(script.contains("finally { $store.Close(); $sha.Dispose() }"));
            assert!(!script.contains("Cert:\\"));
            assert!(!script.contains("Import-Module"));
        }
    }

    #[test]
    fn certificate_identity_requires_a_full_sha256() {
        assert!(is_sha256(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_sha256("0123"));
        assert!(!is_sha256(
            "z123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn invite_pin_mismatch_keeps_the_secret_and_changes_one_pin_digit() {
        let fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mismatched =
            mismatch_invite_fingerprint(&format!("safe_secret-1.{fingerprint}"), fingerprint)
                .unwrap();
        assert!(mismatched.starts_with("safe_secret-1."));
        let changed = mismatched.rsplit_once('.').unwrap().1;
        assert!(is_sha256(changed));
        assert_ne!(changed, fingerprint);
        assert_eq!(&changed[1..], &fingerprint[1..]);
    }

    #[test]
    fn native_trust_install_is_pinned_to_run_owned_paths() {
        let node = node();
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        let run_dir = node.run_dir(&run_id).unwrap();
        let script = native_trust_install_command(
            &node,
            &run_id,
            &format!("{run_dir}/data/certmesh/ca/ca-cert.pem"),
            &format!("{run_dir}/trust-state"),
        )
        .unwrap();
        assert!(script.contains("sudo -n env KOI_DATA_DIR="));
        assert!(script.contains("test ! -e"));
        assert!(native_trust_install_command(&node, &run_id, "/tmp/ca.pem", "/tmp/state").is_err());
    }

    #[test]
    fn native_trust_removal_targets_only_the_recorded_fingerprint() {
        let node = node();
        let run_id = RunId::parse("v1-20260719T000000Z-deadbeef").unwrap();
        let run_dir = node.run_dir(&run_id).unwrap();
        let fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let script = native_trust_remove_command(
            &node,
            &run_id,
            "koi-ca-cert",
            fingerprint,
            &format!("{run_dir}/trust-state"),
        )
        .unwrap();
        assert!(script.contains("koi-ca-cert-0123456789abcdef.crt"));
        assert!(script.contains("koi-ca-cert-0123456789abcdef.pem"));
        assert!(script.contains("/etc/ssl/certs/*.[0-9]*"));
        assert!(script.contains("readlink"));
        assert!(native_trust_remove_command(
            &node,
            &run_id,
            "other",
            fingerprint,
            &format!("{run_dir}/trust-state"),
        )
        .is_err());
    }

    #[test]
    fn parsers_keep_evaluation_centralized() {
        let tools = parse_bool_map("curl=yes\njq=no\n");
        assert_eq!(tools.get("curl"), Some(&true));
        assert_eq!(tools.get("jq"), Some(&false));

        let services = parse_services("koi|active|enabled\navahi-daemon|inactive|disabled\n");
        assert_eq!(services["koi"].active, "active");
        assert_eq!(services["avahi-daemon"].enabled, "disabled");
    }
}
