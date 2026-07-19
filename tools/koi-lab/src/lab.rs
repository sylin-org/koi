use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::model::{
    output_path, ArtifactIdentity, CertmeshSmokeReport, CheckResult, CleanupPlan, DeployedNode,
    DeploymentManifest, LabConfig, NativeTrustReport, NodeCleanupPlan, NodeSnapshot, NodeSpec,
    PreflightReport, RunId, ServiceSnapshot,
};
use crate::putty::PuttyTransport;

const REQUIRED_LOCAL_TOOLS: &[&str] = &["cross", "docker", "git", "plink", "pscp"];
const REQUIRED_REMOTE_TOOLS: &[&str] = &["sha256sum", "systemctl", "ss", "realpath", "readlink"];
const SCENARIO_REMOTE_TOOLS: &[&str] = &["curl", "jq", "dig", "nc", "docker", "openssl", "setsid"];
const TEST_PORTS: &[u16] = &[5641, 5642, 5643];
const MAX_CLOCK_SKEW_SECONDS: i64 = 5;

pub struct Lab {
    repo_root: PathBuf,
    config: LabConfig,
    transport: PuttyTransport,
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

    pub fn build_release(&self) -> Result<ArtifactIdentity> {
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
        self.artifact_identity(None)
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

    pub fn certmesh_smoke(&self, run_id: &RunId) -> Result<CertmeshSmokeReport> {
        let plan = self.cleanup_plan(run_id)?;
        if plan
            .nodes
            .iter()
            .any(|node| !node.owner_matches || !node.run_dir_present)
        {
            bail!("certmesh smoke refused: run does not own both staged node directories");
        }
        let ca = self.remote_by_id("brook")?;
        let member = self.remote_by_id("granite")?;
        let trust_before_ca = self.system_trust_fingerprint(ca)?;
        let trust_before_member = self.system_trust_fingerprint(member)?;

        self.start_run_daemon(ca, run_id)?;
        self.start_run_daemon(member, run_id)?;
        let ca_url = self.node_url(ca)?;
        let member_url = self.node_url(member)?;
        wait_for_http(&format!("{ca_url}/healthz"))?;
        wait_for_http(&format!("{member_url}/healthz"))?;

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
        let join_command = format!(
            "set -eu; test \"$(cat {member_run_dir}/owner)\" = {}; env KOI_DATA_DIR={member_run_dir}/data XDG_RUNTIME_DIR={member_run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1 {member_run_dir}/koi certmesh join {ca_url} --invite {invite_token} --json",
            run_id.as_str()
        );
        self.transport.run_checked(member, &join_command)?;

        let status = curl_json("GET", &format!("{ca_url}/v1/certmesh/status"), None, None)?;
        let members = status
            .get("members")
            .and_then(Value::as_array)
            .context("CA status did not contain a members array")?;
        let member_present = members
            .iter()
            .any(|value| value.get("hostname").and_then(Value::as_str) == Some(member.hostname()));
        if !member_present {
            bail!(
                "CA roster does not contain {} after join",
                member.hostname()
            );
        }

        let diagnosis_command = format!(
            "env KOI_DATA_DIR={member_run_dir}/data KOI_NO_CREDENTIAL_STORE=1 {member_run_dir}/koi trust diagnose --json"
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
        let trust_after_ca = self.system_trust_fingerprint(ca)?;
        let trust_after_member = self.system_trust_fingerprint(member)?;
        if trust_before_ca != trust_after_ca || trust_before_member != trust_after_member {
            bail!("non-privileged certmesh smoke changed a Linux system trust store");
        }

        let report = CertmeshSmokeReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            ca_node: ca.id().to_owned(),
            member_node: member.id().to_owned(),
            checks: vec![
                CheckResult {
                    name: "windows_to_brook_health".into(),
                    passed: true,
                    detail: format!("{ca_url}/healthz returned OK"),
                },
                CheckResult {
                    name: "windows_to_granite_health".into(),
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
                    name: "granite_joined_brook".into(),
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
        let path = output_path(run_id.as_str()).join("certmesh-smoke.json");
        self.write_json(&path, &report)?;
        Ok(report)
    }

    pub fn certmesh_native_trust(
        &self,
        run_id: &RunId,
        allow_system_mutation: bool,
    ) -> Result<NativeTrustReport> {
        require_system_mutation(allow_system_mutation)?;
        let ca = self.remote_by_id("brook")?;
        let service = self.remote_by_id("granite")?;
        if !self.transport.run(ca, "sudo -n true")?.status.success() {
            bail!("native trust refused: {} lacks passwordless sudo", ca.id());
        }

        // This establishes certmesh and proves its non-privileged invariants first.
        // It does not alter either system trust store.
        self.certmesh_smoke(run_id)?;

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

        let trust_before = self.system_trust_fingerprint(ca)?;
        if self
            .native_tls_curl(ca, service, service.hostname())?
            .status
            .success()
        {
            bail!("native trust precondition failed: the fresh CA was already trusted");
        }

        let ca_run_dir = ca.run_dir(run_id)?;
        let ca_pem = format!("{ca_run_dir}/data/certmesh/ca/ca-cert.pem");
        let trust_state = format!("{ca_run_dir}/trust-state");
        let install_command = native_trust_install_command(ca, run_id, &ca_pem, &trust_state)?;
        let install_output = self.transport.run_checked(ca, &install_command)?;
        let install_json: Value = serde_json::from_str(install_output.trim())
            .context("native trust install returned invalid JSON")?;
        let installed = install_json
            .get("installed")
            .context("native trust install omitted installed result")?;
        let installed_name = required_json_string(installed, "name")?;
        let installed_fingerprint = required_json_string(installed, "fingerprint")?;
        if installed_name != "koi-ca-cert"
            || installed_fingerprint.len() != 64
            || !installed_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("native trust install returned an unsafe identity");
        }

        let exercise_result = (|| -> Result<Vec<CheckResult>> {
            let native_curl = self.native_tls_curl(ca, service, service.hostname())?;
            if !native_curl.status.success()
                || String::from_utf8_lossy(&native_curl.stdout).trim() != "OK"
            {
                bail!(
                    "native curl did not trust the Koi proxy after install: {}",
                    String::from_utf8_lossy(&native_curl.stderr).trim()
                );
            }

            let native_openssl = self.native_tls_openssl(ca, service, service.hostname())?;
            if !native_openssl.status.success() {
                bail!(
                    "openssl did not verify the Koi proxy after install: {}",
                    String::from_utf8_lossy(&native_openssl.stderr).trim()
                );
            }

            let wrong_hostname = format!("wrong-{}", service.hostname());
            if self
                .native_tls_curl(ca, service, &wrong_hostname)?
                .status
                .success()
            {
                bail!("native curl accepted the service certificate for a wrong hostname");
            }

            let list_command = format!(
                "sudo -n env KOI_DATA_DIR={trust_state} {ca_run_dir}/koi --json trust list"
            );
            let list_output = self.transport.run_checked(ca, &list_command)?;
            let list: Value = serde_json::from_str(list_output.trim())
                .context("native trust list returned invalid JSON")?;
            let tracked = list
                .get("roots")
                .and_then(Value::as_array)
                .is_some_and(|roots| {
                    roots.iter().any(|root| {
                        root.get("name").and_then(Value::as_str) == Some(&installed_name)
                            && root.get("fingerprint").and_then(Value::as_str)
                                == Some(&installed_fingerprint)
                    })
                });
            if !tracked {
                bail!("Koi trust state did not track the installed fingerprint");
            }

            Ok(vec![
                CheckResult {
                    name: "native_tls_fails_before_install".into(),
                    passed: true,
                    detail: "brook curl rejected granite's fresh CA before installation".into(),
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
                    detail: "brook curl and openssl verified granite without a custom CA".into(),
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
                    detail: format!("Koi tracked sha256 {installed_fingerprint}"),
                },
            ])
        })();

        // The removal path runs even when any post-install assertion fails.
        let removal_result = self.remove_native_trust(
            ca,
            run_id,
            &installed_name,
            &installed_fingerprint,
            &trust_state,
        );
        let trust_after = self.system_trust_fingerprint(ca)?;
        if let Err(error) = removal_result {
            bail!(
                "native trust cleanup failed for {} (manual source retained at {}): {error:#}",
                installed_fingerprint,
                ca_pem
            );
        }
        if trust_after != trust_before {
            bail!("native trust cleanup did not restore brook's captured system-store fingerprint");
        }
        if self
            .native_tls_curl(ca, service, service.hostname())?
            .status
            .success()
        {
            bail!("native curl still trusts the service after exact root removal");
        }
        let mut checks = exercise_result?;
        checks.push(CheckResult {
            name: "native_tls_fails_after_remove".into(),
            passed: true,
            detail: "brook curl rejected granite after the root was removed".into(),
        });
        checks.push(CheckResult {
            name: "system_trust_restored".into(),
            passed: true,
            detail: "brook's complete trust-store fingerprint matches the captured baseline".into(),
        });

        let report = NativeTrustReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            ca_node: ca.id().to_owned(),
            service_node: service.id().to_owned(),
            client_node: ca.id().to_owned(),
            ca_fingerprint: installed_fingerprint,
            checks,
            system_trust_restored: true,
            secrets_redacted: true,
        };
        let path = output_path(run_id.as_str()).join("native-trust.json");
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

    fn remote_by_id(&self, id: &str) -> Result<&NodeSpec> {
        self.config
            .remotes()
            .find(|node| node.id() == id)
            .with_context(|| format!("lab config has no remote node {id}"))
    }

    fn node_url(&self, node: &NodeSpec) -> Result<String> {
        Ok(format!(
            "http://{}:{}",
            node.address(),
            node.lab_ports()?.http
        ))
    }

    fn start_run_daemon(&self, node: &NodeSpec, run_id: &RunId) -> Result<()> {
        let run_dir = node.run_dir(run_id)?;
        let lock_dir = node.lock_dir()?;
        let ports = node.lab_ports()?;
        let http_port = ports.http;
        let mtls_port = ports.mtls;
        let acme_port = ports.acme;
        let proxy_port = ports.proxy;
        let command = format!(
            "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; ! ss -H -lnt | grep -Eq ':({http_port}|{mtls_port}|{acme_port}|{proxy_port}) '; mkdir {run_dir}/data {run_dir}/runtime; setsid -f sh -c 'echo $$ > {run_dir}/daemon.pid; exec env KOI_DATA_DIR={run_dir}/data XDG_RUNTIME_DIR={run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1 {run_dir}/koi --daemon --port {http_port} --http-bind 0.0.0.0 --mtls-port {mtls_port} --acme-port {acme_port} --no-ipc --no-mdns --no-dns --no-health --no-udp --no-runtime --no-acme --no-mcp-http >>{run_dir}/daemon.log 2>&1'",
            run_id.as_str(),
            run_id.as_str()
        );
        self.transport.run_checked(node, &command)?;
        Ok(())
    }

    fn daemon_token(&self, node: &NodeSpec, run_id: &RunId) -> Result<String> {
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

    fn system_trust_fingerprint(&self, node: &NodeSpec) -> Result<String> {
        self.remote_line(
            node,
            "find /usr/local/share/ca-certificates /etc/ssl/certs -maxdepth 2 -printf '%p|%y|%s|%l\\n' 2>/dev/null | sort | sha256sum | cut -d' ' -f1",
        )
    }

    fn native_tls_curl(
        &self,
        client: &NodeSpec,
        service: &NodeSpec,
        hostname: &str,
    ) -> Result<std::process::Output> {
        let port = service.lab_ports()?.proxy;
        self.transport.run(
            client,
            &format!(
                "curl --noproxy '*' --silent --show-error --fail --max-time 10 --resolve {hostname}:{port}:{} https://{hostname}:{port}/healthz",
                service.address()
            ),
        )
    }

    fn native_tls_openssl(
        &self,
        client: &NodeSpec,
        service: &NodeSpec,
        hostname: &str,
    ) -> Result<std::process::Output> {
        let port = service.lab_ports()?.proxy;
        self.transport.run(
            client,
            &format!(
                "openssl s_client -connect {}:{port} -servername {hostname} -verify_return_error -verify_hostname {hostname} </dev/null >/dev/null 2>&1",
                service.address()
            ),
        )
    }

    fn remove_native_trust(
        &self,
        node: &NodeSpec,
        run_id: &RunId,
        name: &str,
        fingerprint: &str,
        trust_state: &str,
    ) -> Result<()> {
        let command = native_trust_remove_command(node, run_id, name, fingerprint, trust_state)?;
        self.transport.run_checked(node, &command)?;
        Ok(())
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
        let tools = parse_bool_map(&self.transport.run_checked(node, &tool_command)?);

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
                .all(|tool| tools.get(*tool).copied().unwrap_or(false));
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

    fn remote_line(&self, node: &NodeSpec, command: &str) -> Result<String> {
        Ok(self.transport.run_checked(node, command)?.trim().to_owned())
    }

    fn git_commit(&self) -> Result<String> {
        command_stdout_in(&self.repo_root, "git", &["rev-parse", "HEAD"])
    }

    fn write_json<T: serde::Serialize>(&self, relative_path: &Path, value: &T) -> Result<PathBuf> {
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

fn require_system_mutation(allow_system_mutation: bool) -> Result<()> {
    if !allow_system_mutation {
        bail!("system mutation refused: pass --allow-system-mutation only for a dedicated lab run");
    }
    Ok(())
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
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; sudo -n env KOI_DATA_DIR={trust_state} {run_dir}/koi --json trust remove {name}; if test -L {leaf}; then test ! -e {anchor}; test \"$(readlink {leaf})\" = {anchor}; for link in /etc/ssl/certs/*.0; do if test -L \"$link\" && test \"$(readlink \"$link\")\" = {name}-{marker}.pem; then sudo -n rm -f -- \"$link\"; fi; done; sudo -n rm -f -- {leaf}; fi; test ! -e {anchor}; test ! -L {leaf}; resolved=$(sudo -n realpath {trust_state}); test \"$resolved\" = {trust_state}; sudo -n rm -rf -- \"$resolved\"",
        run_id.as_str(),
        run_id.as_str()
    ))
}

fn cleanup_script(node: &NodeSpec, run_id: &RunId) -> Result<String> {
    let root = node.remote_root()?;
    let lock = node.lock_dir()?;
    let run_dir = node.run_dir(run_id)?;
    Ok(format!(
        "set -eu; test -f {lock}/owner; test \"$(cat {lock}/owner)\" = {}; if test -d {run_dir}; then test -f {run_dir}/owner; test \"$(cat {run_dir}/owner)\" = {}; if test -f {run_dir}/daemon.pid; then pid=$(cat {run_dir}/daemon.pid); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; if kill -0 \"$pid\" 2>/dev/null; then exe=$(readlink -f /proc/\"$pid\"/exe); test \"$exe\" = {run_dir}/koi; kill \"$pid\"; i=0; while kill -0 \"$pid\" 2>/dev/null && test \"$i\" -lt 50; do sleep .1; i=$((i+1)); done; if kill -0 \"$pid\" 2>/dev/null; then kill -KILL \"$pid\"; fi; fi; rm -f {run_dir}/daemon.pid; fi; rm -f {run_dir}/daemon.log {run_dir}/koi.partial; for owned in {run_dir}/data {run_dir}/runtime; do if test -d \"$owned\"; then resolved=$(realpath \"$owned\"); test \"$resolved\" = \"$owned\"; rm -rf -- \"$resolved\"; fi; done; rm -f {run_dir}/koi {run_dir}/artifact.sha256 {run_dir}/owner; rmdir {run_dir}; fi; rmdir {root}/runs 2>/dev/null || true; rm -f {lock}/owner; rmdir {lock}",
        run_id.as_str(),
        run_id.as_str()
    ))
}

fn wait_for_http(url: &str) -> Result<()> {
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

fn curl_json(method: &str, url: &str, token: Option<&str>, body: Option<&Value>) -> Result<Value> {
    let serialized = body.map(serde_json::to_string).transpose()?;
    let text = curl_text(method, url, token, serialized.as_deref())?;
    serde_json::from_str(&text).with_context(|| format!("{url} returned invalid JSON"))
}

fn curl_text(method: &str, url: &str, token: Option<&str>, body: Option<&str>) -> Result<String> {
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
            body,
        ]);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to start curl.exe for {url}"))?;
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
        assert!(!script.contains("sudo"));
        assert!(script.contains("readlink -f /proc/\"$pid\"/exe"));
        assert!(script.contains("test \"$exe\" = /home/stone/koi-test/runs/"));
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
