//! W4 (ADR-032): Windows-hosted CA rotation.
//!
//! The CA daemon runs on THIS workstation (run-owned `koi.exe`, catalog
//! ports, HTTP+mTLS bound to the LAN behind scenario-scoped firewall rules)
//! and a physical Linux member enrolls against it over the real network:
//! wrong-pin refusal before keygen, join with local CSR custody (mode 0600),
//! CA roster membership, renewal with key rotation and roster fingerprint
//! convergence, revocation pulled to a RED self-revocation diagnosis, and
//! refused rejoin with the local identity left byte-identical. The
//! Windows-member half of W4 (member on Windows, CA on Linux) is proven by
//! `exercise_windows_member_custody` inside `certmesh-native-trust`.
//!
//! Gated on elevation, `--allow-system-mutation`, and the catalog granting
//! the workstation `firewall` mutations; every rule is scenario-named and
//! removed on every path.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::Digest;

use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, RunId, WindowsCaReport};

const FIREWALL_HTTP_RULE: &str = "koi-lab w4 ca http (tcp 18541)";
const FIREWALL_MTLS_RULE: &str = "koi-lab w4 ca mtls (tcp 18542)";

#[derive(Default)]
struct WindowsCaResources {
    ca_daemon: bool,
    ca_created: bool,
    member_daemon: bool,
    firewall_rules: Vec<&'static str>,
}

impl Lab {
    pub fn certmesh_lifecycle_windows_ca(
        &self,
        run_id: &RunId,
        member_id: Option<&str>,
        allow_system_mutation: bool,
    ) -> Result<WindowsCaReport> {
        crate::lab::require_system_mutation(allow_system_mutation)?;
        crate::lab::ensure_windows_elevated()?;

        let windows = crate::planner::machine_by_id(self.config(), "windows")
            .context("catalog has no windows machine")?;
        if !windows.allows_mutation("firewall") {
            bail!(
                "the catalog does not grant firewall mutations to {}",
                windows.id()
            );
        }
        let member = crate::planner::machine_by_id(self.config(), member_id.unwrap_or("brook"))
            .context("catalog has no such member machine")?;
        if !member.supports_role("member") {
            bail!("{} does not declare the member role", member.id());
        }
        if !matches!(member, crate::model::NodeSpec::PuttyLinux { .. }) {
            bail!("the W4 member must be a physical Linux node");
        }

        let mut resources = WindowsCaResources::default();
        let result = self.run_windows_ca_lifecycle(
            run_id,
            windows.address(),
            windows,
            member,
            &mut resources,
        );
        let cleanup = self.cleanup_windows_ca(run_id, windows, member, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "firewall rules, CA daemon, member daemon, and run directories were removed",
                ));
                let path = output_path(run_id.as_str()).join("certmesh-lifecycle-windows-ca.json");
                self.write_evidence(&path, &report)?;
                Ok(report)
            }
            (Err(e), Ok(())) => Err(e),
            (Ok(_), Err(cleanup_error)) => {
                bail!("checks passed but exact cleanup failed: {cleanup_error:#}")
            }
            (Err(e), Err(cleanup_error)) => {
                bail!("{e:#}; compensating cleanup also failed: {cleanup_error:#}")
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_windows_ca_lifecycle(
        &self,
        run_id: &RunId,
        windows_address: &str,
        windows: &crate::model::NodeSpec,
        member: &crate::model::NodeSpec,
        resources: &mut WindowsCaResources,
    ) -> Result<WindowsCaReport> {
        let artifact_sha256 = self
            .remote_line(
                member,
                &format!("cat {}/artifact.sha256", member.run_dir(run_id)?),
            )
            .context("read staged artifact sha256 from the member")?;

        // ── Scenario-scoped firewall: the CA answers the LAN on 18541/18542 ──
        let ca_root = self.prepare_windows_member_dir(run_id)?;
        let exe = ca_root.join("koi.exe");
        self.firewall_rule(FIREWALL_HTTP_RULE, "18541", &exe)?;
        self.firewall_rule(FIREWALL_MTLS_RULE, "18542", &exe)?;
        resources.firewall_rules = vec![FIREWALL_HTTP_RULE, FIREWALL_MTLS_RULE];

        // ── Windows CA daemon (HTTP+mTLS on the LAN, everything else off) ──
        let ports = windows.lab_ports()?;
        let _ca_child = self.start_windows_ca_daemon(&ca_root, &ports)?;
        resources.ca_daemon = true;
        let ca_url = format!("http://{windows_address}:{}", ports.http);
        wait_for_http(&format!("{ca_url}/healthz"))
            .context("Windows CA daemon did not become healthy")?;
        let ca_token =
            self.require_windows_breadcrumb(&ca_root, &format!("http://127.0.0.1:{}", ports.http))?;

        let entropy = format!("{:x}", sha2::Sha256::digest(run_id.as_str().as_bytes()));
        curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/create"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "passphrase": format!("koi-lab-{}", run_id.as_str()),
                "entropy_hex": entropy,
                "operator": "koi-lab",
                "enrollment_open": true,
                "requires_approval": false,
                "auto_unlock": true
            })),
        )
        .context("Windows CA create failed")?;
        resources.ca_created = true;

        // ── Linux member daemon ──
        self.start_run_daemon(member, run_id)
            .context("start the Linux member run daemon")?;
        resources.member_daemon = true;
        let member_url = self.node_url(member)?;
        wait_for_http(&format!("{member_url}/healthz"))
            .context("Linux member daemon did not become healthy")?;

        // ── Wrong-pin refusal before any key exists ──
        let invite = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/invite"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "hostname": member.hostname(),
                "ttl_mins": 30
            })),
        )?;
        let invite_token = required_str(&invite, "token")?;
        let ca_fingerprint = required_str(&invite, "ca_fingerprint")?;
        let mismatched = mismatch_invite_fingerprint(&invite_token, &ca_fingerprint)?;
        let member_run_dir = member.run_dir(run_id)?;
        // Every member-side koi CLI invocation resolves its LOCAL custody
        // daemon through the breadcrumb, so it must see the RUN's runtime dir
        // — never an ambient XDG_RUNTIME_DIR or the node's standing service
        // (/var/run/koi.endpoint exists since the real-install cutover).
        let koi_env = format!(
            "env KOI_DATA_DIR={member_run_dir}/data \
             XDG_RUNTIME_DIR={member_run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1"
        );
        let wrong_pin = self
            .remote_line(
                member,
                &format!(
                    "{koi_env} {member_run_dir}/koi certmesh join {ca_url} --invite '{mismatched}' \
                 --ca-mtls-port {} --json",
                    ports.mtls
                ),
            )
            .context("wrong-pin refusal attempt on the member");
        if wrong_pin.is_ok() {
            bail!("Linux member accepted a deliberately mismatched invite pin");
        }
        let key_check = self.remote_line(
            member,
            &format!(
                "test -f {member_run_dir}/data/certs/{}/key.pem && echo PRESENT || echo ABSENT",
                member.hostname()
            ),
        )?;
        if key_check.contains("PRESENT") {
            bail!("wrong-pin attempt generated a member private key on the Linux member");
        }
        let wrong_pin_check = passed(
            "wrong_pin_refusal_before_keygen",
            "the member refused the mismatched pin and created no private key",
        );

        // ── Real join: local CSR custody on the Linux member ──
        self.remote_line(
            member,
            &format!(
                "{koi_env} {member_run_dir}/koi certmesh join {ca_url} --invite '{invite_token}' \
                 --ca-mtls-port {} --json",
                ports.mtls
            ),
        )
        .context("member join with local CSR custody")?;
        let mode = self
            .remote_line(
                member,
                &format!(
                    "stat -c '%a' {member_run_dir}/data/certs/{}/key.pem",
                    member.hostname()
                ),
            )
            .context("stat member private key mode")?;
        if mode.trim() != "600" {
            bail!("Linux member private key is mode {mode}, not 0600");
        }
        let join_check = passed(
            "member_join_local_custody",
            "the member joined the Windows CA with its private key never leaving the node (0600)",
        );

        let status = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&ca_token),
            None,
        )?;
        if !status_has_active_member(&status, member.hostname()) {
            bail!("the Windows CA roster did not contain the Linux member");
        }
        let roster_check = passed(
            "ca_roster_contains_member",
            "the Windows CA roster lists the Linux member as active",
        );

        // ── Renewal rotates the identity; the CA converges ──
        let before = member_identity_evidence(self, member, run_id)
            .context("capture member identity before renewal")?;
        self.remote_line(
            member,
            &format!("{koi_env} {member_run_dir}/koi certmesh renew --json"),
        )
        .context("explicit member renewal")?;
        let rotated = member_identity_evidence(self, member, run_id)
            .context("capture member identity after renewal")?;
        if rotated.key_sha256 == before.key_sha256 {
            bail!("renewal did not rotate the member private key");
        }
        if rotated.cert_sha256 == before.cert_sha256 {
            bail!("renewal did not replace the member certificate");
        }
        let status = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&ca_token),
            None,
        )?;
        let roster_fingerprint = status
            .get("members")
            .and_then(Value::as_array)
            .and_then(|members| {
                members
                    .iter()
                    .find(|m| m.get("hostname").and_then(Value::as_str) == Some(member.hostname()))
            })
            .and_then(|m| m.get("cert_fingerprint"))
            .and_then(Value::as_str)
            .context("CA roster omitted the renewed member fingerprint")?
            .to_ascii_lowercase();
        if roster_fingerprint != rotated.cert_fingerprint.to_ascii_lowercase() {
            bail!("CA roster fingerprint does not match the renewed member leaf");
        }
        let renewal_check = passed(
            "renewal_rotates_identity_and_converges",
            "renewal rotated key+certificate and the Windows CA roster converged to the new leaf",
        );

        // ── Revocation: the member pulls it and diagnoses RED ──
        curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/revoke"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "hostname": member.hostname(),
                "reason": "koi-lab w4 windows-hosted ca rotation",
                "operator": "koi-lab"
            })),
        )?;
        // A daemon restart forces the trust-bundle pull that carries the
        // revocation (the member has no other reason to contact the CA).
        // The restart is the shared preserve-state primitive: a fresh
        // `start_run_daemon` would refuse because the run's data directory
        // already exists, and a raw `pkill -f` would match the transport's
        // own `sh -c` wrapper argv and kill the session out from under
        // itself.
        self.restart_run_daemon(member, run_id)
            .context("restart member daemon for the revocation pull")?;
        wait_for_http(&format!("{member_url}/healthz")).context("member restart health")?;
        // `trust diagnose` exits non-zero BY DESIGN when the diagnosis is RED
        // (fail-loud contract) — and RED is exactly what this check expects,
        // so capture stdout regardless of exit status instead of
        // run_checked's fail-on-nonzero.
        let red_output = self
            .remote_output(
                member,
                &format!("{koi_env} {member_run_dir}/koi trust diagnose --json"),
            )
            .context("member trust diagnosis after revocation")?;
        let red: Value = serde_json::from_str(String::from_utf8_lossy(&red_output.stdout).trim())
            .context("member diagnosis was not JSON")?;
        if red.get("overall").and_then(Value::as_str) != Some("red") {
            bail!("revoked member diagnosis was not RED");
        }
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
        let red_check = passed(
            "revocation_pull_red",
            "the member pulled its revocation from the Windows CA and diagnosed RED (self_revocation)",
        );

        // ── Refused renewal and rejoin; identity immutable ──
        // Refusals are CLI errors: the reason lands on stderr with a
        // non-zero exit, so judge the captured output, not run_checked.
        let denied_renewal = self
            .remote_output(
                member,
                &format!("{koi_env} {member_run_dir}/koi certmesh renew --json"),
            )
            .context("revoked-member renewal attempt")?;
        let denied_renewal_text = format!(
            "{} {}",
            String::from_utf8_lossy(&denied_renewal.stdout),
            String::from_utf8_lossy(&denied_renewal.stderr)
        );
        if denied_renewal.status.success()
            || !denied_renewal_text.to_ascii_lowercase().contains("revoked")
        {
            bail!("revoked member renewal was not refused by the Windows CA");
        }
        let rejoin_invite = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/invite"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "hostname": member.hostname(),
                "ttl_mins": 30
            })),
        )?;
        let rejoin_token = required_str(&rejoin_invite, "token")?;
        let denied_rejoin = self
            .remote_output(
                member,
                &format!(
                    "{koi_env} {member_run_dir}/koi certmesh join {ca_url} --invite '{rejoin_token}' \
                 --ca-mtls-port {} --json",
                    ports.mtls
                ),
            )
            .context("revoked-member rejoin attempt")?;
        let denied_rejoin_text = format!(
            "{} {}",
            String::from_utf8_lossy(&denied_rejoin.stdout),
            String::from_utf8_lossy(&denied_rejoin.stderr)
        );
        if denied_rejoin.status.success()
            || !denied_rejoin_text.to_ascii_lowercase().contains("revoked")
        {
            bail!("revoked member rejoin was not refused by the Windows CA");
        }
        let after = member_identity_evidence(self, member, run_id)
            .context("capture member identity after refused renewal/rejoin")?;
        if after.key_sha256 != rotated.key_sha256 || after.cert_sha256 != rotated.cert_sha256 {
            bail!("refused renewal/rejoin changed the active local identity");
        }
        let refusal_check = passed(
            "renewal_and_rejoin_refused_identity_immutable",
            "the Windows CA refused the revoked member's renewal and rejoin; the local identity is byte-identical",
        );

        Ok(WindowsCaReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            ca_node: "windows".into(),
            member_node: member.id().to_owned(),
            artifact_sha256,
            checks: vec![
                wrong_pin_check,
                join_check,
                roster_check,
                renewal_check,
                red_check,
                refusal_check,
            ],
            // The report carries only run ids, node ids, the artifact hash,
            // and fixed check strings — never invite tokens, pins, or
            // passphrases.
            secrets_redacted: true,
        })
    }

    fn firewall_rule(&self, name: &'static str, port: &str, exe: &std::path::Path) -> Result<()> {
        crate::lab::firewall_rule(name, "tcp", port, exe)
    }

    fn cleanup_windows_ca(
        &self,
        run_id: &RunId,
        windows: &crate::model::NodeSpec,
        member: &crate::model::NodeSpec,
        resources: &mut WindowsCaResources,
    ) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        if resources.member_daemon {
            if let Err(e) = self.stop_webhook_daemon(member, run_id) {
                errors.push(format!("stop member daemon: {e:#}"));
            }
            if let Err(e) = self.remove_webhook_sink_files(member, run_id) {
                errors.push(format!("remove member run files: {e:#}"));
            }
        }
        if resources.ca_daemon {
            // The spawned CA daemon may still be running (it outlives failed
            // health checks); stop it by exact executable identity, then
            // remove the directory it was holding open.
            let root = self.windows_member_dir(run_id);
            let exe = root.join("koi.exe");
            if exe.is_file() {
                match crate::lab::windows_process_ids_for_executable(&exe) {
                    Ok(process_ids) => {
                        for process_id in process_ids {
                            if let Err(e) = crate::lab::stop_exact_windows_process(process_id, &exe)
                            {
                                errors.push(format!("stop CA daemon pid {process_id}: {e:#}"));
                            }
                        }
                    }
                    Err(e) => errors.push(format!("enumerate CA daemon processes: {e:#}")),
                }
            }
            if let Err(e) = self.remove_windows_member_dir(run_id, &root) {
                errors.push(format!("remove Windows CA run dir: {e:#}"));
            }
        }
        if !resources.firewall_rules.is_empty() {
            if let Err(e) = crate::lab::firewall_rules_remove(&resources.firewall_rules) {
                errors.push(format!("{e:#}"));
            }
        }
        let _ = windows;
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("cleanup errors: {}", errors.join("; "))
        }
    }
}

fn required_str(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context(format!("invite response omitted {key}"))
}

fn mismatch_invite_fingerprint(token: &str, real_fingerprint: &str) -> Result<String> {
    // Flip the first hex character of the embedded CA fingerprint so the pin
    // differs while the token shape stays plausible.
    let mutated = match real_fingerprint.chars().next() {
        Some('0') => format!("1{}", &real_fingerprint[1..]),
        Some(_) => format!("0{}", &real_fingerprint[1..]),
        None => bail!("CA fingerprint was empty"),
    };
    let secret = token
        .split('.')
        .next()
        .context("invite token had no secret half")?;
    Ok(format!("{secret}.{mutated}"))
}

fn status_has_active_member(status: &Value, hostname: &str) -> bool {
    status
        .get("members")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|m| {
                m.get("hostname").and_then(Value::as_str) == Some(hostname)
                    && m.get("status").and_then(Value::as_str) == Some("active")
            })
        })
}

struct MemberIdentity {
    key_sha256: String,
    cert_sha256: String,
    cert_fingerprint: String,
}

fn member_identity_evidence(
    lab: &Lab,
    member: &crate::model::NodeSpec,
    run_id: &RunId,
) -> Result<MemberIdentity> {
    let run_dir = member.run_dir(run_id)?;
    let output = lab.remote_line(
        member,
        &format!(
            "sha256sum {run_dir}/data/certs/{}/key.pem {run_dir}/data/certs/{}/cert.pem",
            member.hostname(),
            member.hostname()
        ),
    )?;
    let mut hashes = output
        .lines()
        .map(|l| l.split_whitespace().next().unwrap_or_default().to_owned());
    let key_sha256 = hashes.next().unwrap_or_default();
    let cert_sha256 = hashes.next().unwrap_or_default();
    let fingerprint = lab.remote_line(
        member,
        &format!(
            "openssl x509 -in {run_dir}/data/certs/{}/cert.pem -noout -fingerprint -sha256 \
             | cut -d= -f2 | tr -d :",
            member.hostname()
        ),
    )?;
    Ok(MemberIdentity {
        key_sha256,
        cert_sha256,
        cert_fingerprint: fingerprint.trim().to_owned(),
    })
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}
