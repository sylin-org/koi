//! W10 (ADR-032): backup and cold recovery with the CA hosted on Windows.
//!
//! The CA daemon runs on THIS workstation (staged through WindowsLabDaemon,
//! catalog ports, HTTP+mTLS reachable on the LAN behind scenario-scoped
//! firewall rules) and a physical Linux member holds custody across the whole
//! arc: encrypted v2 backup, wrong-backup-passphrase prevalidation that must
//! not disturb the live CA, exact run-scoped data loss (the owned data root
//! is erased and the daemon restarts uninitialized), restore under a NEW CA
//! passphrase, fingerprint + roster continuity, the machine binding rewritten
//! for this host, member renewal over the restored mTLS, a restart that comes
//! back LOCKED (no credential store), refused renewal with byte-identical
//! member identity, unlock only under the restored passphrase, and a second
//! key-rotating renewal the roster converges to.
//!
//! Assertion pattern: `certmesh-recovery` (the Linux recovery lane).
//! Enroll/renew mechanics: `certmesh-lifecycle-windows-ca` (W4).
//!
//! Gated on elevation, `--allow-system-mutation`, and the catalog granting
//! the workstation `firewall` mutations; every rule is scenario-named and
//! removed on every path.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::Digest;

use crate::certmesh_lifecycle_windows_ca::{
    member_identity_evidence, passed, required_str, status_has_active_member, MemberIdentity,
};
use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, RunId, WindowsRecoveryReport};
use crate::windows_daemon::{WindowsDaemonCapabilities, WindowsLabDaemon};

const FIREWALL_HTTP_RULE: &str = "koi-lab w10 ca http (tcp 18541)";
const FIREWALL_MTLS_RULE: &str = "koi-lab w10 ca mtls (tcp 18542)";

#[derive(Default)]
struct WindowsRecoveryResources {
    daemon: Option<WindowsLabDaemon>,
    firewall_rules: Vec<String>,
    member_daemon: bool,
}

impl Lab {
    pub fn certmesh_recovery_windows(
        &self,
        run_id: &RunId,
        member_id: Option<&str>,
        allow_system_mutation: bool,
    ) -> Result<WindowsRecoveryReport> {
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
            bail!("the W10 member must be a physical Linux node");
        }

        let mut resources = WindowsRecoveryResources::default();
        let result = self.run_windows_recovery(run_id, windows, member, &mut resources);
        let cleanup_errors = self.cleanup_windows_recovery(run_id, member, &mut resources);
        match (result, cleanup_errors.is_empty()) {
            (Ok(mut report), true) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "firewall rules, the CA daemon, the member daemon, and run directories were removed",
                ));
                let path = output_path(run_id.as_str()).join("certmesh-recovery-windows.json");
                self.write_evidence(&path, &report)?;
                Ok(report)
            }
            (Err(e), true) => Err(e),
            (Ok(_), false) => bail!(
                "checks passed but exact cleanup failed: {}",
                cleanup_errors.join("; ")
            ),
            (Err(e), false) => bail!(
                "{e:#}; compensating cleanup also failed: {}",
                cleanup_errors.join("; ")
            ),
        }
    }

    fn run_windows_recovery(
        &self,
        run_id: &RunId,
        windows: &crate::model::NodeSpec,
        member: &crate::model::NodeSpec,
        resources: &mut WindowsRecoveryResources,
    ) -> Result<WindowsRecoveryReport> {
        let artifact_sha256 = self
            .remote_line(
                member,
                &format!("cat {}/artifact.sha256", member.run_dir(run_id)?),
            )
            .context("read staged artifact sha256 from the member")?;

        let ports = windows.lab_ports()?;
        let ca_passphrase = format!("koi-lab-{}", run_id.as_str());
        let backup_passphrase = format!("koi-lab-backup-{}", run_id.as_str());
        let restored_passphrase = format!("koi-lab-restored-{}", run_id.as_str());

        // ── Stage the Windows CA daemon (fresh-start semantics) ──
        // The handle lives in `resources` from the first spawn on, so every
        // error path cleans up a daemon that may already be running.
        let daemon = WindowsLabDaemon::stage(self, run_id, ports)?;
        resources.daemon = Some(daemon);
        let daemon = resources.daemon.as_mut().expect("CA daemon staged");
        let exe = daemon.exe().to_path_buf();
        let ca_url = format!("http://{}:{}", windows.address(), ports.http);
        let breadcrumb_url = format!("http://127.0.0.1:{}", ports.http);

        // ── Scenario-scoped firewall: the CA answers the member on the LAN ──
        let http_rule = FIREWALL_HTTP_RULE.to_string();
        crate::lab::firewall_rule(&http_rule, "tcp", &ports.http.to_string(), &exe)
            .with_context(|| format!("firewall rule {http_rule}"))?;
        resources.firewall_rules.push(http_rule);
        let mtls_rule = FIREWALL_MTLS_RULE.to_string();
        crate::lab::firewall_rule(&mtls_rule, "tcp", &ports.mtls.to_string(), &exe)
            .with_context(|| format!("firewall rule {mtls_rule}"))?;
        resources.firewall_rules.push(mtls_rule);

        let spawn_capabilities = WindowsDaemonCapabilities {
            trust_plane: true,
            ..Default::default()
        };
        daemon
            .spawn(&spawn_capabilities)
            .context("start the Windows CA daemon")?;
        let ca_token = self
            .require_windows_breadcrumb(daemon.root(), &breadcrumb_url)
            .context("read the Windows CA daemon breadcrumb")?;

        // ── Create the CA (trust plane mounts; mTLS answers joins) ──
        let entropy = format!("{:x}", sha2::Sha256::digest(run_id.as_str().as_bytes()));
        curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/create"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "passphrase": ca_passphrase,
                "entropy_hex": entropy,
                "operator": "koi-lab",
                "enrollment_open": true,
                "requires_approval": false,
                "auto_unlock": true
            })),
        )
        .context("Windows CA create failed")?;
        let status = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&ca_token),
            None,
        )?;
        let ca_fingerprint = required_str(&status, "ca_fingerprint")?;

        // ── Linux member daemon; join under local CSR custody ──
        self.start_run_daemon(member, run_id)
            .context("start the Linux member run daemon")?;
        resources.member_daemon = true;
        let member_url = self.node_url(member)?;
        wait_for_http(&format!("{member_url}/healthz"))
            .context("Linux member daemon did not become healthy")?;

        let member_run_dir = member.run_dir(run_id)?;
        let koi_env = format!(
            "env KOI_DATA_DIR={member_run_dir}/data \
             XDG_RUNTIME_DIR={member_run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1"
        );
        let invite = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/invite"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "hostname": member.hostname(),
                "ttl_mins": 30
            })),
        )?;
        self.remote_line(
            member,
            &format!(
                "{koi_env} {member_run_dir}/koi certmesh join {ca_url} --invite '{}' \
                 --ca-mtls-port {} --json",
                required_str(&invite, "token")?,
                ports.mtls
            ),
        )
        .context("member join against the Windows CA")?;
        let before_backup = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&ca_token),
            None,
        )?;
        if !status_has_active_member(&before_backup, member.hostname()) {
            bail!("backup precondition failed: member is not active in the CA roster");
        }

        // ── Encrypted backup ──
        let backup = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/backup"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "ca_passphrase": ca_passphrase,
                "backup_passphrase": backup_passphrase
            })),
        )?;
        let backup_hex = required_str(&backup, "backup_hex")?;
        if backup.get("format").and_then(Value::as_str) != Some("koi-backup-v1")
            || backup.get("version").and_then(Value::as_u64) != Some(2)
        {
            bail!("CA returned an unexpected backup format/version");
        }

        // ── Prevalidation: a wrong backup passphrase must not disturb the CA ──
        let wrong_restore = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/restore"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "backup_hex": backup_hex,
                "backup_passphrase": "deliberately-wrong-passphrase",
                "new_passphrase": restored_passphrase
            })),
        );
        if wrong_restore.is_ok() {
            bail!("restore accepted a deliberately wrong backup passphrase");
        }
        let after_wrong = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&ca_token),
            None,
        )?;
        if required_str(&after_wrong, "ca_fingerprint")? != ca_fingerprint
            || !status_has_active_member(&after_wrong, member.hostname())
        {
            bail!("failed restore changed the live CA before validation completed");
        }
        let backup_check = passed(
            "encrypted_backup_and_prevalidation",
            "v2 encrypted backup created; wrong passphrase was rejected without changing live state",
        );

        // ── Exact data loss: stop, erase the owned data root, restart ──
        stop_and_quiesce(daemon)?;
        wipe_windows_daemon_state(daemon.root()).context("erase the Windows CA data root")?;
        daemon
            .spawn(&spawn_capabilities)
            .context("restart the Windows CA daemon after data loss")?;
        let recovery_token = self
            .require_windows_breadcrumb(daemon.root(), &breadcrumb_url)
            .context("read the restarted daemon breadcrumb")?;
        let empty = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&recovery_token),
            None,
        )?;
        if empty.get("ca_initialized").and_then(Value::as_bool) != Some(false) {
            bail!("run-scoped data-loss simulation did not produce a fresh CA state");
        }
        let data_loss_check = passed(
            "run_scoped_data_loss",
            "only the owned CA data root was erased; the replacement daemon started uninitialized",
        );

        // ── Restore under a NEW CA passphrase ──
        let restored = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/restore"),
            Some(&recovery_token),
            Some(&serde_json::json!({
                "backup_hex": backup_hex,
                "backup_passphrase": backup_passphrase,
                "new_passphrase": restored_passphrase
            })),
        )?;
        if restored.get("restored").and_then(Value::as_bool) != Some(true) {
            bail!("restore did not report success");
        }
        let restored_status = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&recovery_token),
            None,
        )?;
        if restored_status.get("ca_locked").and_then(Value::as_bool) != Some(false)
            || required_str(&restored_status, "ca_fingerprint")? != ca_fingerprint
            || !status_has_active_member(&restored_status, member.hostname())
        {
            bail!("restored CA did not recover its identity and active roster");
        }
        let bind_path = daemon
            .root()
            .join("data")
            .join("certmesh")
            .join("ca")
            .join("machine.bind");
        let machine_bind = std::fs::read_to_string(&bind_path)
            .with_context(|| format!("could not read {}", bind_path.display()))?;
        if machine_bind.trim().len() != 64
            || !machine_bind.trim().bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("the restored CA did not rewrite a machine binding for this host");
        }
        let restore_check = passed(
            "ca_identity_and_roster_restored",
            "CA fingerprint, active member roster, and this host's machine binding survived recovery",
        );

        // ── Member renewal over the restored mTLS ──
        wait_for_member_operator_renewal(self, member, run_id)
            .context("member renewal after restore")?;
        let renewal_check = passed(
            "recovery_binding_and_member_renewal",
            "the member renewed (key rotation) over the restored trust without re-enrollment",
        );

        // ── Restart comes back LOCKED (no credential store in the lane) ──
        stop_and_quiesce(daemon)?;
        daemon
            .spawn(&spawn_capabilities)
            .context("restart the restored Windows CA daemon")?;
        let restarted_token = self
            .require_windows_breadcrumb(daemon.root(), &breadcrumb_url)
            .context("read the restarted CA breadcrumb")?;
        let locked = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&restarted_token),
            None,
        )?;
        if locked.get("ca_locked").and_then(Value::as_bool) != Some(true)
            || required_str(&locked, "ca_fingerprint")? != ca_fingerprint
        {
            bail!("restored CA did not restart locked with the same public identity");
        }
        let locked_identity = member_identity_evidence(self, member, run_id)
            .context("capture member identity while the CA is locked")?;
        let denied_renewal = self
            .remote_output(
                member,
                &format!("{koi_env} {member_run_dir}/koi certmesh renew --json"),
            )
            .context("renewal attempt against the locked CA")?;
        if denied_renewal.status.success() {
            bail!("member renewal succeeded while the restored CA was locked");
        }
        let after_locked_denial = member_identity_evidence(self, member, run_id)
            .context("capture member identity after locked-CA renewal denial")?;
        if after_locked_denial.key_sha256 != locked_identity.key_sha256
            || after_locked_denial.cert_sha256 != locked_identity.cert_sha256
        {
            bail!("failed renewal against the locked CA changed member identity");
        }
        let locked_check = passed(
            "restart_locks_recovered_key",
            "restart locked the CA; renewal failed without changing the member identity",
        );

        // ── Only the restored passphrase unlocks; continuity resumes ──
        if curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/unlock"),
            Some(&restarted_token),
            Some(&serde_json::json!({ "passphrase": ca_passphrase })),
        )
        .is_ok()
        {
            bail!("the pre-restore CA passphrase unlocked the recovered key");
        }
        let unlocked = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/unlock"),
            Some(&restarted_token),
            Some(&serde_json::json!({ "passphrase": restored_passphrase })),
        )?;
        if unlocked.get("success").and_then(Value::as_bool) != Some(true) {
            bail!("the restored passphrase did not unlock the recovered CA");
        }
        wait_for_member_operator_renewal(self, member, run_id)
            .context("member renewal after unlock")?;
        let converged = curl_json(
            "GET",
            &format!("{ca_url}/v1/certmesh/status"),
            Some(&restarted_token),
            None,
        )?;
        let final_identity = member_identity_evidence(self, member, run_id)
            .context("capture member identity after the second renewal")?;
        let roster_fingerprint = converged
            .get("members")
            .and_then(Value::as_array)
            .and_then(|members| {
                members
                    .iter()
                    .find(|m| m.get("hostname").and_then(Value::as_str) == Some(member.hostname()))
            })
            .and_then(|m| m.get("cert_fingerprint"))
            .and_then(Value::as_str)
            .context("CA roster omitted the member after the second renewal")?
            .to_ascii_lowercase();
        if roster_fingerprint != final_identity.cert_fingerprint.to_ascii_lowercase() {
            bail!("CA roster did not converge to the member identity renewed after unlock");
        }
        let continuity_check = passed(
            "new_passphrase_restores_continuity",
            "old CA passphrase failed; restored passphrase unlocked; a second key-rotating renewal converged the roster",
        );

        // ── The restore must be in the CA's own audit trail ──
        let audit_path = daemon
            .root()
            .join("data")
            .join("logs")
            .join("certmesh-audit.log");
        let audit = std::fs::read_to_string(&audit_path)
            .with_context(|| format!("could not read {}", audit_path.display()))?;
        if !audit.contains("backup_restored") {
            bail!("the CA audit log did not record the restore");
        }
        let audit_check = passed(
            "audit_log_records_restore",
            "the Windows CA's certmesh audit log carries the backup_restored event",
        );

        Ok(WindowsRecoveryReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            windows_node: windows.id().to_owned(),
            member_node: member.id().to_owned(),
            artifact_sha256,
            ca_fingerprint,
            checks: vec![
                backup_check,
                data_loss_check,
                restore_check,
                renewal_check,
                locked_check,
                continuity_check,
                audit_check,
            ],
            // The report carries run ids, node ids, the artifact hash, the
            // public CA fingerprint, and fixed check strings — never
            // invite tokens or passphrases.
            secrets_redacted: true,
        })
    }

    fn cleanup_windows_recovery(
        &self,
        run_id: &RunId,
        member: &crate::model::NodeSpec,
        resources: &mut WindowsRecoveryResources,
    ) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();
        if resources.member_daemon {
            if let Err(e) = self.stop_run_daemon(member, run_id) {
                errors.push(format!("stop member daemon: {e:#}"));
            }
        }
        if let Some(mut daemon) = resources.daemon.take() {
            if let Err(e) = daemon.stop() {
                errors.push(format!("stop CA daemon: {e:#}"));
            }
            daemon.await_quiescence();
            if let Err(e) = self.remove_windows_member_dir(run_id, daemon.root()) {
                errors.push(format!("remove Windows CA run dir: {e:#}"));
            }
        }
        if !resources.firewall_rules.is_empty() {
            if let Err(e) = crate::lab::firewall_rules_remove(&resources.firewall_rules) {
                errors.push(format!("{e:#}"));
            }
        }
        errors
    }
}

/// Stop the staged daemon and let Windows release its file handles before the
/// caller mutates the directory the executable was holding.
fn stop_and_quiesce(daemon: &mut WindowsLabDaemon) -> Result<()> {
    daemon.stop().context("stop the staged Windows CA daemon")?;
    daemon.await_quiescence();
    Ok(())
}

/// Erase the run-owned daemon state so the next start is uninitialized
/// (Windows counterpart of the Linux lane's wipe: KOI_DATA_DIR is the whole
/// CA state; program-data is recreated empty to match the staging shape).
fn wipe_windows_daemon_state(root: &std::path::Path) -> Result<()> {
    remove_dir_retrying(&root.join("data")).context("could not remove the run-owned data root")?;
    let program_data = root.join("program-data");
    remove_dir_retrying(&program_data).context("could not remove program-data")?;
    std::fs::create_dir_all(&program_data)
        .with_context(|| format!("could not recreate {}", program_data.display()))?;
    Ok(())
}

fn remove_dir_retrying(path: &std::path::Path) -> Result<()> {
    // Windows can hold file handles briefly after a kill; retry the removal
    // until the grace window closes.
    let mut last: Option<std::io::Error> = None;
    for _ in 0..20 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("removal kept failing")))
        .with_context(|| format!("could not remove {}", path.display()))
}

fn wait_for_member_operator_renewal(
    lab: &Lab,
    member: &crate::model::NodeSpec,
    run_id: &RunId,
) -> Result<()> {
    let before: MemberIdentity = member_identity_evidence(lab, member, run_id)?;
    let run_dir = member.run_dir(run_id)?;
    let command = format!(
        "set -eu; test \"$(cat {run_dir}/owner)\" = {}; env KOI_DATA_DIR={run_dir}/data \
         XDG_RUNTIME_DIR={run_dir}/runtime KOI_NO_CREDENTIAL_STORE=1 {run_dir}/koi certmesh renew --json",
        run_id.as_str()
    );
    let mut last = String::new();
    for _ in 0..40 {
        let output = lab.remote_output(member, &command)?;
        if output.status.success() {
            let renewed: Value = serde_json::from_slice(&output.stdout)
                .context("operator renewal returned invalid JSON")?;
            if renewed.get("renewed").and_then(Value::as_bool) == Some(true) {
                let after = member_identity_evidence(lab, member, run_id)?;
                if after.key_sha256 == before.key_sha256 || after.cert_sha256 == before.cert_sha256
                {
                    bail!("operator renewal did not rotate member identity material");
                }
                return Ok(());
            }
            last = renewed.to_string();
        } else {
            last = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!("member renewal did not recover after the restore: {last}")
}
