//! W6 + W9 (ADR-032): Windows-hosted serving lane.
//!
//! A run-owned daemon on THIS workstation serves the LAN for real: DNS on the
//! standard port 53 (the lane's claim — the scenario is elevation-gated), and
//! the health runtime. A physical Linux member is the cross-host verifier and
//! the health target:
//!
//! - W6: an A record added on the Windows daemon is answered cross-host by
//!   `dig` from the Linux member AND by the OS-native resolver
//!   (`Resolve-DnsName`) locally.
//! - W9 (Windows → Linux): the Windows daemon's TCP health check drives a
//!   run-owned fixture on the Linux member through the real Up → Down → Up
//!   state machine.
//! - W9 (Linux → Windows): the Linux daemon's TCP health check watches the
//!   Windows daemon's HTTP surface and sees it up.
//!
//! Gated on elevation, `--allow-system-mutation`, and the catalog granting
//! the workstation `firewall` mutations; every rule is scenario-named and
//! removed on every path.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::process::Command;
use std::time::Duration;

use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, RunId, WindowsBreadthReport};

const FIREWALL_HTTP_RULE: &str = "koi-lab w6 http (tcp 18541)";
const FIREWALL_DNS_UDP_RULE: &str = "koi-lab w6 dns (udp 53)";
const FIREWALL_DNS_TCP_RULE: &str = "koi-lab w6 dns (tcp 53)";
const DNS_NAME: &str = "winbreadth.internal";
const HEALTH_WINDOWS_TO_LINUX: &str = "w9-linux-fixture";
const HEALTH_LINUX_TO_WINDOWS: &str = "w9-windows-http";

#[derive(Default)]
struct BreadthResources {
    windows_daemon: bool,
    member_daemon: bool,
    fixture_active: bool,
    firewall_rules: Vec<&'static str>,
    dns_record: bool,
    health_windows_to_linux: bool,
    health_linux_to_windows: bool,
    windows_token: Option<String>,
    member_token: Option<String>,
}

impl Lab {
    pub fn windows_breadth(
        &self,
        run_id: &RunId,
        member_id: Option<&str>,
        allow_system_mutation: bool,
    ) -> Result<WindowsBreadthReport> {
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
        if !matches!(member, crate::model::NodeSpec::PuttyLinux { .. }) {
            bail!("the breadth member must be a physical Linux node");
        }

        let mut resources = BreadthResources::default();
        let result =
            self.run_windows_breadth(run_id, windows.address(), windows, member, &mut resources);
        let cleanup = self.cleanup_windows_breadth(run_id, windows, member, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "firewall rules, both daemons, the fixture, the DNS record, and health \
                     entries were removed",
                ));
                let path = output_path(run_id.as_str()).join("windows-breadth.json");
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
    fn run_windows_breadth(
        &self,
        run_id: &RunId,
        windows_address: &str,
        windows: &crate::model::NodeSpec,
        member: &crate::model::NodeSpec,
        resources: &mut BreadthResources,
    ) -> Result<WindowsBreadthReport> {
        let artifact_sha256 = self
            .remote_line(
                member,
                &format!("cat {}/artifact.sha256", member.run_dir(run_id)?),
            )
            .context("read staged artifact sha256 from the member")?;

        let ports = windows.lab_ports()?;
        let member_ports = member.lab_ports()?;

        // ── Scenario-scoped firewall: HTTP on the LAN, DNS on the standard port ──
        let ca_root = self
            .prepare_windows_member_dir(run_id)
            .context("stage the Windows serving daemon directory")?;
        let exe = ca_root.join("koi.exe");
        for (name, protocol, port) in [
            (FIREWALL_HTTP_RULE, "tcp", ports.http.to_string()),
            (FIREWALL_DNS_UDP_RULE, "udp", "53".to_string()),
            (FIREWALL_DNS_TCP_RULE, "tcp", "53".to_string()),
        ] {
            crate::lab::firewall_rule(name, protocol, &port, &exe)
                .with_context(|| format!("firewall rule {name}"))?;
            resources.firewall_rules.push(name);
        }

        // ── Windows serving daemon ──
        let _windows_child = self
            .start_windows_serving_daemon(&ca_root, &ports)
            .context("start the Windows serving daemon")?;
        resources.windows_daemon = true;
        let windows_url = format!("http://{windows_address}:{}", ports.http);
        wait_for_http(&format!("{windows_url}/healthz"))
            .context("Windows serving daemon did not become healthy")?;
        let windows_token = self
            .require_windows_breadcrumb(&ca_root, &format!("http://127.0.0.1:{}", ports.http))
            .context("read the Windows daemon breadcrumb")?;
        resources.windows_token = Some(windows_token.clone());

        // ── Linux member daemon (serving profile, as the cross-host verifier) ──
        self.start_story_daemon(member, run_id)
            .context("start the Linux member run daemon")?;
        resources.member_daemon = true;
        let member_url = self.node_url(member)?;
        wait_for_http(&format!("{member_url}/healthz"))
            .context("Linux member daemon did not become healthy")?;
        let breadcrumb = self
            .remote_line(
                member,
                &format!("cat {}/runtime/koi.endpoint", member.run_dir(run_id)?),
            )
            .context("read the Linux member breadcrumb")?;
        let member_endpoint = breadcrumb
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .context("Linux member breadcrumb had no endpoint")?
            .to_owned();
        let member_dat = breadcrumb
            .lines()
            .nth(1)
            .and_then(|line| line.trim().strip_prefix("dat:").map(str::to_owned));
        if member_endpoint != member_url {
            bail!(
                "Linux member breadcrumb endpoint {member_endpoint} does not match the \
                 catalog URL {member_url}"
            );
        }
        resources.member_token = member_dat.clone();

        // ── W6: DNS served on the standard port, verified from both OSes ──
        curl_json(
            "POST",
            &format!("{windows_url}/v1/dns/add"),
            Some(&windows_token),
            Some(&serde_json::json!({
                "name": DNS_NAME,
                "ip": windows_address,
                "ttl": 30
            })),
        )
        .context("add the W6 DNS record on the Windows daemon")?;
        resources.dns_record = true;

        let dig_answer = self
            .remote_line(
                member,
                &format!(
                    "dig @{} -p 53 {DNS_NAME} A +short | sed -n '1p'",
                    windows.address()
                ),
            )
            .context("cross-host dig against the Windows DNS server")?;
        if dig_answer.trim() != windows.address() {
            bail!(
                "W6 cross-host dig returned {:?}, expected {}",
                dig_answer.trim(),
                windows.address()
            );
        }

        let resolve = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("(Resolve-DnsName -Server 127.0.0.1 -Name {DNS_NAME} -Type A).IPAddress"),
            ])
            .output()
            .context("run Resolve-DnsName")?;
        let resolve_text = String::from_utf8_lossy(&resolve.stdout).to_string();
        if !resolve.status.success() || !resolve_text.contains(windows_address) {
            bail!(
                "W6 Resolve-DnsName did not return {}: status={} output={}",
                windows.address(),
                resolve.status,
                resolve_text.trim()
            );
        }
        let w6_check = passed(
            "w6_dns_standard_port_served_from_windows",
            format!(
                "the Windows daemon served {DNS_NAME} on port 53, answered cross-host by dig \
                 from {} and locally by Resolve-DnsName",
                member.id()
            ),
        );

        // ── W9 (Windows → Linux): the real Up → Down → Up state machine ──
        self.start_story_fixture(member, run_id)
            .context("start the Linux member fixture")?;
        resources.fixture_active = true;
        curl_json(
            "POST",
            &format!("{windows_url}/v1/health/add"),
            Some(&windows_token),
            Some(&serde_json::json!({
                "name": HEALTH_WINDOWS_TO_LINUX,
                "kind": "tcp",
                "target": format!("{}:{}", member.address(), member_ports.fixture),
                "interval_secs": 1,
                "timeout_secs": 1
            })),
        )
        .context("add the Windows→Linux health check")?;
        resources.health_windows_to_linux = true;
        wait_for_health(&windows_url, HEALTH_WINDOWS_TO_LINUX, "up")
            .context("Windows→Linux check did not come up")?;
        self.stop_story_fixture(member, run_id)
            .context("stop the Linux member fixture (down phase)")?;
        resources.fixture_active = false;
        wait_for_health(&windows_url, HEALTH_WINDOWS_TO_LINUX, "down")
            .context("Windows→Linux check did not go down")?;
        self.start_story_fixture(member, run_id)
            .context("restart the Linux member fixture (up phase)")?;
        resources.fixture_active = true;
        wait_for_health(&windows_url, HEALTH_WINDOWS_TO_LINUX, "up")
            .context("Windows→Linux check did not come back up")?;
        let w9_windows_to_linux = passed(
            "w9_health_windows_checks_linux",
            format!(
                "the Windows daemon drove a TCP check of {}:{} through up → down → up",
                member.address(),
                member_ports.fixture
            ),
        );

        // ── W9 (Linux → Windows): the member watches the Windows HTTP surface ──
        curl_json(
            "POST",
            &format!("{member_url}/v1/health/add"),
            member_dat.as_deref(),
            Some(&serde_json::json!({
                "name": HEALTH_LINUX_TO_WINDOWS,
                "kind": "tcp",
                "target": format!("{}:{}", windows.address(), ports.http),
                "interval_secs": 1,
                "timeout_secs": 1
            })),
        )
        .context("add the Linux→Windows health check on the member daemon")?;
        resources.health_linux_to_windows = true;
        wait_for_health(&member_url, HEALTH_LINUX_TO_WINDOWS, "up")
            .context("Linux→Windows check did not come up")?;
        let w9_linux_to_windows = passed(
            "w9_health_linux_checks_windows",
            format!(
                "the {} daemon's TCP check saw the Windows HTTP surface at {}:{} up",
                member.id(),
                windows.address(),
                ports.http
            ),
        );

        Ok(WindowsBreadthReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            windows_node: "windows".into(),
            member_node: member.id().to_owned(),
            artifact_sha256,
            checks: vec![w6_check, w9_windows_to_linux, w9_linux_to_windows],
            secrets_redacted: true,
        })
    }

    fn cleanup_windows_breadth(
        &self,
        run_id: &RunId,
        windows: &crate::model::NodeSpec,
        member: &crate::model::NodeSpec,
        resources: &mut BreadthResources,
    ) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        let ports = windows
            .lab_ports()
            .expect("catalog windows node has lab ports");
        let windows_url = format!("http://{}:{}", windows.address(), ports.http);
        let member_url = self.node_url(member).expect("catalog member node url");

        // Mutations are DAT-gated, so cleanup reuses the run's tokens. A lost
        // token still must not block the rest of the cleanup — record and go.
        if resources.health_windows_to_linux {
            if let Some(token) = &resources.windows_token {
                if let Err(e) = curl_json(
                    "DELETE",
                    &format!("{windows_url}/v1/health/remove/{HEALTH_WINDOWS_TO_LINUX}"),
                    Some(token),
                    None,
                ) {
                    errors.push(format!("remove Windows health entry: {e:#}"));
                }
            }
        }
        if resources.health_linux_to_windows {
            if let Some(token) = &resources.member_token {
                if let Err(e) = curl_json(
                    "DELETE",
                    &format!("{member_url}/v1/health/remove/{HEALTH_LINUX_TO_WINDOWS}"),
                    Some(token),
                    None,
                ) {
                    errors.push(format!("remove member health entry: {e:#}"));
                }
            }
        }
        if resources.dns_record {
            if let Some(token) = &resources.windows_token {
                if let Err(e) = curl_json(
                    "DELETE",
                    &format!("{windows_url}/v1/dns/remove/{DNS_NAME}"),
                    Some(token),
                    None,
                ) {
                    errors.push(format!("remove DNS record: {e:#}"));
                }
            }
        }
        if resources.fixture_active {
            if let Err(e) = self.stop_story_fixture(member, run_id) {
                errors.push(format!("stop member fixture: {e:#}"));
            }
            resources.fixture_active = false;
        }
        if resources.member_daemon {
            if let Err(e) = self.stop_webhook_daemon(member, run_id) {
                errors.push(format!("stop member daemon: {e:#}"));
            }
            if let Err(e) = self.remove_webhook_sink_files(member, run_id) {
                errors.push(format!("remove member run files: {e:#}"));
            }
        }
        if resources.windows_daemon {
            let root = self.windows_member_dir(run_id);
            let exe = root.join("koi.exe");
            if exe.is_file() {
                match crate::lab::windows_process_ids_for_executable(&exe) {
                    Ok(process_ids) => {
                        for process_id in process_ids {
                            if let Err(e) = crate::lab::stop_exact_windows_process(process_id, &exe)
                            {
                                errors.push(format!("stop Windows daemon pid {process_id}: {e:#}"));
                            }
                        }
                    }
                    Err(e) => errors.push(format!("enumerate Windows daemon processes: {e:#}")),
                }
            }
            if let Err(e) = self.remove_windows_member_dir(run_id, &root) {
                errors.push(format!("remove Windows run dir: {e:#}"));
            }
        }
        if !resources.firewall_rules.is_empty() {
            if let Err(e) = crate::lab::firewall_rules_remove(&resources.firewall_rules) {
                errors.push(format!("{e:#}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("cleanup errors: {}", errors.join("; "))
        }
    }
}

fn wait_for_health(base: &str, name: &str, expected: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..40 {
        let status = curl_json("GET", &format!("{base}/v1/health/status"), None, None)?;
        let matched = status
            .get("services")
            .and_then(Value::as_array)
            .is_some_and(|services| {
                services.iter().any(|service| {
                    service.get("name").and_then(Value::as_str) == Some(name)
                        && service.get("status").and_then(Value::as_str) == Some(expected)
                })
            });
        if matched {
            return Ok(());
        }
        last = status;
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!("health check {name} did not become {expected}: {last}")
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}
