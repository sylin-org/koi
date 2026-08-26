//! W5 (ADR-032): mDNS announce/browse from Windows, over the real LAN.
//!
//! A run-owned daemon on THIS workstation announces an ephemeral service via
//! mDNS (firewall provisioned: UDP 5353 + the announced TCP port, both
//! program-scoped), and the physical Linux member discovers it through its
//! own browse subscription. Then the direction flips: the member announces
//! and the Windows daemon's browser sees it.
//!
//! Measured context (ADR-030 amendment + this arc): Windows never auto-skips
//! mDNS; elevated processes receive multicast fully; this workstation's 5353
//! is held with reuse semantics by system services and the daemon coexists
//! with it (reception proven 2026-08-24/25). Discovery here is the missing
//! claim.
//!
//! Gated on elevation, `--allow-system-mutation`, and the catalog granting
//! the workstation `firewall` mutations; every rule is scenario-named and
//! removed on every path.

use anyhow::{bail, Context, Result};
use std::time::Duration;

use crate::model::{output_path, CheckResult, RunId, WindowsMdnsReport};
use crate::probe::SseCapture;

use crate::lab::{curl_json, wait_for_http, Lab};

const FIREWALL_MDNS_RULE: &str = "koi-lab w5 mdns (udp 5353)";
const FIREWALL_HTTP_RULE: &str = "koi-lab w5 http (tcp 18541)";
const SERVICE_TYPE: &str = "_koi-v1._tcp.local.";
/// Squat-free scratch ports for the ephemeral announcements (probed free).
const ANNOUNCE_PORT_CANDIDATES: std::ops::RangeInclusive<u16> = 18673..=18692;

#[derive(Default)]
struct MdnsResources {
    windows_daemon: bool,
    member_daemon: bool,
    firewall_rules: Vec<String>,
}

impl Lab {
    pub fn windows_mdns(
        &self,
        run_id: &RunId,
        member_id: Option<&str>,
        allow_system_mutation: bool,
    ) -> Result<WindowsMdnsReport> {
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
            bail!("the W5 member must be a physical Linux node");
        }

        let mut resources = MdnsResources::default();
        let result = self.run_windows_mdns(run_id, windows.address(), member, &mut resources);
        let cleanup = self.cleanup_windows_mdns(run_id, member, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "firewall rules and both daemons were removed",
                ));
                let path = output_path(run_id.as_str()).join("windows-mdns.json");
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

    fn run_windows_mdns(
        &self,
        run_id: &RunId,
        windows_address: &str,
        member: &crate::model::NodeSpec,
        resources: &mut MdnsResources,
    ) -> Result<WindowsMdnsReport> {
        let artifact_sha256 = self
            .remote_line(
                member,
                &format!("cat {}/artifact.sha256", member.run_dir(run_id)?),
            )
            .context("read staged artifact sha256 from the member")?;

        let ports = crate::planner::machine_by_id(self.config(), "windows")
            .context("catalog has no windows machine")?
            .lab_ports()?;

        // Scratch ports for the ephemeral announcements: probed exclusively
        // free so the announced TCP port is real (a browser can connect).
        let windows_announce_port = ANNOUNCE_PORT_CANDIDATES
            .clone()
            .find(|candidate| std::net::TcpListener::bind(("0.0.0.0", *candidate)).is_ok())
            .context("no free announce port in 18673..=18692")?;
        let member_announce_port = ((windows_announce_port + 1)..=18692)
            .find(|candidate| std::net::TcpListener::bind(("0.0.0.0", *candidate)).is_ok())
            .context("no second free announce port in 18673..=18692")?;

        // ── Scenario-scoped firewall: mDNS + the announced HTTP surface ──
        let ca_root = self
            .prepare_windows_member_dir(run_id)
            .context("stage the Windows mDNS daemon directory")?;
        let exe = ca_root.join("koi.exe");
        for (name, protocol, port) in [
            (FIREWALL_MDNS_RULE, "udp", "5353".to_string()),
            (FIREWALL_HTTP_RULE, "tcp", ports.http.to_string()),
        ] {
            crate::lab::firewall_rule(name, protocol, &port, &exe)
                .with_context(|| format!("firewall rule {name}"))?;
            resources.firewall_rules.push(name.to_string());
        }

        // ── Windows daemon with mDNS announcing enabled ──
        let _windows_child = self
            .start_windows_serving_daemon(&ca_root, &ports, 18653, true)
            .context("start the Windows mDNS daemon")?;
        resources.windows_daemon = true;
        let windows_url = format!("http://{windows_address}:{}", ports.http);
        wait_for_http(&format!("{windows_url}/healthz"))
            .context("Windows mDNS daemon did not become healthy")?;
        let windows_token = self
            .require_windows_breadcrumb(&ca_root, &format!("http://127.0.0.1:{}", ports.http))
            .context("read the Windows daemon breadcrumb")?;

        // ── Linux member daemon (announcing enabled by the story profile) ──
        self.start_story_daemon(member, run_id)
            .context("start the Linux member run daemon")?;
        resources.member_daemon = true;
        let member_url = self.node_url(member)?;
        wait_for_http(&format!("{member_url}/healthz"))
            .context("Linux member daemon did not become healthy")?;
        let member_dat = self
            .remote_line(
                member,
                &format!("cat {}/runtime/koi.endpoint", member.run_dir(run_id)?),
            )
            .context("read the Linux member breadcrumb")
            .ok()
            .and_then(|body| {
                body.lines()
                    .nth(1)
                    .and_then(|line| line.trim().strip_prefix("dat:").map(str::to_owned))
            });

        // ── W5 direction A: Windows announces, the member discovers ──
        // The member subscribes (type-scoped browse) BEFORE the announcement,
        // exactly like story Act 4.
        let member_capture = SseCapture::start(
            &format!("{member_url}/v1/mdns/subscribe?type={SERVICE_TYPE}&idle_for=8"),
            None,
            25,
            "member mDNS",
        )?;
        std::thread::sleep(Duration::from_millis(500));
        let service_name = format!("win-{}._{}", run_id.as_str(), SERVICE_TYPE);
        curl_json(
            "POST",
            &format!("{windows_url}/v1/mdns/announce"),
            Some(&windows_token),
            Some(&serde_json::json!({
                "name": service_name,
                "type": SERVICE_TYPE,
                "port": windows_announce_port,
                "ip": windows_address,
                "lease_secs": 60,
                "txt": {"run": run_id.as_str(), "surface": "w5-mdns"}
            })),
        )
        .context("Windows mDNS announce")?;
        let member_capture_text = member_capture.finish().context("member mDNS capture")?;
        if !member_capture_text.contains(&service_name) {
            bail!(
                "W5 direction A failed: the member's browse stream never carried \
                 {service_name}; capture tail: {}",
                member_capture_text
                    .lines()
                    .rev()
                    .take(6)
                    .collect::<Vec<_>>()
                    .join(" | ")
            );
        }
        let w5_windows_announces = passed(
            "w5_windows_announces_member_discovers",
            format!(
                "the Windows daemon announced {service_name} on {}:{windows_announce_port} \
                 and the {} browser subscription discovered it",
                windows_address,
                member.id()
            ),
        );

        // ── W5 direction B: the member announces, Windows discovers ──
        let windows_capture = SseCapture::start(
            &format!("{windows_url}/v1/mdns/subscribe?type={SERVICE_TYPE}&idle_for=8"),
            Some(&windows_token),
            25,
            "windows mDNS",
        )?;
        std::thread::sleep(Duration::from_millis(500));
        let member_service_name = format!("nix-{}._{}", run_id.as_str(), SERVICE_TYPE);
        curl_json(
            "POST",
            &format!("{member_url}/v1/mdns/announce"),
            member_dat.as_deref(),
            Some(&serde_json::json!({
                "name": member_service_name,
                "type": SERVICE_TYPE,
                "port": member_announce_port,
                "ip": member.address(),
                "lease_secs": 60,
                "txt": {"run": run_id.as_str(), "surface": "w5-mdns"}
            })),
        )
        .context("member mDNS announce")?;
        let windows_capture_text = windows_capture.finish().context("windows mDNS capture")?;
        if !windows_capture_text.contains(&member_service_name) {
            bail!(
                "W5 direction B failed: the Windows browse stream never carried \
                 {member_service_name}; capture tail: {}",
                windows_capture_text
                    .lines()
                    .rev()
                    .take(6)
                    .collect::<Vec<_>>()
                    .join(" | ")
            );
        }
        let w5_member_announces = passed(
            "w5_member_announces_windows_discovers",
            format!(
                "the {} daemon announced {member_service_name} on {}:{member_announce_port} \
                 and the Windows browser subscription discovered it",
                member.id(),
                member.address()
            ),
        );

        Ok(WindowsMdnsReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            windows_node: "windows".into(),
            member_node: member.id().to_owned(),
            artifact_sha256,
            checks: vec![w5_windows_announces, w5_member_announces],
            secrets_redacted: true,
        })
    }

    fn cleanup_windows_mdns(
        &self,
        run_id: &RunId,
        member: &crate::model::NodeSpec,
        resources: &mut MdnsResources,
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

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}
