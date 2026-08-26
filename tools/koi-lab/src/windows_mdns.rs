//! W5 (ADR-032): mDNS announce/browse from Windows, verified by the OS
//! stacks themselves.
//!
//! The standing lab's koi daemons deliberately skip their own mDNS on Linux
//! (garden-first ADR-030 decision: resolved/avahi own 5353 there) — Windows
//! is the only koi mDNS participant. The honest lane therefore pairs Koi's
//! mDNS against the OS stacks on the avahi-equipped member (test01):
//!
//! - Direction A: the Windows daemon announces an ephemeral service via its
//!   announce API; `avahi-browse` on the member (THE standard mDNS consumer)
//!   discovers it — proof that Koi's announcements are standards-conformant.
//! - Direction B: `avahi-publish` on the member announces a service; the
//!   Windows daemon's browser sees it — proof that Koi's browser consumes
//!   standard announcements.
//!
//! Measured context (ADR-030 amendment): Windows never auto-skips mDNS;
//! elevated processes receive multicast fully; this workstation's 5353 is
//! held with reuse semantics by system services and the daemon coexists with
//! it. Firewall provisioned: UDP 5353, program-scoped.
//!
//! Gated on elevation, `--allow-system-mutation`, and the catalog granting
//! the workstation `firewall` mutations; every rule is scenario-named and
//! removed on every path.

use anyhow::{bail, Context, Result};
use std::time::Duration;

use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, RunId, WindowsMdnsReport};

const AVAHI_BROWSE_TYPE: &str = "_http._tcp";
const FIREWALL_MDNS_RULE: &str = "koi-lab w5 mdns (udp 5353)";
const SERVICE_TYPE: &str = "_http._tcp.local.";
/// avahi tools want the type WITHOUT the domain suffix ("Invalid service
/// type" otherwise, measured on test01).

#[derive(Default)]
struct MdnsResources {
    windows_daemon: bool,
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
        let member = crate::planner::machine_by_id(self.config(), member_id.unwrap_or("test01"))
            .context("catalog has no such member machine")?;
        if !matches!(member, crate::model::NodeSpec::PuttyLinux { .. }) {
            bail!("the W5 member must be a physical Linux node");
        }
        // The member is the OS mDNS stack (avahi), not a koi daemon — the
        // Linux koi daemons deliberately skip their own mDNS (ADR-030).
        let avahi = self
            .remote_line(
                member,
                "command -v avahi-browse >/dev/null && echo yes || echo no",
            )
            .context("check avahi on the member")?;
        if avahi.trim() != "yes" {
            bail!(
                "the W5 member {} has no avahi tooling; the lane verifies against the OS \
                 mDNS stack",
                member.id()
            );
        }

        let mut resources = MdnsResources::default();
        let result = self.run_windows_mdns(run_id, windows.address(), member, &mut resources);
        let cleanup = self.cleanup_windows_mdns(run_id, member, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "firewall rules and the Windows daemon were removed",
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

        // ── Scenario-scoped firewall: mDNS multicast for the run daemon ──
        let ca_root = self
            .prepare_windows_member_dir(run_id)
            .context("stage the Windows mDNS daemon directory")?;
        let exe = ca_root.join("koi.exe");
        crate::lab::firewall_rule(FIREWALL_MDNS_RULE, "udp", "5353", &exe)
            .with_context(|| format!("firewall rule {FIREWALL_MDNS_RULE}"))?;
        resources
            .firewall_rules
            .push(FIREWALL_MDNS_RULE.to_string());

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

        // ── Direction A: Windows announces, avahi discovers ──
        let instance_a = format!("w5-win-{}", run_id.as_str());
        // avahi-browse in the background, dumping to a file; -p = parseable.
        self.remote_line(
            member,
            &format!(
                "nohup timeout 20 avahi-browse -p -t -- {AVAHI_BROWSE_TYPE} > /tmp/w5-{}-browse.txt 2>&1 &",
                run_id.as_str()
            ),
        )
        .context("start avahi-browse on the member")?;
        std::thread::sleep(Duration::from_millis(700));
        curl_json(
            "POST",
            &format!("{windows_url}/v1/mdns/announce"),
            Some(&windows_token),
            Some(&serde_json::json!({
                "name": instance_a,
                "type": SERVICE_TYPE,
                "port": ports.http,
                "ip": windows_address,
                "lease_secs": 60,
                "txt": {"run": run_id.as_str(), "surface": "w5-mdns"}
            })),
        )
        .context("Windows mDNS announce")?;
        std::thread::sleep(Duration::from_secs(4));
        let browse = self
            .remote_line(
                member,
                &format!(
                    "grep -F '{instance_a}' /tmp/w5-{}-browse.txt | sed -n '1p'",
                    run_id.as_str()
                ),
            )
            .unwrap_or_default();
        self.remote_line(
            member,
            &format!("rm -f /tmp/w5-{}-browse.txt", run_id.as_str()),
        )
        .ok();
        if !browse.contains(&instance_a) {
            bail!(
                "W5 direction A failed: avahi-browse never saw {instance_a}; the Windows \
                 announcement is not standards-conformant (or the member's multicast path \
                 is down)"
            );
        }
        let w5_windows_announces = passed(
            "w5_windows_announces_avahi_discovers",
            format!(
                "the Windows daemon announced {instance_a} ({windows_address}:{}) and \
                 avahi-browse on {} discovered it through the standard mDNS stack",
                ports.http,
                member.id()
            ),
        );

        // ── Direction B: avahi publishes, Windows discovers ──
        let instance_b = format!("w5-nix-{}", run_id.as_str());
        // The published record is truthful: member SSH on port 22.
        self.remote_line(
            member,
            &format!(
                "nohup timeout 25 avahi-publish -s '{instance_b}' {AVAHI_BROWSE_TYPE} 22 run={} >/dev/null 2>&1 &",
                run_id.as_str()
            ),
        )
        .context("start avahi-publish on the member")?;
        let mut snapshot_hit = String::new();
        for _ in 0..40 {
            if let Ok(snapshot) = curl_json(
                "GET",
                &format!("{windows_url}/v1/mdns/browser/snapshot"),
                Some(&windows_token),
                None,
            ) {
                let text = snapshot.to_string();
                if text.contains(&instance_b) {
                    snapshot_hit = text;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if snapshot_hit.is_empty() {
            bail!(
                "W5 direction B failed: the Windows browser never saw {instance_b} \
                 announced by avahi on {}",
                member.address()
            );
        }
        let w5_member_announces = passed(
            "w5_avahi_publishes_windows_discovers",
            format!(
                "avahi-publish on {} announced {instance_b} and the Windows browser \
                 snapshot discovered it",
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
        self.remote_line(
            member,
            &format!("rm -f /tmp/w5-{}-browse.txt", run_id.as_str()),
        )
        .ok();
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
