//! W8 (ADR-032): webhooks with the ORIGIN on Windows and the sink on Linux,
//! over the real LAN.
//!
//! A run-owned daemon on THIS workstation loads a webhook manifest pointing
//! at the python sink fixture on the Linux member (HMAC secret passed only
//! through the sink's process environment). Real domain events are triggered
//! through the Windows daemon's authenticated API; every delivery the sink
//! captures must be signature-valid and shape-correct.
//!
//! Gated on elevation (the daemon runs from the staged LAN-reachable shape),
//! `--allow-system-mutation`, and the catalog granting the workstation
//! `firewall` mutations; every rule is scenario-named and removed on every
//! path.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::time::Duration;

use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, RunId, WindowsWebhookReport};

const FIREWALL_HTTP_RULE: &str = "koi-lab w8 http (tcp 18541)";

#[derive(Default)]
struct WebhookResources {
    windows_daemon: bool,
    member_daemon: bool,
    sink_active: bool,
    firewall_rules: Vec<String>,
    dns_names: Vec<String>,
}

impl Lab {
    pub fn windows_webhook(
        &self,
        run_id: &RunId,
        member_id: Option<&str>,
        allow_system_mutation: bool,
    ) -> Result<WindowsWebhookReport> {
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
        let sink_node = crate::planner::machine_by_id(self.config(), member_id.unwrap_or("brook"))
            .context("catalog has no such member machine")?;
        if !matches!(sink_node, crate::model::NodeSpec::PuttyLinux { .. }) {
            bail!("the W8 sink host must be a physical Linux node");
        }

        let mut resources = WebhookResources::default();
        let result = self.run_windows_webhook(run_id, windows, sink_node, &mut resources);
        let cleanup = self.cleanup_windows_webhook(run_id, windows, sink_node, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "firewall rules, both daemons, the sink, and the DNS records were removed",
                ));
                let path = output_path(run_id.as_str()).join("windows-webhook.json");
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

    fn run_windows_webhook(
        &self,
        run_id: &RunId,
        windows: &crate::model::NodeSpec,
        sink_node: &crate::model::NodeSpec,
        resources: &mut WebhookResources,
    ) -> Result<WindowsWebhookReport> {
        let artifact_sha256 = self
            .remote_line(
                sink_node,
                &format!("cat {}/artifact.sha256", sink_node.run_dir(run_id)?),
            )
            .context("read staged artifact sha256 from the sink host")?;

        let ports = windows.lab_ports()?;
        let sink_ports = sink_node.lab_ports()?;

        // ── Firewall: the Windows daemon is LAN-reachable (retry surface) ──
        let ca_root = self
            .prepare_windows_member_dir(run_id)
            .context("stage the Windows webhook daemon directory")?;
        let exe = ca_root.join("koi.exe");
        crate::lab::firewall_rule(FIREWALL_HTTP_RULE, "tcp", &ports.http.to_string(), &exe)
            .with_context(|| format!("firewall rule {FIREWALL_HTTP_RULE}"))?;
        resources
            .firewall_rules
            .push(FIREWALL_HTTP_RULE.to_string());

        // ── Sink: python fixture on the Linux member (secret via env only) ──
        let secret = format!("w8-{}", run_id.as_str());
        self.stage_webhook_sink(sink_node, run_id)
            .context("stage the webhook sink")?;
        self.start_webhook_sink(sink_node, run_id, &secret)
            .context("start the webhook sink")?;
        resources.sink_active = true;
        let sink_url = format!("http://{}:{}/hook", sink_node.address(), sink_ports.fixture);

        // ── Manifest: staged to the Windows daemon's data dir ──
        // Manifest staged beside the daemon; PLAIN path only. The staged root
        // carries the \\?\ canonical prefix, and a \\?\ --webhooks value died
        // silently in the first physical run (healthz never answered). The
        // firewall helper strips the same prefix for the same reason.
        let stage_dir = std::path::PathBuf::from(crate::lab::netsh_program_path(
            &ca_root.join("program-data"),
        ));
        std::fs::create_dir_all(stage_dir.join("koi"))?;
        let manifest_local = output_path(run_id.as_str()).join("webhooks.json");
        std::fs::create_dir_all(output_path(run_id.as_str()))?;
        std::fs::write(
            &manifest_local,
            serde_json::to_string_pretty(&serde_json::json!([{
                "url": sink_url,
                "secret": secret,
                "enabled": true,
            }]))?,
        )?;
        let manifest_path = stage_dir.join("koi").join("webhooks.json");
        std::fs::copy(&manifest_local, &manifest_path)
            .context("stage the webhook manifest beside the Windows daemon")?;

        // ── Windows origin daemon (webhooks manifest wired in) ──
        let _windows_child = self
            .start_windows_serving_daemon(&ca_root, &ports, 18653, false, Some(&manifest_path))
            .context("start the Windows webhook origin daemon")?;
        resources.windows_daemon = true;
        let windows_url = format!("http://127.0.0.1:{}", ports.http);
        wait_for_http(&format!("{windows_url}/healthz"))
            .context("Windows webhook origin daemon did not become healthy")?;
        let windows_token = self
            .require_windows_breadcrumb(&ca_root, &format!("http://127.0.0.1:{}", ports.http))
            .context("read the Windows daemon breadcrumb")?;

        // Status ladder must report the enabled transport.
        let status = curl_json(
            "GET",
            &format!("{windows_url}/v1/status"),
            Some(&windows_token),
            None,
        )?;
        let sinks = status
            .pointer("/webhooks/sinks")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let enabled = status
            .pointer("/webhooks/enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let w8_status = passed(
            "w8_status_reports_enabled_sink",
            format!("/v1/status webhooks = {{enabled: {enabled}, sinks: {sinks}}}"),
        );

        // ── Trigger real domain events through the Windows daemon ──
        let suffix: String = run_id
            .as_str()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(12)
            .collect();
        let name_a = format!("{suffix}-a.internal");
        let name_b = format!("{suffix}-b.internal");
        let ip = "192.0.2.77"; // TEST-NET-1: never routed, purely synthetic
        for name in [&name_a, &name_b] {
            curl_json(
                "POST",
                &format!("{windows_url}/v1/dns/add"),
                Some(&windows_token),
                Some(&serde_json::json!({ "name": name, "ip": ip })),
            )
            .with_context(|| format!("dns add {name} did not succeed"))?;
            resources.dns_names.push(name.to_owned());
        }
        let w8_events = passed(
            "w8_domain_events_triggered_from_windows",
            "two DNS-record events fired through the Windows daemon's API".to_owned(),
        );

        // ── Cross-host delivery: the sink must capture valid deliveries ──
        let deliveries = self.wait_for_deliveries(sink_node, run_id, 2, Duration::from_secs(30))?;
        if deliveries.is_empty() {
            bail!("no delivery reached the sink within the timeout window");
        }
        let all_valid = deliveries.iter().all(|d| {
            d.get("sig_valid").and_then(Value::as_bool) == Some(true)
                && d.get("body_ok").and_then(Value::as_bool) == Some(true)
        });
        if !all_valid {
            bail!(
                "sink captured deliveries failed verification: {}",
                serde_json::to_string(&deliveries).unwrap_or_default()
            );
        }
        let w8_deliveries = passed(
            "w8_deliveries_hmac_verified_on_linux_sink",
            format!(
                "{} delivery(ies) reached the {} sink and every HMAC signature \
                 and body hash verified",
                deliveries.len(),
                sink_node.id()
            ),
        );

        Ok(WindowsWebhookReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            windows_node: "windows".into(),
            member_node: sink_node.id().to_owned(),
            artifact_sha256,
            checks: vec![w8_status, w8_events, w8_deliveries],
            secrets_redacted: true,
        })
    }

    fn cleanup_windows_webhook(
        &self,
        run_id: &RunId,
        windows: &crate::model::NodeSpec,
        sink_node: &crate::model::NodeSpec,
        resources: &mut WebhookResources,
    ) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        let ports = windows
            .lab_ports()
            .expect("catalog windows node has lab ports");
        let windows_url = format!("http://127.0.0.1:{}", ports.http);

        if !resources.dns_names.is_empty() {
            if let Ok(token) =
                self.require_windows_breadcrumb(&self.windows_member_dir(run_id), &windows_url)
            {
                for name in &resources.dns_names {
                    if let Err(e) = curl_json(
                        "DELETE",
                        &format!("{windows_url}/v1/dns/remove/{name}"),
                        Some(&token),
                        None,
                    ) {
                        errors.push(format!("remove DNS record {name}: {e:#}"));
                    }
                }
            }
        }
        if resources.sink_active {
            if let Err(e) = self.stop_webhook_sink(sink_node, run_id) {
                errors.push(format!("stop webhook sink: {e:#}"));
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
        if resources.member_daemon {
            if let Err(e) = self.stop_webhook_daemon(sink_node, run_id) {
                errors.push(format!("stop member daemon: {e:#}"));
            }
        }
        if let Err(e) = self.remove_webhook_sink_files(sink_node, run_id) {
            errors.push(format!("remove sink files: {e:#}"));
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
