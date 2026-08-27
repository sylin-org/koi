//! W8 (ADR-032): webhooks with the ORIGIN on Windows and the sink on Linux,
//! over the real LAN. Built on [`crate::windows_daemon::WindowsLabDaemon`] —
//! staging, paths, env, flags, log, and kill live in one owner; failure
//! evidence is captured before teardown (the doctrine the first physical run
//! violated by deleting its own daemon.log).
//!
//! The Windows daemon loads a webhook manifest pointing at the python sink
//! fixture on the Linux member (HMAC secret passed only through the sink's
//! process environment). Real domain events are triggered through the
//! Windows daemon's authenticated API; every delivery the sink captures must
//! be signature-valid and shape-correct.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::time::Duration;

use crate::lab::{curl_json, Lab};
use crate::model::{output_path, CheckResult, RunId, WindowsWebhookReport};
use crate::windows_daemon::{WindowsDaemonCapabilities, WindowsLabDaemon};

const FIREWALL_HTTP_RULE: &str = "koi-lab w8 http (tcp 18541)";

#[derive(Default)]
struct WebhookResources {
    daemon: Option<WindowsLabDaemon>,
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
        let mut daemon = WindowsLabDaemon::stage(self, run_id, ports)?;
        let exe = daemon.exe().to_path_buf();
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

        // ── Manifest: staged beside the daemon (plain path — the builder's
        //    choke point already stripped \\?\) ──
        let manifest_path = daemon
            .root()
            .join("program-data")
            .join("koi")
            .join("webhooks.json");
        std::fs::create_dir_all(manifest_path.parent().expect("manifest parent"))?;
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
        std::fs::copy(&manifest_local, &manifest_path)
            .context("stage the webhook manifest beside the Windows daemon")?;

        // ── Windows origin daemon ──
        let capabilities = WindowsDaemonCapabilities {
            webhooks_manifest: Some(manifest_path),
            ..Default::default()
        };
        daemon
            .spawn(&capabilities)
            .context("start the Windows webhook origin daemon")?;
        resources.daemon = Some(daemon);
        let windows_url = {
            let daemon = resources.daemon.as_ref().expect("daemon staged");
            daemon.http_url()
        };
        let windows_token = {
            let daemon = resources.daemon.as_ref().expect("daemon staged");
            self.require_windows_breadcrumb(daemon.root(), &windows_url)
                .context("read the Windows daemon breadcrumb")?
        };

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
        if sinks != 1 || !enabled {
            // Capture the daemon's own words before any cleanup runs.
            let evidence = resources.daemon.as_ref().expect("daemon staged").evidence();
            bail!("webhooks did not activate (enabled: {enabled}, sinks: {sinks}); {evidence}");
        }
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
            if let Some(daemon) = &resources.daemon {
                if let Ok(token) = self.require_windows_breadcrumb(daemon.root(), &windows_url) {
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
        }
        if resources.sink_active {
            if let Err(e) = self.stop_webhook_sink(sink_node, run_id) {
                errors.push(format!("stop webhook sink: {e:#}"));
            }
        }
        if let Some(mut daemon) = resources.daemon.take() {
            if let Err(e) = daemon.stop() {
                errors.push(format!("stop Windows daemon: {e:#}"));
            }
            if let Err(e) = daemon.teardown(self, run_id) {
                errors.push(format!("remove Windows run dir: {e:#}"));
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
