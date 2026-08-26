//! Physical webhook fan-out scenario (ADR-028 / V1-10).
//!
//! One run-owned daemon on the primary node serves the merged event stream with a
//! webhook sink manifest pointing at the observer node; the observer hosts only
//! the Python sink fixture, which validates each delivery's HMAC signature at
//! receive time. The controller triggers real domain events (DNS entry add) and
//! asserts cross-host delivery with exact envelope shape, valid signatures, and
//! daemon health throughout. Non-privileged; exact cleanup on every path.

use std::collections::BTreeSet;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, NodeSpec, RunId, TrustRotation, WebhookFanoutReport};

#[derive(Default)]
struct WebhookFanoutResources {
    manifest_staged: bool,
    sink_staged: bool,
    sink_active: bool,
    primary_daemon: bool,
}

impl Lab {
    pub fn webhook_fanout(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
    ) -> Result<WebhookFanoutReport> {
        if rotation == TrustRotation::WindowsClient {
            bail!("webhook fan-out requires one of the two physical Linux rotations");
        }
        let plan = self.cleanup_plan(run_id)?;
        if plan
            .nodes
            .iter()
            .any(|node| !node.owner_matches || !node.run_dir_present)
        {
            bail!("webhook fan-out refused: run does not own both staged node directories");
        }

        let roles = rotation.roles();
        let primary = self.remote_by_id(roles.ca)?;
        let sink_node = self.remote_by_id(roles.service)?;
        let mut resources = WebhookFanoutResources::default();
        let result = self.run_webhook_fanout(run_id, rotation, primary, sink_node, &mut resources);
        let cleanup = self.cleanup_webhook_fanout(run_id, primary, sink_node, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "daemon, sink fixture, manifest, deliveries, and markers were removed by exact owned identity",
                ));
                let path = output_path(run_id.as_str())
                    .join(format!("webhook-fanout-{}.json", rotation.as_str()));
                self.write_evidence(&path, &report)?;
                Ok(report)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => {
                Err(cleanup_error).context("webhook checks passed but cleanup failed")
            }
            (Err(error), Err(cleanup_error)) => Err(error).context(format!(
                "webhook fan-out failed; compensating cleanup also failed: {cleanup_error:#}"
            )),
        }
    }

    fn run_webhook_fanout(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
        primary: &NodeSpec,
        sink_node: &NodeSpec,
        resources: &mut WebhookFanoutResources,
    ) -> Result<WebhookFanoutReport> {
        let artifact_sha256 = self.remote_line(
            primary,
            &format!("cat {}/artifact.sha256", primary.run_dir(run_id)?),
        )?;

        // ── Sink fixture on the observer ──
        let secret = format!("sink-{}", run_id.as_str());
        let sink_port = sink_node.lab_ports()?.fixture;
        let url = format!("http://{}:{sink_port}/hook", sink_node.address());
        self.stage_webhook_sink(sink_node, run_id)?;
        resources.sink_staged = true;
        self.start_webhook_sink(sink_node, run_id, &secret)?;
        resources.sink_active = true;

        // ── Primary daemon with the sink manifest ──
        self.stage_webhook_manifest(primary, run_id, &url, &secret)?;
        resources.manifest_staged = true;
        self.start_webhook_fanout_daemon(primary, run_id)?;
        resources.primary_daemon = true;

        let primary_url = self.node_url(primary)?;
        wait_for_http(&format!("{primary_url}/healthz"))
            .context("primary daemon did not become healthy")?;

        // The status ladder must report the enabled transport.
        let token = self.daemon_token(primary, run_id)?;
        let status = curl_json(
            "GET",
            &format!("{primary_url}/v1/status"),
            Some(&token),
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

        // ── Trigger real domain events over the authenticated API ──
        let suffix = webhook_suffix(run_id);
        let name_a = format!("{suffix}-a");
        let name_b = format!("{suffix}-b");
        let ip = "192.0.2.77"; // TEST-NET-1: never routed, purely synthetic
        for name in [&name_a, &name_b] {
            curl_json(
                "POST",
                &format!("{primary_url}/v1/dns/add"),
                Some(&token),
                Some(&serde_json::json!({ "name": name, "ip": ip })),
            )
            .with_context(|| format!("dns add {name} did not succeed"))?;
        }

        // ── Cross-host delivery ──
        let deliveries = self.wait_for_deliveries(sink_node, run_id, 3, Duration::from_secs(30))?;
        let mut checks = Vec::new();
        checks.push(check(
            sinks == 1 && enabled,
            "status_reports_enabled_sink",
            format!("/v1/status webhooks = {{enabled: {enabled}, sinks: {sinks}}}"),
        ));

        if deliveries.is_empty() {
            checks.push(check(
                false,
                "deliveries_captured",
                "no delivery reached the sink within the timeout window",
            ));
            return Ok(self.report(
                run_id,
                rotation,
                primary,
                sink_node,
                artifact_sha256,
                0,
                checks,
            ));
        }
        checks.push(check(
            true,
            "deliveries_captured",
            format!("{} delivery line(s) captured by the sink", deliveries.len()),
        ));

        // Every captured delivery must be signature-valid and shape-correct.
        let all_valid = deliveries.iter().all(|d| {
            d.get("sig_valid").and_then(Value::as_bool) == Some(true)
                && d.get("body_ok").and_then(Value::as_bool) == Some(true)
        });
        checks.push(check(
            all_valid,
            "hmac_and_envelope_valid_on_every_delivery",
            "each delivery verified its HMAC at receive time and parsed as a v=1 envelope",
        ));

        // The triggered DNS events must be present among the delivered types.
        let mut types: BTreeSet<String> = BTreeSet::new();
        for d in &deliveries {
            if let Some(t) = d.get("event_type").and_then(Value::as_str) {
                types.insert(t.to_string());
            }
        }
        checks.push(check(
            types.contains("dns.updated"),
            "triggered_event_type_present",
            format!("delivered event types observed: {}", {
                let v: Vec<&str> = types.iter().map(String::as_str).collect();
                v.join(", ")
            }),
        ));

        // Daemon must remain healthy after fanning out.
        wait_for_http(&format!("{primary_url}/healthz")).context("post-delivery health check")?;
        checks.push(check(
            true,
            "daemon_healthy_after_delivery",
            "primary daemon stayed healthy after cross-host fan-out",
        ));

        Ok(self.report(
            run_id,
            rotation,
            primary,
            sink_node,
            artifact_sha256,
            deliveries.len() as u32,
            checks,
        ))
    }

    /// Poll the observer's deliveries file until it holds `want` lines.
    pub(crate) fn wait_for_deliveries(
        &self,
        sink_node: &NodeSpec,
        run_id: &RunId,
        want: usize,
        timeout: Duration,
    ) -> Result<Vec<Value>> {
        let run_dir = sink_node.run_dir(run_id)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let raw = self
                .remote_line(
                    sink_node,
                    &format!(
                    "if test -f {run_dir}/deliveries.jsonl; then cat {run_dir}/deliveries.jsonl; fi"
                ),
                )
                .unwrap_or_default();
            let lines: Vec<Value> = raw
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            if lines.len() >= want {
                return Ok(lines);
            }
            thread::sleep(Duration::from_millis(300));
        }
        // Return whatever exists so failure checks can report honestly.
        let raw = self.remote_line(
            sink_node,
            &format!("if test -f {run_dir}/deliveries.jsonl; then cat {run_dir}/deliveries.jsonl; fi"),
        )
        .unwrap_or_default();
        Ok(raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn report(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
        primary: &NodeSpec,
        sink_node: &NodeSpec,
        artifact_sha256: String,
        deliveries: u32,
        checks: Vec<CheckResult>,
    ) -> WebhookFanoutReport {
        WebhookFanoutReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            rotation,
            primary_node: primary.id().to_string(),
            sink_node: sink_node.id().to_string(),
            artifact_sha256,
            deliveries_captured: deliveries,
            checks,
            secrets_redacted: true,
        }
    }

    fn cleanup_webhook_fanout(
        &self,
        run_id: &RunId,
        primary: &NodeSpec,
        sink_node: &NodeSpec,
        resources: &mut WebhookFanoutResources,
    ) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        if resources.primary_daemon {
            if let Err(e) = self.stop_webhook_daemon(primary, run_id) {
                errors.push(format!("stop primary daemon: {e:#}"));
            }
        }
        if resources.sink_active {
            if let Err(e) = self.stop_webhook_sink(sink_node, run_id) {
                errors.push(format!("stop sink: {e:#}"));
            }
        }
        if resources.manifest_staged {
            // Manifest removal rides the generic run-dir allowlist via remove files.
            if let Err(e) = self.remove_webhook_sink_files(primary, run_id) {
                errors.push(format!("remove primary webhook files: {e:#}"));
            }
        }
        if resources.sink_staged || resources.sink_active {
            if let Err(e) = self.remove_webhook_sink_files(sink_node, run_id) {
                errors.push(format!("remove sink files: {e:#}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("cleanup errors: {}", errors.join("; "))
        }
    }
}

fn webhook_suffix(run_id: &RunId) -> String {
    run_id
        .as_str()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(12)
        .collect()
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}

fn check(condition: bool, name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    if condition {
        passed(name, detail)
    } else {
        CheckResult {
            name: name.into(),
            passed: false,
            detail: detail.into(),
        }
    }
}
