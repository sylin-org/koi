use std::collections::{BTreeSet, HashMap};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde_json::Value;

use crate::lab::{curl_json, wait_for_http, Lab, RuntimeFaultRole};
use crate::model::{
    output_path, CheckResult, NodeSpec, RunId, RuntimeReconnectReport, TrustRotation,
};
use crate::probe::SseCapture;

#[derive(Default)]
struct RuntimeReconnectResources {
    proxy_staged: bool,
    proxy_active: bool,
    primary_daemon: bool,
    observer_daemon: bool,
    image_owned: bool,
    network_owned: bool,
    containers: HashMap<&'static str, RuntimeFaultRole>,
}

impl Lab {
    pub fn runtime_reconnect(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
    ) -> Result<RuntimeReconnectReport> {
        if rotation == TrustRotation::WindowsClient {
            bail!("runtime reconnect requires one of the two physical Linux rotations");
        }
        let plan = self.cleanup_plan(run_id)?;
        if plan
            .nodes
            .iter()
            .any(|node| !node.owner_matches || !node.run_dir_present)
        {
            bail!("runtime reconnect refused: run does not own both staged node directories");
        }

        let roles = rotation.roles();
        let primary = self.remote_by_id(roles.ca)?;
        let observer = self.remote_by_id(roles.service)?;
        let mut resources = RuntimeReconnectResources::default();
        let result =
            self.run_runtime_reconnect(run_id, primary, observer, rotation, &mut resources);
        let cleanup = self.cleanup_runtime_reconnect(run_id, primary, observer, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "relay, daemons, four containers, network, image, sockets, and markers were removed by exact owned identity",
                ));
                let path = output_path(run_id.as_str())
                    .join(format!("runtime-reconnect-{}.json", rotation.as_str()));
                self.write_json(&path, &report)?;
                Ok(report)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => {
                Err(cleanup_error).context("reconnect checks passed but cleanup failed")
            }
            (Err(error), Err(cleanup_error)) => Err(error).context(format!(
                "runtime reconnect failed; compensating cleanup also failed: {cleanup_error:#}"
            )),
        }
    }

    fn run_runtime_reconnect(
        &self,
        run_id: &RunId,
        primary: &NodeSpec,
        observer: &NodeSpec,
        rotation: TrustRotation,
        resources: &mut RuntimeReconnectResources,
    ) -> Result<RuntimeReconnectReport> {
        self.stage_runtime_proxy(primary, run_id)?;
        resources.proxy_staged = true;
        self.start_runtime_proxy(primary, run_id)?;
        resources.proxy_active = true;
        self.start_runtime_reconnect_daemon(primary, run_id)?;
        resources.primary_daemon = true;
        self.start_story_daemon(observer, run_id)?;
        resources.observer_daemon = true;

        let primary_url = self.node_url(primary)?;
        let observer_url = self.node_url(observer)?;
        wait_for_http(&format!("{primary_url}/healthz"))?;
        wait_for_http(&format!("{observer_url}/healthz"))?;
        wait_for_runtime_active(&primary_url, true)?;

        self.stage_story_container_image(primary, run_id)?;
        resources.image_owned = true;
        let unchanged =
            self.start_runtime_fault_container(primary, run_id, RuntimeFaultRole::Unchanged)?;
        resources.containers.insert(
            RuntimeFaultRole::Unchanged.as_str(),
            RuntimeFaultRole::Unchanged,
        );
        let stopped =
            self.start_runtime_fault_container(primary, run_id, RuntimeFaultRole::Stopped)?;
        resources.containers.insert(
            RuntimeFaultRole::Stopped.as_str(),
            RuntimeFaultRole::Stopped,
        );
        let updated =
            self.start_runtime_fault_container(primary, run_id, RuntimeFaultRole::Updated)?;
        resources.containers.insert(
            RuntimeFaultRole::Updated.as_str(),
            RuntimeFaultRole::Updated,
        );

        let unchanged_before = wait_for_runtime_instance(&primary_url, &unchanged)?;
        wait_for_runtime_instance(&primary_url, &stopped)?;
        let updated_before = wait_for_runtime_instance(&primary_url, &updated)?;
        let suffix = runtime_suffix(run_id);
        let service_name = format!("koi-reconnect-{suffix}");
        let dns_name = format!("reconnect-{suffix}.internal");
        let full_service_name = format!("{service_name}._http._tcp.local.");
        let health_name = format!("runtime:{service_name}");
        wait_for_derived_service(
            self,
            primary,
            observer,
            &primary_url,
            &observer_url,
            &service_name,
            &dns_name,
            &full_service_name,
            &health_name,
        )?;
        let registration_before = mdns_registration_id(&primary_url, &service_name)?;
        let artifact_sha256 = self.remote_line(
            primary,
            &format!("cat {}/artifact.sha256", primary.run_dir(run_id)?),
        )?;

        let token = self.daemon_token(primary, run_id)?;
        let events = SseCapture::start(
            &format!("{primary_url}/v1/events"),
            Some(&token),
            15,
            "runtime reconnect",
        )?;
        thread::sleep(Duration::from_millis(300));

        self.stop_runtime_proxy(primary, run_id)?;
        resources.proxy_active = false;
        wait_for_runtime_active(&primary_url, false)?;
        require_inventory(&primary_url, &[&unchanged, &stopped, &updated], &[])?;
        let registration_disconnected = mdns_registration_id(&primary_url, &service_name)?;
        if registration_disconnected != registration_before {
            bail!("unchanged mDNS registration changed while Docker was disconnected");
        }
        wait_for_derived_service(
            self,
            primary,
            observer,
            &primary_url,
            &observer_url,
            &service_name,
            &dns_name,
            &full_service_name,
            &health_name,
        )?;

        self.stop_runtime_fault_container(primary, run_id, RuntimeFaultRole::Stopped)?;
        resources
            .containers
            .remove(RuntimeFaultRole::Stopped.as_str());
        let started =
            self.start_runtime_fault_container(primary, run_id, RuntimeFaultRole::Started)?;
        resources.containers.insert(
            RuntimeFaultRole::Started.as_str(),
            RuntimeFaultRole::Started,
        );
        self.connect_runtime_fault_network(primary, run_id, RuntimeFaultRole::Updated)?;
        resources.network_owned = true;

        // With the relay down, Koi must preserve its last good inventory rather
        // than observing direct Docker mutations through another path.
        require_inventory(&primary_url, &[&unchanged, &stopped, &updated], &[&started])?;

        self.start_runtime_proxy(primary, run_id)?;
        resources.proxy_active = true;
        wait_for_runtime_active(&primary_url, true)?;
        require_inventory(&primary_url, &[&unchanged, &updated, &started], &[&stopped])?;
        let updated_after = wait_for_runtime_instance(&primary_url, &updated)?;
        if updated_before.get("ips") == updated_after.get("ips") {
            bail!("run-owned Docker network attachment did not produce a material IP update");
        }
        let unchanged_after = wait_for_runtime_instance(&primary_url, &unchanged)?;
        require_same_operational_json(&unchanged_before, &unchanged_after)?;
        wait_for_derived_service(
            self,
            primary,
            observer,
            &primary_url,
            &observer_url,
            &service_name,
            &dns_name,
            &full_service_name,
            &health_name,
        )?;
        let registration_after = mdns_registration_id(&primary_url, &service_name)?;
        if registration_after != registration_before {
            bail!(
                "unchanged service registration churned across reconnect: {registration_before} -> {registration_after}"
            );
        }

        let captured = events.finish()?;
        let runtime_events = parse_runtime_events(&captured)?;
        require_exact_runtime_events(&runtime_events, &unchanged, &stopped, &updated, &started)?;

        Ok(RuntimeReconnectReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            rotation,
            primary_node: primary.id().to_owned(),
            observer_node: observer.id().to_owned(),
            artifact_sha256,
            checks: vec![
                passed(
                    "run_owned_socket_relay",
                    "mode-0600 Unix relay was the daemon's process-scoped DOCKER_HOST; the host Docker daemon was never restarted",
                ),
                passed(
                    "disconnect_health_and_inventory",
                    "runtime health became inactive while the last good three-instance inventory remained available",
                ),
                passed(
                    "unchanged_resources_preserved",
                    format!(
                        "mDNS registration {registration_before} plus DNS, health, proxy configuration, and live proxy traffic survived without churn"
                    ),
                ),
                passed(
                    "exact_relist_deltas",
                    "one stopped, one started, and one materially updated instance were emitted between disconnect and reconnect",
                ),
                passed(
                    "inclusive_replay_deduplicated",
                    "the unchanged ID emitted no lifecycle event and replay added no duplicate start/stop/update facts",
                ),
                passed(
                    "reconnect_health",
                    "runtime health returned active after reconciliation and cursor handoff",
                ),
            ],
            secrets_redacted: true,
        })
    }

    fn cleanup_runtime_reconnect(
        &self,
        run_id: &RunId,
        primary: &NodeSpec,
        observer: &NodeSpec,
        resources: &mut RuntimeReconnectResources,
    ) -> Result<()> {
        let mut failures = Vec::new();
        for role in RuntimeFaultRole::ALL {
            if resources.containers.remove(role.as_str()).is_some() {
                if let Err(error) = self.stop_runtime_fault_container(primary, run_id, role) {
                    failures.push(format!("container {}: {error:#}", role.as_str()));
                }
            }
        }
        if resources.network_owned {
            if let Err(error) = self.remove_runtime_fault_network(primary, run_id) {
                failures.push(format!("network: {error:#}"));
            } else {
                resources.network_owned = false;
            }
        }
        if resources.image_owned {
            if let Err(error) = self.remove_story_container_image(primary, run_id) {
                failures.push(format!("image: {error:#}"));
            } else {
                resources.image_owned = false;
            }
        }
        if resources.primary_daemon {
            if let Err(error) = self.stop_story_daemon(primary, run_id) {
                failures.push(format!("primary daemon: {error:#}"));
            } else {
                resources.primary_daemon = false;
            }
        }
        if resources.observer_daemon {
            if let Err(error) = self.stop_story_daemon(observer, run_id) {
                failures.push(format!("observer daemon: {error:#}"));
            } else {
                resources.observer_daemon = false;
            }
        }
        if resources.proxy_active {
            if let Err(error) = self.stop_runtime_proxy(primary, run_id) {
                failures.push(format!("relay: {error:#}"));
            } else {
                resources.proxy_active = false;
            }
        }
        if resources.proxy_staged && !resources.proxy_active {
            if let Err(error) = self.remove_runtime_proxy_files(primary, run_id) {
                failures.push(format!("relay files: {error:#}"));
            } else {
                resources.proxy_staged = false;
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            bail!("{}", failures.join("; "))
        }
    }
}

fn wait_for_runtime_active(base: &str, expected: bool) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..80 {
        let status = curl_json("GET", &format!("{base}/v1/runtime/status"), None, None)?;
        if status.get("active").and_then(Value::as_bool) == Some(expected) {
            return Ok(());
        }
        last = status;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("runtime active={expected} did not converge: {last}")
}

fn wait_for_runtime_instance(base: &str, id: &str) -> Result<Value> {
    let mut last = Value::Null;
    for _ in 0..80 {
        let instances = curl_json("GET", &format!("{base}/v1/runtime/instances"), None, None)?;
        if let Some(instance) = instances.as_array().and_then(|items| {
            items
                .iter()
                .find(|item| item.get("id").and_then(Value::as_str) == Some(id))
        }) {
            return Ok(instance.clone());
        }
        last = instances;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("runtime did not observe {id}: {last}")
}

fn require_inventory(base: &str, present: &[&str], absent: &[&str]) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..80 {
        let instances = curl_json("GET", &format!("{base}/v1/runtime/instances"), None, None)?;
        let ids: BTreeSet<_> = instances
            .as_array()
            .context("runtime instances response was not an array")?
            .iter()
            .filter_map(|item| item.get("id").and_then(Value::as_str))
            .collect();
        if present.iter().all(|id| ids.contains(*id)) && absent.iter().all(|id| !ids.contains(*id))
        {
            return Ok(());
        }
        last = instances;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("runtime inventory did not converge: {last}")
}

#[allow(clippy::too_many_arguments)]
fn wait_for_derived_service(
    lab: &Lab,
    primary: &NodeSpec,
    observer: &NodeSpec,
    primary_url: &str,
    observer_url: &str,
    service_name: &str,
    dns_name: &str,
    full_service_name: &str,
    health_name: &str,
) -> Result<()> {
    wait_for_dns(primary_url, dns_name, primary.address())?;
    wait_for_mdns(observer_url, full_service_name)?;
    wait_for_health(primary_url, health_name)?;
    let ports = primary.lab_ports()?;
    wait_for_proxy(
        primary_url,
        service_name,
        ports.proxy,
        &format!("http://{}:{}", primary.address(), ports.container),
    )?;
    let body = lab.remote_line(
        observer,
        &format!(
            "curl --silent --fail --insecure --max-time 4 https://{}:{}/healthz",
            primary.address(),
            ports.proxy
        ),
    )?;
    if body != "OK" {
        bail!("preserved proxy returned {body:?}, expected OK");
    }
    Ok(())
}

fn wait_for_dns(base: &str, name: &str, expected: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..80 {
        match curl_json(
            "GET",
            &format!("{base}/v1/dns/lookup?name={name}&type=A"),
            None,
            None,
        ) {
            Ok(value)
                if value
                    .get("ips")
                    .and_then(Value::as_array)
                    .is_some_and(|ips| ips.iter().any(|ip| ip.as_str() == Some(expected))) =>
            {
                return Ok(())
            }
            Ok(value) => last = value,
            Err(error) => last = Value::String(format!("{error:#}")),
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("DNS entry {name} did not converge to {expected}: {last}")
}

fn wait_for_mdns(base: &str, name: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..60 {
        match curl_json(
            "GET",
            &format!("{base}/v1/mdns/resolve?name={name}"),
            None,
            None,
        ) {
            Ok(value) if value.get("resolved").is_some() => return Ok(()),
            Ok(value) => last = value,
            Err(error) => last = Value::String(format!("{error:#}")),
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("mDNS service {name} did not resolve: {last}")
}

fn wait_for_health(base: &str, name: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..60 {
        let status = curl_json("GET", &format!("{base}/v1/health/status"), None, None)?;
        if status
            .get("services")
            .and_then(Value::as_array)
            .is_some_and(|services| {
                services.iter().any(|service| {
                    service.get("name").and_then(Value::as_str) == Some(name)
                        && service.get("status").and_then(Value::as_str) == Some("up")
                })
            })
        {
            return Ok(());
        }
        last = status;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("health check {name} did not become up: {last}")
}

fn wait_for_proxy(base: &str, name: &str, port: u16, expected_backend: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..60 {
        let status = curl_json("GET", &format!("{base}/v1/proxy/status"), None, None)?;
        if status
            .get("proxies")
            .and_then(Value::as_array)
            .is_some_and(|proxies| {
                proxies.iter().any(|proxy| {
                    proxy.get("name").and_then(Value::as_str) == Some(name)
                        && proxy.get("listen_port").and_then(Value::as_u64) == Some(u64::from(port))
                        && proxy.get("backend").and_then(Value::as_str) == Some(expected_backend)
                        && proxy.get("state").and_then(Value::as_str) == Some("running")
                })
            })
        {
            return Ok(());
        }
        last = status;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("proxy {name}:{port} did not remain live: {last}")
}

fn mdns_registration_id(base: &str, name: &str) -> Result<String> {
    let registrations = curl_json("GET", &format!("{base}/v1/mdns/admin/ls"), None, None)?;
    registrations
        .as_array()
        .context("mDNS admin list was not an array")?
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|item| item.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .with_context(|| format!("mDNS admin list did not contain {name}"))
}

fn require_same_operational_json(before: &Value, after: &Value) -> Result<()> {
    for field in [
        "id", "name", "ports", "ips", "metadata", "backend", "state", "image",
    ] {
        if before.get(field) != after.get(field) {
            bail!("unchanged runtime field {field} changed across reconnect");
        }
    }
    Ok(())
}

fn parse_runtime_events(capture: &str) -> Result<Vec<Value>> {
    capture
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(serde_json::from_str::<Value>)
        .filter_map(|result| match result {
            Ok(value)
                if value
                    .get("event_type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind.starts_with("runtime.")) =>
            {
                Some(Ok(value))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error.into())),
        })
        .collect()
}

fn require_exact_runtime_events(
    events: &[Value],
    unchanged: &str,
    stopped: &str,
    updated: &str,
    started: &str,
) -> Result<()> {
    for kind in [
        "runtime.disconnected",
        "runtime.stopped",
        "runtime.started",
        "runtime.updated",
        "runtime.reconnected",
    ] {
        let count = events
            .iter()
            .filter(|event| event.get("event_type").and_then(Value::as_str) == Some(kind))
            .count();
        if count != 1 {
            bail!("expected exactly one {kind}, observed {count}: {events:?}");
        }
    }

    for (kind, expected_id) in [
        ("runtime.stopped", stopped),
        ("runtime.started", started),
        ("runtime.updated", updated),
    ] {
        let actual = events
            .iter()
            .find(|event| event.get("event_type").and_then(Value::as_str) == Some(kind))
            .and_then(|event| event.pointer("/data/id"))
            .and_then(Value::as_str);
        if actual != Some(expected_id) {
            bail!("{kind} carried {actual:?}, expected {expected_id}");
        }
    }

    let unchanged_events = events.iter().filter(|event| {
        matches!(
            event.get("event_type").and_then(Value::as_str),
            Some("runtime.started" | "runtime.stopped" | "runtime.updated")
        ) && event.pointer("/data/id").and_then(Value::as_str) == Some(unchanged)
    });
    if unchanged_events.count() != 0 {
        bail!("unchanged container emitted a lifecycle event: {events:?}");
    }

    let disconnected = events
        .iter()
        .position(|event| {
            event.get("event_type").and_then(Value::as_str) == Some("runtime.disconnected")
        })
        .context("missing runtime.disconnected")?;
    let reconnected = events
        .iter()
        .position(|event| {
            event.get("event_type").and_then(Value::as_str) == Some("runtime.reconnected")
        })
        .context("missing runtime.reconnected")?;
    if disconnected >= reconnected {
        bail!("runtime reconnect marker preceded its disconnect marker");
    }
    Ok(())
}

fn runtime_suffix(run_id: &RunId) -> String {
    run_id
        .as_str()
        .rsplit('-')
        .next()
        .unwrap_or("fault")
        .to_ascii_lowercase()
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_event_contract_rejects_unchanged_churn_and_accepts_one_delta_each() {
        let event = |event_type: &str, id: Option<&str>| {
            serde_json::json!({
                "event_v": 1,
                "event_type": event_type,
                "id": format!("event-{event_type}"),
                "data": id.map_or_else(|| serde_json::json!({"backend": "docker"}), |id| serde_json::json!({"id": id}))
            })
        };
        let events = vec![
            event("runtime.disconnected", None),
            event("runtime.stopped", Some("stop")),
            event("runtime.started", Some("start")),
            event("runtime.updated", Some("update")),
            event("runtime.reconnected", None),
        ];
        require_exact_runtime_events(&events, "same", "stop", "update", "start").unwrap();

        let mut churned = events;
        churned.push(event("runtime.started", Some("same")));
        assert!(require_exact_runtime_events(&churned, "same", "stop", "update", "start").is_err());
    }

    #[test]
    fn parses_only_runtime_wire_events_from_sse() {
        let capture = "event: runtime.disconnected\ndata: {\"event_v\":1,\"event_type\":\"runtime.disconnected\",\"id\":\"1\",\"data\":{\"backend\":\"docker\"}}\n\nevent: dns.updated\ndata: {\"event_v\":1,\"event_type\":\"dns.updated\",\"id\":\"2\",\"data\":{}}\n\n";
        let events = parse_runtime_events(capture).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "runtime.disconnected");
    }
}
