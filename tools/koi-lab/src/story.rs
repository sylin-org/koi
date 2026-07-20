use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde_json::{json, Value};

use crate::lab::{curl_json, require_system_mutation, wait_for_http, InstalledTrust, Lab};
use crate::model::{
    output_path, CapabilityStoryReport, CheckResult, NodeSpec, RunId, TrustRotation,
};

const COVERED_ACTS: &[u8] = &[0, 3, 4, 5, 6, 7, 8, 10, 11];
const STORY_SERVICE_TYPE: &str = "_koi-v1._tcp.local.";
const CONTAINER_SERVICE_TYPE: &str = "_http._tcp.local.";

#[derive(Default)]
struct StoryResources {
    dns_names: Vec<String>,
    mdns_id: Option<String>,
    health_name: Option<String>,
    udp_id: Option<String>,
    proxy_name: Option<String>,
    installed_trust: Option<InstalledTrust>,
    fixture_active: bool,
    container_owned: bool,
    image_owned: bool,
}

struct SseCapture {
    child: Option<Child>,
    label: String,
}

impl SseCapture {
    fn start(url: &str, token: Option<&str>, timeout_secs: u64, label: &str) -> Result<Self> {
        let mut command = Command::new("curl.exe");
        command.args([
            "--silent",
            "--show-error",
            "--no-buffer",
            "--max-time",
            &timeout_secs.to_string(),
            url,
        ]);
        if let Some(token) = token {
            command.args(["--header", &format!("x-koi-token: {token}")]);
        }
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start {label} SSE capture"))?;
        Ok(Self {
            child: Some(child),
            label: label.to_owned(),
        })
    }

    fn finish(mut self) -> Result<String> {
        self.finish_allowing(&[28])
    }

    /// Finish a stream whose server was deliberately restarted. Curl reports
    /// exit 18 when a chunked SSE response closes without its terminating
    /// chunk; that is expected only at this explicit restart boundary.
    fn finish_after_server_restart(mut self) -> Result<String> {
        self.finish_allowing(&[18])
    }

    fn finish_allowing(&mut self, allowed_exit_codes: &[i32]) -> Result<String> {
        let child = self
            .child
            .take()
            .context("SSE capture was already consumed")?;
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for {} SSE capture", self.label))?;
        if !output.status.success()
            && !output
                .status
                .code()
                .is_some_and(|code| allowed_exit_codes.contains(&code))
        {
            bail!(
                "{} SSE capture failed (exit {}): {}",
                self.label,
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        String::from_utf8(output.stdout)
            .with_context(|| format!("{} SSE capture returned non-UTF-8 data", self.label))
    }
}

impl Drop for SseCapture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Lab {
    pub fn capability_story(
        &self,
        run_id: &RunId,
        allow_system_mutation: bool,
        rotation: TrustRotation,
    ) -> Result<CapabilityStoryReport> {
        require_system_mutation(allow_system_mutation)?;
        if rotation == TrustRotation::WindowsClient {
            bail!(
                "capability story currently supports the two physical Linux rotations; the Windows role joins when its privileged lane is available"
            );
        }
        let plan = self.cleanup_plan(run_id)?;
        if plan
            .nodes
            .iter()
            .any(|node| !node.owner_matches || !node.run_dir_present)
        {
            bail!("capability story refused: run does not own both staged node directories");
        }

        let roles = rotation.roles();
        let primary = self.remote_by_id(roles.ca)?;
        let observer = self.remote_by_id(roles.service)?;
        let mut resources = StoryResources::default();

        let result = self.run_capability_story(run_id, primary, observer, rotation, &mut resources);
        let cleanup = self.cleanup_story_resources(run_id, primary, observer, &mut resources);
        match (result, cleanup) {
            (Ok(report), Ok(())) => {
                let path = output_path(run_id.as_str())
                    .join(format!("capability-story-{}.json", rotation.as_str()));
                self.write_json(&path, &report)?;
                Ok(report)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => {
                Err(cleanup_error).context("story checks passed but compensating cleanup failed")
            }
            (Err(error), Err(cleanup_error)) => Err(error).context(format!(
                "capability story failed; compensating cleanup also failed: {cleanup_error:#}"
            )),
        }
    }

    fn run_capability_story(
        &self,
        run_id: &RunId,
        primary: &NodeSpec,
        observer: &NodeSpec,
        rotation: TrustRotation,
        resources: &mut StoryResources,
    ) -> Result<CapabilityStoryReport> {
        self.start_story_daemon(primary, run_id)?;
        self.start_story_daemon(observer, run_id)?;
        let primary_url = self.node_url(primary)?;
        let observer_url = self.node_url(observer)?;
        wait_for_http(&format!("{primary_url}/healthz"))?;
        wait_for_http(&format!("{observer_url}/healthz"))?;
        let mut primary_token = self.daemon_token(primary, run_id)?;

        let suffix = story_suffix(run_id);
        let dns_name = format!("story-{suffix}.internal");
        let service_name = format!("koi-story-{suffix}");
        let health_name = format!("story-{suffix}");
        let full_service_name = format!("{service_name}.{STORY_SERVICE_TYPE}");
        let container_service_name = format!("koi-container-{suffix}");
        let container_dns_name = format!("container-{suffix}");
        let container_fqdn = format!("{container_dns_name}.internal");
        let container_full_service_name =
            format!("{container_service_name}.{CONTAINER_SERVICE_TYPE}");
        let mut checks = Vec::new();

        // The fixture image is assembled locally from the exact deployed static
        // binary, then loaded under a run-specific tag on the active node.
        resources.image_owned = true;
        self.stage_story_container_image(primary, run_id)?;

        // Act 0: both real daemons are healthy, isolated, and advertise protected breadcrumbs.
        for node in [primary, observer] {
            let run_dir = node.run_dir(run_id)?;
            self.run_remote_checked(
                node,
                &format!(
                    "set -eu; test \"$(cat {run_dir}/owner)\" = {}; test -d {run_dir}/data; test -d {run_dir}/runtime; test \"$(stat -c %a {run_dir}/runtime/koi.endpoint)\" = 600; test -S {run_dir}/runtime/koi.sock",
                    run_id.as_str()
                ),
            )?;
        }
        checks.push(passed(
            "act_0_genesis_isolation",
            format!(
                "{} and {} are healthy with distinct run roots, mode-0600 breadcrumbs, and Unix IPC sockets",
                primary.id(),
                observer.id()
            ),
        ));

        let dashboard_capture = SseCapture::start(
            &format!("{primary_url}/v1/dashboard/events"),
            None,
            120,
            "dashboard",
        )?;
        thread::sleep(Duration::from_millis(300));

        // Act 3: one static in-zone record is visible through both HTTP and a real remote DNS query.
        resources.dns_names.push(dns_name.clone());
        let added = curl_json(
            "POST",
            &format!("{primary_url}/v1/dns/add"),
            Some(&primary_token),
            Some(&json!({
                "name": dns_name,
                "ip": primary.address(),
                "ttl": 30
            })),
        )?;
        if !added
            .get("entries")
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| name.trim_end_matches('.') == dns_name)
                        && entry.get("ip").and_then(Value::as_str) == Some(primary.address())
                })
            })
        {
            bail!("DNS add response did not contain the run-owned entry");
        }
        let lookup = curl_json(
            "GET",
            &format!("{primary_url}/v1/dns/lookup?name={dns_name}&type=A"),
            None,
            None,
        )?;
        if !lookup
            .get("ips")
            .and_then(Value::as_array)
            .is_some_and(|ips| ips.iter().any(|ip| ip.as_str() == Some(primary.address())))
        {
            bail!("HTTP DNS lookup did not resolve the run-owned entry");
        }
        let resolved = self.remote_line(
            observer,
            &format!(
                "dig @{} -p {} {} A +short | sed -n '1p'",
                primary.address(),
                primary.lab_ports()?.dns,
                dns_name
            ),
        )?;
        if resolved != primary.address() {
            bail!(
                "real DNS query returned {resolved:?}, expected {}",
                primary.address()
            );
        }
        let observer_status = self.remote_line(
            observer,
            &format!(
                "curl --silent --output /dev/null --write-out '%{{http_code}}' '{observer_url}/v1/dns/lookup?name={dns_name}&type=A'"
            ),
        )?;
        if observer_status != "404" {
            bail!("observer state-isolation lookup returned HTTP {observer_status}, expected 404");
        }
        checks.push(passed(
            "act_3_dns",
            format!(
                "{dns_name} resolved to {} through HTTP and dig on port {}; observer state remained isolated",
                primary.address(),
                primary.lab_ports()?.dns
            ),
        ));

        // Act 4: subscribe on the observer before announcing on the primary.
        let mdns_capture = SseCapture::start(
            &format!("{observer_url}/v1/mdns/subscribe?type={STORY_SERVICE_TYPE}&idle_for=8"),
            None,
            20,
            "mDNS",
        )?;
        thread::sleep(Duration::from_millis(500));
        let registration = curl_json(
            "POST",
            &format!("{primary_url}/v1/mdns/announce"),
            Some(&primary_token),
            Some(&json!({
                "name": service_name,
                "type": STORY_SERVICE_TYPE,
                "port": primary.lab_ports()?.http,
                "ip": primary.address(),
                "lease_secs": 30,
                "txt": {"run": run_id.as_str(), "surface": "v1-breadth"}
            })),
        )?;
        let mdns_id = registration
            .get("registered")
            .and_then(|registered| registered.get("id"))
            .and_then(Value::as_str)
            .context("mDNS announce response did not contain registered.id")?
            .to_owned();
        resources.mdns_id = Some(mdns_id.clone());
        wait_for_mdns_resolution(&observer_url, &full_service_name)?;
        let heartbeat = curl_json(
            "PUT",
            &format!("{primary_url}/v1/mdns/heartbeat/{mdns_id}"),
            Some(&primary_token),
            None,
        )?;
        if heartbeat
            .get("renewed")
            .and_then(|renewed| renewed.get("id"))
            .and_then(Value::as_str)
            != Some(mdns_id.as_str())
        {
            bail!("mDNS heartbeat did not renew the run-owned registration");
        }

        // Act 10 IPC assertion runs while the advertised service is still resolvable.
        require_ipc_resolution(self, primary, run_id, &full_service_name)?;

        curl_json(
            "DELETE",
            &format!("{primary_url}/v1/mdns/unregister/{mdns_id}"),
            Some(&primary_token),
            None,
        )?;
        resources.mdns_id = None;
        let mdns_events = mdns_capture.finish()?;
        if !mdns_events.contains(&service_name)
            || !mdns_events.contains("\"event\":\"resolved\"")
            || !mdns_events.contains("\"event\":\"removed\"")
        {
            bail!(
                "observer mDNS stream did not contain resolved and removed events: {mdns_events}"
            );
        }
        checks.push(passed(
            "act_4_mdns",
            format!(
                "{} discovered, resolved, renewed, and observed removal of {}",
                observer.id(),
                full_service_name
            ),
        ));

        // Acts 5 + 11: the real Docker event is the only drive. The composition
        // orchestrator must derive all four domain resources and reverse them.
        let container_mdns_capture = SseCapture::start(
            &format!("{observer_url}/v1/mdns/subscribe?type={CONTAINER_SERVICE_TYPE}&idle_for=12"),
            None,
            30,
            "container mDNS",
        )?;
        thread::sleep(Duration::from_millis(500));
        resources.container_owned = true;
        let container_id = self.start_story_container(
            primary,
            run_id,
            &container_service_name,
            &container_dns_name,
        )?;
        let instance = wait_for_runtime_instance(&primary_url, &container_id)?;
        require_runtime_metadata(
            &instance,
            &container_service_name,
            &container_dns_name,
            primary.lab_ports()?.proxy,
            run_id,
        )?;
        wait_for_dns_address(&primary_url, &container_fqdn, primary.address())?;
        let container_dns_answer = self.remote_line(
            observer,
            &format!(
                "dig @{} -p {} {} A +short | sed -n '1p'",
                primary.address(),
                primary.lab_ports()?.dns,
                container_fqdn
            ),
        )?;
        if container_dns_answer != primary.address() {
            bail!(
                "orchestrated DNS returned {container_dns_answer:?}, expected {}",
                primary.address()
            );
        }
        wait_for_mdns_resolution(&observer_url, &container_full_service_name)?;
        let runtime_health_name = format!("runtime:{container_service_name}");
        wait_for_health(&primary_url, &runtime_health_name, "up")?;
        wait_for_proxy(
            &primary_url,
            &container_service_name,
            primary.lab_ports()?.proxy,
            &format!(
                "http://{}:{}",
                primary.address(),
                primary.lab_ports()?.container
            ),
        )?;
        let proxy_body = self.remote_line(
            observer,
            &format!(
                "curl --silent --fail --insecure --max-time 4 https://{}:{}/healthz",
                primary.address(),
                primary.lab_ports()?.proxy
            ),
        )?;
        if proxy_body != "OK" {
            bail!("orchestrated proxy returned {proxy_body:?}, expected OK");
        }
        checks.push(passed(
            "act_5_runtime_orchestration",
            format!(
                "Docker instance {} produced mDNS, {container_fqdn} DNS, {runtime_health_name} health, and a live proxy on {}",
                &container_id[..12],
                primary.lab_ports()?.proxy
            ),
        ));

        // V1-05 startup reconciliation: leave the container running while Koi
        // stops cleanly (which withdraws all derived resources), then prove the
        // replacement daemon reconstructs them from Docker's existing inventory.
        let daemon_pid_before = self.remote_line(
            primary,
            &format!("cat {}/daemon.pid", primary.run_dir(run_id)?),
        )?;
        self.restart_story_daemon(primary, run_id)?;
        wait_for_http(&format!("{primary_url}/healthz"))?;
        let daemon_pid_after = self.remote_line(
            primary,
            &format!("cat {}/daemon.pid", primary.run_dir(run_id)?),
        )?;
        if daemon_pid_after == daemon_pid_before {
            bail!("capability daemon PID did not change across the controlled restart");
        }
        primary_token = self.daemon_token(primary, run_id)?;
        let dashboard_events_before_restart = dashboard_capture.finish_after_server_restart()?;
        let dashboard_capture = SseCapture::start(
            &format!("{primary_url}/v1/dashboard/events"),
            None,
            120,
            "dashboard after restart",
        )?;
        thread::sleep(Duration::from_millis(300));

        let reconciled = wait_for_runtime_instance(&primary_url, &container_id)?;
        require_runtime_metadata(
            &reconciled,
            &container_service_name,
            &container_dns_name,
            primary.lab_ports()?.proxy,
            run_id,
        )?;
        wait_for_dns_address(&primary_url, &container_fqdn, primary.address())?;
        wait_for_mdns_resolution(&observer_url, &container_full_service_name)?;
        wait_for_health(&primary_url, &runtime_health_name, "up")?;
        wait_for_proxy(
            &primary_url,
            &container_service_name,
            primary.lab_ports()?.proxy,
            &format!(
                "http://{}:{}",
                primary.address(),
                primary.lab_ports()?.container
            ),
        )?;
        let reconciled_body = self.remote_line(
            observer,
            &format!(
                "curl --silent --fail --insecure --max-time 4 https://{}:{}/healthz",
                primary.address(),
                primary.lab_ports()?.proxy
            ),
        )?;
        if reconciled_body != "OK" {
            bail!("reconciled proxy returned {reconciled_body:?}, expected OK");
        }
        checks.push(passed(
            "v1_05_daemon_restart_reconciliation",
            format!(
                "container {} stayed running while Koi PID {daemon_pid_before} -> {daemon_pid_after}; runtime inventory and mDNS/DNS/health/live-proxy state were reconstructed",
                &container_id[..12]
            ),
        ));

        self.stop_story_container(primary, run_id)?;
        resources.container_owned = false;
        wait_for_runtime_absence(&primary_url, &container_id)?;
        let container_mdns_events = container_mdns_capture.finish()?;
        if !container_mdns_events.contains(&container_service_name)
            || !container_mdns_events.contains("\"event\":\"resolved\"")
            || !container_mdns_events.contains("\"event\":\"removed\"")
        {
            bail!(
                "container mDNS stream did not contain resolved and removed events: {container_mdns_events}"
            );
        }
        wait_for_http_absence(&format!(
            "{primary_url}/v1/dns/lookup?name={container_fqdn}&type=A"
        ))?;
        wait_for_mdns_absence(&format!(
            "{observer_url}/v1/mdns/resolve?name={container_full_service_name}"
        ))?;
        wait_for_health_absence(&primary_url, &runtime_health_name)?;
        wait_for_proxy_absence(&primary_url, &container_service_name)?;
        let stale_proxy = self.run_remote(
            observer,
            &format!(
                "curl --silent --fail --insecure --max-time 2 https://{}:{}/healthz",
                primary.address(),
                primary.lab_ports()?.proxy
            ),
        )?;
        if stale_proxy.status.success() {
            bail!("orchestrated proxy data plane remained reachable after container stop");
        }
        self.remove_story_container_image(primary, run_id)?;
        resources.image_owned = false;
        checks.push(passed(
            "act_11_runtime_teardown",
            "container stop removed the runtime instance, mDNS, DNS, health, proxy listener, container, and run-tagged image",
        ));

        // Act 6: a run-owned TCP fixture drives the real Up -> Down -> Up state machine.
        self.start_story_fixture(primary, run_id)?;
        resources.fixture_active = true;
        resources.health_name = Some(health_name.clone());
        curl_json(
            "POST",
            &format!("{primary_url}/v1/health/add"),
            Some(&primary_token),
            Some(&json!({
                "name": health_name,
                "kind": "tcp",
                "target": format!("127.0.0.1:{}", primary.lab_ports()?.fixture),
                "interval_secs": 1,
                "timeout_secs": 1
            })),
        )?;
        wait_for_health(&primary_url, &health_name, "up")?;
        self.stop_story_fixture(primary, run_id)?;
        resources.fixture_active = false;
        wait_for_health(&primary_url, &health_name, "down")?;
        self.start_story_fixture(primary, run_id)?;
        resources.fixture_active = true;
        wait_for_health(&primary_url, &health_name, "up")?;
        checks.push(passed(
            "act_6_health",
            format!(
                "TCP check {health_name} transitioned up -> down -> up on run-owned port {}",
                primary.lab_ports()?.fixture
            ),
        ));

        checks.extend(self.run_act_7(run_id, rotation, primary, observer, resources)?);

        // Act 8: bind a real socket, subscribe over protected SSE, loop a datagram, renew, unbind.
        let binding = curl_json(
            "POST",
            &format!("{primary_url}/v1/udp/bind"),
            Some(&primary_token),
            Some(&json!({
                "port": 0,
                "addr": "127.0.0.1",
                "lease_secs": 30,
                "allow_remote": false
            })),
        )?;
        let udp_id = string_field(&binding, "id")?;
        let local_addr = string_field(&binding, "local_addr")?;
        resources.udp_id = Some(udp_id.clone());
        let udp_capture = SseCapture::start(
            &format!("{primary_url}/v1/udp/recv/{udp_id}?idle_for=3"),
            Some(&primary_token),
            8,
            "UDP",
        )?;
        thread::sleep(Duration::from_millis(300));
        let sent = curl_json(
            "POST",
            &format!("{primary_url}/v1/udp/send/{udp_id}"),
            Some(&primary_token),
            Some(&json!({"dest": local_addr, "payload": "a29pLXN0b3J5"})),
        )?;
        if sent.get("sent").and_then(Value::as_u64) != Some(9) {
            bail!("UDP send did not report the expected 9-byte payload");
        }
        let renewed = curl_json(
            "PUT",
            &format!("{primary_url}/v1/udp/heartbeat/{udp_id}"),
            Some(&primary_token),
            None,
        )?;
        if renewed.get("renewed").and_then(Value::as_str) != Some(udp_id.as_str()) {
            bail!("UDP heartbeat did not renew the run-owned binding");
        }
        let udp_events = udp_capture.finish()?;
        if !udp_events.contains("a29pLXN0b3J5") || !udp_events.contains(&udp_id) {
            bail!("UDP SSE stream did not contain the looped datagram: {udp_events}");
        }
        curl_json(
            "DELETE",
            &format!("{primary_url}/v1/udp/bind/{udp_id}"),
            Some(&primary_token),
            None,
        )?;
        resources.udp_id = None;
        let udp_status = curl_json(
            "GET",
            &format!("{primary_url}/v1/udp/status"),
            Some(&primary_token),
            None,
        )?;
        if udp_status
            .get("bindings")
            .and_then(Value::as_array)
            .is_some_and(|bindings| {
                bindings
                    .iter()
                    .any(|item| item.get("id").and_then(Value::as_str) == Some(udp_id.as_str()))
            })
        {
            bail!("UDP binding remained after unbind");
        }
        checks.push(passed(
            "act_8_udp",
            "protected SSE received the looped datagram; heartbeat and unbind succeeded",
        ));

        // Act 10: every enabled capability and every public aggregation surface is observable.
        let status = curl_json("GET", &format!("{primary_url}/v1/status"), None, None)?;
        for name in [
            "mdns", "certmesh", "dns", "health", "proxy", "udp", "runtime",
        ] {
            require_healthy_capability(&status, name)?;
        }
        if status.get("mcp_http").and_then(Value::as_bool) != Some(true) {
            bail!("unified status did not report MCP HTTP enabled");
        }
        let snapshot = curl_json(
            "GET",
            &format!("{primary_url}/v1/dashboard/snapshot"),
            None,
            None,
        )?;
        if snapshot
            .get("capabilities")
            .and_then(Value::as_array)
            .is_none()
            || snapshot.pointer("/dns/running").and_then(Value::as_bool) != Some(true)
            || snapshot
                .pointer("/health/services")
                .and_then(Value::as_array)
                .is_none()
        {
            bail!("dashboard snapshot did not contain the shared capability ladder and domain details");
        }
        let host = curl_json("GET", &format!("{primary_url}/v1/host"), None, None)?;
        if host.get("hostname").and_then(Value::as_str) != Some(primary.hostname()) {
            bail!("host endpoint did not report {}", primary.hostname());
        }
        let openapi = curl_json("GET", &format!("{primary_url}/openapi.json"), None, None)?;
        for path in [
            "/v1/dns/lookup",
            "/v1/mdns/discover",
            "/v1/health/status",
            "/v1/udp/status",
            "/v1/runtime/instances",
            "/v1/status",
        ] {
            if openapi
                .get("paths")
                .and_then(|paths| paths.get(path))
                .is_none()
            {
                bail!("OpenAPI document is missing {path}");
            }
        }
        let prometheus = curl_json(
            "GET",
            &format!("{primary_url}/v1/sd/prometheus"),
            Some(&primary_token),
            None,
        )?;
        if !prometheus.is_array() {
            bail!("Prometheus service discovery response is not an array");
        }
        let card = curl_json(
            "GET",
            &format!("{primary_url}/.well-known/mcp/server-card.json"),
            None,
            None,
        )?;
        if card.pointer("/mcp/enabled").and_then(Value::as_bool) != Some(true)
            || card.pointer("/mcp/path").and_then(Value::as_str) != Some("/v1/mcp")
        {
            bail!("MCP server card does not advertise the enabled HTTP transport");
        }
        require_mcp_resources(&primary_url, &primary_token)?;
        let dashboard_events = format!(
            "{dashboard_events_before_restart}\n{}",
            dashboard_capture.finish()?
        );
        if !dashboard_events.contains("dns.updated") || !dashboard_events.contains("health.changed")
        {
            bail!("dashboard stream did not contain DNS and health events: {dashboard_events}");
        }
        checks.push(passed(
            "act_10_aggregation",
            "status, dashboard snapshot/events, host, OpenAPI, Prometheus, MCP resources, and Unix IPC were live",
        ));

        Ok(CapabilityStoryReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            rotation,
            primary_node: primary.id().to_owned(),
            observer_node: observer.id().to_owned(),
            covered_acts: COVERED_ACTS.to_vec(),
            checks,
            secrets_redacted: true,
        })
    }

    fn run_act_7(
        &self,
        run_id: &RunId,
        rotation: TrustRotation,
        ca: &NodeSpec,
        service: &NodeSpec,
        resources: &mut StoryResources,
    ) -> Result<Vec<CheckResult>> {
        self.require_native_client_privilege(ca)?;
        let trust_before = self.native_trust_fingerprint(ca)?;
        let provisioned = self.provision_certmesh(run_id, ca, service)?;
        let ca_url = self.node_url(ca)?;
        let service_url = self.node_url(service)?;
        let ca_token = self.daemon_token(ca, run_id)?;
        let service_token = self.daemon_token(service, run_id)?;
        let service_name = format!("{}.internal", service.hostname());
        let service_port = service.lab_ports()?.proxy;

        curl_json(
            "POST",
            &format!("{ca_url}/v1/dns/add"),
            Some(&ca_token),
            Some(&json!({
                "name": service_name,
                "ip": service.address(),
                "ttl": 30
            })),
        )?;
        resources.dns_names.push(service_name.clone());
        let dns_answer = self.remote_line(
            service,
            &format!(
                "dig @{} -p {} {} A +short | sed -n '1p'",
                ca.address(),
                ca.lab_ports()?.dns,
                service_name
            ),
        )?;
        if dns_answer != service.address() {
            bail!(
                "Act 7 DNS returned {dns_answer:?}, expected {}",
                service.address()
            );
        }

        curl_json(
            "POST",
            &format!("{service_url}/v1/proxy/add"),
            Some(&service_token),
            Some(&json!({
                "name": service_name,
                "listen_port": service_port,
                "backend": format!("127.0.0.1:{}", service.lab_ports()?.http),
                "allow_remote": true
            })),
        )?;
        resources.proxy_name = Some(service_name.clone());
        wait_for_proxy_source(&service_url, &service_name, service_port, "certmesh")?;

        if self
            .native_tls_curl(ca, service, &service_name)?
            .status
            .success()
        {
            bail!("Act 7 precondition failed: fresh run CA was already natively trusted");
        }

        let installed = self.install_native_trust(ca, ca, run_id)?;
        resources.installed_trust = Some(installed);
        let installed = resources
            .installed_trust
            .as_ref()
            .context("native trust resource disappeared after install")?;
        if !self.native_trust_is_tracked(ca, run_id, installed)? {
            bail!("native trust install was not tracked by Koi");
        }

        require_native_proxy(self, ca, service, &service_name, run_id)?;
        let wrong_name = format!("wrong-{}", service_name);
        if self
            .native_tls_curl(ca, service, &wrong_name)?
            .status
            .success()
        {
            bail!("native TLS accepted the certmesh leaf for a wrong hostname");
        }

        let daemon_pid = self.remote_line(
            service,
            &format!("cat {}/daemon.pid", service.run_dir(run_id)?),
        )?;
        let identity_before = self.member_identity_evidence(service, run_id)?;
        let served_before = proxy_leaf_fingerprint(self, ca, service, &service_name)?;
        if !served_before.eq_ignore_ascii_case(&identity_before.cert_fingerprint) {
            bail!("proxy did not serve the member leaf before rotation");
        }

        let renewal =
            self.run_remote_checked(service, &self.member_renew_command(service, run_id)?)?;
        let renewal: Value =
            serde_json::from_str(renewal.trim()).context("Act 7 renewal returned invalid JSON")?;
        if renewal.get("renewed").and_then(Value::as_bool) != Some(true) {
            bail!("Act 7 renewal did not report a completed key rotation");
        }
        let identity_after = self.member_identity_evidence(service, run_id)?;
        if identity_after.key_sha256 == identity_before.key_sha256
            || identity_after.cert_sha256 == identity_before.cert_sha256
        {
            bail!("Act 7 renewal did not rotate both member key and certificate");
        }

        let mut served_after = String::new();
        for _ in 0..100 {
            served_after = proxy_leaf_fingerprint(self, ca, service, &service_name)?;
            if served_after.eq_ignore_ascii_case(&identity_after.cert_fingerprint) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if served_after.eq_ignore_ascii_case(&served_before)
            || !served_after.eq_ignore_ascii_case(&identity_after.cert_fingerprint)
        {
            bail!("proxy did not hot-reload the rotated certmesh leaf");
        }
        let daemon_pid_after = self.remote_line(
            service,
            &format!("cat {}/daemon.pid", service.run_dir(run_id)?),
        )?;
        if daemon_pid_after != daemon_pid {
            bail!("service daemon restarted during proxy certificate rotation");
        }
        wait_for_proxy_source(&service_url, &service_name, service_port, "certmesh")?;
        require_native_proxy(self, ca, service, &service_name, run_id)?;

        let acme = self.acme_mini_act(run_id, rotation, ca, service)?;

        let installed = resources
            .installed_trust
            .take()
            .context("native trust resource disappeared before removal")?;
        self.remove_native_trust(ca, run_id, &installed)?;
        if self.native_trust_fingerprint(ca)? != trust_before {
            bail!("Act 7 native trust cleanup did not restore the complete baseline");
        }
        if self
            .native_tls_curl(ca, service, &service_name)?
            .status
            .success()
        {
            bail!("native TLS still trusted the proxy after exact root removal");
        }

        Ok(vec![
            passed(
                "act_7_certmesh_proxy_tls",
                format!(
                    "{service_name}:{service_port} resolved through Koi DNS, failed before trust, verified with curl and OpenSSL after install, rejected a wrong hostname, and failed after exact removal; CA {}…; posture {}",
                    &provisioned.ca_fingerprint[..16],
                    provisioned.member_posture
                ),
            ),
            passed(
                "act_7_proxy_hot_rotation",
                format!(
                    "proxy served member leaf {}… then hot-reloaded {}… without daemon restart",
                    &served_before[..16],
                    &served_after[..16]
                ),
            ),
            acme,
        ])
    }

    fn cleanup_story_resources(
        &self,
        run_id: &RunId,
        primary: &NodeSpec,
        observer: &NodeSpec,
        resources: &mut StoryResources,
    ) -> Result<()> {
        let primary_url = self.node_url(primary)?;
        let token = self.daemon_token(primary, run_id).ok();
        let observer_url = self.node_url(observer)?;
        let observer_token = self.daemon_token(observer, run_id).ok();
        let mut failures = Vec::new();
        let needs_http_cleanup = resources.udp_id.is_some()
            || resources.mdns_id.is_some()
            || resources.health_name.is_some()
            || !resources.dns_names.is_empty();
        if needs_http_cleanup && token.is_none() {
            failures.push("daemon token unavailable for HTTP resource cleanup".to_owned());
        }
        if resources.proxy_name.is_some() && observer_token.is_none() {
            failures.push("observer token unavailable for proxy cleanup".to_owned());
        }

        if let Some(installed) = resources.installed_trust.take() {
            if let Err(error) = self.remove_native_trust(primary, run_id, &installed) {
                failures.push(format!("native trust: {error:#}"));
            }
        }

        if resources.container_owned {
            if let Err(error) = self.cleanup_story_container(primary, run_id) {
                failures.push(format!("container: {error:#}"));
            } else {
                resources.container_owned = false;
            }
        }
        if resources.image_owned {
            if let Err(error) = self.cleanup_story_container_image(primary, run_id) {
                failures.push(format!("container image: {error:#}"));
            } else {
                resources.image_owned = false;
            }
        }

        if let (Some(id), Some(token)) = (resources.udp_id.take(), token.as_deref()) {
            if let Err(error) = curl_json(
                "DELETE",
                &format!("{primary_url}/v1/udp/bind/{id}"),
                Some(token),
                None,
            ) {
                failures.push(format!("UDP {id}: {error:#}"));
            }
        }
        if let (Some(id), Some(token)) = (resources.mdns_id.take(), token.as_deref()) {
            if let Err(error) = curl_json(
                "DELETE",
                &format!("{primary_url}/v1/mdns/unregister/{id}"),
                Some(token),
                None,
            ) {
                failures.push(format!("mDNS {id}: {error:#}"));
            }
        }
        if let (Some(name), Some(token)) = (resources.health_name.take(), token.as_deref()) {
            if let Err(error) = curl_json(
                "DELETE",
                &format!("{primary_url}/v1/health/remove/{name}"),
                Some(token),
                None,
            ) {
                failures.push(format!("health {name}: {error:#}"));
            }
        }
        if let Some(token) = token.as_deref() {
            for name in std::mem::take(&mut resources.dns_names) {
                if let Err(error) = curl_json(
                    "DELETE",
                    &format!("{primary_url}/v1/dns/remove/{name}"),
                    Some(token),
                    None,
                ) {
                    failures.push(format!("DNS {name}: {error:#}"));
                }
            }
        }
        if let (Some(name), Some(observer_token)) =
            (resources.proxy_name.take(), observer_token.as_deref())
        {
            if let Err(error) = curl_json(
                "DELETE",
                &format!("{observer_url}/v1/proxy/remove/{name}"),
                Some(observer_token),
                None,
            ) {
                failures.push(format!("proxy {name}: {error:#}"));
            }
        }
        if resources.fixture_active {
            if let Err(error) = self.stop_story_fixture(primary, run_id) {
                failures.push(format!("fixture: {error:#}"));
            } else {
                resources.fixture_active = false;
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            bail!("{}", failures.join("; "))
        }
    }
}

fn story_suffix(run_id: &RunId) -> String {
    run_id
        .as_str()
        .rsplit('-')
        .next()
        .unwrap_or("story")
        .to_ascii_lowercase()
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}

fn string_field(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("response did not contain string field {field}"))
}

fn wait_for_mdns_resolution(base: &str, name: &str) -> Result<Value> {
    let mut last = String::new();
    for _ in 0..40 {
        match curl_json(
            "GET",
            &format!("{base}/v1/mdns/resolve?name={name}"),
            None,
            None,
        ) {
            Ok(value) if value.get("resolved").is_some() => return Ok(value),
            Ok(value) => last = value.to_string(),
            Err(error) => last = format!("{error:#}"),
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("mDNS resolution for {name} did not converge: {last}")
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
        thread::sleep(Duration::from_millis(250));
    }
    bail!("health check {name} did not become {expected}: {last}")
}

fn wait_for_runtime_instance(base: &str, container_id: &str) -> Result<Value> {
    let mut last = Value::Null;
    for _ in 0..80 {
        let instances = curl_json("GET", &format!("{base}/v1/runtime/instances"), None, None)?;
        if let Some(instance) = instances.as_array().and_then(|items| {
            items.iter().find(|item| {
                item.get("id").and_then(Value::as_str) == Some(container_id)
                    && item.get("state").and_then(Value::as_str) == Some("running")
            })
        }) {
            return Ok(instance.clone());
        }
        last = instances;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("runtime did not observe container {container_id}: {last}")
}

fn require_runtime_metadata(
    instance: &Value,
    service_name: &str,
    dns_name: &str,
    proxy_port: u16,
    run_id: &RunId,
) -> Result<()> {
    let metadata = instance
        .get("metadata")
        .context("runtime instance omitted metadata")?;
    let valid = metadata.get("enable").and_then(Value::as_bool) == Some(true)
        && metadata.get("name").and_then(Value::as_str) == Some(service_name)
        && metadata.get("dns_name").and_then(Value::as_str) == Some(dns_name)
        && metadata.get("service_type").and_then(Value::as_str) == Some("_http._tcp")
        && metadata.get("health_path").and_then(Value::as_str) == Some("/healthz")
        && metadata.get("health_kind").and_then(Value::as_str) == Some("http")
        && metadata.get("proxy_port").and_then(Value::as_u64) == Some(u64::from(proxy_port))
        && metadata.pointer("/txt/run").and_then(Value::as_str) == Some(run_id.as_str());
    if !valid {
        bail!("runtime did not preserve the run-owned Koi metadata: {metadata}");
    }
    Ok(())
}

fn wait_for_dns_address(base: &str, name: &str, expected: &str) -> Result<()> {
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

fn wait_for_proxy(base: &str, name: &str, listen_port: u16, expected_backend: &str) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..80 {
        let status = curl_json("GET", &format!("{base}/v1/proxy/status"), None, None)?;
        let ready = status
            .get("proxies")
            .and_then(Value::as_array)
            .is_some_and(|proxies| {
                proxies.iter().any(|proxy| {
                    proxy.get("name").and_then(Value::as_str) == Some(name)
                        && proxy.get("listen_port").and_then(Value::as_u64)
                            == Some(u64::from(listen_port))
                        && proxy.get("backend").and_then(Value::as_str) == Some(expected_backend)
                        && proxy.get("state").and_then(Value::as_str) == Some("running")
                        && proxy.get("cert_source").and_then(Value::as_str) == Some("self-signed")
                })
            });
        if ready {
            return Ok(());
        }
        last = status;
        thread::sleep(Duration::from_millis(250));
    }
    bail!("proxy {name} did not become live on {listen_port}: {last}")
}

fn wait_for_proxy_source(
    base: &str,
    name: &str,
    listen_port: u16,
    cert_source: &str,
) -> Result<()> {
    let mut last = Value::Null;
    for _ in 0..100 {
        let status = curl_json("GET", &format!("{base}/v1/proxy/status"), None, None)?;
        let ready = status
            .get("proxies")
            .and_then(Value::as_array)
            .is_some_and(|proxies| {
                proxies.iter().any(|proxy| {
                    proxy.get("name").and_then(Value::as_str) == Some(name)
                        && proxy.get("listen_port").and_then(Value::as_u64)
                            == Some(u64::from(listen_port))
                        && proxy.get("state").and_then(Value::as_str) == Some("running")
                        && proxy.get("error").is_none_or(Value::is_null)
                        && proxy.get("cert_source").and_then(Value::as_str) == Some(cert_source)
                })
            });
        if ready {
            return Ok(());
        }
        last = status;
        thread::sleep(Duration::from_millis(100));
    }
    bail!("proxy {name}:{listen_port} did not reach running/{cert_source} state: {last}")
}

fn require_native_proxy(
    lab: &Lab,
    client: &NodeSpec,
    service: &NodeSpec,
    hostname: &str,
    run_id: &RunId,
) -> Result<()> {
    let curl = lab.native_tls_curl(client, service, hostname)?;
    if !curl.status.success() || String::from_utf8_lossy(&curl.stdout).trim() != "OK" {
        bail!(
            "native curl did not verify {hostname}: {}",
            String::from_utf8_lossy(&curl.stderr).trim()
        );
    }
    let secondary = lab.native_tls_secondary(client, service, hostname, run_id)?;
    if !secondary.status.success() {
        bail!(
            "secondary native client did not verify {hostname}: {}",
            String::from_utf8_lossy(&secondary.stderr).trim()
        );
    }
    Ok(())
}

fn proxy_leaf_fingerprint(
    lab: &Lab,
    client: &NodeSpec,
    service: &NodeSpec,
    hostname: &str,
) -> Result<String> {
    let fingerprint = lab.remote_line(
        client,
        &format!(
            "openssl s_client -connect {}:{} -servername {hostname} </dev/null 2>/dev/null | openssl x509 -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1",
            service.address(),
            service.lab_ports()?.proxy
        ),
    )?;
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("proxy returned invalid leaf fingerprint {fingerprint:?}");
    }
    Ok(fingerprint.to_ascii_lowercase())
}

fn wait_for_runtime_absence(base: &str, container_id: &str) -> Result<()> {
    for _ in 0..80 {
        let instances = curl_json("GET", &format!("{base}/v1/runtime/instances"), None, None)?;
        let present = instances.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("id").and_then(Value::as_str) == Some(container_id))
        });
        if !present {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("runtime retained stopped container {container_id}")
}

fn wait_for_http_absence(url: &str) -> Result<()> {
    let mut last = 0;
    for _ in 0..80 {
        last = http_status("GET", url, None)?;
        if last == 404 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("resource {url} remained visible with HTTP {last}")
}

fn wait_for_mdns_absence(url: &str) -> Result<()> {
    // The resolve endpoint performs bounded active discovery. A missing service
    // is therefore represented as either not-found or discovery timeout.
    let status = http_status("GET", url, None)?;
    if matches!(status, 404 | 504) {
        return Ok(());
    }
    bail!("mDNS resource {url} remained visible with HTTP {status}")
}

fn wait_for_health_absence(base: &str, name: &str) -> Result<()> {
    for _ in 0..80 {
        let status = curl_json("GET", &format!("{base}/v1/health/status"), None, None)?;
        let present = status
            .get("services")
            .and_then(Value::as_array)
            .is_some_and(|services| {
                services
                    .iter()
                    .any(|service| service.get("name").and_then(Value::as_str) == Some(name))
            });
        if !present {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("health check {name} remained after container stop")
}

fn wait_for_proxy_absence(base: &str, name: &str) -> Result<()> {
    for _ in 0..80 {
        let status = curl_json("GET", &format!("{base}/v1/proxy/status"), None, None)?;
        let present = status
            .get("proxies")
            .and_then(Value::as_array)
            .is_some_and(|proxies| {
                proxies
                    .iter()
                    .any(|proxy| proxy.get("name").and_then(Value::as_str) == Some(name))
            });
        if !present {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("proxy {name} remained after container stop")
}

fn require_healthy_capability(status: &Value, name: &str) -> Result<()> {
    let healthy = status
        .get("capabilities")
        .and_then(Value::as_array)
        .is_some_and(|capabilities| {
            capabilities.iter().any(|capability| {
                capability.get("name").and_then(Value::as_str) == Some(name)
                    && capability.get("healthy").and_then(Value::as_bool) == Some(true)
            })
        });
    if !healthy {
        bail!("unified status did not report enabled capability {name} healthy");
    }
    Ok(())
}

fn require_ipc_resolution(
    lab: &Lab,
    node: &NodeSpec,
    run_id: &RunId,
    service_name: &str,
) -> Result<()> {
    let run_dir = node.run_dir(run_id)?;
    let request = json!({"resolve": service_name}).to_string();
    let output = lab.run_remote(
        node,
        &format!(
            "set -eu; test -S {run_dir}/runtime/koi.sock; printf '%s\\n' '{request}' | timeout 6 nc -N -U {run_dir}/runtime/koi.sock | sed -n '1p'"
        ),
    )?;
    // timeout may end the otherwise persistent IPC session after the first response.
    if !output.status.success() && output.status.code() != Some(124) {
        bail!(
            "Unix IPC probe failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let line = String::from_utf8(output.stdout).context("Unix IPC returned non-UTF-8 data")?;
    let value: Value =
        serde_json::from_str(line.trim()).context("Unix IPC returned invalid JSON")?;
    if value.get("resolved").is_none() {
        bail!("Unix IPC did not resolve {service_name}: {value}");
    }
    Ok(())
}

fn require_mcp_resources(base: &str, token: &str) -> Result<()> {
    let url = format!("{base}/v1/mcp");
    let unauthorized = http_status("POST", &url, None)?;
    if unauthorized != 401 {
        bail!("MCP request without DAT returned HTTP {unauthorized}, expected 401");
    }
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "koi-lab", "version": "1"}
        }
    });
    let (session, body) = mcp_post(&url, token, None, &initialize)?;
    let session = session.context("MCP initialize did not return mcp-session-id")?;
    if !body.contains("protocolVersion") {
        bail!("MCP initialize response was malformed: {body}");
    }
    let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    mcp_post(&url, token, Some(&session), &initialized)?;
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}});
    let (_, resources) = mcp_post(&url, token, Some(&session), &list)?;
    for uri in [
        "koi://lan/inventory",
        "koi://health",
        "koi://dns/zone",
        "koi://mdns/services",
    ] {
        if !resources.contains(uri) {
            bail!("MCP resources/list is missing {uri}: {resources}");
        }
    }
    let read = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/read",
        "params": {"uri": "koi://dns/zone"}
    });
    let (_, resource) = mcp_post(&url, token, Some(&session), &read)?;
    if !resource.contains("contents") {
        bail!("MCP resources/read returned no contents: {resource}");
    }
    Ok(())
}

fn http_status(method: &str, url: &str, token: Option<&str>) -> Result<u16> {
    let mut command = Command::new("curl.exe");
    command.args([
        "--silent",
        "--output",
        "NUL",
        "--write-out",
        "%{http_code}",
        "--request",
        method,
        url,
    ]);
    if let Some(token) = token {
        command.args(["--header", &format!("x-koi-token: {token}")]);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to query {url}"))?;
    let status = String::from_utf8(output.stdout).context("curl status was not UTF-8")?;
    status
        .trim()
        .parse::<u16>()
        .with_context(|| format!("curl returned invalid HTTP status {status:?}"))
}

fn mcp_post(
    url: &str,
    token: &str,
    session: Option<&str>,
    body: &Value,
) -> Result<(Option<String>, String)> {
    let mut command = Command::new("curl.exe");
    command.args([
        "--silent",
        "--show-error",
        "--max-time",
        "10",
        "--dump-header",
        "-",
        "--request",
        "POST",
        "--header",
        "content-type: application/json",
        "--header",
        "accept: application/json, text/event-stream",
        "--header",
        "mcp-protocol-version: 2025-06-18",
        "--header",
        &format!("x-koi-token: {token}"),
    ]);
    if let Some(session) = session {
        command.args(["--header", &format!("mcp-session-id: {session}")]);
    }
    command
        .args(["--data-binary", "@-", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start MCP request to {url}"))?;
    child
        .stdin
        .take()
        .context("MCP curl stdin was not piped")?
        .write_all(body.to_string().as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "MCP request failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let response = String::from_utf8(output.stdout).context("MCP response was not UTF-8")?;
    let session = response.lines().find_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("mcp-session-id")
                .then(|| value.trim().to_owned())
        })
    });
    let body = response
        .rsplit_once("\r\n\r\n")
        .map(|(_, body)| body)
        .or_else(|| response.rsplit_once("\n\n").map(|(_, body)| body))
        .unwrap_or(&response)
        .to_owned();
    Ok((session, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn story_suffix_is_path_and_dns_safe() {
        let id = RunId::parse("v1-20260719T000000Z-deadBEEF").unwrap();
        assert_eq!(story_suffix(&id), "deadbeef");
    }

    #[test]
    fn breadth_report_names_only_the_implemented_acts() {
        assert_eq!(COVERED_ACTS, &[0, 3, 4, 5, 6, 7, 8, 10, 11]);
    }
}
