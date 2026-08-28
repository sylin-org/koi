use anyhow::{bail, Context, Result};
use chrono::Utc;

use crate::derived::wait_for_derived_service;
use crate::lab::{require_system_mutation, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, NodeSpec, RunId, ServiceLifecycleReport};

const SERVICE_NODE: &str = "brook";
const OBSERVER_NODE: &str = "granite";

#[derive(Default)]
struct ServiceResources {
    service_attempted: bool,
    observer_daemon: bool,
    image_owned: bool,
    container_owned: bool,
}

#[derive(Clone, Copy)]
struct ServiceState {
    pid: u32,
    restarts: u64,
}

impl Lab {
    pub fn service_lifecycle(
        &self,
        run_id: &RunId,
        allow_system_mutation: bool,
    ) -> Result<ServiceLifecycleReport> {
        require_system_mutation(allow_system_mutation)?;
        let service = self.remote_by_id(SERVICE_NODE)?;
        if !service.allows_mutation("systemd") {
            bail!(
                "{} does not grant systemd mutations in the lab catalog",
                service.id()
            );
        }
        let plan = self.cleanup_plan(run_id)?;
        if plan
            .nodes
            .iter()
            .any(|node| !node.owner_matches || !node.run_dir_present)
        {
            bail!("service lifecycle refused: run does not own both staged node directories");
        }

        let service = self.remote_by_id(SERVICE_NODE)?;
        let observer = self.remote_by_id(OBSERVER_NODE)?;
        let observer_baseline = original_service_identity(self, observer)?;
        let mut resources = ServiceResources::default();
        let result = self.run_service_lifecycle(run_id, service, observer, &mut resources);
        let cleanup = self.cleanup_service_lifecycle(run_id, service, observer, &mut resources);

        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                require_brook_baseline(self, service, run_id)?;
                let observer_after = original_service_identity(self, observer)?;
                if observer_after != observer_baseline {
                    bail!(
                        "observer's installed Koi service changed: {observer_baseline} -> {observer_after}"
                    );
                }
                report.checks.push(passed(
                    "exact_service_cleanup",
                    "transient unit unloaded; Brook's permanent service/binary/data baseline remained absent",
                ));
                report.checks.push(passed(
                    "observer_service_untouched",
                    format!("Granite's installed service identity remained {observer_after}"),
                ));
                let path = output_path(run_id.as_str()).join("service-lifecycle-linux.json");
                self.write_evidence(&path, &report)?;
                Ok(report)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => {
                Err(cleanup_error).context("service checks passed but cleanup failed")
            }
            (Err(error), Err(cleanup_error)) => Err(error).context(format!(
                "service lifecycle failed; compensating cleanup also failed: {cleanup_error:#}"
            )),
        }
    }

    fn run_service_lifecycle(
        &self,
        run_id: &RunId,
        service: &NodeSpec,
        observer: &NodeSpec,
        resources: &mut ServiceResources,
    ) -> Result<ServiceLifecycleReport> {
        resources.service_attempted = true;
        start_transient_service(self, service, run_id)?;
        let unit_name = transient_unit_name(run_id);
        let initial = require_service_state(self, service, run_id, 0, 0)?;

        self.start_story_daemon(observer, run_id)?;
        resources.observer_daemon = true;
        let service_url = self.node_url(service)?;
        let observer_url = self.node_url(observer)?;
        wait_for_http(&format!("{service_url}/healthz"))?;
        wait_for_http(&format!("{observer_url}/healthz"))?;
        let token_before = self.daemon_token(service, run_id)?;

        resources.image_owned = true;
        self.stage_story_container_image(service, run_id)?;
        let suffix = service_suffix(run_id);
        let service_name = format!("koi-service-{suffix}");
        let dns_name = format!("service-{suffix}.internal");
        let full_service_name = format!("{service_name}._http._tcp.local.");
        let health_name = format!("runtime:{service_name}");
        resources.container_owned = true;
        self.start_story_container(service, run_id, &service_name, &dns_name)?;
        wait_for_derived_service(
            self,
            service,
            observer,
            &service_url,
            &observer_url,
            &service_name,
            &dns_name,
            &full_service_name,
            &health_name,
        )?;

        kill_transient_service(self, service, run_id, initial.pid)?;
        let restarted = require_service_state(self, service, run_id, initial.pid, 1)?;
        wait_for_http(&format!("{service_url}/healthz"))?;
        let token_after = self.daemon_token(service, run_id)?;
        if token_after == token_before {
            bail!("daemon access token did not rotate across the supervised restart");
        }
        wait_for_derived_service(
            self,
            service,
            observer,
            &service_url,
            &observer_url,
            &service_name,
            &dns_name,
            &full_service_name,
            &health_name,
        )?;

        let artifact_sha256 = self.remote_line(
            service,
            &format!("cat {}/artifact.sha256", service.run_dir(run_id)?),
        )?;
        Ok(ServiceLifecycleReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: Utc::now(),
            service_node: service.id().to_owned(),
            observer_node: observer.id().to_owned(),
            unit_name,
            artifact_sha256,
            initial_pid: initial.pid,
            restarted_pid: restarted.pid,
            restart_count: restarted.restarts,
            checks: vec![
                passed(
                    "systemd_readiness",
                    "transient service reached active/running through Koi's Type=notify READY signal",
                ),
                passed(
                    "exact_service_identity",
                    "unit was transient, ran as the configured lab user, and MainPID resolved to the staged run-owned artifact",
                ),
                passed(
                    "restart_on_failure",
                    format!(
                        "systemd replaced SIGKILLed PID {} with PID {} (NRestarts={})",
                        initial.pid, restarted.pid, restarted.restarts
                    ),
                ),
                passed(
                    "fresh_process_boundary",
                    "the daemon access token rotated across the supervised restart",
                ),
                passed(
                    "derived_surface_reconstruction",
                    "runtime inventory, DNS, cross-host mDNS, health, TLS proxy state, and live proxy traffic reconverged",
                ),
            ],
            secrets_redacted: true,
        })
    }

    fn cleanup_service_lifecycle(
        &self,
        run_id: &RunId,
        service: &NodeSpec,
        observer: &NodeSpec,
        resources: &mut ServiceResources,
    ) -> Result<()> {
        let mut failures = Vec::new();
        if resources.service_attempted {
            let script = transient_service_cleanup_script(service, run_id, false)?;
            if let Err(error) = self.run_remote_checked(service, &script) {
                failures.push(format!("transient service: {error:#}"));
            } else {
                resources.service_attempted = false;
            }
        }
        if resources.container_owned {
            if let Err(error) = self.cleanup_story_container(service, run_id) {
                failures.push(format!("container: {error:#}"));
            } else {
                resources.container_owned = false;
            }
        }
        if resources.image_owned {
            if let Err(error) = self.cleanup_story_container_image(service, run_id) {
                failures.push(format!("image: {error:#}"));
            } else {
                resources.image_owned = false;
            }
        }
        if resources.observer_daemon {
            if let Err(error) = self.stop_story_daemon(observer, run_id) {
                failures.push(format!("observer daemon: {error:#}"));
            } else {
                resources.observer_daemon = false;
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("{}", failures.join("; "))
        }
    }
}

fn start_transient_service(lab: &Lab, node: &NodeSpec, run_id: &RunId) -> Result<()> {
    if node.id() != SERVICE_NODE {
        bail!("transient service lifecycle is restricted to {SERVICE_NODE}");
    }
    let run_dir = node.run_dir(run_id)?;
    let lock_dir = node.lock_dir()?;
    let user = node.remote_user()?;
    let ports = node.lab_ports()?;
    let guarded_ports = ports.all().map(|port| port.to_string()).join("|");
    let unit = transient_unit_name(run_id);
    let command = format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; command -v systemd-run >/dev/null; sudo -n true; test ! -e /etc/systemd/system/koi.service; test ! -e /usr/local/bin/koi; test ! -e /var/lib/koi; test \"$(systemctl show --value -p LoadState koi.service)\" = not-found; test \"$(systemctl show --value -p LoadState {unit})\" = not-found; test ! -e {run_dir}/systemd-unit; test ! -e {run_dir}/data; test ! -e {run_dir}/runtime; ! ss -H -lntup | grep -Eq ':({guarded_ports}) '; mkdir {run_dir}/data {run_dir}/runtime; printf '%s' {unit} > {run_dir}/systemd-unit; sudo -n systemd-run --quiet --collect --unit={unit} --property=Type=notify --property=Restart=on-failure --property=RestartSec=1s --property=TimeoutStartSec=30s --property=TimeoutStopSec=30s --property=User={user} --property=WorkingDirectory={run_dir} --setenv=KOI_DATA_DIR={run_dir}/data --setenv=KOI_DNS_ZONE=internal --setenv=XDG_RUNTIME_DIR={run_dir}/runtime --setenv=KOI_NO_CREDENTIAL_STORE=1 {run_dir}/koi --daemon --port {} --http-bind 0.0.0.0 --mtls-port {} --acme-port {} --dns-port {} --dns-public --announce-http --runtime docker",
        run_id.as_str(),
        run_id.as_str(),
        ports.http,
        ports.mtls,
        ports.acme,
        ports.dns,
    );
    lab.run_remote_checked(node, &command)?;
    Ok(())
}

fn kill_transient_service(
    lab: &Lab,
    node: &NodeSpec,
    run_id: &RunId,
    expected_pid: u32,
) -> Result<()> {
    let run_dir = node.run_dir(run_id)?;
    let lock_dir = node.lock_dir()?;
    let unit = transient_unit_name(run_id);
    let command = format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test \"$(cat {run_dir}/systemd-unit)\" = {unit}; test \"$(systemctl show --value -p MainPID {unit})\" = {expected_pid}; test \"$(readlink -f /proc/{expected_pid}/exe)\" = {run_dir}/koi; sudo -n systemctl kill --kill-whom=main --signal=KILL {unit}",
        run_id.as_str(),
        run_id.as_str(),
    );
    lab.run_remote_checked(node, &command)?;
    Ok(())
}

fn require_service_state(
    lab: &Lab,
    node: &NodeSpec,
    run_id: &RunId,
    previous_pid: u32,
    minimum_restarts: u64,
) -> Result<ServiceState> {
    let run_dir = node.run_dir(run_id)?;
    let lock_dir = node.lock_dir()?;
    let unit = transient_unit_name(run_id);
    let user = node.remote_user()?;
    let fragment = format!("/run/systemd/transient/{unit}");
    let command = format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; test \"$(cat {run_dir}/systemd-unit)\" = {unit}; i=0; while test \"$(systemctl show --value -p ActiveState {unit})\" != active -o \"$(systemctl show --value -p SubState {unit})\" != running -o \"$(systemctl show --value -p MainPID {unit})\" = 0 -o \"$(systemctl show --value -p MainPID {unit})\" = {previous_pid} -o \"$(systemctl show --value -p NRestarts {unit})\" -lt {minimum_restarts}; do test \"$i\" -lt 120; sleep .25; i=$((i+1)); done; test \"$(systemctl show --value -p Type {unit})\" = notify; test \"$(systemctl show --value -p Restart {unit})\" = on-failure; test \"$(systemctl show --value -p Transient {unit})\" = yes; test \"$(systemctl show --value -p FragmentPath {unit})\" = {fragment}; test \"$(systemctl show --value -p User {unit})\" = {user}; pid=$(systemctl show --value -p MainPID {unit}); restarts=$(systemctl show --value -p NRestarts {unit}); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; case \"$restarts\" in ''|*[!0-9]*) exit 76;; esac; test \"$(readlink -f /proc/\"$pid\"/exe)\" = {run_dir}/koi; printf '%s|%s' \"$pid\" \"$restarts\"",
        run_id.as_str(),
        run_id.as_str(),
    );
    let output = lab.run_remote_checked(node, &command)?;
    let (pid, restarts) = output
        .trim()
        .split_once('|')
        .context("systemd state output did not contain pid|restart-count")?;
    Ok(ServiceState {
        pid: pid.parse().context("systemd MainPID was not a u32")?,
        restarts: restarts
            .parse()
            .context("systemd NRestarts was not a u64")?,
    })
}

pub(crate) fn transient_service_cleanup_script(
    node: &NodeSpec,
    run_id: &RunId,
    require_present: bool,
) -> Result<String> {
    let run_dir = node.run_dir(run_id)?;
    let lock_dir = node.lock_dir()?;
    let user = node.remote_user()?;
    let unit = transient_unit_name(run_id);
    let fragment = format!("/run/systemd/transient/{unit}");
    let required = if require_present { "true" } else { "false" };
    Ok(format!(
        "set -eu; test \"$(cat {lock_dir}/owner)\" = {}; test \"$(cat {run_dir}/owner)\" = {}; required={required}; if test -f {run_dir}/systemd-unit; then test \"$(cat {run_dir}/systemd-unit)\" = {unit}; load=$(systemctl show --value -p LoadState {unit}); if test \"$load\" != not-found; then test \"$(systemctl show --value -p Transient {unit})\" = yes; test \"$(systemctl show --value -p FragmentPath {unit})\" = {fragment}; test \"$(systemctl show --value -p User {unit})\" = {user}; pid=$(systemctl show --value -p MainPID {unit}); case \"$pid\" in ''|*[!0-9]*) exit 76;; esac; if test \"$pid\" != 0; then test \"$(readlink -f /proc/\"$pid\"/exe)\" = {run_dir}/koi; fi; sudo -n systemctl stop {unit}; fi; sudo -n systemctl reset-failed {unit} 2>/dev/null || true; i=0; while test \"$(systemctl show --value -p LoadState {unit})\" != not-found -a \"$i\" -lt 80; do sleep .1; i=$((i+1)); done; test \"$(systemctl show --value -p LoadState {unit})\" = not-found; rm -f {run_dir}/systemd-unit; elif test \"$required\" = true; then exit 76; fi",
        run_id.as_str(),
        run_id.as_str(),
    ))
}

fn require_brook_baseline(lab: &Lab, node: &NodeSpec, run_id: &RunId) -> Result<()> {
    let unit = transient_unit_name(run_id);
    let ports = node
        .lab_ports()?
        .all()
        .map(|port| port.to_string())
        .join("|");
    lab.run_remote_checked(
        node,
        &format!(
            "set -eu; test \"$(systemctl show --value -p LoadState {unit})\" = not-found; test \"$(systemctl show --value -p LoadState koi.service)\" = not-found; test ! -e /etc/systemd/system/koi.service; test ! -e /usr/local/bin/koi; test ! -e /var/lib/koi; test ! -e /run/koi; test ! -e /run/koi.sock; test ! -e /run/koi.endpoint; test ! -e /root/.koi; ! ss -H -lntup | grep -Eq ':({ports}) '; echo clean"
        ),
    )?;
    Ok(())
}

fn original_service_identity(lab: &Lab, node: &NodeSpec) -> Result<String> {
    lab.remote_line(
        node,
        "set -eu; guard() { echo \"koi-lab service-lifecycle precondition failed: $1\" >&2; exit 71; }; i=0; while [ \"$(systemctl show --value -p ActiveState koi.service)\" != active ] && [ \"$i\" -lt 40 ]; do sleep .5; i=$((i+1)); done; test \"$(systemctl show --value -p ActiveState koi.service)\" = active || guard \"koi.service not active (state: $(systemctl show --value -p ActiveState koi.service))\"; test \"$(systemctl is-enabled koi.service)\" = enabled || guard \"koi.service not enabled\"; pid=$(systemctl show --value -p MainPID koi.service); case \"$pid\" in ''|0|*[!0-9]*) exit 76;; esac; systemctl show koi.service -p MainPID -p FragmentPath -p ExecStart -p ActiveState -p UnitFileState",
    )
}

fn transient_unit_name(run_id: &RunId) -> String {
    format!("koi-lab-{}.service", run_id.as_str().to_ascii_lowercase())
}

fn service_suffix(run_id: &RunId) -> &str {
    run_id.as_str().rsplit('-').next().unwrap_or("service")
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

    fn node() -> NodeSpec {
        NodeSpec::PuttyLinux {
            id: "brook".into(),
            hostname: "stone-platinum-brook".into(),
            address: "192.168.1.44".into(),
            user: "stone".into(),
            host_key: "SHA256:test".into(),
            architecture: "x86_64".into(),
            remote_root: "/home/stone/koi-test".into(),
            http_port: 16541,
            mtls_port: 16542,
            acme_port: 16543,
            proxy_port: 16544,
            dns_port: 16553,
            fixture_port: 16554,
            container_port: 16555,
            roles: Vec::new(),
            mutations: Vec::new(),
            privilege: "dedicated-box".into(),
            password_env: None,
        }
    }

    #[test]
    fn transient_cleanup_is_unit_user_fragment_and_executable_scoped() {
        let run_id = RunId::parse("v1-20260720T000000Z-deadbeef").unwrap();
        let script = transient_service_cleanup_script(&node(), &run_id, true).unwrap();
        assert!(script.contains("required=true"));
        assert!(script.contains("koi-lab-v1-20260720t000000z-deadbeef.service"));
        assert!(script.contains("Transient"));
        assert!(script.contains("/run/systemd/transient/koi-lab-"));
        assert!(script.contains("test \"$(systemctl show --value -p User"));
        assert!(script.contains("readlink -f /proc/\"$pid\"/exe"));
        assert!(script.contains("sudo -n systemctl stop"));
        assert!(!script.contains("koi.service; sudo"));
    }

    #[test]
    fn service_suffix_is_the_run_entropy() {
        let run_id = RunId::parse("v1-20260720T000000Z-deadbeef").unwrap();
        assert_eq!(service_suffix(&run_id), "deadbeef");
    }
}
