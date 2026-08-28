//! W7 (ADR-032): TLS proxy serving ON Windows, verified by BOTH OS-native
//! stacks over the real LAN.
//!
//! A run-owned daemon on THIS workstation joins a brook-hosted certmesh CA
//! with local key custody, then serves a LAN-reachable TLS proxy whose leaf
//! is its certmesh identity. Verification:
//!
//! - openssl from the Linux CA host: full chain + hostname verification
//!   against the system trust store (`-verify_return_error -verify_hostname`).
//! - Schannel from Windows: curl through the system store (`--resolve` keeps
//!   the DNS honest without a hosts-file mutation).
//! - Wrong-host rejection: openssl with a mismatched hostname must fail.
//!
//! Trust lifecycle uses the tracked native-trust machinery (install → verify
//! → exact remove) for both the Linux self-trust and the Windows
//! LocalMachine\Root, mirroring the native-trust lane's exact-restoration
//! doctrine.
//!
//! Gated on elevation (trust install), `--allow-system-mutation`, and the
//! catalog granting the workstation `firewall` mutations; every rule is
//! scenario-named and removed on every path.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::Digest;
use std::time::Duration;

use crate::lab::{curl_json, wait_for_http, Lab};
use crate::model::{output_path, CheckResult, RunId, WindowsProxyReport};

const FIREWALL_PROXY_RULE: &str = "koi-lab w7 proxy (tcp 18544)";

#[derive(Default)]
struct ProxyResources {
    windows_daemon: bool,
    member_daemon: bool,
    firewall_rules: Vec<String>,
    proxy_name: Option<String>,
    windows_trust: Option<crate::lab::InstalledTrust>,
    brook_trust: Option<crate::lab::InstalledTrust>,
}

impl Lab {
    pub fn windows_proxy(
        &self,
        run_id: &RunId,
        member_id: Option<&str>,
        allow_system_mutation: bool,
    ) -> Result<WindowsProxyReport> {
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
        let ca = crate::planner::machine_by_id(self.config(), member_id.unwrap_or("brook"))
            .context("catalog has no such member machine")?;
        if !ca.supports_role("ca") {
            bail!("{} does not declare the ca role", ca.id());
        }

        let mut resources = ProxyResources::default();
        let result = self.run_windows_proxy(run_id, windows, ca, &mut resources);
        let cleanup = self.cleanup_windows_proxy(run_id, windows, ca, &mut resources);
        match (result, cleanup) {
            (Ok(mut report), Ok(())) => {
                report.checks.push(passed(
                    "run_owned_cleanup",
                    "firewall rules, both daemons, the proxy, and both native-trust \
                     installations were removed",
                ));
                let path = output_path(run_id.as_str()).join("windows-proxy.json");
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

    fn run_windows_proxy(
        &self,
        run_id: &RunId,
        windows: &crate::model::NodeSpec,
        ca: &crate::model::NodeSpec,
        resources: &mut ProxyResources,
    ) -> Result<WindowsProxyReport> {
        let artifact_sha256 = self
            .remote_line(ca, &format!("cat {}/artifact.sha256", ca.run_dir(run_id)?))
            .context("read staged artifact sha256 from the CA host")?;

        let ports = windows.lab_ports()?;
        let ca_ports = ca.lab_ports()?;
        let hostname = windows.hostname();

        // ── Scenario-scoped firewall: the proxy listener is LAN-reachable ──
        let ca_root = self
            .prepare_windows_member_dir(run_id)
            .context("stage the Windows proxy daemon directory")?;
        let exe = ca_root.join("koi.exe");
        crate::lab::firewall_rule(FIREWALL_PROXY_RULE, "tcp", &ports.proxy.to_string(), &exe)
            .with_context(|| format!("firewall rule {FIREWALL_PROXY_RULE}"))?;
        resources
            .firewall_rules
            .push(FIREWALL_PROXY_RULE.to_string());

        // ── CA daemon on the Linux member ──
        self.start_story_daemon(ca, run_id)
            .context("start the CA run daemon")?;
        resources.member_daemon = true;
        let ca_url = self.node_url(ca)?;
        wait_for_http(&format!("{ca_url}/healthz")).context("CA daemon did not become healthy")?;
        let ca_token = self
            .remote_line(
                ca,
                &format!("cat {}/runtime/koi.endpoint", ca.run_dir(run_id)?),
            )
            .context("read the CA breadcrumb")
            .ok()
            .and_then(|body| {
                body.lines()
                    .nth(1)
                    .and_then(|line| line.trim().strip_prefix("dat:").map(str::to_owned))
            })
            .context("CA breadcrumb had no DAT token")?;

        // CA creation: enrollment open for exactly this run.
        let entropy = format!("{:x}", sha2::Sha256::digest(run_id.as_str().as_bytes()));
        curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/create"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "passphrase": format!("koi-lab-{}", run_id.as_str()),
                "entropy_hex": entropy,
                "operator": "koi-lab",
                "enrollment_open": true,
                "requires_approval": false,
                "auto_unlock": true
            })),
        )
        .context("CA create on the Linux member")?;

        // ── Windows member daemon (certmesh on, proxy runtime on) ──
        let mut windows_child = self
            .start_windows_serving_daemon(&ca_root, &ports, 18653, false, None)
            .context("start the Windows member daemon")?;
        resources.windows_daemon = true;
        let windows_url = format!("http://127.0.0.1:{}", ports.http);
        wait_for_http(&format!("{windows_url}/healthz"))
            .context("Windows member daemon did not become healthy")?;

        // ── Join with local key custody (invite pin + CSR never leave) ──
        let invite = curl_json(
            "POST",
            &format!("{ca_url}/v1/certmesh/invite"),
            Some(&ca_token),
            Some(&serde_json::json!({
                "hostname": hostname,
                "ttl_mins": 30
            })),
        )
        .context("mint the enrollment invite")?;
        let invite_token = invite
            .get("token")
            .and_then(Value::as_str)
            .context("invite response omitted token")?
            .to_owned();
        let join_args: Vec<String> = vec![
            "certmesh".to_owned(),
            "join".to_owned(),
            ca_url.clone(),
            "--invite".to_owned(),
            invite_token,
            "--ca-mtls-port".to_owned(),
            ca_ports.mtls.to_string(),
            "--json".to_owned(),
        ];
        let joined = self
            .run_windows_member_koi(&ca_root, &join_args)
            .context("run certmesh join on the Windows member")?;
        if !joined.status.success() {
            bail!(
                "Windows member join failed: {}",
                String::from_utf8_lossy(&joined.stderr).trim()
            );
        }

        // Restart so the daemon loads the freshly written identity, then
        // confirm the trust diagnosis is healthy.
        windows_child
            .kill()
            .context("stop the Windows daemon for the identity reload")?;
        windows_child
            .wait()
            .context("wait for the Windows daemon stop")?;
        let _windows_child = self
            .start_windows_serving_daemon(&ca_root, &ports, 18653, false, None)
            .context("restart the Windows member daemon with its identity")?;
        wait_for_http(&format!("{windows_url}/healthz"))
            .context("Windows member daemon did not become healthy after restart")?;
        let diagnosis = self
            .run_windows_member_koi(
                &ca_root,
                &[
                    "trust".to_owned(),
                    "diagnose".to_owned(),
                    "--json".to_owned(),
                ],
            )
            .context("run trust diagnose on the Windows member")?;
        let diagnosis: Value = serde_json::from_slice(&diagnosis.stdout)
            .context("Windows member diagnosis was not JSON")?;
        if diagnosis.get("overall").and_then(Value::as_str) != Some("healthy") {
            bail!(
                "Windows member diagnosis was not healthy after join: {}",
                diagnosis
            );
        }
        let w7_join = passed(
            "w7_windows_member_joined_local_custody",
            format!(
                "the Windows daemon joined the {} CA with local key custody and \
                 diagnosed healthy as {hostname}.internal",
                ca.id()
            ),
        );

        // ── Native trust on both sides (tracked, exact removal) ──
        let brook_trust = self
            .install_native_trust(ca, ca, run_id)
            .context("install the CA root into the Linux CA host's system store")?;
        resources.brook_trust = Some(brook_trust);
        let windows_trust = self
            .install_native_trust(windows, ca, run_id)
            .context("install the CA root into the Windows LocalMachine Root store")?;
        resources.windows_trust = Some(windows_trust);

        // ── The proxy: LAN-reachable, certmesh-sourced leaf ──
        let proxy_name = format!("{hostname}-proxy");
        curl_json(
            "POST",
            &format!("{windows_url}/v1/proxy/add"),
            Some(
                &self
                    .require_windows_breadcrumb(&ca_root, &windows_url)
                    .context("read the Windows daemon breadcrumb")?,
            ),
            Some(&serde_json::json!({
                "name": proxy_name,
                "listen_port": ports.proxy,
                "backend": format!("127.0.0.1:{}", ports.http),
                "allow_remote": true
            })),
        )
        .context("add the certmesh-sourced proxy on the Windows daemon")?;
        resources.proxy_name = Some(proxy_name.clone());
        wait_for_proxy_source(&windows_url, &proxy_name, ports.proxy, "certmesh")
            .context("proxy did not become a running certmesh-sourced listener")?;

        // ── Verify A: openssl from the Linux CA host (chain + hostname) ──
        // remote_line fails on a nonzero exit, so reaching here means the
        // chain + hostname verification passed.
        let tls_name = format!("{hostname}.internal");
        self.remote_line(
            ca,
            &format!(
                "openssl s_client -connect {}:{} -servername {tls_name} \
                 -verify_return_error -verify_hostname {tls_name} </dev/null >/dev/null 2>&1",
                windows.address(),
                ports.proxy
            ),
        )
        .context("openssl verify against the Windows proxy")?;
        let w7_openssl = passed(
            "w7_openssl_linux_verifies_windows_proxy",
            format!(
                "openssl on {} verified the Windows-served proxy at {}:{} for {tls_name} \
                 (chain + hostname) against the system trust store",
                ca.id(),
                windows.address(),
                ports.proxy
            ),
        );

        // ── Verify B: wrong-host rejection (openssl) ──
        if self
            .remote_line(
                ca,
                &format!(
                    "openssl s_client -connect {}:{} -servername {tls_name} \
                     -verify_return_error -verify_hostname wrong.host.internal \
                     </dev/null >/dev/null 2>&1",
                    windows.address(),
                    ports.proxy
                ),
            )
            .is_ok()
        {
            bail!("W7 openssl accepted a wrong hostname against the Windows proxy");
        }
        let w7_wrong_host = passed(
            "w7_wrong_host_rejected",
            "openssl rejected a mismatched hostname against the same connection".to_owned(),
        );

        // ── Verify C: Schannel from Windows (system store) ──
        // The machine trust store settles asynchronously after a root import
        // (RL-19: the first handshake can race lsass propagation); the positive
        // assertion retries briefly before it is allowed to go red.
        let mut schannel = self
            .native_tls_curl(windows, windows, &tls_name)
            .context("Schannel curl against the Windows proxy")?;
        let mut attempts = 1;
        while !schannel.status.success() && attempts < 5 {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            schannel = self
                .native_tls_curl(windows, windows, &tls_name)
                .context("Schannel curl against the Windows proxy")?;
            attempts += 1;
        }
        if !schannel.status.success() {
            bail!(
                "W7 Schannel did not verify the Windows proxy ({} attempts): {} {}",
                attempts,
                String::from_utf8_lossy(&schannel.stdout),
                String::from_utf8_lossy(&schannel.stderr)
            );
        }
        let w7_schannel = passed(
            "w7_schannel_windows_verifies_windows_proxy",
            format!(
                "Schannel curl on Windows verified the Windows-served proxy at \
                 {}:{} for {tls_name} through the system store",
                windows.address(),
                ports.proxy
            ),
        );

        Ok(WindowsProxyReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            windows_node: "windows".into(),
            member_node: ca.id().to_owned(),
            artifact_sha256,
            checks: vec![w7_join, w7_openssl, w7_wrong_host, w7_schannel],
            secrets_redacted: true,
        })
    }

    fn cleanup_windows_proxy(
        &self,
        run_id: &RunId,
        windows: &crate::model::NodeSpec,
        ca: &crate::model::NodeSpec,
        resources: &mut ProxyResources,
    ) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        let ports = windows
            .lab_ports()
            .expect("catalog windows node has lab ports");
        let windows_url = format!("http://127.0.0.1:{}", ports.http);

        if let Some(name) = &resources.proxy_name {
            if let Ok(token) =
                self.require_windows_breadcrumb(&self.windows_member_dir(run_id), &windows_url)
            {
                if let Err(e) = curl_json(
                    "DELETE",
                    &format!("{windows_url}/v1/proxy/remove/{name}"),
                    Some(&token),
                    None,
                ) {
                    errors.push(format!("remove proxy: {e:#}"));
                }
            }
        }
        if let Some(installed) = &resources.windows_trust {
            if let Err(e) = self.remove_native_trust(windows, run_id, installed) {
                errors.push(format!("remove Windows native trust: {e:#}"));
            }
        }
        if let Some(installed) = &resources.brook_trust {
            if let Err(e) = self.remove_native_trust(ca, run_id, installed) {
                errors.push(format!("remove Linux native trust: {e:#}"));
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
            if let Err(e) = self.stop_webhook_daemon(ca, run_id) {
                errors.push(format!("stop CA daemon: {e:#}"));
            }
            if let Err(e) = self.remove_webhook_sink_files(ca, run_id) {
                errors.push(format!("remove CA run files: {e:#}"));
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
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!("proxy {name} did not become a running {cert_source}-sourced listener: {last}")
}

fn passed(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: true,
        detail: detail.into(),
    }
}
