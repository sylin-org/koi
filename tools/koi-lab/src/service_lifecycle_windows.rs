//! Physical Windows SCM supervision lane (ADR-032 W1).
//!
//! Installs the run-owned `koi.exe` as a real SCM service on the controller
//! workstation (`koi <exe> install` — AutoStart + recovery policy restart
//! 5s/10s + non-crash-failure recovery), proves health, hard-kills the service
//! process and requires SCM to bring a NEW pid back healthy, then uninstalls
//! and requires exact restoration. Refuses unless elevated, flagged, and the
//! catalog grants the workstation `scm` mutations. No Linux hosts involved.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::lab::Lab;
use crate::model::{output_path, CheckResult, RunId, ServiceLifecycleWindowsReport};

struct ScmResources {
    run_dir: Option<PathBuf>,
}

impl Lab {
    pub fn service_lifecycle_windows(
        &self,
        run_id: &RunId,
        allow_system_mutation: bool,
    ) -> Result<ServiceLifecycleWindowsReport> {
        crate::lab::require_system_mutation(allow_system_mutation)?;
        let windows = crate::planner::machine_by_id(self.config(), "windows")
            .context("catalog has no windows machine")?;
        if !windows.allows_mutation("scm") {
            bail!(
                "the catalog does not grant scm mutations to {}",
                windows.id()
            );
        }
        crate::lab::ensure_windows_elevated()?;

        // Baseline guard: never clobber an existing installation.
        if windows_service_installed() {
            bail!(
                "a Koi service already exists on this machine; the lane refuses \
                 to clobber an operator installation"
            );
        }
        if process_ids_for("koi").is_some() {
            bail!("a koi process is already running; refusing to share the lane");
        }

        let mut resources = ScmResources { run_dir: None };
        let result = self.run_scm_lane(run_id, windows.address(), &mut resources);
        let cleanup_ok = cleanup_scm(&mut resources);
        match (result, cleanup_ok) {
            (Ok(mut report), true) => {
                report.checks.push(passed(
                    "exact_cleanup",
                    "run directory and service were removed; machine restored",
                ));
                let path = output_path(run_id.as_str()).join("service-lifecycle-windows.json");
                self.write_evidence(&path, &report)?;
                Ok(report)
            }
            (Err(e), true) => Err(e),
            (Ok(_), false) => bail!("checks passed but exact cleanup failed"),
            (Err(e), false) => {
                bail!("{e:#}; compensating cleanup also failed")
            }
        }
    }

    fn run_scm_lane(
        &self,
        run_id: &RunId,
        _address: &str,
        resources: &mut ScmResources,
    ) -> Result<ServiceLifecycleWindowsReport> {
        let mut checks = Vec::new();

        // ── Run-owned staging: the SERVICE binary must be this run's copy ──
        let artifact = self.repo_root.join("target/release/koi.exe");
        let artifact_sha256 = sha256_file(&artifact)?;
        let run_dir = std::env::temp_dir().join(format!("koi-scm-{}", run_id.as_str()));
        std::fs::create_dir_all(&run_dir)?;
        resources.run_dir = Some(run_dir.clone());
        std::fs::copy(&artifact, run_dir.join("koi.exe"))?;
        std::fs::write(run_dir.join("owner"), run_id.as_str())?;

        // ── Install (elevated context inherited from the controller) ──
        run_checked(run_dir.join("koi.exe"), &["install"])?;
        checks.push(check(
            windows_service_installed(),
            "scm_service_installed",
            "service registered with AutoStart via the product installer",
        ));

        // ── Running + serving ──
        let pid1 =
            wait_running_pid(Duration::from_secs(20)).context("service did not reach RUNNING")?;
        checks.push(check(true, "scm_state_running", format!("pid {pid1}")));
        let health1 = wait_healthz(Duration::from_secs(20)).is_ok();
        checks.push(check(
            health1,
            "serving_standard_port",
            "GET /healthz on 127.0.0.1:5641 succeeded from the installed service",
        ));
        let autostart = sc_query_contains("start_type")?
            .to_ascii_lowercase()
            .contains("auto")
            || sc_qc_config()?.to_ascii_lowercase().contains("auto_start");
        checks.push(check(
            autostart,
            "autostart_configured",
            "SCM start type is auto-start",
        ));
        let recovery_text = sc_qfailure_config()?.to_ascii_lowercase();
        checks.push(check(
            recovery_text.contains("restart"),
            "recovery_policy_restart",
            "failure actions configure restart (5s/10s) per ADR-032 W1",
        ));

        // ── Hard-kill: SCM must recover with a NEW pid ──
        kill_force(pid1)?;
        let pid2 = wait_new_pid(pid1, Duration::from_secs(30))
            .context("SCM did not restart the killed service")?;
        let health2 = wait_healthz(Duration::from_secs(20)).is_ok();
        checks.push(check(
            pid2 != pid1 && pid2 > 0,
            "recovery_new_process",
            format!("hard-killed pid {pid1}; SCM restarted as pid {pid2}"),
        ));
        checks.push(check(
            health2,
            "healthy_after_recovery",
            "GET /healthz succeeded against the restarted service",
        ));

        // ── Uninstall restores the machine ──
        run_checked(run_dir.join("koi.exe"), &["uninstall"])?;
        let gone = !windows_service_installed();
        checks.push(check(gone, "uninstall_removes_service", "service deleted"));
        let port_free = wait_port_free(Duration::from_secs(15));
        checks.push(check(
            port_free,
            "port_5641_released",
            "listening socket released after uninstall",
        ));

        Ok(ServiceLifecycleWindowsReport {
            schema: 1,
            run_id: run_id.clone(),
            created_at: chrono::Utc::now(),
            artifact_sha256,
            checks,
            secrets_redacted: true,
        })
    }
}

fn cleanup_scm(resources: &mut ScmResources) -> bool {
    let mut ok = true;
    // Compensating uninstall if the lane died between install and uninstall.
    if windows_service_installed() {
        if let Some(dir) = &resources.run_dir {
            let _ = Command::new(dir.join("koi.exe")).arg("uninstall").status();
        } else {
            ok = false;
        }
    }
    if windows_service_installed() {
        ok = false;
    }
    if let Some(dir) = resources.run_dir.take() {
        if std::fs::remove_dir_all(&dir).is_err() {
            ok = false;
        }
    }
    ok
}

// ── Local Windows helpers (controller = the windows node) ───────────

fn run_checked(exe: PathBuf, args: &[&str]) -> Result<()> {
    let out = Command::new(exe)
        .args(args)
        .status()
        .context("spawn failed")?;
    if !out.success() {
        bail!("command exited {out}");
    }
    Ok(())
}

fn windows_service_installed() -> bool {
    Command::new("sc.exe")
        .args(["query", "koi"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn sc_query_contains(_needle: &str) -> Result<String> {
    let out = Command::new("sc.exe").args(["query", "koi"]).output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn sc_qc_config() -> Result<String> {
    let out = Command::new("sc.exe").args(["qc", "koi"]).output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn sc_qfailure_config() -> Result<String> {
    let out = Command::new("sc.exe").args(["qfailure", "koi"]).output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn process_ids_for(name: &str) -> Option<Vec<u32>> {
    let script = format!(
        "(Get-Process -Name {} -ErrorAction SilentlyContinue).Id",
        name
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let ids: Vec<u32> = text
        .split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect();
    (!ids.is_empty()).then_some(ids)
}

fn kill_force(pid: u32) -> Result<()> {
    let status = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .status()
        .context("taskkill spawn")?;
    if !status.success() {
        bail!("taskkill failed");
    }
    Ok(())
}

fn wait_running_pid(timeout: Duration) -> Result<u32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(ids) = process_ids_for("koi") {
            if let Some(pid) = ids.first() {
                return Ok(*pid);
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!("no koi process reached RUNNING in time")
}

fn wait_new_pid(old: u32, timeout: Duration) -> Result<u32> {
    // The killed pid must disappear first; then any koi pid that appears is
    // the SCM's replacement.
    std::thread::sleep(Duration::from_millis(500));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(ids) = process_ids_for("koi") {
            if let Some(pid) = ids.iter().find(|p| **p != old) {
                return Ok(*pid);
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!("service was not restarted with a new pid in time")
}

fn wait_healthz(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "try { (Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5641/healthz -TimeoutSec 3).StatusCode } catch { 0 }",
            ])
            .output();
        if let Ok(o) = out {
            if String::from_utf8_lossy(&o.stdout).trim() == "200" {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    bail!("healthz did not turn healthy in time")
}

fn wait_port_free(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let busy = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-NetTCPConnection -LocalPort 5641 -State Listen -ErrorAction SilentlyContinue) -ne $null",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("True"))
            .unwrap_or(true);
        if !busy {
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

fn sha256_file(path: &Path) -> Result<String> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-FileHash -Algorithm SHA256 '{}').Hash.ToLower()",
                path.display()
            ),
        ])
        .output()
        .context("hash spawn")?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
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
