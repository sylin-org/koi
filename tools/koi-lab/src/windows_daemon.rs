//! Owner of a staged Windows lab daemon: staging, plain paths, env, flags,
//! log file, and kill-by-exe.
//!
//! Why this exists: every Windows lane re-assembled staging paths, environment
//! variables, and CLI flags by hand. The staging root arrives canonicalized
//! (`\\?\F:\...`), and handing that prefix to child processes or external
//! tools has produced two silent physical-run failures (netsh RL-14, the W8
//! webhooks manifest). One builder strips the prefix at ONE choke point and
//! owns everything downstream of staging.
//!
//! Doctrine: on failure, [`WindowsLabDaemon::evidence`] is captured BEFORE
//! [`Self::teardown`] deletes the run directory.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::model::LabPorts;

/// Capabilities a lane can enable on the staged daemon. Everything not listed
/// stays disabled (`--no-*`), keeping the daemon's surface exactly the lane's
/// claim.
#[derive(Default)]
pub struct WindowsDaemonCapabilities {
    pub mdns_announce: bool,
    pub dns_public_port: Option<u16>,
    pub webhooks_manifest: Option<PathBuf>,
}

pub struct WindowsLabDaemon {
    /// Plain (prefix-stripped) staging root — safe to hand to child processes
    /// and external tools.
    root_plain: PathBuf,
    exe: PathBuf,
    ports: LabPorts,
    child: Option<Child>,
}

impl WindowsLabDaemon {
    /// Stage the run-owned executable and own its lifecycle. Fails if the
    /// target directory already exists (fresh-start semantics, unchanged).
    pub fn stage(
        lab: &crate::lab::Lab,
        run_id: &crate::model::RunId,
        ports: LabPorts,
    ) -> Result<Self> {
        let root = lab.prepare_windows_member_dir(run_id)?;
        // Strip the \\?\ canonical prefix at the single choke point: child
        // processes and external tools get plain paths only.
        let root_plain = PathBuf::from(crate::lab::netsh_program_path(&root));
        let exe = root_plain.join("koi.exe");
        Ok(Self {
            root_plain,
            exe,
            ports,
            child: None,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root_plain
    }

    pub fn exe(&self) -> &Path {
        &self.exe
    }

    pub fn http_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.http)
    }

    /// Spawn the daemon with the requested capabilities and wait for healthz.
    /// Returns the capability summary the lane can embed in evidence.
    pub fn spawn(&mut self, capabilities: &WindowsDaemonCapabilities) -> Result<String> {
        if self.child.is_some() {
            bail!("daemon already running");
        }
        let mut command = Command::new(&self.exe);
        command
            .env("KOI_DATA_DIR", self.root_plain.join("data"))
            .env("ProgramData", self.root_plain.join("program-data"))
            .env("KOI_NO_CREDENTIAL_STORE", "1")
            .env("KOI_DNS_ZONE", "internal")
            .env("KOI_LOG", "warn")
            .args(["--daemon", "--port"])
            .arg(self.ports.http.to_string())
            .args(["--http-bind", "0.0.0.0", "--mtls-port"])
            .arg(self.ports.mtls.to_string());

        match capabilities.dns_public_port {
            Some(port) => command.args(["--dns-port", &port.to_string(), "--dns-public"]),
            None => command.arg("--no-dns"),
        };
        if capabilities.mdns_announce {
            command.arg("--announce-http");
        } else {
            command.arg("--no-mdns");
        }
        match &capabilities.webhooks_manifest {
            Some(manifest) => {
                command.arg(format!("--webhooks {}", manifest.display()));
            }
            None => {
                command.arg("--no-webhooks");
            }
        }
        command.args([
            "--no-ipc",
            "--no-udp",
            "--no-runtime",
            "--no-acme",
            "--no-mcp-http",
        ]);

        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root_plain.join("daemon.log"))
            .context("open the staged daemon log")?;
        let stderr = log_file
            .try_clone()
            .context("clone the daemon log handle")?;
        command
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr));

        let child = command.spawn().context("spawn the staged Windows daemon")?;
        self.child = Some(child);

        crate::lab::wait_for_http(&format!("{}/healthz", self.http_url()))
            .context("staged Windows daemon did not become healthy")?;
        Ok(self.capability_summary(capabilities))
    }

    /// Kill the staged daemon by exact executable identity.
    pub fn stop(&mut self) -> Result<()> {
        if let Some(child) = self.child.take() {
            let mut child = child;
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            child.kill().context("kill the staged Windows daemon")?;
            child.wait().context("reap the staged Windows daemon")?;
            return Ok(());
        }
        // No tracked child (e.g. the caller restarted the process out-of-band):
        // fall back to exact-exe identification.
        if self.exe.is_file() {
            let process_ids = crate::lab::windows_process_ids_for_executable(&self.exe)?;
            for pid in process_ids {
                crate::lab::stop_exact_windows_process(pid, &self.exe)?;
            }
        }
        Ok(())
    }

    /// Grace period after stop: Windows can hold sockets briefly post-kill.
    pub fn await_quiescence(&self) {
        std::thread::sleep(Duration::from_millis(500));
    }

    /// Failure evidence from the daemon's own log. MUST be captured before
    /// teardown deletes the run directory.
    pub fn evidence(&self) -> String {
        let log = self.root_plain.join("daemon.log");
        match std::fs::read_to_string(&log) {
            Ok(content) => {
                let total = content.lines().count();
                let tail: Vec<&str> = content.lines().rev().take(25).collect();
                let mut tail: Vec<&str> = tail;
                tail.reverse();
                format!(
                    "daemon.log tail ({total} total lines): {}",
                    tail.join(" ‖ ")
                )
            }
            Err(e) => format!("daemon.log unavailable: {e}"),
        }
    }

    /// Remove everything staging created. Only call after evidence capture.
    pub fn teardown(self, lab: &crate::lab::Lab, run_id: &crate::model::RunId) -> Result<()> {
        self.await_quiescence();
        lab.remove_windows_member_dir(run_id, &lab.windows_member_dir(run_id))
    }

    fn capability_summary(&self, capabilities: &WindowsDaemonCapabilities) -> String {
        let mut parts = vec![format!("http:{}", self.ports.http)];
        if let Some(port) = capabilities.dns_public_port {
            parts.push(format!("dns-public:{port}"));
        }
        if capabilities.mdns_announce {
            parts.push("mdns-announce".to_owned());
        }
        if capabilities.webhooks_manifest.is_some() {
            parts.push("webhooks".to_owned());
        }
        parts.join(", ")
    }
}
