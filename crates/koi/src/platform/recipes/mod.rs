//! Recipe-based installer machinery (ADR-036): one pipeline, per-init recipes.
//!
//! The binary is universal and the config substrate is universal; what varies
//! per machine is the init system, free ports, and verification tools. This
//! module owns the shared pipeline pieces (port planning, atomic staging,
//! config persistence, self-verification); the per-init recipes live in
//! sibling modules and inherit them.
//!
//! Evidence base: `docs/lab/os-install-facts.md` (2026-08-31 fleet).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

pub const STD_HTTP: u16 = 5641;
pub const STD_MTLS: u16 = 5642;
pub const STD_ACME: u16 = 5643;
/// Shift the contiguous port run by tens when the standard run is occupied (max scan).
const MAX_SHIFT: u32 = 100;

#[cfg(target_os = "linux")]
pub mod manual;
#[cfg(target_os = "linux")]
pub mod openrc;
#[cfg(target_os = "linux")]
pub mod systemd;
#[cfg(target_os = "linux")]
mod transaction;

// ── Init detection (capability-keyed, root-parameterized for tests) ─

/// The supervision capability a machine actually has. Distro names drift;
/// these don't (ADR-036).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    /// `/run/systemd/system` exists — the canonical systemd check.
    Systemd,
    /// `rc-update` is present — Alpine, Gentoo, Artix-openrc.
    Openrc,
    /// Nothing supported; the manual recipe takes over honestly.
    None,
}

#[cfg(target_os = "linux")]
pub fn detect_in(root: &Path) -> InitSystem {
    if root.join("run/systemd/system").exists() {
        return InitSystem::Systemd;
    }
    for dir in ["sbin", "usr/sbin", "bin", "usr/bin"] {
        if root.join(dir).join("rc-update").exists() {
            return InitSystem::Openrc;
        }
    }
    InitSystem::None
}

#[cfg(target_os = "linux")]
pub fn detect() -> InitSystem {
    detect_in(Path::new("/"))
}

/// Install for the detected init system. `--user` selects the user shape
/// where one exists; everywhere else the manual recipe says so and fails.
#[cfg(target_os = "linux")]
pub fn install(user: bool, operator: Option<&str>, data_dir: &Path) -> anyhow::Result<()> {
    if !user {
        super::check_root("install")?;
    }

    let init = detect();
    if !user {
        // System service recipes own durable transactions which must include
        // operator policy alongside the binary, registration, and config.
        match init {
            InitSystem::Systemd => return systemd::install_system(operator, data_dir),
            InitSystem::Openrc => return openrc::install_system(operator, data_dir),
            InitSystem::None => {}
        }
    }

    // Other recipes retain the in-process operator rollback introduced by
    // the cross-fleet installer hardening. They do not mutate systemd state.
    let policy = FileSnapshot::capture(&koi_config::local_access::policy_path(data_dir))?;
    super::record_unix_operator(user, operator, data_dir)?;
    let result = match (init, user) {
        (InitSystem::Systemd, false) => unreachable!("handled by the durable system transaction"),
        (InitSystem::Systemd, true) => systemd::install_user(),
        (InitSystem::Openrc, false) => {
            unreachable!("handled by the durable OpenRC transaction")
        }
        (InitSystem::Openrc, true) => manual::install_user(),
        (InitSystem::None, user) => {
            if user {
                manual::install_user()
            } else {
                manual::install_system()
            }
        }
    };
    if let Err(error) = result {
        policy.restore()?;
        return Err(error.context("installation failed; prior local-operator policy restored"));
    }
    Ok(())
}

/// Byte-and-mode snapshot for the small set of product-owned files changed by
/// an installer transaction. An absent file is a state too: rollback removes
/// a file that the failed attempt introduced.
#[cfg(any(unix, test))]
#[derive(Debug)]
pub(crate) struct FileSnapshot {
    path: PathBuf,
    body: Option<Vec<u8>>,
    permissions: Option<std::fs::Permissions>,
}

#[cfg(any(unix, test))]
impl FileSnapshot {
    pub(crate) fn capture(path: &Path) -> std::io::Result<Self> {
        match std::fs::read(path) {
            Ok(body) => Ok(Self {
                path: path.to_path_buf(),
                body: Some(body),
                permissions: Some(std::fs::metadata(path)?.permissions()),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_path_buf(),
                body: None,
                permissions: None,
            }),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn restore(&self) -> std::io::Result<()> {
        match &self.body {
            Some(body) => {
                if let Some(parent) = self.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&self.path, body)?;
                if let Some(permissions) = &self.permissions {
                    std::fs::set_permissions(&self.path, permissions.clone())?;
                }
                Ok(())
            }
            None => match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            },
        }
    }
}

/// Uninstall every koi service shape found on this machine (system unit,
/// user unit, OpenRC init script). Binary and operator config are preserved.
#[cfg(target_os = "linux")]
pub fn uninstall() -> anyhow::Result<()> {
    let mut any = false;
    if systemd::system_unit_path().exists() {
        systemd::uninstall_system()?;
        any = true;
    }
    if systemd::user_unit_path().exists() {
        systemd::uninstall_user()?;
        any = true;
    }
    if openrc::initd_path().exists() {
        openrc::uninstall_system()?;
        any = true;
    }
    if !any {
        println!("Koi is not installed as a service. Nothing to uninstall.");
    }
    Ok(())
}

// ── Port planning ───────────────────────────────────────────────────

/// The three configured daemon ports a machine will use, and why. Pond is the
/// derived fourth port (`http + 3`) and deliberately is not another config key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortPlan {
    pub http: u16,
    pub mtls: u16,
    pub acme: u16,
    pub shifted: bool,
}

impl PortPlan {
    pub fn standard() -> Self {
        Self {
            http: STD_HTTP,
            mtls: STD_MTLS,
            acme: STD_ACME,
            shifted: false,
        }
    }

    /// The configured ports shifted by `n` tens; `None` on u16 overflow.
    pub fn shift(n: u32) -> Option<Self> {
        // n is bounded by MAX_SHIFT (100) in planning; u32::MAX still
        // refuses cleanly via the multiply.
        let base = n.checked_mul(10)?;
        Some(Self {
            http: STD_HTTP + base as u16,
            mtls: STD_MTLS + base as u16,
            acme: STD_ACME + base as u16,
            shifted: n > 0,
        })
    }

    /// One line the operator reads: the complete run and, when shifted, why it matters.
    pub fn describe(&self) -> String {
        let pond = koi_serve::pond::port_for_http(self.http)
            .map(|port| port.to_string())
            .unwrap_or_else(|| "unavailable".to_string());
        if self.shifted {
            format!(
                "{}:{}:{}:{} (shifted — the standard {}:{}:{}:{} was occupied)",
                self.http,
                self.mtls,
                self.acme,
                pond,
                STD_HTTP,
                STD_MTLS,
                STD_ACME,
                koi_serve::pond::DEFAULT_POND_PORT
            )
        } else {
            format!(
                "{}:{}:{}:{} (standard)",
                self.http, self.mtls, self.acme, pond
            )
        }
    }
}

/// A port is usable if we could bind it ourselves right now.
pub fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
}

/// Plan the complete four-port run against a probe. Pure w.r.t. the probe so tests can pin it.
pub fn plan_ports_with(is_free: impl Fn(u16) -> bool) -> PortPlan {
    for n in 0..=MAX_SHIFT {
        if let Some(plan) = PortPlan::shift(n) {
            let configured_free = [plan.http, plan.mtls, plan.acme].into_iter().all(&is_free);
            let pond_free = koi_serve::pond::port_for_http(plan.http).is_some_and(&is_free);
            if configured_free && pond_free {
                return plan;
            }
        }
    }
    // Practically unreachable (a hundred shifted runs all occupied); the
    // honest fallback is the standard plan — the daemon's own bind will fail
    // loudly with a clear cause rather than a mystery port.
    PortPlan::standard()
}

/// Plan against this machine right now.
pub fn plan_ports() -> PortPlan {
    plan_ports_with(port_free)
}

// ── Existing machine decisions are honored, never re-planned ────────

/// Where a machine's ports may already be decided (ADR-036 §3): a systemd
/// drop-in (the pre-036 fleet mechanism) or the config file itself.
#[derive(Debug, Clone)]
pub enum Existing {
    /// Ports already decided on this machine — use them verbatim.
    Declared(PortPlan, String),
    /// A config file exists but declares no ports (keys may be appended).
    ConfigWithoutPorts(PathBuf),
    /// Nothing declared; plan freely.
    Nothing,
}

/// Parse `Environment=KOI_PORT=…` lines from a systemd drop-in directory.
#[cfg(target_os = "linux")]
fn ports_from_dropin_dir(dir: &Path) -> Option<(u16, u16, u16, String)> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut http = None;
    let mut mtls = None;
    let mut acme = None;
    let mut source = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let body = std::fs::read_to_string(&path).ok()?;
        for line in body.lines() {
            let Some(rest) = line.trim().strip_prefix("Environment=") else {
                continue;
            };
            let rest = rest.trim_matches('"');
            let Some((key, value)) = rest.split_once('=') else {
                continue;
            };
            match key.trim() {
                "KOI_PORT" => http = value.trim().parse().ok(),
                "KOI_MTLS_PORT" => mtls = value.trim().parse().ok(),
                "KOI_ACME_PORT" => acme = value.trim().parse().ok(),
                _ => {}
            }
        }
        if source.is_none() {
            source = Some(path.display().to_string());
        }
    }
    Some((http?, mtls?, acme?, source?))
}

/// Ports declared in a config file body, parsed by the substrate itself.
pub fn ports_from_config_body(path: &Path) -> Option<(u16, u16, u16)> {
    let body = std::fs::read_to_string(path).ok()?;
    let cfg = crate::config_file::parse(&body).ok()?;
    Some((cfg.port?, cfg.mtls_port?, cfg.acme_port?))
}

/// Detect existing port decisions for a Linux system install.
#[cfg(target_os = "linux")]
pub fn honor_existing_linux() -> Existing {
    let dropin = Path::new("/etc/systemd/system/koi.service.d");
    if dropin.exists() {
        if let Some((http, mtls, acme, source)) = ports_from_dropin_dir(dropin) {
            return Existing::Declared(
                PortPlan {
                    http,
                    mtls,
                    acme,
                    shifted: http != STD_HTTP,
                },
                format!("systemd drop-in {source}"),
            );
        }
    }
    let cfg = Path::new("/etc/koi/config.toml");
    if cfg.exists() {
        if let Some((http, mtls, acme)) = ports_from_config_body(cfg) {
            return Existing::Declared(
                PortPlan {
                    http,
                    mtls,
                    acme,
                    shifted: http != STD_HTTP,
                },
                format!("config {}", cfg.display()),
            );
        }
        return Existing::ConfigWithoutPorts(cfg.to_path_buf());
    }
    Existing::Nothing
}

/// Existing decisions for a user install: only the user's own config file.
pub fn honor_existing_config(config_path: &Path) -> Existing {
    if config_path.exists() {
        if let Some((http, mtls, acme)) = ports_from_config_body(config_path) {
            return Existing::Declared(
                PortPlan {
                    http,
                    mtls,
                    acme,
                    shifted: http != STD_HTTP,
                },
                format!("config {}", config_path.display()),
            );
        }
        return Existing::ConfigWithoutPorts(config_path.to_path_buf());
    }
    Existing::Nothing
}

// ── Persisting a shifted plan in the config substrate ───────────────

const INSTALLER_MARKER: &str =
    "# --- koi install: standard ports were occupied; this port run was chosen ---";

fn port_lines(plan: &PortPlan) -> String {
    format!(
        "port = {}\nmtls_port = {}\nacme_port = {}\n",
        plan.http, plan.mtls, plan.acme
    )
}

/// Create a fresh config carrying a shifted plan. Refuses to clobber an
/// existing file (the operator's config is never destroyed).
pub fn write_config_new(path: &Path, plan: &PortPlan) -> anyhow::Result<()> {
    if path.exists() {
        anyhow::bail!("{} already exists; not touching it", path.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = format!(
        "{}{}\n{}\n",
        crate::config_file::TEMPLATE,
        INSTALLER_MARKER,
        {
            let mut lines = port_lines(plan);
            // Keep the file's final newline tidy.
            if lines.ends_with('\n') {
                lines.pop();
            }
            lines
        }
    );
    std::fs::write(path, body)?;
    Ok(())
}

/// Append the configured ports under the installer marker. Existing keys are never
/// modified; the caller has already verified none are declared.
pub fn append_config_ports(path: &Path, plan: &PortPlan) -> anyhow::Result<()> {
    let mut body = std::fs::read_to_string(path)?;
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body.push('\n');
    body.push_str(INSTALLER_MARKER);
    body.push('\n');
    body.push_str(&port_lines(plan));
    std::fs::write(path, body)?;
    Ok(())
}

/// Persist a shifted plan per ADR-036: honor what exists, write only when
/// shifted. Returns a human line for the summary (empty when nothing needed).
#[cfg_attr(windows, allow(dead_code))] // only the non-transactional recipes use it
pub fn persist_plan(existing: &Existing, planned: &PortPlan, fresh_path: &Path) -> String {
    persist_plan_checked(existing, planned, fresh_path).unwrap_or_else(|error| match existing {
        Existing::ConfigWithoutPorts(path) => {
            format!(
                "warning: could not record ports in {}: {error}",
                path.display()
            )
        }
        Existing::Nothing => format!("warning: could not write {}: {error}", fresh_path.display()),
        Existing::Declared(_, _) => {
            format!("warning: could not preserve declared ports: {error}")
        }
    })
}

/// Persist a shifted plan and surface any write failure to transactional
/// installers. Older platform recipes retain [`persist_plan`]'s diagnostic
/// string until their own rollback boundaries are implemented.
pub fn persist_plan_checked(
    existing: &Existing,
    planned: &PortPlan,
    fresh_path: &Path,
) -> anyhow::Result<String> {
    if !planned.shifted {
        return Ok(String::new());
    }
    match existing {
        Existing::Declared(_, source) => Ok(format!("ports stay as declared by {source}")),
        Existing::ConfigWithoutPorts(path) => {
            append_config_ports(path, planned)?;
            Ok(format!("port run appended to {}", path.display()))
        }
        Existing::Nothing => {
            write_config_new(fresh_path, planned)?;
            Ok(format!("port run written to {}", fresh_path.display()))
        }
    }
}

// ── Atomic binary staging (the ETXTBSY fix) ─────────────────────────

/// Stage the running binary at `dst` without ETXTBSY: same file → nothing to
/// do; otherwise copy to `dst.new` and `rename(2)` into place (renaming over a
/// running executable is legal on Linux/macOS).
///
/// Returns `false` when source and destination were already the same file
/// (the natural upgrade invocation `sudo /usr/local/bin/koi install`).
#[cfg(any(unix, test))]
pub fn stage_binary(src: &Path, dst: &Path) -> anyhow::Result<bool> {
    let same = src
        .canonicalize()
        .ok()
        .zip(dst.canonicalize().ok())
        .is_some_and(|(s, d)| s == d);
    if same {
        set_executable(dst);
        return Ok(false);
    }
    let tmp = PathBuf::from(format!("{}.new", dst.display()));
    std::fs::copy(src, &tmp)?;
    set_executable(&tmp);
    if let Err(e) = std::fs::rename(&tmp, dst) {
        let _ = std::fs::remove_file(&tmp);
        // Windows: the running service holds the destination.
        anyhow::bail!(
            "could not replace {} ({e}); if the koi service is running from it, \
             stop it first and re-run",
            dst.display()
        );
    }
    Ok(true)
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(all(not(unix), test))]
fn set_executable(_path: &Path) {}

// ── Verification with koi's own client (no curl anywhere) ───────────

/// The Windows service's config file (the ADR-031 platform default the
/// service mode actually reads).
#[cfg(windows)]
pub fn windows_config_path() -> PathBuf {
    let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(pd).join("koi").join("config.toml")
}

/// Wait for `/healthz` on loopback by speaking HTTP directly. The installer
/// never assumes third-party tools exist (three fleet boxes have no curl).
pub fn healthz_wait(port: u16, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if healthz_once(port) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    false
}

fn healthz_once(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    const REQUEST: &str = "GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    if stream.write_all(REQUEST.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 128];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    head.starts_with("HTTP/1.") && head.contains("200")
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn file_snapshot_restores_contents_and_mode() {
        use std::os::unix::fs::PermissionsExt;

        let root = koi_common::test::ensure_data_dir("installer-snapshot");
        let path = root.join("installed");
        std::fs::write(&path, b"before").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let snapshot = FileSnapshot::capture(&path).unwrap();
        std::fs::write(&path, b"after").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        snapshot.restore().unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"before");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn absent_file_snapshot_removes_failed_install_output() {
        let root = koi_common::test::ensure_data_dir("installer-snapshot");
        let path = root.join("introduced");
        let _ = std::fs::remove_file(&path);
        let snapshot = FileSnapshot::capture(&path).unwrap();
        std::fs::write(&path, b"failed attempt").unwrap();

        snapshot.restore().unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn port_run_shifts_by_tens() {
        assert_eq!(PortPlan::shift(0), Some(PortPlan::standard()));
        let one = PortPlan::shift(1).unwrap();
        assert_eq!((one.http, one.mtls, one.acme), (5651, 5652, 5653));
        assert!(one.shifted);
        assert!(
            PortPlan::shift(u32::MAX).is_none(),
            "overflow refuses, not wraps"
        );
    }

    #[test]
    fn plan_skips_occupied_runs() {
        // The probe answers "is this port free"; 5641+5642 held by
        // another product → the first fully-free run wins.
        let held = |p: u16| p == STD_HTTP || p == STD_MTLS;
        let plan = plan_ports_with(|p| !held(p));
        assert_eq!((plan.http, plan.mtls, plan.acme), (5651, 5652, 5653));
        // Everything from the standard run through two shifts occupied.
        let wide_held = |p: u16| (STD_HTTP..=STD_ACME + 20).contains(&p);
        assert_eq!(plan_ports_with(|p| !wide_held(p)).http, STD_ACME + 30 - 2);
    }

    #[test]
    fn plan_skips_a_run_when_only_pond_is_occupied() {
        let plan = plan_ports_with(|port| port != koi_serve::pond::DEFAULT_POND_PORT);
        assert_eq!((plan.http, plan.mtls, plan.acme), (5651, 5652, 5653));
        assert!(plan.describe().starts_with("5651:5652:5653:5654"));
    }

    #[test]
    fn plan_standard_when_free() {
        let plan = plan_ports_with(|_| true);
        assert_eq!(plan, PortPlan::standard());
        assert!(plan.describe().contains("standard"));
        assert!(PortPlan::shift(1).unwrap().describe().contains("shifted"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dropin_parsing_reads_port_env() {
        let dir = koi_common::test::ensure_data_dir("recipes-tests");
        let dropin = dir.join("koi.service.d");
        std::fs::create_dir_all(&dropin).unwrap();
        std::fs::write(
            dropin.join("ports.conf"),
            "[Service]\nEnvironment=KOI_PORT=21441\nEnvironment=\"KOI_MTLS_PORT=21442\"\nEnvironment=KOI_ACME_PORT=21443\n",
        )
        .unwrap();
        let (http, mtls, acme, source) =
            ports_from_dropin_dir(&dropin).expect("drop-in ports parse");
        assert_eq!((http, mtls, acme), (21441, 21442, 21443));
        assert!(source.ends_with("ports.conf"));
        let _ = std::fs::remove_dir_all(&dropin);
    }

    #[test]
    fn fresh_config_parses_and_carries_the_trio() {
        let dir = koi_common::test::ensure_data_dir("recipes-tests");
        let path = dir.join("fresh-config.toml");
        let _ = std::fs::remove_file(&path);
        let plan = PortPlan::shift(1).unwrap();
        write_config_new(&path, &plan).unwrap();
        let parsed = crate::config_file::load(&path).unwrap().expect("parses");
        assert_eq!(parsed.port, Some(5651));
        assert_eq!(parsed.mtls_port, Some(5652));
        assert_eq!(parsed.acme_port, Some(5653));
        // Second write refuses to clobber.
        assert!(write_config_new(&path, &plan).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_only_adds_keys_it_does_not_own() {
        let dir = koi_common::test::ensure_data_dir("recipes-tests");
        let path = dir.join("append-config.toml");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "version = 1\nhttp_bind = \"loopback\"\n").unwrap();
        append_config_ports(&path, &PortPlan::shift(1).unwrap()).unwrap();
        let parsed = crate::config_file::load(&path)
            .unwrap()
            .expect("parses after append");
        assert_eq!(parsed.port, Some(5651));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("http_bind = \"loopback\""),
            "operator keys untouched"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn staging_same_file_is_a_no_op() {
        let dir = koi_common::test::ensure_data_dir("recipes-tests");
        let bin = dir.join("staged-koi");
        std::fs::write(&bin, b"#!/bin/sh\ntrue\n").unwrap();
        set_executable(&bin);
        // Source == destination: no copy, no error, no .new litter.
        assert!(!stage_binary(&bin, &bin).unwrap());
        assert!(!dir.join(format!("{}.new", bin.display())).exists());
        let _ = std::fs::remove_file(&bin);
    }

    #[test]
    fn staging_replaces_atomically() {
        let dir = koi_common::test::ensure_data_dir("recipes-tests");
        let src = dir.join("src-koi");
        let dst = dir.join("dst-koi");
        std::fs::write(&src, b"new-bytes").unwrap();
        std::fs::write(&dst, b"old-bytes").unwrap();
        assert!(stage_binary(&src, &dst).unwrap());
        assert_eq!(std::fs::read(&dst).unwrap(), b"new-bytes");
        assert!(!dir.join(format!("{}.new", dst.display())).exists());
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&dst);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn init_detection_is_capability_keyed() {
        // `ensure_data_dir` is process-wide: other parallel tests use the same
        // root. Keep this test's destructive cleanup inside an owned child.
        let dir = koi_common::test::ensure_data_dir("recipes-tests").join("recipes-detect");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Nothing → manual.
        assert_eq!(detect_in(&dir), InitSystem::None);
        // The canonical systemd marker wins over everything.
        std::fs::create_dir_all(dir.join("run/systemd/system")).unwrap();
        std::fs::create_dir_all(dir.join("sbin")).unwrap();
        std::fs::write(dir.join("sbin/rc-update"), b"#!/bin/sh\n").unwrap();
        assert_eq!(detect_in(&dir), InitSystem::Systemd);
        std::fs::remove_dir_all(dir.join("run/systemd")).unwrap();
        // rc-update alone → OpenRC, in any of the usual homes.
        assert_eq!(detect_in(&dir), InitSystem::Openrc);
        std::fs::remove_file(dir.join("sbin/rc-update")).unwrap();
        std::fs::create_dir_all(dir.join("usr/sbin")).unwrap();
        std::fs::write(dir.join("usr/sbin/rc-update"), b"#!/bin/sh\n").unwrap();
        assert_eq!(detect_in(&dir), InitSystem::Openrc);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
