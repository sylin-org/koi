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
#[cfg(unix)]
pub(crate) mod transaction;

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
pub fn detect_in(root: &Path) -> anyhow::Result<InitSystem> {
    if directory_exists(&root.join("run/systemd/system"))? {
        return Ok(InitSystem::Systemd);
    }
    for dir in ["sbin", "usr/sbin", "bin", "usr/bin"] {
        if file_target_exists(&root.join(dir).join("rc-update"))? {
            return Ok(InitSystem::Openrc);
        }
    }
    Ok(InitSystem::None)
}

#[cfg(target_os = "linux")]
pub fn detect() -> anyhow::Result<InitSystem> {
    detect_in(Path::new("/"))
}

/// Install for the detected init system. `--user` selects the user shape
/// where one exists; everywhere else the manual recipe says so and fails.
#[cfg(target_os = "linux")]
pub fn install(user: bool, operator: Option<&str>, data_dir: &Path) -> anyhow::Result<()> {
    if !user {
        super::check_root("install")?;
    }
    let _install_lock = if user {
        super::install_lock::InstallLock::acquire_user()?
    } else {
        super::install_lock::InstallLock::acquire_system()?
    };

    let init = detect()?;
    refuse_parallel_registration(init, user, data_dir)?;
    // Native service recipes own their complete durable transaction, including
    // operator policy. The manual fallback retains the smaller local snapshot.
    match (init, user) {
        (InitSystem::Systemd, false) => return systemd::install_system(operator, data_dir),
        (InitSystem::Systemd, true) => return systemd::install_user(operator, data_dir),
        (InitSystem::Openrc, false) => return openrc::install_system(operator, data_dir),
        _ => {}
    }

    // Other recipes retain the in-process operator rollback introduced by
    // the cross-fleet installer hardening. They do not mutate systemd state.
    let policy = FileSnapshot::capture(&koi_config::local_access::policy_path(data_dir))?;
    super::record_unix_operator(user, operator, data_dir)?;
    let result = match (init, user) {
        (InitSystem::Systemd, _) => unreachable!("handled by the durable systemd transaction"),
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

#[cfg(target_os = "linux")]
fn refuse_parallel_registration(
    selected: InitSystem,
    user: bool,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let systemd_system = regular_file_exists(&systemd::system_unit_path())?;
    let systemd_user = regular_file_exists(&systemd::user_unit_path()?)?;
    let openrc = regular_file_exists(&openrc::initd_path())?;
    let selected_systemd_system = selected == InitSystem::Systemd && !user;
    let selected_systemd_user = selected == InitSystem::Systemd && user;
    let selected_openrc = selected == InitSystem::Openrc && !user;

    let conflicts = [
        (systemd_system && !selected_systemd_system, "systemd system"),
        (systemd_user && !selected_systemd_user, "systemd user"),
        (openrc && !selected_openrc, "OpenRC"),
    ]
    .into_iter()
    .filter_map(|(present, name)| present.then_some(name))
    .collect::<Vec<_>>();
    if !conflicts.is_empty() {
        anyhow::bail!(
            "refusing to create a parallel Koi service while {} registration exists; uninstall it first",
            conflicts.join(" and ")
        );
    }

    let foreign_recovery = [
        (
            systemd::transaction_pending(data_dir, false)? && !selected_systemd_system,
            "systemd system",
        ),
        (
            systemd::transaction_pending(data_dir, true)? && !selected_systemd_user,
            "systemd user",
        ),
        (
            openrc::transaction_pending(data_dir)? && !selected_openrc,
            "OpenRC",
        ),
    ]
    .into_iter()
    .filter_map(|(pending, name)| pending.then_some(name))
    .collect::<Vec<_>>();
    if !foreign_recovery.is_empty() {
        anyhow::bail!(
            "an unfinished {} service transaction must be recovered with its native manager before installing",
            foreign_recovery.join(" and ")
        );
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
    #[cfg(unix)]
    permissions: Option<std::fs::Permissions>,
}

#[cfg(any(unix, test))]
impl FileSnapshot {
    pub(crate) fn capture(path: &Path) -> std::io::Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_file() => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("expected a regular file at {}", path.display()),
            )),
            Ok(_metadata) => Ok(Self {
                path: path.to_path_buf(),
                body: Some(std::fs::read(path)?),
                #[cfg(unix)]
                permissions: Some(_metadata.permissions()),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: path.to_path_buf(),
                body: None,
                #[cfg(unix)]
                permissions: None,
            }),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn restore(&self) -> std::io::Result<()> {
        match &self.body {
            Some(body) => {
                #[cfg(unix)]
                let options = {
                    use std::os::unix::fs::PermissionsExt;
                    self.permissions.as_ref().map_or_else(
                        koi_common::persist::AtomicWriteOptions::new,
                        |permissions| {
                            koi_common::persist::AtomicWriteOptions::new()
                                .with_unix_mode(permissions.mode())
                        },
                    )
                };
                #[cfg(not(unix))]
                let options = koi_common::persist::AtomicWriteOptions::new();
                let outcome = koi_common::persist::write_bytes_atomic_with_options(
                    &self.path, body, options,
                )?;
                koi_common::persist::require_durable(
                    outcome,
                    "restoring the install-time operator policy",
                )
            }
            None => {
                let outcome = koi_common::persist::remove_file_durable(&self.path)?;
                koi_common::persist::require_durable(
                    outcome,
                    "removing an install-time operator policy created by a failed install",
                )
            }
        }
    }
}

/// Uninstall every koi service shape found on this machine (system unit,
/// user unit, OpenRC init script). Binary and operator config are preserved.
#[cfg(target_os = "linux")]
pub fn uninstall(data_dir: &Path) -> anyhow::Result<()> {
    let system_unit = regular_file_exists(&systemd::system_unit_path())?
        || systemd::transaction_pending(data_dir, false)?;
    let user_unit = regular_file_exists(&systemd::user_unit_path()?)?
        || systemd::transaction_pending(data_dir, true)?;
    let openrc_unit =
        regular_file_exists(&openrc::initd_path())? || openrc::transaction_pending(data_dir)?;
    let _system_lock = if system_unit || openrc_unit {
        super::check_root("uninstall")?;
        Some(super::install_lock::InstallLock::acquire_system()?)
    } else {
        None
    };
    let _user_lock = if user_unit {
        Some(super::install_lock::InstallLock::acquire_user()?)
    } else {
        None
    };
    let mut any = false;
    if system_unit {
        systemd::uninstall_system(data_dir)?;
        any = true;
    }
    if user_unit {
        systemd::uninstall_user(data_dir)?;
        any = true;
    }
    if openrc_unit {
        openrc::uninstall_system(data_dir)?;
        any = true;
    }
    if !any {
        println!("Koi is not installed as a service. Nothing to uninstall.");
    }
    Ok(())
}

/// Observe a product-owned regular-file target without confusing an I/O
/// failure, directory, or special file with absence.
pub(crate) fn regular_file_exists(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => anyhow::bail!("expected a regular file at {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Observe an executable/tool path while allowing the platform's ordinary
/// symlink layout. A dangling or unreadable symlink remains uncertainty.
#[cfg(target_os = "linux")]
pub(crate) fn file_target_exists(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => anyhow::bail!("expected a file target at {}", path.display()),
            Err(error) => Err(error.into()),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn directory_exists(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => anyhow::bail!("expected a directory at {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
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

/// Whether this install is creating a deployment or replacing the recipe's
/// existing Koi service registration. The recipe owns that platform fact;
/// shared planning owns what it means for endpoint selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallDisposition {
    Fresh,
    ReplacingOwned,
}

/// Select the effective port run for an install without mistaking the Koi
/// deployment being replaced for a foreign listener.
///
/// A declared machine decision always wins. An older Koi deployment with no
/// declaration is, by definition, using the standard run and keeps it even
/// while its process is still listening. Only a fresh deployment probes the
/// machine and shifts around genuine incumbents.
pub fn plan_install_ports_with(
    existing: &Existing,
    disposition: InstallDisposition,
    is_free: impl Fn(u16) -> bool,
) -> PortPlan {
    match existing {
        Existing::Declared(plan, _) => *plan,
        Existing::ConfigWithoutPorts(_) | Existing::Nothing
            if disposition == InstallDisposition::ReplacingOwned =>
        {
            PortPlan::standard()
        }
        Existing::ConfigWithoutPorts(_) | Existing::Nothing => plan_ports_with(is_free),
    }
}

/// Select the effective install plan against this machine right now.
pub fn plan_install_ports(existing: &Existing, disposition: InstallDisposition) -> PortPlan {
    plan_install_ports_with(existing, disposition, port_free)
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
fn ports_from_dropin_dir(dir: &Path) -> anyhow::Result<Option<(u16, u16, u16, String)>> {
    let mut paths = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    let mut http = None;
    let mut mtls = None;
    let mut acme = None;
    let mut sources = Vec::new();
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("conf") {
            continue;
        }
        if !regular_file_exists(&path)? {
            continue;
        }
        let body = std::fs::read_to_string(&path)?;
        for line in body.lines() {
            let Some(rest) = line.trim().strip_prefix("Environment=") else {
                continue;
            };
            let rest = rest.trim_matches('"');
            let Some((key, value)) = rest.split_once('=') else {
                continue;
            };
            let parsed = || {
                value.trim().parse::<u16>().map_err(|error| {
                    anyhow::anyhow!("invalid {key} port in {}: {error}", path.display())
                })
            };
            match key.trim() {
                "KOI_PORT" => http = Some(parsed()?),
                "KOI_MTLS_PORT" => mtls = Some(parsed()?),
                "KOI_ACME_PORT" => acme = Some(parsed()?),
                _ => {}
            }
        }
        if http.is_some() || mtls.is_some() || acme.is_some() {
            sources.push(path.display().to_string());
        }
    }
    match (http, mtls, acme) {
        (None, None, None) => Ok(None),
        (Some(http), Some(mtls), Some(acme)) => Ok(Some((http, mtls, acme, sources.join(", ")))),
        _ => anyhow::bail!(
            "incomplete Koi port declaration in systemd drop-ins at {}",
            dir.display()
        ),
    }
}

/// Ports declared in a config file body, parsed by the substrate itself.
pub fn ports_from_config_body(path: &Path) -> anyhow::Result<Option<(u16, u16, u16)>> {
    let body = std::fs::read_to_string(path)?;
    ports_from_config_text(path, &body)
}

fn ports_from_config_text(path: &Path, body: &str) -> anyhow::Result<Option<(u16, u16, u16)>> {
    let cfg = crate::config_file::parse(body).map_err(anyhow::Error::msg)?;
    match (cfg.port, cfg.mtls_port, cfg.acme_port) {
        (None, None, None) => Ok(None),
        (Some(http), Some(mtls), Some(acme)) => Ok(Some((http, mtls, acme))),
        _ => anyhow::bail!(
            "{} must declare port, mtls_port, and acme_port together",
            path.display()
        ),
    }
}

/// Detect existing port decisions for a Linux system install.
#[cfg(target_os = "linux")]
pub fn honor_existing_linux() -> anyhow::Result<Existing> {
    let dropin = Path::new("/etc/systemd/system/koi.service.d");
    if directory_exists(dropin)? {
        if let Some((http, mtls, acme, source)) = ports_from_dropin_dir(dropin)? {
            return Ok(Existing::Declared(
                PortPlan {
                    http,
                    mtls,
                    acme,
                    shifted: http != STD_HTTP,
                },
                format!("systemd drop-in {source}"),
            ));
        }
    }
    let cfg = Path::new("/etc/koi/config.toml");
    if regular_file_exists(cfg)? {
        if let Some((http, mtls, acme)) = ports_from_config_body(cfg)? {
            return Ok(Existing::Declared(
                PortPlan {
                    http,
                    mtls,
                    acme,
                    shifted: http != STD_HTTP,
                },
                format!("config {}", cfg.display()),
            ));
        }
        return Ok(Existing::ConfigWithoutPorts(cfg.to_path_buf()));
    }
    Ok(Existing::Nothing)
}

/// Existing decisions for a user install: only the user's own config file.
pub fn honor_existing_config(config_path: &Path) -> anyhow::Result<Existing> {
    if regular_file_exists(config_path)? {
        if let Some((http, mtls, acme)) = ports_from_config_body(config_path)? {
            return Ok(Existing::Declared(
                PortPlan {
                    http,
                    mtls,
                    acme,
                    shifted: http != STD_HTTP,
                },
                format!("config {}", config_path.display()),
            ));
        }
        return Ok(Existing::ConfigWithoutPorts(config_path.to_path_buf()));
    }
    Ok(Existing::Nothing)
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
    let outcome = koi_common::persist::write_bytes_atomic_new_with_options(
        path,
        body.as_bytes(),
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o644),
    )
    .map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!("{} already exists; not touching it", path.display())
        } else {
            anyhow::Error::from(error)
        }
    })?;
    koi_common::persist::require_durable(outcome, "creating the installer config")?;
    Ok(())
}

/// Append the configured ports under the installer marker. Existing keys are never
/// modified; the caller has already verified none are declared.
pub fn append_config_ports(path: &Path, plan: &PortPlan) -> anyhow::Result<()> {
    #[cfg(unix)]
    let (options, owner) = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            anyhow::bail!("expected a regular config file at {}", path.display());
        }
        (
            koi_common::persist::AtomicWriteOptions::new()
                .with_unix_mode(metadata.permissions().mode()),
            (metadata.uid(), metadata.gid()),
        )
    };
    #[cfg(not(unix))]
    let options = koi_common::persist::AtomicWriteOptions::new();
    let mut body = std::fs::read_to_string(path)?;
    if ports_from_config_text(path, &body)?.is_some() {
        anyhow::bail!(
            "{} changed after install planning and now declares ports; retry so that decision is honored",
            path.display()
        );
    }
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body.push('\n');
    body.push_str(INSTALLER_MARKER);
    body.push('\n');
    body.push_str(&port_lines(plan));
    #[cfg(unix)]
    let outcome = koi_common::persist::write_bytes_atomic_with_options_and_prepare_stage(
        path,
        body.as_bytes(),
        options,
        |stage| chown_unix(stage, owner.0, owner.1),
    )?;
    #[cfg(not(unix))]
    let outcome =
        koi_common::persist::write_bytes_atomic_with_options(path, body.as_bytes(), options)?;
    koi_common::persist::require_durable(outcome, "updating the installer config")?;
    Ok(())
}

#[cfg(unix)]
fn chown_unix(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Persist a shifted plan and surface every write failure to the owning
/// service-manager transaction.
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
        set_executable(dst)?;
        return Ok(false);
    }
    let (outcome, _) = koi_common::persist::copy_file_atomic_with_options(
        src,
        dst,
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o755),
    )?;
    koi_common::persist::require_durable(outcome, "installing the Koi executable")?;
    Ok(true)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(all(not(unix), test))]
fn set_executable(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

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
    if stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .is_err()
    {
        return false;
    }
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

    #[test]
    fn install_plan_preserves_declared_ports_without_probing() {
        let declared = PortPlan::shift(3).unwrap();
        let existing = Existing::Declared(declared, "operator config".to_string());
        let probes = std::cell::Cell::new(0);

        let plan = plan_install_ports_with(&existing, InstallDisposition::Fresh, |_| {
            probes.set(probes.get() + 1);
            false
        });

        assert_eq!(plan, declared);
        assert_eq!(probes.get(), 0);
    }

    #[test]
    fn install_plan_preserves_an_owned_legacy_standard_run() {
        for existing in [
            Existing::Nothing,
            Existing::ConfigWithoutPorts(PathBuf::from("legacy-config.toml")),
        ] {
            let probes = std::cell::Cell::new(0);
            let plan =
                plan_install_ports_with(&existing, InstallDisposition::ReplacingOwned, |_| {
                    probes.set(probes.get() + 1);
                    false
                });

            assert_eq!(plan, PortPlan::standard());
            assert_eq!(probes.get(), 0, "the replaced Koi listener is not probed");
        }
    }

    #[test]
    fn fresh_install_shifts_around_a_foreign_listener() {
        let plan = plan_install_ports_with(&Existing::Nothing, InstallDisposition::Fresh, |port| {
            ![
                STD_HTTP,
                STD_MTLS,
                STD_ACME,
                koi_serve::pond::DEFAULT_POND_PORT,
            ]
            .contains(&port)
        });

        assert_eq!(plan, PortPlan::shift(1).unwrap());
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
        let (http, mtls, acme, source) = ports_from_dropin_dir(&dropin)
            .expect("drop-in inspection")
            .expect("drop-in ports parse");
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
    fn malformed_or_partial_config_is_not_treated_as_no_decision() {
        let dir = koi_common::test::ensure_data_dir("recipes-tests");
        let malformed = dir.join("malformed-installer-config.toml");
        let partial = dir.join("partial-installer-config.toml");
        std::fs::write(&malformed, "not = [valid").unwrap();
        std::fs::write(&partial, "version = 1\nport = 5641\n").unwrap();
        assert!(honor_existing_config(&malformed).is_err());
        assert!(honor_existing_config(&partial).is_err());
        let _ = std::fs::remove_file(malformed);
        let _ = std::fs::remove_file(partial);
    }

    #[test]
    fn non_file_config_target_is_not_absence() {
        let dir =
            koi_common::test::ensure_data_dir("recipes-tests").join("installer-config-directory");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(honor_existing_config(&dir).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn racing_fresh_config_creators_never_clobber() {
        let dir = std::env::temp_dir().join(format!(
            "koi-config-create-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = std::sync::Arc::new(dir.join("config.toml"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers = (1..=8)
            .map(|shift| {
                let path = std::sync::Arc::clone(&path);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_config_new(&path, &PortPlan::shift(shift).unwrap())
                })
            })
            .collect::<Vec<_>>();
        let successes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(successes, 1);
        crate::config_file::load(&path)
            .unwrap()
            .expect("one complete config is visible");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(dir);
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
        let error = append_config_ports(&path, &PortPlan::shift(2).unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("changed after install planning"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn staging_same_file_is_a_no_op() {
        let dir = koi_common::test::ensure_data_dir("recipes-tests");
        let bin = dir.join("staged-koi");
        std::fs::write(&bin, b"#!/bin/sh\ntrue\n").unwrap();
        set_executable(&bin).unwrap();
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
        assert_eq!(detect_in(&dir).unwrap(), InitSystem::None);
        // The canonical systemd marker wins over everything.
        std::fs::create_dir_all(dir.join("run/systemd/system")).unwrap();
        std::fs::create_dir_all(dir.join("sbin")).unwrap();
        std::fs::write(dir.join("sbin/rc-update"), b"#!/bin/sh\n").unwrap();
        assert_eq!(detect_in(&dir).unwrap(), InitSystem::Systemd);
        std::fs::remove_dir_all(dir.join("run/systemd")).unwrap();
        // rc-update alone → OpenRC, in any of the usual homes.
        assert_eq!(detect_in(&dir).unwrap(), InitSystem::Openrc);
        std::fs::remove_file(dir.join("sbin/rc-update")).unwrap();
        std::fs::create_dir_all(dir.join("usr/sbin")).unwrap();
        std::fs::write(dir.join("usr/sbin/rc-update"), b"#!/bin/sh\n").unwrap();
        assert_eq!(detect_in(&dir).unwrap(), InitSystem::Openrc);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
