//! systemd recipe (ADR-036): system and `--user` installs.
//!
//! Covers Debian/Ubuntu/Fedora/Arch and their derivatives — every systemd
//! machine on the fleet. Port decisions are honored from drop-ins or
//! `config.toml`; a shifted plan persists in the config substrate.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use super::transaction::{staged_restore_path, FileSnapshot};
use super::{
    append_config_ports, healthz_wait, honor_existing_config, honor_existing_linux,
    persist_plan_checked, plan_install_ports, regular_file_exists, write_config_new, Existing,
    InstallDisposition,
};

const SERVICE_NAME: &str = "koi";
const TRANSACTION_VERSION: u16 = 3;
const TRANSACTION_FILENAME: &str = "systemd-install-transaction.json";
const USER_TRANSACTION_FILENAME: &str = "systemd-user-install-transaction.json";
const UNIT_TEMPLATE: &str = include_str!("templates/koi.service");
const USER_UNIT_TEMPLATE: &str = include_str!("templates/koi-user.service");
const PRIOR_LINGER_MARKER: &str = "# X-Koi-Prior-Linger=";

pub fn system_unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/koi.service")
}

pub fn user_unit_path() -> anyhow::Result<PathBuf> {
    Ok(user_config_root()?.join("systemd/user/koi.service"))
}

pub fn install_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/koi")
}

fn render(template: &str, bin: &std::path::Path) -> String {
    // LF regardless of how git checked the template out: a CRLF shebang makes
    // the kernel hunt an interpreter named with a carriage return (measured on
    // Alpine: "Failed executing /etc/init.d/koi: No such file or directory").
    template
        .replace("\r\n", "\n")
        .replace("{{BIN}}", &bin.display().to_string())
}

fn render_user_unit(bin: &Path, prior_linger: bool) -> String {
    let mut unit = render(USER_UNIT_TEMPLATE, bin);
    if !unit.ends_with('\n') {
        unit.push('\n');
    }
    unit.push_str(PRIOR_LINGER_MARKER);
    unit.push_str(if prior_linger { "yes\n" } else { "no\n" });
    unit
}

fn prior_linger_from_unit(path: &Path) -> anyhow::Result<Option<bool>> {
    if !regular_file_exists(path)? {
        return Ok(None);
    }
    let body = std::fs::read_to_string(path)?;
    match body
        .lines()
        .find_map(|line| line.trim().strip_prefix(PRIOR_LINGER_MARKER))
    {
        Some("yes") => Ok(Some(true)),
        Some("no") => Ok(Some(false)),
        Some(value) => anyhow::bail!(
            "{} has invalid prior-linger marker '{value}'",
            path.display()
        ),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Preparing,
    Armed,
    Settled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstallManifest {
    version: u16,
    phase: TransactionPhase,
    was_active: bool,
    was_enabled: bool,
    http_port: u16,
    files: Vec<FileSnapshot>,
    temporary_paths: Vec<PathBuf>,
    #[serde(default)]
    user: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    was_linger: Option<bool>,
}

struct InstallTransaction {
    path: PathBuf,
    manifest: InstallManifest,
}

impl InstallTransaction {
    fn begin(
        data_dir: &Path,
        user: bool,
        was_active: bool,
        was_enabled: bool,
        was_linger: Option<bool>,
        http_port: u16,
        paths: Vec<PathBuf>,
    ) -> anyhow::Result<Self> {
        let path = transaction_path(data_dir, user);
        recover_interrupted(&path)?;

        let files = paths
            .into_iter()
            .map(FileSnapshot::inspect)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (scope_bin, scope_unit) = if user {
            (user_bin_path()?, user_unit_path()?)
        } else {
            (install_bin_path(), system_unit_path())
        };
        let temporary_paths = files
            .iter()
            .flat_map(|file| [staged_restore_path(&file.path)])
            .chain([
                staged_binary_path(&scope_bin),
                staged_unit_path(&scope_unit),
            ])
            .collect();
        let mut manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Preparing,
            was_active,
            was_enabled,
            http_port,
            files,
            temporary_paths,
            user,
            was_linger,
        };
        write_manifest(&path, &manifest)?;
        for file in &mut manifest.files {
            if let Err(error) = file.prepare() {
                let cleanup = settle_and_cleanup(&path, &manifest);
                if let Err(cleanup_error) = cleanup {
                    return Err(error.context(format!(
                        "preparation cleanup is incomplete ({cleanup_error}); re-run `koi install` to retry"
                    )));
                }
                return Err(error);
            }
        }
        manifest.phase = TransactionPhase::Armed;
        if let Err(error) = write_manifest(&path, &manifest) {
            if let Err(cleanup_error) = settle_and_cleanup(&path, &manifest) {
                return Err(error.context(format!(
                    "could not disarm the failed checkpoint ({cleanup_error}); re-run `koi install` to retry recovery"
                )));
            }
            return Err(error);
        }
        Ok(Self { path, manifest })
    }

    fn commit(&mut self) -> anyhow::Result<()> {
        let mut settled = self.manifest.clone();
        settled.phase = TransactionPhase::Settled;
        write_manifest(&self.path, &settled)?;
        self.manifest = settled;
        cleanup_settled(&self.path, &self.manifest)
    }

    fn rollback(mut self) -> anyhow::Result<()> {
        // A failed Settled write may already be visible without being proven
        // crash-durable. Re-arm durably before the first restorative effect.
        self.manifest.phase = TransactionPhase::Armed;
        write_manifest(&self.path, &self.manifest)?;
        restore_manifest(&self.path, &self.manifest)
    }
}

/// Install as a system service (root).
pub fn install_system(operator: Option<&str>, data_dir: &Path) -> anyhow::Result<()> {
    super::super::check_root("install")?;

    let exe = std::env::current_exe()?;
    let bin = install_bin_path();
    let unit = system_unit_path();
    println!("Installing Koi service (systemd)...");
    println!("  Binary: {}", exe.display());

    // Recovery may change the service from stopped/broken back to its prior
    // active state, so measure lifecycle state only after it completes.
    recover_interrupted(&transaction_path(data_dir, false))?;
    let manager = SystemdManager::system();
    let prior = manager.observe(&unit, false)?;
    if prior.active {
        manager.verify_process_image(&prior, &bin)?;
    }
    let was_active = prior.active;
    let was_enabled = prior.enabled;

    // The platform recipe identifies its own durable service registration;
    // shared planning decides whether a live listener is Koi or foreign.
    let disposition = if prior.registered {
        InstallDisposition::ReplacingOwned
    } else {
        InstallDisposition::Fresh
    };
    let existing = honor_existing_linux()?;
    let planned = plan_install_ports(&existing, disposition);
    let config = PathBuf::from("/etc/koi/config.toml");
    let policy = koi_config::local_access::policy_path(data_dir);
    let transaction = InstallTransaction::begin(
        data_dir,
        false,
        was_active,
        was_enabled,
        None,
        planned.http,
        vec![
            bin.clone(),
            unit.clone(),
            config.clone(),
            policy,
            koi_config::breadcrumb::breadcrumb_path(),
        ],
    )?;

    let result = (|| -> anyhow::Result<String> {
        super::super::record_unix_operator(false, operator, data_dir)?;
        if was_active || was_enabled {
            println!("  Existing service found, updating...");
        }
        if was_active {
            print!("  Stopping service...");
            manager.checked(&["stop", SERVICE_NAME], "stop the existing service")?;
            if manager.observe(&unit, false)?.active {
                anyhow::bail!("systemd kept the previous service active after stop");
            }
            println!(" done.");
        }

        // Stage after the stop: upgrading from the installed path must work
        // (ETXTBSY fix — same-file staging is a no-op, rename is atomic).
        print!("  Staging {}...", bin.display());
        if super::stage_binary(&exe, &bin)? {
            println!(" done.");
        } else {
            println!(" already in place.");
        }

        let persisted = persist_effective_system_plan(&existing, &planned, &config)?;
        print!("  Writing {}...", unit.display());
        write_unit(&unit, &render(UNIT_TEMPLATE, &bin))?;
        println!(" done.");

        manager.checked(&["daemon-reload"], "reload systemd")?;
        manager.checked(&["enable", SERVICE_NAME], "enable the service")?;
        println!("  Service enabled (start on boot)");
        manager.checked(&["start", SERVICE_NAME], "start the service")?;
        println!(
            "  Service {}",
            if was_active { "restarted" } else { "started" }
        );

        manager.verify_running(&unit, &bin)?;
        print!("  Verifying (healthz on {})...", planned.http);
        if !healthz_wait(planned.http, std::time::Duration::from_secs(20)) {
            println!(" failed.");
            anyhow::bail!(
                "service did not answer /healthz on {}; check journalctl -u {SERVICE_NAME}",
                planned.http
            );
        }
        println!(" healthy.");
        Ok(persisted)
    })();

    let persisted = finish_install_transaction(transaction, result)?;

    println!();
    println!("Koi service installed.");
    println!("  Ports: {}", planned.describe());
    if !persisted.is_empty() {
        println!("  {persisted}");
    }
    println!("  Config: /etc/koi/config.toml (koi config show)");
    println!("  Logs: journalctl -u {SERVICE_NAME}");
    println!("  Use `koi status` to see module state.");
    Ok(())
}

fn transaction_path(data_dir: &Path, user: bool) -> PathBuf {
    data_dir.join("state").join(if user {
        USER_TRANSACTION_FILENAME
    } else {
        TRANSACTION_FILENAME
    })
}

pub(super) fn transaction_pending(data_dir: &Path, user: bool) -> anyhow::Result<bool> {
    regular_file_exists(&transaction_path(data_dir, user))
}

fn persist_effective_system_plan(
    existing: &Existing,
    planned: &super::PortPlan,
    config: &Path,
) -> anyhow::Result<String> {
    let legacy_dropin = matches!(
        existing,
        Existing::Declared(_, source) if source.starts_with("systemd drop-in ")
    );
    if !legacy_dropin {
        return persist_plan_checked(existing, planned, config);
    }

    // The pre-ADR-036 fleet stored its port decision only in a systemd
    // drop-in. The current unit names config.toml as the durable substrate,
    // and uninstall intentionally removes drop-ins, so migrate the effective
    // run before reporting a successful upgrade.
    match honor_existing_config(config)? {
        Existing::Declared(configured, source) if configured == *planned => Ok(format!(
            "legacy systemd port run is already preserved by {source}"
        )),
        Existing::Declared(configured, source) => anyhow::bail!(
            "legacy systemd ports {} conflict with {} from {source}; reconcile them before reinstalling",
            planned.describe(),
            configured.describe()
        ),
        Existing::ConfigWithoutPorts(path) => {
            append_config_ports(&path, planned)?;
            Ok(format!(
                "legacy systemd port run migrated to {}",
                path.display()
            ))
        }
        Existing::Nothing => {
            write_config_new(config, planned)?;
            Ok(format!(
                "legacy systemd port run migrated to {}",
                config.display()
            ))
        }
    }
}

fn staged_binary_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.new", path.display()))
}

fn staged_unit_path(path: &Path) -> PathBuf {
    path.with_extension("service.new")
}

fn write_manifest(path: &Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    let outcome = koi_common::persist::write_json_pretty_commit_with_options(
        path,
        manifest,
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o600),
    )?;
    koi_common::persist::require_durable(outcome, "persisting the systemd install manifest")?;
    Ok(())
}

fn recover_interrupted(path: &Path) -> anyhow::Result<()> {
    let manifest = match koi_common::persist::read_json::<InstallManifest>(path) {
        Ok(manifest) => manifest,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            anyhow::bail!(
                "cannot recover interrupted installation: {} is unreadable: {error}",
                path.display()
            )
        }
    };
    if !matches!(manifest.version, 1 | 2 | TRANSACTION_VERSION) {
        anyhow::bail!(
            "cannot recover interrupted installation: {} has version {}, expected 1, 2, or {}",
            path.display(),
            manifest.version,
            TRANSACTION_VERSION
        );
    }
    match manifest.phase {
        TransactionPhase::Preparing => {
            println!(
                "  Cleaning an interrupted pre-mutation checkpoint at {}...",
                path.display()
            );
            settle_and_cleanup(path, &manifest)?;
            println!(" done.");
            Ok(())
        }
        TransactionPhase::Armed => {
            println!(
                "  Recovering an interrupted systemd installation from {}...",
                path.display()
            );
            restore_manifest(path, &manifest)?;
            println!(" done.");
            Ok(())
        }
        TransactionPhase::Settled => cleanup_settled(path, &manifest),
    }
}

fn restore_manifest(path: &Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    for file in &manifest.files {
        file.validate_backup(manifest.version >= 2)?;
    }
    let manager = SystemdManager::new(manifest.user);
    let unit = if manifest.user {
        user_unit_path()?
    } else {
        system_unit_path()
    };
    let expected_registered = manifest
        .files
        .iter()
        .find(|file| file.path == unit)
        .ok_or_else(|| anyhow::anyhow!("systemd recovery manifest omits its unit file"))?
        .existed;
    manager.stop_and_disable_candidate(&unit)?;
    for file in &manifest.files {
        file.restore()?;
    }
    manager.checked(&["daemon-reload"], "reload the restored systemd unit")?;

    let restored = manager.observe(&unit, false)?;
    let enabled_now = restored.enabled;
    if manifest.was_enabled && !enabled_now {
        manager.checked(&["enable", SERVICE_NAME], "restore service enablement")?;
    } else if !manifest.was_enabled && enabled_now {
        manager.checked(&["disable", SERVICE_NAME], "restore disabled service state")?;
    }
    if let Some(was_linger) = manifest.was_linger {
        manager.restore_linger(was_linger)?;
    }
    if manifest.was_active {
        manager.checked(&["start", SERVICE_NAME], "restart the previous service")?;
        let bin = if manifest.user {
            user_bin_path()?
        } else {
            install_bin_path()
        };
        let running = manager.observe(&unit, false)?;
        if !running.registered || !running.active {
            anyhow::bail!("systemd did not restart the previous service generation");
        }
        manager.verify_process_image(&running, &bin)?;
        if !healthz_wait(manifest.http_port, std::time::Duration::from_secs(20)) {
            anyhow::bail!(
                "restored service did not answer /healthz on {}",
                manifest.http_port
            );
        }
    }
    let final_state = manager.observe(&unit, false)?;
    if final_state.registered != expected_registered
        || final_state.enabled != manifest.was_enabled
        || final_state.active != manifest.was_active
    {
        anyhow::bail!(
            "systemd rollback did not restore the exact registration, enablement, and activity state"
        );
    }

    settle_and_cleanup(path, manifest)
}

fn write_unit(path: &Path, body: &str) -> anyhow::Result<()> {
    let outcome = koi_common::persist::write_bytes_atomic_with_options(
        path,
        body.as_bytes(),
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o644),
    )?;
    koi_common::persist::require_durable(outcome, "installing the systemd unit")?;
    Ok(())
}

fn settle_and_cleanup(path: &Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    let mut settled = manifest.clone();
    settled.version = TRANSACTION_VERSION;
    settled.phase = TransactionPhase::Settled;
    write_manifest(path, &settled)?;
    cleanup_settled(path, &settled)
}

fn cleanup_settled(path: &Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    debug_assert_eq!(manifest.phase, TransactionPhase::Settled);
    for file in &manifest.files {
        if let Err(error) = file.cleanup() {
            eprintln!(
                "  Warning: committed installer backup {} remains for cleanup: {error}",
                file.backup.display()
            );
            return Ok(());
        }
    }
    if let Err(error) = cleanup_temporary_paths(&manifest.temporary_paths) {
        eprintln!("  Warning: committed installer staging remains for cleanup: {error}");
        return Ok(());
    }
    match koi_common::persist::remove_file_durable(path) {
        Ok(outcome) => {
            if let Err(error) = koi_common::persist::require_durable(
                outcome,
                "removing the settled systemd install manifest",
            ) {
                eprintln!("  Warning: settled installer manifest cleanup is uncertain: {error}");
            }
        }
        Err(error) => eprintln!(
            "  Warning: settled installer manifest {} remains for cleanup: {error}",
            path.display()
        ),
    }
    Ok(())
}

fn cleanup_temporary_paths(paths: &[PathBuf]) -> anyhow::Result<()> {
    for path in paths {
        let outcome = koi_common::persist::remove_file_durable(path)?;
        koi_common::persist::require_durable(outcome, "removing installer staging debris")?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SystemdState {
    registered: bool,
    enabled: bool,
    active: bool,
    failed: bool,
    pid: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct SystemdManager {
    user: bool,
}

impl SystemdManager {
    const fn new(user: bool) -> Self {
        Self { user }
    }

    const fn system() -> Self {
        Self::new(false)
    }

    const fn user() -> Self {
        Self::new(true)
    }

    fn output(&self, args: &[&str]) -> std::io::Result<std::process::Output> {
        let mut command = Command::new("systemctl");
        if self.user {
            command.arg("--user");
        }
        command.env("LC_ALL", "C").args(args).output()
    }

    fn checked(&self, args: &[&str], action: &str) -> anyhow::Result<std::process::Output> {
        let output = self
            .output(args)
            .map_err(|error| anyhow::anyhow!("could not {action}: {error}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            anyhow::bail!(
                "could not {action}: systemctl {}{} exited {}{}{}",
                if self.user { "--user " } else { "" },
                args.join(" "),
                output.status,
                if detail.is_empty() { "" } else { ": " },
                detail
            );
        }
        Ok(output)
    }

    fn observe(&self, unit: &Path, allow_failed: bool) -> anyhow::Result<SystemdState> {
        let output = self.checked(
            &[
                "show",
                SERVICE_NAME,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=UnitFileState",
                "--property=MainPID",
                "--property=FragmentPath",
                "--property=ExecStart",
            ],
            "inspect the systemd service",
        )?;
        let expected_bin = if self.user {
            user_bin_path()?
        } else {
            install_bin_path()
        };
        parse_systemd_state(
            &String::from_utf8(output.stdout)
                .map_err(|error| anyhow::anyhow!("systemctl returned non-UTF-8 state: {error}"))?,
            unit,
            &expected_bin,
            allow_failed,
        )
    }

    fn stop_and_disable_candidate(&self, unit: &Path) -> anyhow::Result<()> {
        // An armed transaction may have crashed between replacing the unit and
        // daemon-reload. Converge the manager onto the visible unit before
        // deciding which lifecycle effects must be reversed.
        self.checked(&["daemon-reload"], "reload systemd before recovery")?;
        let mut state = self.observe(unit, true)?;
        if state.active {
            self.checked(&["stop", SERVICE_NAME], "stop the failed replacement")?;
            state = self.observe(unit, true)?;
        }
        if state.failed {
            self.checked(
                &["reset-failed", SERVICE_NAME],
                "clear the failed replacement state",
            )?;
            state = self.observe(unit, false)?;
        }
        if state.enabled {
            self.checked(&["disable", SERVICE_NAME], "disable the failed replacement")?;
            state = self.observe(unit, false)?;
        }
        if state.active || state.enabled {
            anyhow::bail!("systemd replacement is still active or enabled after teardown");
        }
        Ok(())
    }

    fn verify_running(&self, unit: &Path, bin: &Path) -> anyhow::Result<()> {
        let state = self.observe(unit, false)?;
        if !state.registered || !state.enabled || !state.active {
            anyhow::bail!(
                "systemd did not retain an enabled, active {SERVICE_NAME}.service generation"
            );
        }
        self.verify_process_image(&state, bin)
    }

    fn verify_process_image(&self, state: &SystemdState, bin: &Path) -> anyhow::Result<()> {
        let pid = state
            .pid
            .ok_or_else(|| anyhow::anyhow!("systemd reports no Koi main process"))?;
        let actual = std::fs::canonicalize(format!("/proc/{pid}/exe"))?;
        let expected = std::fs::canonicalize(bin)?;
        if actual != expected {
            anyhow::bail!(
                "systemd started {} instead of {}",
                actual.display(),
                expected.display()
            );
        }
        Ok(())
    }

    fn linger(&self) -> anyhow::Result<bool> {
        if !self.user {
            anyhow::bail!("linger is only defined for a systemd user manager");
        }
        let uid = unsafe { libc::getuid() }.to_string();
        let output = checked_command(
            Command::new("loginctl")
                .env("LC_ALL", "C")
                .args(["show-user", &uid, "--property=Linger", "--value"])
                .output(),
            "inspect user linger",
            "loginctl show-user",
        )?;
        match String::from_utf8_lossy(&output.stdout).trim() {
            "yes" => Ok(true),
            "no" => Ok(false),
            value => anyhow::bail!("loginctl returned unsupported linger state '{value}'"),
        }
    }

    fn set_linger(&self, enabled: bool) -> anyhow::Result<()> {
        let uid = unsafe { libc::getuid() }.to_string();
        let action = if enabled {
            "enable-linger"
        } else {
            "disable-linger"
        };
        checked_command(
            Command::new("loginctl")
                .env("LC_ALL", "C")
                .args([action, &uid])
                .output(),
            if enabled {
                "enable user linger"
            } else {
                "disable user linger"
            },
            &format!("loginctl {action} {uid}"),
        )?;
        if self.linger()? != enabled {
            anyhow::bail!("loginctl did not retain the requested linger state");
        }
        Ok(())
    }

    fn restore_linger(&self, expected: bool) -> anyhow::Result<()> {
        if self.linger()? != expected {
            self.set_linger(expected)?;
        }
        Ok(())
    }
}

fn parse_systemd_state(
    body: &str,
    expected_unit: &Path,
    expected_bin: &Path,
    allow_failed: bool,
) -> anyhow::Result<SystemdState> {
    let mut load = None;
    let mut active = None;
    let mut unit_file = None;
    let mut pid = None;
    let mut fragment = None;
    let mut program = None;
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            anyhow::bail!("malformed systemctl show line '{line}'");
        };
        match key {
            "LoadState" => load = Some(value),
            "ActiveState" => active = Some(value),
            "UnitFileState" => unit_file = Some(value),
            "MainPID" => pid = Some(value.parse::<u32>()?),
            "FragmentPath" => fragment = Some(value),
            "ExecStart" => {
                program = value
                    .strip_prefix("{ path=")
                    .and_then(|value| value.split_once(" ;"))
                    .map(|(value, _)| PathBuf::from(value.trim()));
            }
            _ => {}
        }
    }
    let load = load.ok_or_else(|| anyhow::anyhow!("systemctl omitted LoadState"))?;
    let active_value = active.ok_or_else(|| anyhow::anyhow!("systemctl omitted ActiveState"))?;
    let unit_file = unit_file.ok_or_else(|| anyhow::anyhow!("systemctl omitted UnitFileState"))?;
    let pid = pid.ok_or_else(|| anyhow::anyhow!("systemctl omitted MainPID"))?;
    let fragment = fragment.ok_or_else(|| anyhow::anyhow!("systemctl omitted FragmentPath"))?;
    let file_exists = regular_file_exists(expected_unit)?;

    if load == "not-found" {
        if file_exists {
            anyhow::bail!(
                "{} exists but systemd has not loaded it; run daemon-reload and retry",
                expected_unit.display()
            );
        }
        if active_value != "inactive" || pid != 0 {
            anyhow::bail!("systemd reports activity for an absent Koi service");
        }
        return Ok(SystemdState {
            registered: false,
            enabled: false,
            active: false,
            failed: false,
            pid: None,
        });
    }
    if load != "loaded" {
        anyhow::bail!("unsupported systemd LoadState '{load}' for {SERVICE_NAME}.service");
    }
    if !file_exists {
        anyhow::bail!("systemd loaded Koi from outside the installer-owned unit path");
    }
    let expected = std::fs::canonicalize(expected_unit)?;
    let actual = std::fs::canonicalize(fragment).map_err(|error| {
        anyhow::anyhow!("cannot resolve systemd FragmentPath '{fragment}': {error}")
    })?;
    if actual != expected {
        anyhow::bail!(
            "systemd owns {SERVICE_NAME}.service through {}, not installer path {}",
            actual.display(),
            expected.display()
        );
    }
    let program =
        program.ok_or_else(|| anyhow::anyhow!("systemd omitted the Koi ExecStart image"))?;
    let expected_program = std::fs::canonicalize(expected_bin)?;
    let actual_program = std::fs::canonicalize(&program)?;
    if actual_program != expected_program {
        anyhow::bail!(
            "systemd declares {} instead of installer-owned {}",
            actual_program.display(),
            expected_program.display()
        );
    }
    let enabled = match unit_file {
        "enabled" => true,
        "disabled" => false,
        other => anyhow::bail!(
            "unsupported systemd UnitFileState '{other}'; Koi only mutates enabled or disabled owned units"
        ),
    };
    let (is_active, failed) = match active_value {
        "active" => (true, false),
        "inactive" => (false, false),
        "failed" if allow_failed => (false, true),
        other => anyhow::bail!(
            "unsupported systemd ActiveState '{other}'; settle it before installing Koi"
        ),
    };
    if is_active != (pid != 0) {
        anyhow::bail!(
            "systemd reported ActiveState={active_value} with inconsistent MainPID={pid}"
        );
    }
    Ok(SystemdState {
        registered: true,
        enabled,
        active: is_active,
        failed,
        pid: (pid != 0).then_some(pid),
    })
}

fn checked_command(
    result: std::io::Result<std::process::Output>,
    action: &str,
    command: &str,
) -> anyhow::Result<std::process::Output> {
    let output = result.map_err(|error| anyhow::anyhow!("could not {action}: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        anyhow::bail!(
            "could not {action}: {command} exited {}{}{}",
            output.status,
            if detail.is_empty() { "" } else { ": " },
            detail
        );
    }
    Ok(output)
}

fn finish_install_transaction(
    mut transaction: InstallTransaction,
    result: anyhow::Result<String>,
) -> anyhow::Result<String> {
    match result {
        Ok(summary) => match transaction.commit() {
            Ok(()) => Ok(summary),
            Err(commit_error) => match transaction.rollback() {
                Ok(()) => anyhow::bail!(
                    "installation verification passed, but its durable commit failed and the previous Koi installation was restored: {commit_error}"
                ),
                Err(rollback_error) => anyhow::bail!(
                    "installation verification passed, but commit failed ({commit_error}) and automatic rollback is incomplete ({rollback_error}). Re-run `koi install` to retry recovery before making manual changes"
                ),
            },
        },
        Err(install_error) => match transaction.rollback() {
            Ok(()) => anyhow::bail!(
                "installation failed and the previous Koi installation was restored: {install_error}"
            ),
            Err(rollback_error) => anyhow::bail!(
                "installation failed ({install_error}); automatic rollback is incomplete ({rollback_error}). Re-run `koi install` to retry recovery before making manual changes"
            ),
        },
    }
}

/// Install as a user service (no root — running with sudo is refused).
pub fn install_user(operator: Option<&str>, data_dir: &Path) -> anyhow::Result<()> {
    if unsafe { libc::getuid() } == 0 {
        anyhow::bail!("--user installs belong to your user account; run without sudo");
    }
    let exe = std::env::current_exe()?;
    let bin = user_bin_path()?;
    let unit = user_unit_path()?;
    let config = user_config_path()?;
    let policy = koi_config::local_access::policy_path(data_dir);
    let manager = SystemdManager::user();

    println!("Installing Koi user service (systemd --user)...");
    println!("  Binary: {}", exe.display());

    recover_interrupted(&transaction_path(data_dir, true))?;
    let prior = manager.observe(&unit, false)?;
    if prior.active {
        manager.verify_process_image(&prior, &bin)?;
    }
    let was_linger = manager.linger()?;
    let linger_before_koi = if prior.registered {
        prior_linger_from_unit(&unit)?.unwrap_or(was_linger)
    } else {
        was_linger
    };
    let existing = honor_existing_config(&config)?;
    let disposition = if prior.registered {
        InstallDisposition::ReplacingOwned
    } else {
        InstallDisposition::Fresh
    };
    let planned = plan_install_ports(&existing, disposition);
    let transaction = InstallTransaction::begin(
        data_dir,
        true,
        prior.active,
        prior.enabled,
        Some(was_linger),
        planned.http,
        vec![
            bin.clone(),
            unit.clone(),
            config.clone(),
            policy,
            koi_config::breadcrumb::breadcrumb_path(),
        ],
    )?;

    let result = (|| -> anyhow::Result<String> {
        super::super::record_unix_operator(true, operator, data_dir)?;
        if prior.active {
            manager.checked(&["stop", SERVICE_NAME], "stop the existing user service")?;
            if manager.observe(&unit, false)?.active {
                anyhow::bail!("systemd kept the previous user service active after stop");
            }
        }
        print!("  Staging {}...", bin.display());
        if super::stage_binary(&exe, &bin)? {
            println!(" done.");
        } else {
            println!(" already in place.");
        }
        let persisted = persist_plan_checked(&existing, &planned, &config)?;
        print!("  Writing {}...", unit.display());
        write_unit(&unit, &render_user_unit(&bin, linger_before_koi))?;
        println!(" done.");

        manager.checked(&["daemon-reload"], "reload the user service manager")?;
        manager.checked(&["enable", SERVICE_NAME], "enable the user service")?;
        manager.set_linger(true)?;
        manager.checked(&["start", SERVICE_NAME], "start the user service")?;
        manager.verify_running(&unit, &bin)?;
        if !healthz_wait(planned.http, std::time::Duration::from_secs(20)) {
            anyhow::bail!(
                "user service did not answer /healthz on {}; check journalctl --user -u {SERVICE_NAME}",
                planned.http
            );
        }
        Ok(persisted)
    })();

    let persisted = finish_install_transaction(transaction, result)?;

    println!();
    println!("Koi user service installed.");
    println!("  Ports: {}", planned.describe());
    if !persisted.is_empty() {
        println!("  {persisted}");
    }
    println!("  Config: {} (koi config show)", config.display());
    println!("  Logs: journalctl --user -u {SERVICE_NAME}");
    Ok(())
}

fn user_bin_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot locate ~/.local/bin"))?;
    Ok(PathBuf::from(home).join(".local/bin/koi"))
}

fn user_config_path() -> anyhow::Result<PathBuf> {
    Ok(user_config_root()?.join("koi/config.toml"))
}

fn user_config_root() -> anyhow::Result<PathBuf> {
    if let Some(root) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(root));
    }
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot locate user configuration"))?;
    Ok(PathBuf::from(home).join(".config"))
}

/// Uninstall the system service and every regular drop-in it owns. The empty
/// drop-in directory, binary, and operator config are preserved.
pub fn uninstall_system(data_dir: &Path) -> anyhow::Result<()> {
    let unit = system_unit_path();
    recover_interrupted(&transaction_path(data_dir, false))?;
    if !regular_file_exists(&unit)? {
        return Ok(());
    }
    super::super::check_root("uninstall")?;
    println!("Uninstalling Koi service (systemd)...");
    uninstall_scope(data_dir, false)?;

    if regular_file_exists(&install_bin_path())? {
        println!("  Binary preserved at: {}", install_bin_path().display());
    }
    println!();
    println!("Koi service uninstalled.");
    Ok(())
}

/// Uninstall the user service.
pub fn uninstall_user(data_dir: &Path) -> anyhow::Result<()> {
    let unit = user_unit_path()?;
    recover_interrupted(&transaction_path(data_dir, true))?;
    if !regular_file_exists(&unit)? {
        return Ok(());
    }
    println!("Uninstalling Koi user service (systemd)...");
    uninstall_scope(data_dir, true)?;
    println!("Koi user service uninstalled.");
    Ok(())
}

fn uninstall_scope(data_dir: &Path, user: bool) -> anyhow::Result<()> {
    recover_interrupted(&transaction_path(data_dir, user))?;
    let manager = SystemdManager::new(user);
    let unit = if user {
        user_unit_path()?
    } else {
        system_unit_path()
    };
    let prior = manager.observe(&unit, false)?;
    if !prior.registered {
        return Ok(());
    }
    let installed_bin = if user {
        user_bin_path()?
    } else {
        install_bin_path()
    };
    if prior.active {
        manager.verify_process_image(&prior, &installed_bin)?;
    }
    let existing = if user {
        honor_existing_config(&user_config_path()?)?
    } else {
        honor_existing_linux()?
    };
    let http_port = match existing {
        Existing::Declared(plan, _) => plan.http,
        Existing::ConfigWithoutPorts(_) | Existing::Nothing => super::STD_HTTP,
    };
    let was_linger = user.then(|| manager.linger()).transpose()?;
    let linger_after_uninstall = if user {
        prior_linger_from_unit(&unit)?.unwrap_or(was_linger.unwrap_or(false))
    } else {
        false
    };
    let dropin = (!user).then(|| PathBuf::from("/etc/systemd/system/koi.service.d"));
    let mut owned_files = vec![unit.clone(), koi_config::breadcrumb::breadcrumb_path()];
    if let Some(dropin) = &dropin {
        owned_files.extend(strict_directory_files(dropin)?);
    }
    let transaction = InstallTransaction::begin(
        data_dir,
        user,
        prior.active,
        prior.enabled,
        was_linger,
        http_port,
        owned_files.clone(),
    )?;

    let result = (|| -> anyhow::Result<()> {
        if prior.active {
            manager.checked(&["stop", SERVICE_NAME], "stop the service")?;
        }
        if prior.enabled {
            manager.checked(&["disable", SERVICE_NAME], "disable the service")?;
        }
        for path in &owned_files {
            remove_file_durable(path)?;
        }
        manager.checked(&["daemon-reload"], "reload systemd after uninstall")?;
        if user {
            manager.restore_linger(linger_after_uninstall)?;
        }
        let final_state = manager.observe(&unit, false)?;
        if final_state.registered || final_state.active || final_state.enabled {
            anyhow::bail!("systemd retained the Koi service after uninstall");
        }
        Ok(())
    })();

    finish_unit_transaction(transaction, result, "uninstall")
}

fn strict_directory_files(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_dir() {
        anyhow::bail!(
            "expected an installer-owned directory at {}",
            path.display()
        );
    }
    let mut files = std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort();
    for file in &files {
        if !regular_file_exists(file)? {
            anyhow::bail!("installer-owned directory contains a vanished entry");
        }
    }
    Ok(files)
}

fn remove_file_durable(path: &Path) -> anyhow::Result<()> {
    let outcome = koi_common::persist::remove_file_durable(path)?;
    koi_common::persist::require_durable(outcome, "removing a systemd installation file")?;
    Ok(())
}

fn finish_unit_transaction(
    mut transaction: InstallTransaction,
    result: anyhow::Result<()>,
    operation: &str,
) -> anyhow::Result<()> {
    match result {
        Ok(()) => match transaction.commit() {
            Ok(()) => Ok(()),
            Err(commit_error) => match transaction.rollback() {
                Ok(()) => anyhow::bail!(
                    "{operation} completed, but its durable commit failed and the previous Koi service was restored: {commit_error}"
                ),
                Err(rollback_error) => anyhow::bail!(
                    "{operation} completed, but commit failed ({commit_error}) and rollback is incomplete ({rollback_error}); re-run the same command to recover"
                ),
            },
        },
        Err(operation_error) => match transaction.rollback() {
            Ok(()) => anyhow::bail!(
                "{operation} failed and the previous Koi service was restored: {operation_error}"
            ),
            Err(rollback_error) => anyhow::bail!(
                "{operation} failed ({operation_error}); rollback is incomplete ({rollback_error}); re-run the same command to recover"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction_test_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "koi-systemd-transaction-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn system_unit_golden() {
        let unit = render(UNIT_TEMPLATE, &PathBuf::from("/usr/local/bin/koi"));
        assert!(unit.contains("ExecStart=/usr/local/bin/koi --daemon"));
        assert!(unit.contains("Type=notify"));
        assert!(
            unit.contains("Environment=XDG_CONFIG_HOME=/etc"),
            "system units resolve config at /etc/koi/config.toml"
        );
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(!unit.contains("{{"));
    }

    #[test]
    fn user_unit_golden() {
        let unit = render_user_unit(&PathBuf::from("/home/x/.local/bin/koi"), false);
        assert!(unit.contains("ExecStart=/home/x/.local/bin/koi --daemon"));
        assert!(
            !unit.contains("XDG_CONFIG_HOME"),
            "user services use the natural ~/.config path"
        );
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("# X-Koi-Prior-Linger=no"));
        assert!(!unit.contains("{{"));
    }

    #[test]
    fn user_unit_retains_the_pre_koi_linger_state() {
        let root = transaction_test_root("linger-marker");
        let unit = root.join("koi.service");
        std::fs::write(
            &unit,
            render_user_unit(Path::new("/home/x/.local/bin/koi"), true),
        )
        .unwrap();
        assert_eq!(prior_linger_from_unit(&unit).unwrap(), Some(true));
        std::fs::write(&unit, "# X-Koi-Prior-Linger=maybe\n").unwrap();
        assert!(prior_linger_from_unit(&unit).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn systemd_state_parser_accepts_only_owned_settled_states() {
        let root = transaction_test_root("state-parser");
        let unit = root.join("koi.service");
        let bin = root.join("koi");
        std::fs::write(&unit, "[Service]\n").unwrap();
        std::fs::write(&bin, "binary").unwrap();
        let body = format!(
            "LoadState=loaded\nActiveState=inactive\nFragmentPath={}\nUnitFileState=enabled\nMainPID=0\nExecStart={{ path={} ; argv[]={}; }}\n",
            unit.display(),
            bin.display(),
            bin.display()
        );
        let state = parse_systemd_state(&body, &unit, &bin, false).unwrap();
        assert!(state.registered);
        assert!(state.enabled);
        assert!(!state.active);

        assert!(parse_systemd_state(
            &body.replace("UnitFileState=enabled", "UnitFileState=masked"),
            &unit,
            &bin,
            false
        )
        .is_err());
        assert!(parse_systemd_state(
            &body.replace("ActiveState=inactive", "ActiveState=activating"),
            &unit,
            &bin,
            false
        )
        .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn systemd_state_parser_distinguishes_native_absence() {
        let root = transaction_test_root("absent-state");
        let unit = root.join("koi.service");
        let bin = root.join("koi");
        let state = parse_systemd_state(
            "LoadState=not-found\nActiveState=inactive\nFragmentPath=\nUnitFileState=\nMainPID=0\nExecStart=\n",
            &unit,
            &bin,
            false,
        )
        .unwrap();
        assert!(!state.registered);
        assert!(!state.active);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_snapshots_restore_existing_and_remove_new_targets() {
        let root = transaction_test_root("restore");
        let existing = root.join("existing");
        let new = root.join("new");
        std::fs::write(&existing, "before").unwrap();

        let mut existing_snapshot = FileSnapshot::inspect(existing.clone()).unwrap();
        let mut new_snapshot = FileSnapshot::inspect(new.clone()).unwrap();
        existing_snapshot.prepare().unwrap();
        new_snapshot.prepare().unwrap();
        std::fs::write(&existing, "after").unwrap();
        std::fs::write(&new, "created").unwrap();

        existing_snapshot.validate_backup(true).unwrap();
        new_snapshot.validate_backup(true).unwrap();
        existing_snapshot.restore().unwrap();
        new_snapshot.restore().unwrap();
        assert_eq!(std::fs::read_to_string(existing).unwrap(), "before");
        assert!(!new.exists());
        existing_snapshot.cleanup().unwrap();
        new_snapshot.cleanup().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_required_backup_fails_closed() {
        let root = transaction_test_root("missing-backup");
        let target = root.join("target");
        std::fs::write(&target, "before").unwrap();
        let snapshot = FileSnapshot::inspect(target).unwrap();
        let error = snapshot.validate_backup(true).unwrap_err().to_string();
        assert!(error.contains("recovery is incomplete"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn changed_backup_fails_integrity_validation() {
        let root = transaction_test_root("changed-backup");
        let target = root.join("target");
        std::fs::write(&target, "before").unwrap();
        let mut snapshot = FileSnapshot::inspect(target).unwrap();
        snapshot.prepare().unwrap();
        std::fs::write(&snapshot.backup, "tampered").unwrap();
        std::fs::write(&snapshot.path, "live state").unwrap();

        let error = snapshot.validate_backup(true).unwrap_err().to_string();
        assert!(error.contains("backup"));
        assert!(error.contains("changed"));
        assert!(snapshot.restore().is_err());
        assert_eq!(
            std::fs::read_to_string(&snapshot.path).unwrap(),
            "live state"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn armed_recovery_rejects_changed_backup_before_native_effects() {
        let root = transaction_test_root("armed-corrupt-backup");
        let target = root.join("target");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        std::fs::write(&target, "prior").unwrap();
        let mut snapshot = FileSnapshot::inspect(target.clone()).unwrap();
        snapshot.prepare().unwrap();
        let manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Armed,
            was_active: false,
            was_enabled: false,
            http_port: 5641,
            files: vec![snapshot.clone()],
            temporary_paths: vec![],
            user: false,
            was_linger: None,
        };
        write_manifest(&manifest_path, &manifest).unwrap();
        std::fs::write(&snapshot.backup, "corrupt").unwrap();

        let error = recover_interrupted(&manifest_path).unwrap_err().to_string();
        assert!(error.contains("changed"));
        assert_eq!(std::fs::read_to_string(target).unwrap(), "prior");
        assert!(manifest_path.exists(), "failed recovery remains retryable");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn settled_recovery_is_cleanup_only() {
        let root = transaction_test_root("settled-cleanup");
        let target = root.join("target");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        std::fs::write(&target, "before").unwrap();
        let mut snapshot = FileSnapshot::inspect(target.clone()).unwrap();
        snapshot.prepare().unwrap();
        std::fs::write(&target, "committed").unwrap();
        let manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Settled,
            was_active: false,
            was_enabled: false,
            http_port: 5641,
            files: vec![snapshot.clone()],
            temporary_paths: vec![],
            user: false,
            was_linger: None,
        };
        write_manifest(&manifest_path, &manifest).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&manifest_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        recover_interrupted(&manifest_path).unwrap();
        assert_eq!(std::fs::read_to_string(target).unwrap(), "committed");
        assert!(!snapshot.backup.exists());
        assert!(!manifest_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn settled_cleanup_failure_retains_a_retryable_manifest() {
        let root = transaction_test_root("settled-cleanup-retry");
        let target = root.join("target");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        std::fs::write(&target, "before").unwrap();
        let mut snapshot = FileSnapshot::inspect(target.clone()).unwrap();
        snapshot.prepare().unwrap();
        std::fs::remove_file(&snapshot.backup).unwrap();
        std::fs::create_dir(&snapshot.backup).unwrap();
        std::fs::write(&target, "committed").unwrap();
        let manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Settled,
            was_active: false,
            was_enabled: false,
            http_port: 5641,
            files: vec![snapshot.clone()],
            temporary_paths: vec![],
            user: false,
            was_linger: None,
        };
        write_manifest(&manifest_path, &manifest).unwrap();

        cleanup_settled(&manifest_path, &manifest).unwrap();
        assert!(manifest_path.exists(), "cleanup failure keeps its journal");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "committed");

        std::fs::remove_dir(&snapshot.backup).unwrap();
        recover_interrupted(&manifest_path).unwrap();
        assert!(!manifest_path.exists());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "committed");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_dropin_ports_migrate_to_the_durable_config() {
        let root = transaction_test_root("legacy-port-migration");
        let config = root.join("config.toml");
        let planned = super::super::PortPlan {
            http: 24441,
            mtls: 24442,
            acme: 24443,
            shifted: true,
        };
        let existing = Existing::Declared(
            planned,
            "systemd drop-in /etc/systemd/system/koi.service.d/ports.conf".to_string(),
        );

        let summary = persist_effective_system_plan(&existing, &planned, &config).unwrap();
        assert!(summary.contains("migrated"));
        assert_eq!(
            super::super::ports_from_config_body(&config).unwrap(),
            Some((24441, 24442, 24443))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_preparation_discards_only_checkpoint_copies() {
        let root = transaction_test_root("preparing-recovery");
        let target = root.join("target");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        std::fs::write(&target, "unchanged").unwrap();
        let mut snapshot = FileSnapshot::inspect(target.clone()).unwrap();
        let manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Preparing,
            was_active: false,
            was_enabled: false,
            http_port: 5641,
            files: vec![snapshot.clone()],
            temporary_paths: vec![staged_restore_path(&target)],
            user: false,
            was_linger: None,
        };
        write_manifest(&manifest_path, &manifest).unwrap();
        snapshot.prepare().unwrap();

        recover_interrupted(&manifest_path).unwrap();
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
        assert!(!snapshot.backup.exists());
        assert!(!manifest_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_recovery_manifest_fails_closed_with_its_path() {
        let root = transaction_test_root("corrupt-manifest");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        std::fs::write(&manifest_path, "{broken").unwrap();
        let error = recover_interrupted(&manifest_path).unwrap_err().to_string();
        assert!(error.contains(&manifest_path.display().to_string()));
        assert!(error.contains("unreadable"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn recovery_manifest_without_unit_fails_before_manager_effects() {
        let root = transaction_test_root("missing-unit");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        let manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Armed,
            was_active: false,
            was_enabled: false,
            http_port: 5641,
            files: vec![],
            temporary_paths: vec![],
            user: false,
            was_linger: None,
        };
        write_manifest(&manifest_path, &manifest).unwrap();

        let error = recover_interrupted(&manifest_path).unwrap_err().to_string();
        assert!(error.contains("omits its unit file"));
        assert!(manifest_path.exists(), "invalid recovery stays armed");
        let _ = std::fs::remove_dir_all(root);
    }
}
