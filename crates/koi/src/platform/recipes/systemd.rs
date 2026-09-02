//! systemd recipe (ADR-036): system and `--user` installs.
//!
//! Covers Debian/Ubuntu/Fedora/Arch and their derivatives — every systemd
//! machine on the fleet. Port decisions are honored from drop-ins or
//! `config.toml`; a shifted plan persists in the config substrate.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use super::transaction::{staged_restore_path, FileSnapshot};
use super::{
    append_config_ports, healthz_wait, honor_existing_config, honor_existing_linux, persist_plan,
    persist_plan_checked, plan_ports, write_config_new, Existing,
};

const SERVICE_NAME: &str = "koi";
const TRANSACTION_VERSION: u16 = 1;
const TRANSACTION_FILENAME: &str = "systemd-install-transaction.json";
const UNIT_TEMPLATE: &str = include_str!("templates/koi.service");
const USER_UNIT_TEMPLATE: &str = include_str!("templates/koi-user.service");

pub fn system_unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/koi.service")
}

pub fn user_unit_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".config/systemd/user/koi.service")
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Preparing,
    Armed,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstallManifest {
    version: u16,
    phase: TransactionPhase,
    was_active: bool,
    was_enabled: bool,
    http_port: u16,
    files: Vec<FileSnapshot>,
    temporary_paths: Vec<PathBuf>,
}

struct InstallTransaction {
    path: PathBuf,
    manifest: InstallManifest,
}

impl InstallTransaction {
    fn begin(
        data_dir: &Path,
        was_active: bool,
        was_enabled: bool,
        http_port: u16,
        paths: Vec<PathBuf>,
    ) -> anyhow::Result<Self> {
        let path = transaction_path(data_dir);
        recover_interrupted(&path)?;

        let files = paths
            .into_iter()
            .map(FileSnapshot::inspect)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let temporary_paths = files
            .iter()
            .flat_map(|file| [staged_restore_path(&file.path)])
            .chain([
                staged_binary_path(&install_bin_path()),
                staged_unit_path(&system_unit_path()),
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
        };
        write_manifest(&path, &manifest)?;
        for file in &manifest.files {
            if let Err(error) = file.prepare() {
                for prepared in &manifest.files {
                    let _ = prepared.cleanup();
                }
                let _ = std::fs::remove_file(&path);
                return Err(error);
            }
        }
        manifest.phase = TransactionPhase::Armed;
        write_manifest(&path, &manifest)?;
        Ok(Self { path, manifest })
    }

    fn commit(&self) -> anyhow::Result<()> {
        // Removing the manifest commits the new state. Leftover backup files
        // are harmless and are removed on this or the next install.
        std::fs::remove_file(&self.path)?;
        for file in &self.manifest.files {
            if let Err(error) = file.cleanup() {
                eprintln!(
                    "  Warning: could not remove committed installer backup {}: {error}",
                    file.backup.display()
                );
            }
        }
        cleanup_temporary_paths(&self.manifest.temporary_paths);
        Ok(())
    }

    fn rollback(self) -> anyhow::Result<()> {
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
    recover_interrupted(&transaction_path(data_dir))?;
    let was_active = systemctl(&["is-active", SERVICE_NAME]);
    let was_enabled = systemctl(&["is-enabled", SERVICE_NAME]);

    // Ports: existing decisions win; plan only when nothing is declared.
    let existing = honor_existing_linux();
    let planned = match &existing {
        Existing::Declared(plan, _) => *plan,
        _ => plan_ports(),
    };
    let config = PathBuf::from("/etc/koi/config.toml");
    let policy = koi_config::local_access::policy_path(data_dir);
    let transaction = InstallTransaction::begin(
        data_dir,
        was_active,
        was_enabled,
        planned.http,
        vec![bin.clone(), unit.clone(), config.clone(), policy],
    )?;

    let result = (|| -> anyhow::Result<String> {
        super::super::record_unix_operator(false, operator, data_dir)?;
        if was_active || was_enabled {
            println!("  Existing service found, updating...");
        }
        if was_active {
            print!("  Stopping service...");
            systemctl_checked(&["stop", SERVICE_NAME], "stop the existing service")?;
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

        systemctl_checked(&["daemon-reload"], "reload systemd")?;
        systemctl_checked(&["enable", SERVICE_NAME], "enable the service")?;
        println!("  Service enabled (start on boot)");
        systemctl_checked(&["start", SERVICE_NAME], "start the service")?;
        println!(
            "  Service {}",
            if was_active { "restarted" } else { "started" }
        );

        verify_service_process(&bin)?;
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

    let persisted = match result {
        Ok(persisted) => {
            if let Err(commit_error) = transaction.commit() {
                eprintln!("  Could not commit installation state: {commit_error}");
                eprintln!("  Restoring the previous installation...");
                match transaction.rollback() {
                    Ok(()) => anyhow::bail!(
                        "installation verification passed, but its durable commit failed and the previous Koi installation was restored: {commit_error}"
                    ),
                    Err(rollback_error) => anyhow::bail!(
                        "installation verification passed, but commit failed ({commit_error}) and automatic rollback is incomplete ({rollback_error}). Re-run `koi install` to retry recovery before making manual changes"
                    ),
                }
            } else {
                persisted
            }
        }
        Err(install_error) => {
            eprintln!("  Installation failed: {install_error}");
            eprintln!("  Restoring the previous installation...");
            match transaction.rollback() {
                Ok(()) => anyhow::bail!(
                    "installation failed and the previous Koi installation was restored: {install_error}"
                ),
                Err(rollback_error) => anyhow::bail!(
                    "installation failed ({install_error}); automatic rollback is incomplete ({rollback_error}). Re-run `koi install` to retry recovery before making manual changes"
                ),
            }
        }
    };

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

fn transaction_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state").join(TRANSACTION_FILENAME)
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
    match honor_existing_config(config) {
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
    koi_common::persist::write_json_pretty(path, manifest)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::File::open(path)?.sync_all()?;
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
    if manifest.version != TRANSACTION_VERSION {
        anyhow::bail!(
            "cannot recover interrupted installation: {} has version {}, expected {}",
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
            for file in &manifest.files {
                file.cleanup()?;
            }
            cleanup_temporary_paths(&manifest.temporary_paths);
            std::fs::remove_file(path)?;
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
    }
}

fn restore_manifest(path: &Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    for file in &manifest.files {
        file.validate_backup()?;
    }
    stop_failed_replacement()?;
    for file in &manifest.files {
        file.restore()?;
    }
    systemctl_checked(&["daemon-reload"], "reload the restored systemd unit")?;

    let enabled_now = systemctl(&["is-enabled", SERVICE_NAME]);
    if manifest.was_enabled && !enabled_now {
        systemctl_checked(&["enable", SERVICE_NAME], "restore service enablement")?;
    } else if !manifest.was_enabled && enabled_now {
        systemctl_checked(&["disable", SERVICE_NAME], "restore disabled service state")?;
    }
    if manifest.was_active {
        systemctl_checked(&["start", SERVICE_NAME], "restart the previous service")?;
        if !healthz_wait(manifest.http_port, std::time::Duration::from_secs(20)) {
            anyhow::bail!(
                "restored service did not answer /healthz on {}",
                manifest.http_port
            );
        }
    }

    // The manifest is removed first to commit restoration. Orphaned backup
    // copies are cleanup-only and cannot trigger a later rollback.
    std::fs::remove_file(path)?;
    for file in &manifest.files {
        file.cleanup()?;
    }
    cleanup_temporary_paths(&manifest.temporary_paths);
    Ok(())
}

fn write_unit(path: &Path, body: &str) -> anyhow::Result<()> {
    let staged = staged_unit_path(path);
    std::fs::write(&staged, body)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644))?;
    std::fs::File::open(&staged)?.sync_all()?;
    koi_common::persist::replace_file(&staged, path)?;
    Ok(())
}

fn stop_failed_replacement() -> anyhow::Result<()> {
    // `Restart=on-failure` can leave an auto-restart queued while is-active is
    // already false. An unconditional stop cancels that job before files are
    // restored. A missing unit is harmless; a still-active process is not.
    let output = systemctl_output(&["stop", SERVICE_NAME]);
    if systemctl(&["is-active", SERVICE_NAME]) {
        return match output {
            Ok(output) => anyhow::bail!(
                "could not stop the failed replacement: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(error) => Err(anyhow::anyhow!(
                "could not stop the failed replacement: {error}"
            )),
        };
    }
    Ok(())
}

fn cleanup_temporary_paths(paths: &[PathBuf]) {
    for path in paths {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "  Warning: could not remove installer staging file {}: {error}",
                path.display()
            ),
        }
    }
}

fn verify_service_process(bin: &Path) -> anyhow::Result<()> {
    if !systemctl(&["is-active", SERVICE_NAME]) {
        anyhow::bail!("systemd did not keep {SERVICE_NAME}.service active");
    }
    let output = systemctl_checked_output(
        &["show", SERVICE_NAME, "--property=MainPID", "--value"],
        "query the installed service process",
    )?;
    let pid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()?;
    if pid == 0 {
        anyhow::bail!("systemd reports no main process for {SERVICE_NAME}.service");
    }
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

fn systemctl_checked(args: &[&str], action: &str) -> anyhow::Result<()> {
    systemctl_checked_output(args, action).map(|_| ())
}

fn systemctl_checked_output(args: &[&str], action: &str) -> anyhow::Result<std::process::Output> {
    let output =
        systemctl_output(args).map_err(|error| anyhow::anyhow!("could not {action}: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "could not {action}: systemctl {} exited {}{}{}",
            args.join(" "),
            output.status,
            if detail.is_empty() { "" } else { ": " },
            detail
        );
    }
    Ok(output)
}

/// Install as a user service (no root — running with sudo is refused).
pub fn install_user() -> anyhow::Result<()> {
    if unsafe { libc::getuid() } == 0 {
        anyhow::bail!("--user installs belong to your user account; run without sudo");
    }
    let exe = std::env::current_exe()?;
    let bin = user_bin_path()?;
    let unit = user_unit_path();

    println!("Installing Koi user service (systemd --user)...");
    println!("  Binary: {}", exe.display());

    if let Some(parent) = bin.parent() {
        std::fs::create_dir_all(parent)?;
    }
    print!("  Staging {}...", bin.display());
    if super::stage_binary(&exe, &bin)? {
        println!(" done.");
    } else {
        println!(" already in place.");
    }

    let config = user_config_path()?;
    let existing = honor_existing_config(&config);
    let planned = match &existing {
        Existing::Declared(plan, _) => *plan,
        _ => plan_ports(),
    };
    let persisted = persist_plan(&existing, &planned, &config);

    if let Some(parent) = unit.parent() {
        std::fs::create_dir_all(parent)?;
    }
    print!("  Writing {}...", unit.display());
    std::fs::write(&unit, render(USER_UNIT_TEMPLATE, &bin))?;
    println!(" done.");

    let _ = systemctl_user(&["daemon-reload"]);
    let _ = systemctl_user(&["enable", SERVICE_NAME]);
    match systemctl_user(&["start", SERVICE_NAME]) {
        Ok(o) if o.status.success() => println!("  Service started"),
        Ok(o) => println!(
            "  Warning: could not start: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => println!("  Warning: could not start: {e}"),
    }
    // Linger: the user service should run at boot, not only at login.
    match Command::new("loginctl").args(["enable-linger"]).output() {
        Ok(o) if o.status.success() => println!("  Linger enabled (starts at boot)"),
        _ => println!("  Warning: could not enable linger (starts at login instead)"),
    }

    print!("  Verifying (healthz on {})...", planned.http);
    if healthz_wait(planned.http, std::time::Duration::from_secs(20)) {
        println!(" healthy.");
    } else {
        println!(" NOT answering yet — check journalctl --user -u {SERVICE_NAME}");
    }

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
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        anyhow::bail!("HOME is not set; cannot locate ~/.local/bin");
    }
    Ok(PathBuf::from(home).join(".local/bin/koi"))
}

fn user_config_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        anyhow::bail!("HOME is not set; cannot locate the user config");
    }
    Ok(PathBuf::from(home).join(".config/koi/config.toml"))
}

/// Uninstall the system service (drops the unit and any drop-in directory;
/// the binary and operator config are preserved).
pub fn uninstall_system() -> anyhow::Result<()> {
    let unit = system_unit_path();
    if !unit.exists() {
        return Ok(());
    }
    super::super::check_root("uninstall")?;
    println!("Uninstalling Koi service (systemd)...");

    if let Some(bc) = koi_config::breadcrumb::read_breadcrumb() {
        let client = crate::client::KoiClient::with_token(&bc.endpoint, &bc.token);
        if client.shutdown().is_ok() {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    if systemctl(&["is-active", SERVICE_NAME]) {
        print!("  Stopping service...");
        let _ = systemctl_output(&["stop", SERVICE_NAME]);
        println!(" done.");
    }
    let _ = systemctl_output(&["disable", SERVICE_NAME]);
    print!("  Removing {}...", unit.display());
    match std::fs::remove_file(&unit) {
        Ok(()) => println!(" done."),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!(" already removed."),
        Err(e) => println!(" warning: {e}"),
    }
    // The pre-036 fleet mechanism: drop-ins must not outlive the unit.
    let dropin = PathBuf::from("/etc/systemd/system/koi.service.d");
    if dropin.exists() {
        print!("  Removing {}...", dropin.display());
        match std::fs::remove_dir_all(&dropin) {
            Ok(()) => println!(" done."),
            Err(e) => println!(" warning: {e}"),
        }
    }
    let _ = systemctl_output(&["daemon-reload"]);
    koi_config::breadcrumb::delete_breadcrumb();

    if install_bin_path().exists() {
        println!("  Binary preserved at: {}", install_bin_path().display());
    }
    println!();
    println!("Koi service uninstalled.");
    Ok(())
}

/// Uninstall the user service.
pub fn uninstall_user() -> anyhow::Result<()> {
    let unit = user_unit_path();
    if !unit.exists() {
        return Ok(());
    }
    println!("Uninstalling Koi user service (systemd)...");
    if let Some(bc) = koi_config::breadcrumb::read_breadcrumb() {
        let client = crate::client::KoiClient::with_token(&bc.endpoint, &bc.token);
        if client.shutdown().is_ok() {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    let _ = systemctl_user(&["disable", "--now", SERVICE_NAME]);
    match std::fs::remove_file(&unit) {
        Ok(()) => println!("  Removed {}", unit.display()),
        Err(e) => println!("  warning: {e}"),
    }
    let _ = systemctl_user(&["daemon-reload"]);
    let _ = Command::new("loginctl").args(["disable-linger"]).output();
    koi_config::breadcrumb::delete_breadcrumb();
    println!("Koi user service uninstalled.");
    Ok(())
}

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn systemctl_output(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("systemctl").args(args).output()
}

fn systemctl_user(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("systemctl")
        .args(["--user"])
        .args(args)
        .output()
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
        let unit = render(USER_UNIT_TEMPLATE, &PathBuf::from("/home/x/.local/bin/koi"));
        assert!(unit.contains("ExecStart=/home/x/.local/bin/koi --daemon"));
        assert!(
            !unit.contains("XDG_CONFIG_HOME"),
            "user services use the natural ~/.config path"
        );
        assert!(unit.contains("WantedBy=default.target"));
        assert!(!unit.contains("{{"));
    }

    #[test]
    fn file_snapshots_restore_existing_and_remove_new_targets() {
        let root = transaction_test_root("restore");
        let existing = root.join("existing");
        let new = root.join("new");
        std::fs::write(&existing, "before").unwrap();

        let existing_snapshot = FileSnapshot::inspect(existing.clone()).unwrap();
        let new_snapshot = FileSnapshot::inspect(new.clone()).unwrap();
        existing_snapshot.prepare().unwrap();
        new_snapshot.prepare().unwrap();
        std::fs::write(&existing, "after").unwrap();
        std::fs::write(&new, "created").unwrap();

        existing_snapshot.validate_backup().unwrap();
        new_snapshot.validate_backup().unwrap();
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
        let error = snapshot.validate_backup().unwrap_err().to_string();
        assert!(error.contains("recovery is incomplete"));
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
            super::super::ports_from_config_body(&config),
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
        let snapshot = FileSnapshot::inspect(target.clone()).unwrap();
        let manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Preparing,
            was_active: false,
            was_enabled: false,
            http_port: 5641,
            files: vec![snapshot.clone()],
            temporary_paths: vec![staged_restore_path(&target)],
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
}
