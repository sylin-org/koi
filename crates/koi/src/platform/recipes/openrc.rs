//! OpenRC recipe (ADR-036): Alpine, Gentoo, Artix-openrc.
//!
//! Installation is a durable transaction: the binary, init script, port
//! configuration, local-operator policy, log rotation, and prior OpenRC state
//! are checkpointed before the running service is touched. Enable, start,
//! process-identity, and health failures restore the previous installation.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};

use super::transaction::{staged_restore_path, FileSnapshot};
use super::{healthz_wait, honor_existing_config, persist_plan_checked, plan_ports, Existing};

const SERVICE_NAME: &str = "koi";
const TRANSACTION_VERSION: u16 = 1;
const TRANSACTION_FILENAME: &str = "openrc-install-transaction.json";
const INITD_TEMPLATE: &str = include_str!("templates/koi-openrc.initd");
const LOGROTATE_TEMPLATE: &str = include_str!("templates/koi.logrotate");
const LOG_DIR: &str = "/var/log/koi";
const LOG_FILE: &str = "/var/log/koi/daemon.log";

pub fn initd_path() -> PathBuf {
    PathBuf::from("/etc/init.d/koi")
}

pub fn logrotate_path() -> PathBuf {
    PathBuf::from("/etc/logrotate.d/koi")
}

pub fn install_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/koi")
}

fn install_bin_path_for(exe: &Path) -> PathBuf {
    // A native package owns /usr/bin/koi. Running its installer must preserve
    // that ownership instead of manufacturing an unowned /usr/local copy.
    if exe == Path::new("/usr/bin/koi") {
        exe.to_path_buf()
    } else {
        install_bin_path()
    }
}

fn render_initd(bin: &Path) -> String {
    INITD_TEMPLATE
        .replace("\r\n", "\n")
        .replace("{{BIN}}", &bin.display().to_string())
}

fn render_logrotate() -> String {
    LOGROTATE_TEMPLATE.replace("\r\n", "\n")
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
    was_started: bool,
    was_enabled: bool,
    http_port: u16,
    log_dir_existed: bool,
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
        was_started: bool,
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
            .flat_map(|file| {
                [
                    staged_restore_path(&file.path),
                    staged_write_path(&file.path),
                ]
            })
            .collect();
        let mut manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Preparing,
            was_started,
            was_enabled,
            http_port,
            log_dir_existed: Path::new(LOG_DIR).exists(),
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

pub fn install_system(operator: Option<&str>, data_dir: &Path) -> anyhow::Result<()> {
    super::super::check_root("install")?;
    recover_interrupted(&transaction_path(data_dir))?;
    require_openrc_tools()?;

    let exe = std::env::current_exe()?;
    let bin = install_bin_path_for(&exe);
    let initd = initd_path();
    let logrotate = logrotate_path();
    println!("Installing Koi service (OpenRC)...");
    println!("  Binary: {}", exe.display());

    let was_started = rc_service_status();
    let was_enabled = rc_update_enabled()?;

    let config = PathBuf::from("/etc/koi/config.toml");
    let existing = honor_existing_config(&config);
    let planned = match &existing {
        Existing::Declared(plan, _) => *plan,
        _ => plan_ports(),
    };
    let policy = koi_config::local_access::policy_path(data_dir);
    let transaction = InstallTransaction::begin(
        data_dir,
        was_started,
        was_enabled,
        planned.http,
        vec![
            bin.clone(),
            initd.clone(),
            config.clone(),
            policy,
            logrotate.clone(),
        ],
    )?;

    let result = (|| -> anyhow::Result<String> {
        super::super::record_unix_operator(false, operator, data_dir)?;
        if was_started || was_enabled {
            println!("  Existing service found, updating...");
        }
        if was_started {
            print!("  Stopping service...");
            rc_service_checked("stop", "stop the existing service")?;
            println!(" done.");
        }

        print!("  Staging {}...", bin.display());
        if super::stage_binary(&exe, &bin)? {
            println!(" done.");
        } else {
            println!(" already in place.");
        }

        let persisted = persist_plan_checked(&existing, &planned, &config)?;
        std::fs::create_dir_all(LOG_DIR)?;
        write_file(&initd, &render_initd(&bin), 0o755)?;
        println!("  Wrote {}", initd.display());
        write_file(&logrotate, &render_logrotate(), 0o644)?;
        println!("  Wrote {}", logrotate.display());

        rc_update_checked("add", "enable the service")?;
        println!("  Service enabled (default runlevel)");
        rc_service_checked("start", "start the service")?;
        println!(
            "  Service {}",
            if was_started { "restarted" } else { "started" }
        );

        verify_service_process(&bin)?;
        print!("  Verifying (healthz on {})...", planned.http);
        if !healthz_wait(planned.http, std::time::Duration::from_secs(20)) {
            println!(" failed.");
            anyhow::bail!(
                "service did not answer /healthz on {}; check {LOG_FILE}",
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
    println!("  Logs: {LOG_FILE} (rotated by {})", logrotate.display());
    println!("  Status: rc-service {SERVICE_NAME} status");
    Ok(())
}

pub fn uninstall_system() -> anyhow::Result<()> {
    let initd = initd_path();
    if !initd.exists() {
        return Ok(());
    }
    super::super::check_root("uninstall")?;
    println!("Uninstalling Koi service (OpenRC)...");

    if let Some(bc) = koi_config::breadcrumb::read_breadcrumb() {
        let client = crate::client::KoiClient::with_token(&bc.endpoint, &bc.token);
        if client.shutdown().is_ok() {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    if rc_service_status() {
        print!("  Stopping service...");
        rc_service_checked("stop", "stop the service")?;
        println!(" done.");
    }
    if rc_update_enabled()? {
        rc_update_checked("delete", "disable the service")?;
    }
    remove_file_checked(&initd)?;
    remove_file_checked(&logrotate_path())?;
    let _ = std::fs::remove_file("/run/koi.pid");
    koi_config::breadcrumb::delete_breadcrumb();
    if install_bin_path().exists() {
        println!("  Binary preserved at: {}", install_bin_path().display());
    }
    println!();
    println!("Koi service uninstalled.");
    Ok(())
}

fn transaction_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state").join(TRANSACTION_FILENAME)
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
                "  Recovering an interrupted OpenRC installation from {}...",
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

    let enabled_now = rc_update_enabled()?;
    if manifest.was_enabled && !enabled_now {
        rc_update_checked("add", "restore service enablement")?;
    } else if !manifest.was_enabled && enabled_now {
        rc_update_checked("delete", "restore disabled service state")?;
    }
    if manifest.was_started {
        rc_service_checked("start", "restart the previous service")?;
        if !healthz_wait(manifest.http_port, std::time::Duration::from_secs(20)) {
            anyhow::bail!(
                "restored service did not answer /healthz on {}",
                manifest.http_port
            );
        }
    }

    std::fs::remove_file(path)?;
    for file in &manifest.files {
        file.cleanup()?;
    }
    cleanup_temporary_paths(&manifest.temporary_paths);
    cleanup_new_log_dir(manifest);
    Ok(())
}

fn require_openrc_tools() -> anyhow::Result<()> {
    for tool in ["rc-service", "rc-update", "supervise-daemon", "logrotate"] {
        if !command_exists(tool) {
            anyhow::bail!(
                "OpenRC installation requires `{tool}` on PATH; install the platform package that provides it and retry"
            );
        }
    }
    if !Path::new("/sbin/openrc-run").is_file() {
        anyhow::bail!("OpenRC installation requires /sbin/openrc-run");
    }
    Ok(())
}

fn command_exists(command: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(command))
            .any(|candidate| candidate.is_file())
    })
}

fn rc_service_status() -> bool {
    Command::new("rc-service")
        .args([SERVICE_NAME, "status"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn rc_update_enabled() -> anyhow::Result<bool> {
    let output = checked_output(
        Command::new("rc-update").args(["show", "default"]).output(),
        "query OpenRC enablement",
        "rc-update show default",
    )?;
    Ok(runlevel_contains(
        &String::from_utf8_lossy(&output.stdout),
        SERVICE_NAME,
    ))
}

fn runlevel_contains(output: &str, service: &str) -> bool {
    output.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.first() == Some(&service) && fields.contains(&"default")
    })
}

fn rc_service_checked(action: &str, description: &str) -> anyhow::Result<()> {
    let rendered = format!("rc-service {SERVICE_NAME} {action}");
    checked_output(
        Command::new("rc-service")
            .args([SERVICE_NAME, action])
            .output(),
        description,
        &rendered,
    )
    .map(|_| ())
}

fn rc_update_checked(action: &str, description: &str) -> anyhow::Result<()> {
    let rendered = format!("rc-update {action} {SERVICE_NAME} default");
    checked_output(
        Command::new("rc-update")
            .args([action, SERVICE_NAME, "default"])
            .output(),
        description,
        &rendered,
    )
    .map(|_| ())
}

fn checked_output(
    result: std::io::Result<Output>,
    action: &str,
    command: &str,
) -> anyhow::Result<Output> {
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

fn stop_failed_replacement() -> anyhow::Result<()> {
    if initd_path().exists() {
        let output = Command::new("rc-service")
            .args([SERVICE_NAME, "stop"])
            .output();
        if rc_service_status() {
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
    }
    Ok(())
}

fn verify_service_process(bin: &Path) -> anyhow::Result<()> {
    if !rc_service_status() {
        anyhow::bail!("OpenRC does not report {SERVICE_NAME} started");
    }
    let expected = std::fs::canonicalize(bin)?;
    let mut daemon_pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let process = entry.path();
        let Ok(actual) = std::fs::canonicalize(process.join("exe")) else {
            continue;
        };
        if actual != expected {
            continue;
        }
        let cmdline = std::fs::read(process.join("cmdline")).unwrap_or_default();
        if cmdline
            .split(|byte| *byte == 0)
            .any(|arg| arg == b"--daemon")
        {
            daemon_pids.push(name.to_string_lossy().into_owned());
        }
    }
    if daemon_pids.len() != 1 {
        anyhow::bail!(
            "OpenRC started {} Koi daemon processes from {} (PIDs: {})",
            daemon_pids.len(),
            expected.display(),
            daemon_pids.join(", ")
        );
    }
    Ok(())
}

fn write_file(path: &Path, body: &str, mode: u32) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let staged = staged_write_path(path);
    std::fs::write(&staged, body)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))?;
    std::fs::File::open(&staged)?.sync_all()?;
    koi_common::persist::replace_file(&staged, path)?;
    Ok(())
}

fn staged_write_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.new", path.display()))
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

fn cleanup_new_log_dir(manifest: &InstallManifest) {
    if manifest.log_dir_existed {
        return;
    }
    let _ = std::fs::remove_file(LOG_FILE);
    let _ = std::fs::remove_dir(LOG_DIR);
}

fn remove_file_checked(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            println!("  Removed {}", path.display());
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction_test_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "koi-openrc-transaction-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn initd_golden_uses_native_supervision_and_health() {
        let script = render_initd(Path::new("/usr/local/bin/koi"));
        assert!(script.starts_with("#!/sbin/openrc-run"));
        assert!(script.contains("command=\"/usr/local/bin/koi\""));
        assert!(script.contains("supervisor=\"supervise-daemon\""));
        assert!(script.contains("respawn_delay=5"));
        assert!(script.contains("respawn_max=3"));
        assert!(script.contains("respawn_period=60"));
        assert!(script.contains("healthcheck_timer=30"));
        assert!(script.contains("status --json"));
        assert!(!script.contains("command_background"));
        assert!(script.contains("need net"));
        assert!(!script.contains("{{"));
    }

    #[test]
    fn logrotate_policy_is_bounded() {
        let policy = render_logrotate();
        assert!(policy.contains(LOG_FILE));
        assert!(policy.contains("size 1M"));
        assert!(policy.contains("rotate 5"));
        assert!(policy.contains("compress"));
        assert!(policy.contains("copytruncate"));
    }

    #[test]
    fn packaged_binary_path_stays_package_owned() {
        assert_eq!(
            install_bin_path_for(Path::new("/usr/bin/koi")),
            PathBuf::from("/usr/bin/koi")
        );
        assert_eq!(
            install_bin_path_for(Path::new("/tmp/koi")),
            PathBuf::from("/usr/local/bin/koi")
        );
    }

    #[test]
    fn default_runlevel_parser_matches_only_koi() {
        let output = "                  koi | default\n                  sshd | default\n";
        assert!(runlevel_contains(output, "koi"));
        assert!(!runlevel_contains(output, "ko"));
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
            was_started: false,
            was_enabled: false,
            http_port: 5641,
            log_dir_existed: true,
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
