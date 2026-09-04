//! macOS launchd service adapter.
//!
//! The adapter owns one crash-recoverable transition around the exact plist,
//! executable, configuration, local operator, launchd generation, and runtime
//! breadcrumb. A command succeeds only after launchd, the real process image,
//! and Koi's health boundary agree.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};

use super::recipes::transaction::{staged_restore_path, FileSnapshot};

const LABEL: &str = "org.sylin.koi";
const TRANSACTION_VERSION: u16 = 1;
const TRANSACTION_FILENAME: &str = "launchd-install-transaction.json";

pub fn plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons/org.sylin.koi.plist")
}

pub fn install_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/koi")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Preparing,
    Armed,
    Settled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LaunchdManifest {
    version: u16,
    phase: TransactionPhase,
    was_loaded: bool,
    http_port: u16,
    files: Vec<FileSnapshot>,
    temporary_paths: Vec<PathBuf>,
}

struct LaunchdTransaction {
    path: PathBuf,
    manifest: LaunchdManifest,
}

impl LaunchdTransaction {
    fn begin(
        data_dir: &Path,
        was_loaded: bool,
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
            .map(|file| staged_restore_path(&file.path))
            .collect();
        let mut manifest = LaunchdManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Preparing,
            was_loaded,
            http_port,
            files,
            temporary_paths,
        };
        write_manifest(&path, &manifest)?;
        for file in &mut manifest.files {
            if let Err(error) = file.prepare() {
                let cleanup = settle_and_cleanup(&path, &manifest);
                if let Err(cleanup_error) = cleanup {
                    return Err(error.context(format!(
                        "launchd checkpoint cleanup is incomplete ({cleanup_error}); re-run the command to recover"
                    )));
                }
                return Err(error);
            }
        }
        manifest.phase = TransactionPhase::Armed;
        if let Err(error) = write_manifest(&path, &manifest) {
            if let Err(cleanup_error) = settle_and_cleanup(&path, &manifest) {
                return Err(error.context(format!(
                    "could not disarm the launchd checkpoint ({cleanup_error}); re-run the command to recover"
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
        self.manifest.phase = TransactionPhase::Armed;
        write_manifest(&self.path, &self.manifest)?;
        restore_manifest(&self.path, &self.manifest)
    }
}

pub fn install(user: bool, operator: Option<&str>, data_dir: &Path) -> anyhow::Result<()> {
    if user {
        anyhow::bail!(
            "--user installs aren't supported on macOS yet (the LaunchAgent shape is not fleet-verified); use `koi install` for the system daemon"
        );
    }
    check_root("install")?;
    let _install_lock = super::install_lock::InstallLock::acquire_system()?;

    let exe = std::env::current_exe()?;
    let bin = install_bin_path();
    let plist = plist_path();
    let config = PathBuf::from("/etc/koi/config.toml");
    let manager = LaunchdManager;

    recover_interrupted(&transaction_path(data_dir))?;
    let prior = manager.observe(&plist)?;
    if prior.loaded {
        manager.verify_running(&prior, &bin)?;
    } else if prior.registered {
        manager.verify_registration(&prior, &bin)?;
    }
    let existing = super::recipes::honor_existing_config(&config)?;
    let disposition = if prior.registered {
        super::recipes::InstallDisposition::ReplacingOwned
    } else {
        super::recipes::InstallDisposition::Fresh
    };
    let planned = super::recipes::plan_install_ports(&existing, disposition);
    let transaction = LaunchdTransaction::begin(
        data_dir,
        prior.loaded,
        planned.http,
        vec![
            bin.clone(),
            plist.clone(),
            config.clone(),
            koi_config::local_access::policy_path(data_dir),
            koi_config::breadcrumb::breadcrumb_path(),
        ],
    )?;

    println!("Installing Koi service (launchd)...");
    println!("  Binary: {}", exe.display());
    let result = (|| -> anyhow::Result<String> {
        super::record_unix_operator(false, operator, data_dir)?;
        if prior.loaded {
            manager.bootout(&plist)?;
        }
        install_owned_binary(&exe, &bin)?;
        let persisted = super::recipes::persist_plan_checked(&existing, &planned, &config)?;
        write_owned_file(&plist, generate_plist(&bin).as_bytes(), 0o644)?;
        manager.bootstrap(&plist)?;
        manager.wait_running(&plist, &bin, std::time::Duration::from_secs(20))?;
        if !super::recipes::healthz_wait(planned.http, std::time::Duration::from_secs(20)) {
            anyhow::bail!(
                "launchd service did not answer /healthz on {}; check /var/log/koi.err",
                planned.http
            );
        }
        Ok(persisted)
    })();
    let persisted = finish_install_transaction(transaction, result)?;

    println!();
    println!("Koi service installed.");
    println!("  Ports: {}", planned.describe());
    if !persisted.is_empty() {
        println!("  {persisted}");
    }
    println!("  Config: {} (koi config show)", config.display());
    println!("  Logs: /var/log/koi.log");
    println!("  Status: sudo launchctl print system/{LABEL}");
    Ok(())
}

pub fn uninstall(data_dir: &Path) -> anyhow::Result<()> {
    let plist = plist_path();
    let pending = super::recipes::regular_file_exists(&transaction_path(data_dir))?;
    if !super::recipes::regular_file_exists(&plist)? && !pending {
        println!("Koi is not installed as a launchd daemon. Nothing to uninstall.");
        return Ok(());
    }
    check_root("uninstall")?;
    let _install_lock = super::install_lock::InstallLock::acquire_system()?;
    recover_interrupted(&transaction_path(data_dir))?;
    if !super::recipes::regular_file_exists(&plist)? {
        println!("Koi is not installed as a launchd daemon. Nothing to uninstall.");
        return Ok(());
    }

    let manager = LaunchdManager;
    let prior = manager.observe(&plist)?;
    if !prior.registered {
        anyhow::bail!("launchd service registration disappeared during uninstall preflight");
    }
    if prior.loaded {
        manager.verify_running(&prior, &install_bin_path())?;
    } else {
        manager.verify_registration(&prior, &install_bin_path())?;
    }
    let config = PathBuf::from("/etc/koi/config.toml");
    let existing = super::recipes::honor_existing_config(&config)?;
    let http_port = match existing {
        super::recipes::Existing::Declared(plan, _) => plan.http,
        super::recipes::Existing::ConfigWithoutPorts(_) | super::recipes::Existing::Nothing => {
            super::recipes::STD_HTTP
        }
    };
    let owned_files = vec![plist.clone(), koi_config::breadcrumb::breadcrumb_path()];
    let transaction =
        LaunchdTransaction::begin(data_dir, prior.loaded, http_port, owned_files.clone())?;
    let result = (|| -> anyhow::Result<()> {
        if prior.loaded {
            manager.bootout(&plist)?;
        }
        for path in &owned_files {
            remove_file_durable(path)?;
        }
        let absent = manager.observe(&plist)?;
        if absent.registered || absent.loaded || absent.pid.is_some() {
            anyhow::bail!("launchd retained the Koi daemon after uninstall");
        }
        Ok(())
    })();
    finish_unit_transaction(transaction, result, "uninstall")?;

    if super::recipes::regular_file_exists(&install_bin_path())? {
        println!("  Binary preserved at: {}", install_bin_path().display());
    }
    println!("Koi service uninstalled.");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaunchdState {
    registered: bool,
    loaded: bool,
    pid: Option<u32>,
    program: Option<PathBuf>,
}

struct LaunchdManager;

impl LaunchdManager {
    fn observe(&self, plist: &Path) -> anyhow::Result<LaunchdState> {
        self.observe_with(plist, false)
    }

    fn observe_with(&self, plist: &Path, allow_nonrunning: bool) -> anyhow::Result<LaunchdState> {
        let output = Command::new("launchctl")
            .env("LC_ALL", "C")
            .args(["print", &format!("system/{LABEL}")])
            .output()
            .map_err(|error| anyhow::anyhow!("could not inspect launchd: {error}"))?;
        let registered = super::recipes::regular_file_exists(plist)?;
        if !output.status.success() {
            let detail = output_detail(&output);
            if detail.contains("Could not find service")
                || detail.contains("service not found")
                || detail.contains("Could not find specified service")
            {
                let program = registered.then(|| program_from_plist(plist)).transpose()?;
                return Ok(LaunchdState {
                    registered,
                    loaded: false,
                    pid: None,
                    program,
                });
            }
            anyhow::bail!(
                "could not inspect launchd: launchctl print exited {}{}{}",
                output.status,
                if detail.is_empty() { "" } else { ": " },
                detail
            );
        }
        if !registered {
            anyhow::bail!("launchd has a live Koi job without the installer-owned plist");
        }
        parse_launchctl_print(&String::from_utf8(output.stdout)?, plist, allow_nonrunning)
    }

    fn bootstrap(&self, plist: &Path) -> anyhow::Result<()> {
        checked_output(
            Command::new("launchctl")
                .env("LC_ALL", "C")
                .args(["bootstrap", "system", &plist.display().to_string()])
                .output(),
            "bootstrap the Koi LaunchDaemon",
            "launchctl bootstrap system",
        )?;
        Ok(())
    }

    fn bootout(&self, plist: &Path) -> anyhow::Result<()> {
        let previous = self.observe_with(plist, true)?;
        checked_output(
            Command::new("launchctl")
                .env("LC_ALL", "C")
                .args(["bootout", &format!("system/{LABEL}")])
                .output(),
            "boot out the Koi LaunchDaemon",
            "launchctl bootout",
        )?;
        let state = self.observe_with(plist, true)?;
        if state.loaded || state.pid.is_some() {
            anyhow::bail!("launchd retained the Koi job after bootout");
        }
        if let Some(pid) = previous.pid {
            wait_for_process_exit(pid, std::time::Duration::from_secs(5))?;
        }
        Ok(())
    }

    fn verify_running(&self, state: &LaunchdState, expected_bin: &Path) -> anyhow::Result<()> {
        if !state.registered || !state.loaded {
            anyhow::bail!("launchd did not retain the Koi LaunchDaemon");
        }
        let pid = state
            .pid
            .ok_or_else(|| anyhow::anyhow!("launchd reports no running Koi process"))?;
        self.verify_registration(state, expected_bin)?;
        let expected = std::fs::canonicalize(expected_bin)?;
        let output = checked_output(
            Command::new("/bin/ps")
                .env("LC_ALL", "C")
                .args(["-p", &pid.to_string(), "-o", "command="])
                .output(),
            "inspect the launchd process image",
            "/bin/ps",
        )?;
        let command = String::from_utf8(output.stdout)?;
        let image = command
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("ps returned no image for launchd PID {pid}"))?;
        let actual = std::fs::canonicalize(image)?;
        if actual != expected {
            anyhow::bail!(
                "launchd PID {pid} runs {} instead of {}",
                actual.display(),
                expected.display()
            );
        }
        Ok(())
    }

    fn wait_running(
        &self,
        plist: &Path,
        expected_bin: &Path,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let state = self.observe_with(plist, true)?;
            if state.loaded && state.pid.is_some() {
                return self.verify_running(&state, expected_bin);
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("launchd did not establish a running Koi process before timeout");
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    fn verify_registration(&self, state: &LaunchdState, expected_bin: &Path) -> anyhow::Result<()> {
        if !state.registered {
            anyhow::bail!("launchd has no installer-owned Koi registration");
        }
        let declared = state
            .program
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("launchd reports no Koi program image"))?;
        let expected = std::fs::canonicalize(expected_bin)?;
        let declared = std::fs::canonicalize(declared)?;
        if declared != expected {
            anyhow::bail!(
                "launchd declares {} instead of {}",
                declared.display(),
                expected.display()
            );
        }
        Ok(())
    }
}

fn wait_for_process_exit(pid: u32, timeout: std::time::Duration) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while process_exists(pid)? {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("launchd removed its job but Koi PID {pid} is still running");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(())
}

fn process_exists(pid: u32) -> anyhow::Result<bool> {
    let pid = i32::try_from(pid).map_err(|_| anyhow::anyhow!("invalid launchd PID {pid}"))?;
    if pid <= 0 {
        anyhow::bail!("invalid launchd PID {pid}");
    }
    // SAFETY: kill with signal 0 does not deliver a signal and accepts any
    // representable pid_t; it only probes whether that process still exists.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error.into()),
    }
}

fn parse_launchctl_print(
    body: &str,
    plist: &Path,
    allow_nonrunning: bool,
) -> anyhow::Result<LaunchdState> {
    let mut state = None;
    let mut pid = None;
    let mut program = None;
    let mut manifest = None;
    for line in body.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("state = ") {
            if state.is_none() {
                state = Some(value.trim().to_string());
            }
        } else if let Some(value) = line.strip_prefix("pid = ") {
            if pid.is_none() {
                pid = Some(value.trim().parse::<u32>()?);
            }
        } else if let Some(value) = line.strip_prefix("program = ") {
            if program.is_none() {
                program = Some(PathBuf::from(value.trim()));
            }
        } else if let Some(value) = line.strip_prefix("path = ") {
            if manifest.is_none() {
                manifest = Some(PathBuf::from(value.trim()));
            }
        }
    }
    let state = state.ok_or_else(|| anyhow::anyhow!("launchctl omitted job state"))?;
    if state != "running" && !allow_nonrunning {
        anyhow::bail!("unsupported launchd job state '{state}'; settle it before continuing");
    }
    let manifest = manifest.ok_or_else(|| anyhow::anyhow!("launchctl omitted plist path"))?;
    if std::fs::canonicalize(&manifest)? != std::fs::canonicalize(plist)? {
        anyhow::bail!(
            "launchd loaded Koi from {}, not {}",
            manifest.display(),
            plist.display()
        );
    }
    Ok(LaunchdState {
        registered: true,
        loaded: true,
        pid: if state == "running" { pid } else { None },
        program,
    })
}

fn program_from_plist(path: &Path) -> anyhow::Result<PathBuf> {
    let body = std::fs::read_to_string(path)?;
    let marker = "<key>ProgramArguments</key>";
    let tail = body
        .split_once(marker)
        .map(|(_, tail)| tail)
        .ok_or_else(|| anyhow::anyhow!("{} has no ProgramArguments", path.display()))?;
    let value = tail
        .split_once("<string>")
        .and_then(|(_, tail)| tail.split_once("</string>"))
        .map(|(value, _)| value)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{} has no program path", path.display()))?;
    let program = PathBuf::from(value.trim());
    if !program.is_absolute() || !super::recipes::regular_file_exists(&program)? {
        anyhow::bail!("{} declares an unavailable program image", path.display());
    }
    Ok(program)
}

fn install_owned_binary(source: &Path, target: &Path) -> anyhow::Result<()> {
    let (outcome, _) = koi_common::persist::copy_file_atomic_with_options_and_prepare_stage(
        source,
        target,
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o755),
        chown_root_wheel,
    )?;
    koi_common::persist::require_durable(outcome, "installing the launchd executable")?;
    Ok(())
}

fn write_owned_file(path: &Path, body: &[u8], mode: u32) -> anyhow::Result<()> {
    let outcome = koi_common::persist::write_bytes_atomic_with_options_and_prepare_stage(
        path,
        body,
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(mode),
        chown_root_wheel,
    )?;
    koi_common::persist::require_durable(outcome, "installing the launchd plist")?;
    Ok(())
}

fn chown_root_wheel(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    if unsafe { libc::chown(path.as_ptr(), 0, 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn checked_output(
    result: std::io::Result<Output>,
    action: &str,
    command: &str,
) -> anyhow::Result<Output> {
    let output = result.map_err(|error| anyhow::anyhow!("could not {action}: {error}"))?;
    if !output.status.success() {
        let detail = output_detail(&output);
        anyhow::bail!(
            "could not {action}: {command} exited {}{}{}",
            output.status,
            if detail.is_empty() { "" } else { ": " },
            detail
        );
    }
    Ok(output)
}

fn output_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    }
}

fn transaction_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state").join(TRANSACTION_FILENAME)
}

fn write_manifest(path: &Path, manifest: &LaunchdManifest) -> anyhow::Result<()> {
    let outcome = koi_common::persist::write_json_pretty_commit_with_options(
        path,
        manifest,
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o600),
    )?;
    koi_common::persist::require_durable(outcome, "persisting the launchd transaction")?;
    Ok(())
}

fn recover_interrupted(path: &Path) -> anyhow::Result<()> {
    let manifest = match koi_common::persist::read_json::<LaunchdManifest>(path) {
        Ok(manifest) => manifest,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => anyhow::bail!(
            "cannot recover launchd transaction {}: {error}",
            path.display()
        ),
    };
    if manifest.version != TRANSACTION_VERSION {
        anyhow::bail!(
            "cannot recover launchd transaction {}: unsupported version {}",
            path.display(),
            manifest.version
        );
    }
    match manifest.phase {
        TransactionPhase::Preparing => settle_and_cleanup(path, &manifest),
        TransactionPhase::Armed => restore_manifest(path, &manifest),
        TransactionPhase::Settled => cleanup_settled(path, &manifest),
    }
}

fn restore_manifest(path: &Path, manifest: &LaunchdManifest) -> anyhow::Result<()> {
    for file in &manifest.files {
        file.validate_backup(true)?;
    }
    let expected_registered = manifest
        .files
        .iter()
        .find(|file| file.path == plist_path())
        .ok_or_else(|| anyhow::anyhow!("launchd recovery manifest omits its plist"))?
        .existed;
    let manager = LaunchdManager;
    let current = manager.observe_with(&plist_path(), true)?;
    if current.loaded {
        manager.bootout(&plist_path())?;
    }
    for file in &manifest.files {
        file.restore()?;
    }
    if manifest.was_loaded {
        manager.bootstrap(&plist_path())?;
        let binary = program_from_plist(&plist_path())?;
        manager.wait_running(&plist_path(), &binary, std::time::Duration::from_secs(20))?;
        if !super::recipes::healthz_wait(manifest.http_port, std::time::Duration::from_secs(20)) {
            anyhow::bail!(
                "restored launchd service did not answer /healthz on {}",
                manifest.http_port
            );
        }
    }
    let final_state = manager.observe(&plist_path())?;
    if final_state.registered != expected_registered || final_state.loaded != manifest.was_loaded {
        anyhow::bail!("launchd rollback did not restore the exact registration and loaded state");
    }
    settle_and_cleanup(path, manifest)
}

fn settle_and_cleanup(path: &Path, manifest: &LaunchdManifest) -> anyhow::Result<()> {
    let mut settled = manifest.clone();
    settled.phase = TransactionPhase::Settled;
    write_manifest(path, &settled)?;
    cleanup_settled(path, &settled)
}

fn cleanup_settled(path: &Path, manifest: &LaunchdManifest) -> anyhow::Result<()> {
    for file in &manifest.files {
        if let Err(error) = file.cleanup() {
            eprintln!(
                "  Warning: committed launchd backup {} remains for cleanup: {error}",
                file.backup.display()
            );
            return Ok(());
        }
    }
    for temporary in &manifest.temporary_paths {
        let cleaned = koi_common::persist::remove_file_durable(temporary).and_then(|outcome| {
            koi_common::persist::require_durable(outcome, "removing launchd transaction debris")
        });
        if let Err(error) = cleaned {
            eprintln!("  Warning: committed launchd staging remains for cleanup: {error}");
            return Ok(());
        }
    }
    let cleaned = koi_common::persist::remove_file_durable(path).and_then(|outcome| {
        koi_common::persist::require_durable(outcome, "removing the settled launchd transaction")
    });
    if let Err(error) = cleaned {
        eprintln!("  Warning: settled launchd transaction remains for cleanup: {error}");
    }
    Ok(())
}

fn remove_file_durable(path: &Path) -> anyhow::Result<()> {
    let outcome = koi_common::persist::remove_file_durable(path)?;
    koi_common::persist::require_durable(outcome, "removing a launchd installation file")?;
    Ok(())
}

fn finish_install_transaction(
    mut transaction: LaunchdTransaction,
    result: anyhow::Result<String>,
) -> anyhow::Result<String> {
    match result {
        Ok(summary) => match transaction.commit() {
            Ok(()) => Ok(summary),
            Err(commit_error) => match transaction.rollback() {
                Ok(()) => anyhow::bail!(
                    "installation commit failed and the previous LaunchDaemon was restored: {commit_error}"
                ),
                Err(rollback_error) => anyhow::bail!(
                    "installation commit failed ({commit_error}); rollback is incomplete ({rollback_error}); re-run `koi install` to recover"
                ),
            },
        },
        Err(install_error) => match transaction.rollback() {
            Ok(()) => anyhow::bail!(
                "installation failed and the previous LaunchDaemon was restored: {install_error}"
            ),
            Err(rollback_error) => anyhow::bail!(
                "installation failed ({install_error}); rollback is incomplete ({rollback_error}); re-run `koi install` to recover"
            ),
        },
    }
}

fn finish_unit_transaction(
    mut transaction: LaunchdTransaction,
    result: anyhow::Result<()>,
    operation: &str,
) -> anyhow::Result<()> {
    match result {
        Ok(()) => match transaction.commit() {
            Ok(()) => Ok(()),
            Err(commit_error) => match transaction.rollback() {
                Ok(()) => anyhow::bail!(
                    "{operation} commit failed and the previous LaunchDaemon was restored: {commit_error}"
                ),
                Err(rollback_error) => anyhow::bail!(
                    "{operation} commit failed ({commit_error}); rollback is incomplete ({rollback_error}); re-run the command to recover"
                ),
            },
        },
        Err(operation_error) => match transaction.rollback() {
            Ok(()) => anyhow::bail!(
                "{operation} failed and the previous LaunchDaemon was restored: {operation_error}"
            ),
            Err(rollback_error) => anyhow::bail!(
                "{operation} failed ({operation_error}); rollback is incomplete ({rollback_error}); re-run the command to recover"
            ),
        },
    }
}

fn generate_plist(bin_path: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>XDG_CONFIG_HOME</key>
        <string>/etc</string>
    </dict>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/koi.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/koi.err</string>
</dict>
</plist>
"#,
        bin = bin_path.display()
    )
}

use super::check_root;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_contains_owned_label_binary_and_config_root() {
        let plist = generate_plist(Path::new("/usr/local/bin/koi"));
        assert!(plist.contains(LABEL));
        assert!(plist.contains("<string>/usr/local/bin/koi</string>"));
        assert!(plist.contains("<string>/etc</string>"));
    }

    #[test]
    fn launchctl_parser_requires_running_pid_and_owned_manifest() {
        let root = std::env::temp_dir().join(format!("koi-launchd-parser-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let plist = root.join("koi.plist");
        std::fs::write(&plist, "plist").unwrap();
        let body = format!(
            "system/{LABEL} = {{\n\tpath = {}\n\tstate = running\n\tprogram = /usr/local/bin/koi\n\tpid = 42\n}}",
            plist.display()
        );
        let state = parse_launchctl_print(&body, &plist, false).unwrap();
        assert!(state.loaded);
        assert_eq!(state.pid, Some(42));
        assert_eq!(state.program, Some(PathBuf::from("/usr/local/bin/koi")));
        assert!(parse_launchctl_print(&body.replace("running", "waiting"), &plist, false).is_err());
        assert!(parse_launchctl_print(&body.replace("running", "waiting"), &plist, true).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn armed_recovery_rejects_changed_backup_before_launchd_effects() {
        let root =
            std::env::temp_dir().join(format!("koi-launchd-corrupt-backup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        std::fs::write(&target, "prior").unwrap();
        let mut snapshot = FileSnapshot::inspect(target.clone()).unwrap();
        snapshot.prepare().unwrap();
        let manifest = LaunchdManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Armed,
            was_loaded: false,
            http_port: 5641,
            files: vec![snapshot.clone()],
            temporary_paths: vec![],
        };
        write_manifest(&manifest_path, &manifest).unwrap();
        std::fs::write(&snapshot.backup, "changed").unwrap();

        let error = recover_interrupted(&manifest_path).unwrap_err().to_string();
        assert!(error.contains("changed"));
        assert_eq!(std::fs::read_to_string(target).unwrap(), "prior");
        assert!(manifest_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn recovery_manifest_without_plist_fails_before_launchd_effects() {
        let root =
            std::env::temp_dir().join(format!("koi-launchd-missing-plist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let manifest_path = root.join(TRANSACTION_FILENAME);
        let manifest = LaunchdManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Armed,
            was_loaded: false,
            http_port: 5641,
            files: vec![],
            temporary_paths: vec![],
        };
        write_manifest(&manifest_path, &manifest).unwrap();

        let error = recover_interrupted(&manifest_path).unwrap_err().to_string();
        assert!(error.contains("omits its plist"));
        assert!(manifest_path.exists(), "invalid recovery stays armed");
        let _ = std::fs::remove_dir_all(root);
    }
}
