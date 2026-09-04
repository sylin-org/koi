//! OpenRC recipe (ADR-036): Alpine, Gentoo, Artix-openrc.
//!
//! Installation is a durable transaction: the binary, init script, port
//! configuration, local-operator policy, log rotation, and prior OpenRC state
//! are checkpointed before the running service is touched. Enable, start,
//! process-identity, and health failures restore the previous installation.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};

use super::transaction::{staged_restore_path, FileSnapshot};
use super::{
    healthz_wait, honor_existing_config, persist_plan_checked, plan_install_ports,
    InstallDisposition,
};

const SERVICE_NAME: &str = "koi";
const TRANSACTION_VERSION: u16 = 3;
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

fn installed_binary_from_initd(path: &Path) -> anyhow::Result<PathBuf> {
    let body = std::fs::read_to_string(path)?;
    let value = body
        .lines()
        .find_map(|line| line.trim().strip_prefix("command="))
        .map(|value| value.trim_matches(['\'', '"']))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{} does not declare an OpenRC command", path.display()))?;
    let binary = PathBuf::from(value);
    if !binary.is_absolute() || !super::regular_file_exists(&binary)? {
        anyhow::bail!(
            "{} declares a missing or non-absolute service image {}",
            path.display(),
            binary.display()
        );
    }
    Ok(binary)
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
    was_started: bool,
    was_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runlevels: Option<Vec<String>>,
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
        runlevels: Vec<String>,
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
            runlevels: Some(runlevels),
            http_port,
            log_dir_existed: directory_exists_strict(Path::new(LOG_DIR))?,
            files,
            temporary_paths,
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
        self.manifest.phase = TransactionPhase::Armed;
        write_manifest(&self.path, &self.manifest)?;
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

    let registered = super::regular_file_exists(&initd)?;
    let prior_runlevels = rc_update_runlevels()?;
    if !registered && !prior_runlevels.is_empty() {
        anyhow::bail!(
            "OpenRC retains Koi in runlevels ({}) without {}; repair that manager state before installing",
            prior_runlevels.join(", "),
            initd.display()
        );
    }
    let was_started = registered && rc_service_state(false)? == OpenRcState::Started;
    let was_enabled = prior_runlevels.iter().any(|level| level == "default");

    let config = PathBuf::from("/etc/koi/config.toml");
    let existing = honor_existing_config(&config)?;
    let disposition = if registered {
        InstallDisposition::ReplacingOwned
    } else {
        InstallDisposition::Fresh
    };
    let prior_bin = if disposition == InstallDisposition::ReplacingOwned {
        let prior_bin = installed_binary_from_initd(&initd)?;
        if was_started {
            verify_service_process(&prior_bin)?;
        } else {
            verify_service_process_count(&prior_bin, 0)?;
        }
        Some(prior_bin)
    } else {
        None
    };
    let mut expected_runlevels = prior_runlevels.clone();
    if !expected_runlevels.iter().any(|level| level == "default") {
        expected_runlevels.push("default".to_string());
        expected_runlevels.sort();
    }
    let planned = plan_install_ports(&existing, disposition);
    let policy = koi_config::local_access::policy_path(data_dir);
    let mut transaction = InstallTransaction::begin(
        data_dir,
        was_started,
        was_enabled,
        prior_runlevels,
        planned.http,
        vec![
            bin.clone(),
            initd.clone(),
            config.clone(),
            policy,
            logrotate.clone(),
            PathBuf::from(LOG_FILE),
            koi_config::breadcrumb::breadcrumb_path(),
            PathBuf::from("/run/koi.pid"),
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
            if rc_service_state(false)? != OpenRcState::Stopped {
                anyhow::bail!("OpenRC kept the previous service started after stop");
            }
            if let Some(prior_bin) = &prior_bin {
                verify_service_process_count(prior_bin, 0)?;
            }
            println!(" done.");
        }

        print!("  Staging {}...", bin.display());
        if super::stage_binary(&exe, &bin)? {
            println!(" done.");
        } else {
            println!(" already in place.");
        }

        let persisted = persist_plan_checked(&existing, &planned, &config)?;
        koi_common::persist::create_dir_all_durable(Path::new(LOG_DIR))?;
        write_file(&initd, &render_initd(&bin), 0o755)?;
        println!("  Wrote {}", initd.display());
        write_file(&logrotate, &render_logrotate(), 0o644)?;
        println!("  Wrote {}", logrotate.display());

        rc_update_checked("add", "default", "enable the service")?;
        println!("  Service enabled (default runlevel)");
        rc_service_checked("start", "start the service")?;
        println!(
            "  Service {}",
            if was_started { "restarted" } else { "started" }
        );

        let actual_runlevels = rc_update_runlevels()?;
        if actual_runlevels != expected_runlevels {
            anyhow::bail!(
                "OpenRC retained runlevels [{}], expected [{}]",
                actual_runlevels.join(", "),
                expected_runlevels.join(", ")
            );
        }
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

pub fn uninstall_system(data_dir: &Path) -> anyhow::Result<()> {
    let initd = initd_path();
    recover_interrupted(&transaction_path(data_dir))?;
    if !super::regular_file_exists(&initd)? {
        return Ok(());
    }
    super::super::check_root("uninstall")?;
    require_openrc_tools()?;
    println!("Uninstalling Koi service (OpenRC)...");

    let installed_bin = installed_binary_from_initd(&initd)?;
    let was_started = rc_service_state(false)? == OpenRcState::Started;
    let prior_runlevels = rc_update_runlevels()?;
    let was_enabled = prior_runlevels.iter().any(|level| level == "default");
    if was_started {
        verify_service_process(&installed_bin)?;
    } else {
        verify_service_process_count(&installed_bin, 0)?;
    }
    let existing = honor_existing_config(Path::new("/etc/koi/config.toml"))?;
    let http_port = match existing {
        super::Existing::Declared(plan, _) => plan.http,
        super::Existing::ConfigWithoutPorts(_) | super::Existing::Nothing => super::STD_HTTP,
    };
    let owned_files = vec![
        initd.clone(),
        logrotate_path(),
        koi_config::breadcrumb::breadcrumb_path(),
        PathBuf::from("/run/koi.pid"),
    ];
    let transaction = InstallTransaction::begin(
        data_dir,
        was_started,
        was_enabled,
        prior_runlevels.clone(),
        http_port,
        owned_files.clone(),
    )?;
    let result = (|| -> anyhow::Result<()> {
        if was_started {
            rc_service_checked("stop", "stop the service")?;
        }
        for runlevel in &prior_runlevels {
            rc_update_checked("delete", runlevel, "disable the service")?;
        }
        for path in &owned_files {
            remove_file_durable(path)?;
        }
        if !rc_update_runlevels()?.is_empty() {
            anyhow::bail!("OpenRC retained Koi in a runlevel");
        }
        verify_service_process_count(&installed_bin, 0)?;
        Ok(())
    })();
    finish_uninstall_transaction(transaction, result)?;
    if super::regular_file_exists(&installed_bin)? {
        println!("  Binary preserved at: {}", installed_bin.display());
    }
    println!();
    println!("Koi service uninstalled.");
    Ok(())
}

fn transaction_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state").join(TRANSACTION_FILENAME)
}

pub(super) fn transaction_pending(data_dir: &Path) -> anyhow::Result<bool> {
    super::regular_file_exists(&transaction_path(data_dir))
}

fn write_manifest(path: &Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    let outcome = koi_common::persist::write_json_pretty_commit_with_options(
        path,
        manifest,
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(0o600),
    )?;
    koi_common::persist::require_durable(outcome, "persisting the OpenRC install manifest")?;
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
                "  Recovering an interrupted OpenRC installation from {}...",
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
    let prior_registered = manifest
        .files
        .iter()
        .find(|file| file.path == initd_path())
        .ok_or_else(|| anyhow::anyhow!("OpenRC recovery manifest omits the init script"))?
        .existed;
    let expected_runlevels = manifest.runlevels.clone().unwrap_or_else(|| {
        if manifest.was_enabled {
            vec!["default".to_string()]
        } else {
            Vec::new()
        }
    });
    stop_failed_replacement()?;

    // A fresh-install rollback must remove runlevel links while the failed
    // candidate init script still exists: rc-update may refuse a dangling
    // service name. An upgrade/uninstall rollback needs the opposite order so
    // its prior script exists before prior runlevels are re-added.
    if !prior_registered {
        restore_runlevels(&expected_runlevels)?;
    }
    for file in &manifest.files {
        file.restore()?;
    }

    if prior_registered {
        restore_runlevels(&expected_runlevels)?;
    }
    if !prior_registered && super::regular_file_exists(&initd_path())? {
        anyhow::bail!("OpenRC rollback retained a newly introduced init script");
    }
    if manifest.was_started {
        rc_service_checked("start", "restart the previous service")?;
        let restored_bin = installed_binary_from_initd(&initd_path())?;
        verify_service_process(&restored_bin)?;
        if !healthz_wait(manifest.http_port, std::time::Duration::from_secs(20)) {
            anyhow::bail!(
                "restored service did not answer /healthz on {}",
                manifest.http_port
            );
        }
    } else if prior_registered {
        if rc_service_state(false)? != OpenRcState::Stopped {
            anyhow::bail!("OpenRC rollback did not restore the stopped state");
        }
        verify_service_process_count(&installed_binary_from_initd(&initd_path())?, 0)?;
    }
    if rc_update_runlevels()? != expected_runlevels {
        anyhow::bail!("OpenRC rollback did not restore exact runlevel membership");
    }

    cleanup_new_log_dir(manifest)?;
    settle_and_cleanup(path, manifest)
}

fn restore_runlevels(expected_runlevels: &[String]) -> anyhow::Result<()> {
    let current_runlevels = rc_update_runlevels()?;
    for runlevel in current_runlevels
        .iter()
        .filter(|runlevel| !expected_runlevels.contains(runlevel))
    {
        rc_update_checked("delete", runlevel, "restore service runlevels")?;
    }
    for runlevel in expected_runlevels
        .iter()
        .filter(|runlevel| !current_runlevels.contains(runlevel))
    {
        rc_update_checked("add", runlevel, "restore service runlevels")?;
    }
    Ok(())
}

fn require_openrc_tools() -> anyhow::Result<()> {
    for tool in ["rc-service", "rc-update", "supervise-daemon", "logrotate"] {
        if !command_exists(tool)? {
            anyhow::bail!(
                "OpenRC installation requires `{tool}` on PATH; install the platform package that provides it and retry"
            );
        }
    }
    if !super::file_target_exists(Path::new("/sbin/openrc-run"))? {
        anyhow::bail!("OpenRC installation requires /sbin/openrc-run");
    }
    Ok(())
}

fn command_exists(command: &str) -> anyhow::Result<bool> {
    let Some(path) = std::env::var_os("PATH") else {
        return Ok(false);
    };
    for directory in std::env::split_paths(&path) {
        if super::file_target_exists(&directory.join(command))? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenRcState {
    Started,
    Stopped,
    Crashed,
}

fn rc_service_state(allow_crashed: bool) -> anyhow::Result<OpenRcState> {
    let output = Command::new("rc-service")
        .env("LC_ALL", "C")
        .args([SERVICE_NAME, "status"])
        .output()
        .map_err(|error| anyhow::anyhow!("could not inspect OpenRC service state: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    classify_openrc_status(output.status.code(), allow_crashed, &detail)
}

fn classify_openrc_status(
    code: Option<i32>,
    allow_crashed: bool,
    detail: &str,
) -> anyhow::Result<OpenRcState> {
    match code {
        Some(0) => Ok(OpenRcState::Started),
        Some(3) => Ok(OpenRcState::Stopped),
        Some(32) if allow_crashed => Ok(OpenRcState::Crashed),
        Some(code @ (4 | 8 | 16 | 32)) => anyhow::bail!(
            "OpenRC reports unsupported transitional/failed Koi state {code}; settle or zap it before installing"
        ),
        _ => anyhow::bail!(
            "could not inspect OpenRC service state: rc-service exited {:?}{}{}",
            code,
            if detail.is_empty() { "" } else { ": " },
            detail
        ),
    }
}

fn rc_update_runlevels() -> anyhow::Result<Vec<String>> {
    let output = checked_output(
        Command::new("rc-update")
            .env("LC_ALL", "C")
            .arg("show")
            .output(),
        "query OpenRC enablement",
        "rc-update show",
    )?;
    let body = String::from_utf8(output.stdout)
        .map_err(|error| anyhow::anyhow!("rc-update returned non-UTF-8 state: {error}"))?;
    parse_runlevels(&body, SERVICE_NAME)
}

fn parse_runlevels(output: &str, service: &str) -> anyhow::Result<Vec<String>> {
    let mut runlevels = Vec::new();
    for line in output.lines() {
        let Some((name, levels)) = line.split_once('|') else {
            if line.split_whitespace().next() == Some(service) {
                anyhow::bail!("malformed rc-update state for {service}: '{line}'");
            }
            continue;
        };
        if name.trim() != service {
            continue;
        }
        if levels.trim().is_empty() {
            anyhow::bail!("rc-update reported {service} without a runlevel");
        }
        runlevels.extend(levels.split_whitespace().map(str::to_string));
    }
    runlevels.sort();
    runlevels.dedup();
    Ok(runlevels)
}

fn rc_service_checked(action: &str, description: &str) -> anyhow::Result<()> {
    let rendered = format!("rc-service {SERVICE_NAME} {action}");
    checked_output(
        Command::new("rc-service")
            .env("LC_ALL", "C")
            .args([SERVICE_NAME, action])
            .output(),
        description,
        &rendered,
    )
    .map(|_| ())
}

fn rc_update_checked(action: &str, runlevel: &str, description: &str) -> anyhow::Result<()> {
    let rendered = format!("rc-update {action} {SERVICE_NAME} {runlevel}");
    checked_output(
        Command::new("rc-update")
            .env("LC_ALL", "C")
            .args([action, SERVICE_NAME, runlevel])
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
    if !super::regular_file_exists(&initd_path())? {
        return Ok(());
    }
    match rc_service_state(true)? {
        OpenRcState::Started => rc_service_checked("stop", "stop the failed replacement")?,
        OpenRcState::Crashed => rc_service_checked("zap", "clear the failed replacement")?,
        OpenRcState::Stopped => {}
    }
    if rc_service_state(false)? != OpenRcState::Stopped {
        anyhow::bail!("OpenRC replacement is still running after teardown");
    }
    Ok(())
}

fn verify_service_process(bin: &Path) -> anyhow::Result<()> {
    if rc_service_state(false)? != OpenRcState::Started {
        anyhow::bail!("OpenRC does not report {SERVICE_NAME} started");
    }
    verify_service_process_count(bin, 1)
}

fn verify_service_process_count(bin: &Path, expected_count: usize) -> anyhow::Result<()> {
    let expected = std::fs::canonicalize(bin)?;
    let mut daemon_pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let process = entry.path();
        let actual = match std::fs::canonicalize(process.join("exe")) {
            Ok(actual) => actual,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if actual != expected {
            continue;
        }
        let cmdline = match std::fs::read(process.join("cmdline")) {
            Ok(cmdline) => cmdline,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if cmdline
            .split(|byte| *byte == 0)
            .any(|arg| arg == b"--daemon")
        {
            daemon_pids.push(name.to_string_lossy().into_owned());
        }
    }
    if daemon_pids.len() != expected_count {
        anyhow::bail!(
            "OpenRC retained {} Koi daemon processes from {}, expected {expected_count} (PIDs: {})",
            daemon_pids.len(),
            expected.display(),
            daemon_pids.join(", ")
        );
    }
    Ok(())
}

fn write_file(path: &Path, body: &str, mode: u32) -> anyhow::Result<()> {
    let outcome = koi_common::persist::write_bytes_atomic_with_options(
        path,
        body.as_bytes(),
        koi_common::persist::AtomicWriteOptions::new().with_unix_mode(mode),
    )?;
    koi_common::persist::require_durable(outcome, "installing an OpenRC service file")?;
    Ok(())
}

fn staged_write_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.new", path.display()))
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
                "removing the settled OpenRC install manifest",
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

fn cleanup_new_log_dir(manifest: &InstallManifest) -> anyhow::Result<()> {
    if manifest.log_dir_existed {
        return Ok(());
    }
    let outcome = koi_common::persist::remove_file_durable(Path::new(LOG_FILE))?;
    koi_common::persist::require_durable(outcome, "removing a failed install log")?;
    match std::fs::remove_dir(LOG_DIR) {
        Ok(()) => {
            if let Some(parent) = Path::new(LOG_DIR).parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn directory_exists_strict(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => anyhow::bail!("expected a directory at {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn remove_file_durable(path: &Path) -> anyhow::Result<()> {
    let outcome = koi_common::persist::remove_file_durable(path)?;
    koi_common::persist::require_durable(outcome, "removing an OpenRC installation file")?;
    Ok(())
}

fn finish_uninstall_transaction(
    mut transaction: InstallTransaction,
    result: anyhow::Result<()>,
) -> anyhow::Result<()> {
    match result {
        Ok(()) => match transaction.commit() {
            Ok(()) => Ok(()),
            Err(commit_error) => match transaction.rollback() {
                Ok(()) => anyhow::bail!(
                    "uninstall completed, but its durable commit failed and the previous OpenRC service was restored: {commit_error}"
                ),
                Err(rollback_error) => anyhow::bail!(
                    "uninstall completed, but commit failed ({commit_error}) and rollback is incomplete ({rollback_error}); re-run `koi uninstall` to recover"
                ),
            },
        },
        Err(uninstall_error) => match transaction.rollback() {
            Ok(()) => anyhow::bail!(
                "uninstall failed and the previous OpenRC service was restored: {uninstall_error}"
            ),
            Err(rollback_error) => anyhow::bail!(
                "uninstall failed ({uninstall_error}); rollback is incomplete ({rollback_error}); re-run `koi uninstall` to recover"
            ),
        },
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
        let output = "                  koi | boot default\n                  sshd | default\n";
        assert_eq!(parse_runlevels(output, "koi").unwrap(), ["boot", "default"]);
        assert!(parse_runlevels(output, "ko").unwrap().is_empty());
        assert!(parse_runlevels("koi default\n", "koi").is_err());
        assert!(parse_runlevels("koi |\n", "koi").is_err());
    }

    #[test]
    fn openrc_status_classifier_refuses_uncertain_states() {
        assert_eq!(
            classify_openrc_status(Some(0), false, "").unwrap(),
            OpenRcState::Started
        );
        assert_eq!(
            classify_openrc_status(Some(3), false, "").unwrap(),
            OpenRcState::Stopped
        );
        assert!(classify_openrc_status(Some(32), false, "crashed").is_err());
        assert_eq!(
            classify_openrc_status(Some(32), true, "crashed").unwrap(),
            OpenRcState::Crashed
        );
        assert!(classify_openrc_status(Some(8), true, "starting").is_err());
        assert!(classify_openrc_status(None, true, "signal").is_err());
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
            was_started: false,
            was_enabled: false,
            runlevels: Some(vec![]),
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
    fn armed_recovery_rejects_a_changed_backup_before_openrc_effects() {
        let root = transaction_test_root("armed-corrupt-backup");
        let target = root.join("target");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        std::fs::write(&target, "prior").unwrap();
        let mut snapshot = FileSnapshot::inspect(target.clone()).unwrap();
        snapshot.prepare().unwrap();
        let manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Armed,
            was_started: false,
            was_enabled: false,
            runlevels: Some(vec![]),
            http_port: 5641,
            log_dir_existed: true,
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
    fn recovery_manifest_without_init_script_fails_before_manager_effects() {
        let root = transaction_test_root("missing-init-script");
        let manifest_path = root.join(TRANSACTION_FILENAME);
        let manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Armed,
            was_started: false,
            was_enabled: false,
            runlevels: Some(vec![]),
            http_port: 5641,
            log_dir_existed: true,
            files: vec![],
            temporary_paths: vec![],
        };
        write_manifest(&manifest_path, &manifest).unwrap();

        let error = recover_interrupted(&manifest_path).unwrap_err().to_string();
        assert!(error.contains("omits the init script"));
        assert!(manifest_path.exists(), "invalid recovery stays armed");
        let _ = std::fs::remove_dir_all(root);
    }
}
