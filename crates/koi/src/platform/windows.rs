use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use std::collections::HashSet;

use anyhow::Context;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceDependency, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use koi_serve::windows_firewall::{self, Removal, RuleSnapshot as FirewallRuleSnapshot};

const SERVICE_NAME: &str = "koi";
const DISPLAY_NAME: &str = "Koi Network Toolkit";
const SERVICE_DESCRIPTION: &str =
    "Koi daemon \u{2014} mDNS discovery, certificate mesh, DNS, health checks, and TLS proxy";

const FIREWALL_RULE_MDNS_LEGACY: &str = "Koi mDNS (UDP)";
const FIREWALL_RULE_HTTP_LEGACY: &str = "Koi HTTP (TCP)";

const RECOVERY_DELAY_FIRST: Duration = Duration::from_secs(5);
const RECOVERY_DELAY_SECOND: Duration = Duration::from_secs(10);
/// Reset failure count after 24 hours of clean running.
const RECOVERY_RESET_SECS: Duration = Duration::from_secs(86_400);

const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_STOP_POLL: Duration = Duration::from_millis(500);

const SERVICE_LOG_FILENAME: &str = "koi.log";

// ── Transactional install state (ADR-036 discipline, SCM recipe) ──────

const TRANSACTION_VERSION: u16 = 3;
const TRANSACTION_FILENAME: &str = "scm-install-transaction.json";
const BACKUP_SUFFIX: &str = ".koi-install-backup";
// Reuse shutdown constants from crate root (defined once in main.rs).
use crate::{SHUTDOWN_DRAIN, SHUTDOWN_TIMEOUT};

// ── Service paths ───────────────────────────────────────────────────
// All paths derive from koi_common::paths which uses %ProgramData%\koi\.

pub fn service_log_path() -> PathBuf {
    koi_common::paths::koi_log_dir().join(SERVICE_LOG_FILENAME)
}

pub fn service_log_dir() -> PathBuf {
    koi_common::paths::koi_log_dir()
}

#[allow(clippy::disallowed_methods)] // per-process service path resolution
pub fn service_data_dir() -> PathBuf {
    koi_common::paths::koi_data_dir()
}

/// Win32 ERROR_SERVICE_DOES_NOT_EXIST (1060).
const ERROR_SERVICE_NOT_FOUND: i32 = 1060;
/// Win32 ERROR_SERVICE_ALREADY_RUNNING (1056).
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
/// Win32 ERROR_INVALID_SERVICE_CONTROL (1052).
const ERROR_INVALID_SERVICE_CONTROL: i32 = 1052;
/// Win32 ERROR_SERVICE_CANNOT_ACCEPT_CTRL (1061).
const ERROR_SERVICE_CANNOT_ACCEPT_CONTROL: i32 = 1061;
/// Win32 ERROR_SERVICE_NOT_ACTIVE (1062).
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
/// Win32 ERROR_ACCESS_DENIED (5).
const ERROR_ACCESS_DENIED: i32 = 5;

const SERVICE_START_TIMEOUT: Duration = Duration::from_secs(20);

// Generate the extern "system" function that the SCM expects.
define_windows_service!(ffi_service_main, service_main);

// ── Install ─────────────────────────────────────────────────────────

/// Install Koi as a Windows Service.
///
/// A durable transaction wraps every mutation (ADR-036 discipline, mirroring
/// the systemd recipe): the binary stages to a fixed product-owned path —
/// never the source checkout the installer ran from — and the prior binary,
/// service config, operator policy, config substrate, and exact Koi-owned
/// firewall rules roll back together when any step fails, including the
/// final health check. An interrupted install recovers on the next run.
pub fn install(
    user: bool,
    operator: Option<&str>,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    if user {
        anyhow::bail!(
            "--user installs aren't supported on Windows yet; use `koi install` \
             (system service) or the workbench's login autostart (ADR-034)"
        );
    }
    ensure_elevated("install")?;
    let _install_lock = crate::platform::install_lock::InstallLock::acquire_system()?;
    let exe_path = std::env::current_exe()?;
    let bin_path = install_bin_path();
    println!("Installing Koi service (SCM)...");
    println!("  Binary: {}", exe_path.display());
    println!("  Install path: {}", bin_path.display());

    // Recovery may restore the service from stopped/broken back to its prior
    // state, so measure lifecycle state only after it completes.
    recover_interrupted(&transaction_path(data_dir))?;

    // Arm durable recovery BEFORE the first mutation: the manifest, the
    // service snapshot, and the file backups must be on disk before the
    // service is stopped, so a crash at any later point recovers.
    //
    // The platform snapshot establishes whether this is a fresh deployment or
    // a verified Koi-owned replacement. Shared planning can therefore choose
    // the final port run before mutation without probing Koi's own listener.
    let service_snapshot = ServiceSnapshot::capture()?;
    let config_path = crate::platform::recipes::windows_config_path();
    let existing = crate::platform::recipes::honor_existing_config(&config_path)?;
    let disposition = if service_snapshot.existed {
        crate::platform::recipes::InstallDisposition::ReplacingOwned
    } else {
        crate::platform::recipes::InstallDisposition::Fresh
    };
    let planned = crate::platform::recipes::plan_install_ports(&existing, disposition);
    let policy_path = koi_config::local_access::policy_path(data_dir);
    let mut transaction = ScmInstallTransaction::begin(
        data_dir,
        &bin_path,
        &config_path,
        &policy_path,
        planned.http,
        service_snapshot,
    )?;

    let result = (|| -> anyhow::Result<(String, crate::platform::recipes::PortPlan)> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
        )?;
        let existing_service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS
                | ServiceAccess::QUERY_CONFIG
                | ServiceAccess::STOP
                | ServiceAccess::CHANGE_CONFIG
                | ServiceAccess::START,
        );
        let mut needs_restart = false;
        if let Ok(service) = &existing_service {
            let status = service.query_status()?;
            if status.current_state != ServiceState::Stopped {
                print!("  Stopping running service...");
                match service.stop() {
                    Ok(_) => {}
                    Err(windows_service::Error::Winapi(ref error))
                        if error.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE) => {}
                    Err(error) => return Err(error.into()),
                }
                wait_for_stop(service)?;
                println!(" done.");
                needs_restart = true;
            }
        }

        record_windows_operator(operator, data_dir)?;

        let service = match existing_service {
            Ok(existing) => {
                println!("  Existing service found, updating...");
                // Update in place: keeping the service identity avoids the
                // delete/recreate gap the old installer could strand a
                // machine in when recreation failed.
                existing.change_config(&build_service_info(&bin_path))?;
                println!("  Service updated");
                existing
            }
            Err(windows_service::Error::Winapi(ref e))
                if e.raw_os_error() == Some(ERROR_SERVICE_NOT_FOUND) =>
            {
                // Fresh install
                let info = build_service_info(&bin_path);
                transaction.mark_service_created()?;
                let svc = manager.create_service(
                    &info,
                    ServiceAccess::CHANGE_CONFIG
                        | ServiceAccess::START
                        | ServiceAccess::QUERY_STATUS
                        | ServiceAccess::QUERY_CONFIG,
                )?;
                println!("  Service installed (AutoStart)");
                svc
            }
            Err(e) => return Err(anyhow::anyhow!("{e}")),
        };

        apply_service_policy(&service)?;

        // Stage after the stop: the running service must not hold the
        // product path. Installing from the installed path is a no-op.
        print!("  Staging {}...", bin_path.display());
        if stage_binary(&exe_path, &bin_path)? {
            println!(" done.");
        } else {
            println!(" already in place.");
        }

        let persisted =
            crate::platform::recipes::persist_plan_checked(&existing, &planned, &config_path)?;

        // Firewall rules. The transaction snapshots the exact prior Koi-owned
        // set, so a later rollback recreates what was replaced and removes
        // what was new.
        let config = crate::cli::Config::from_service_launch().map_err(anyhow::Error::msg)?;
        let ports = firewall_ports_for_config(&config);
        windows_firewall::remove(FIREWALL_RULE_MDNS_LEGACY)?;
        windows_firewall::remove(FIREWALL_RULE_HTTP_LEGACY)?;
        for port in &ports {
            let rule_name = firewall_rule_name(port);
            transaction.mark_rule_created(&rule_name)?;
            windows_firewall::replace_managed(
                &rule_name,
                port.protocol.as_str(),
                port.port,
                &bin_path,
            )?;
        }
        if !ports.is_empty() {
            println!("  Firewall rules set ({})", firewall_ports_summary(&ports));
        }

        println!(
            "  Service {}",
            if needs_restart {
                "restarted"
            } else {
                "started"
            }
        );
        start_with_retry(&service)?;
        let pid = verify_service_process(&service, &bin_path)?;
        println!("  SCM process: PID {pid}, image {}", bin_path.display());

        print!("  Verifying (healthz on {})...", planned.http);
        std::io::Write::flush(&mut std::io::stdout())?;
        if !crate::platform::recipes::healthz_wait(planned.http, Duration::from_secs(20)) {
            println!(" failed.");
            anyhow::bail!(
                "service did not answer /healthz on {} within 20s; check {} and the Windows event log",
                planned.http,
                service_log_path().display()
            );
        }
        println!(" healthy.");
        Ok((persisted, planned))
    })();

    let (persisted, planned) = match result {
        Ok(pair) => match transaction.commit() {
            Ok(()) => pair,
            Err(commit_error) => {
                eprintln!("  Could not commit installation state: {commit_error}");
                eprintln!("  Restoring the previous installation...");
                return match transaction.rollback() {
                    Ok(()) => Err(anyhow::anyhow!(
                        "installation verification passed, but its durable commit failed and the previous Koi installation was restored: {commit_error}"
                    )),
                    Err(rollback_error) => Err(anyhow::anyhow!(
                        "installation verification passed, but commit failed ({commit_error}) and automatic rollback is incomplete ({rollback_error}). Re-run `koi install` to retry recovery before making manual changes"
                    )),
                };
            }
        },
        Err(install_error) => {
            eprintln!("  Installation failed: {install_error}");
            eprintln!("  Restoring the previous installation...");
            return match transaction.rollback() {
                Ok(()) => Err(anyhow::anyhow!(
                    "installation failed and the previous Koi installation was restored: {install_error}"
                )),
                Err(rollback_error) => Err(anyhow::anyhow!(
                    "installation failed ({install_error}); automatic rollback is incomplete ({rollback_error}). Re-run `koi install` to retry recovery before making manual changes"
                )),
            };
        }
    };

    println!();
    println!("Koi service installed.");
    println!("  Binary: {}", bin_path.display());
    println!("  Ports: {}", planned.describe());
    if !persisted.is_empty() {
        println!("  {persisted}");
    }
    println!("  Config: {} (koi config show)", config_path.display());
    println!("  Logs: {}", service_log_path().display());
    println!("  Use `koi status` to see module state.");

    Ok(())
}

/// Recover a durable SCM install transaction before the normal config file is
/// parsed. The transaction may own that file, so recovery cannot depend on it
/// remaining valid after an interrupted replacement.
pub(crate) fn recover_install_before_config(data_dir: &std::path::Path) -> anyhow::Result<()> {
    ensure_elevated("install")?;
    let _install_lock = crate::platform::install_lock::InstallLock::acquire_system()?;
    recover_interrupted(&transaction_path(data_dir))
}

fn record_windows_operator(
    requested: Option<&str>,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let sid = match requested {
        Some(value) if value.starts_with("S-") => value.to_string(),
        Some(value) => {
            anyhow::bail!("Windows --operator currently requires a SID (S-1-...); got '{value}'")
        }
        None => current_user_sid()?,
    };
    let policy = koi_config::local_access::LocalAccessPolicy::new(
        koi_config::local_access::LocalOperator::WindowsSid { sid: sid.clone() },
    );
    let outcome = koi_config::local_access::save_commit(data_dir, &policy)?;
    koi_common::persist::require_durable(outcome, "persisting the local operator policy")?;
    println!("  Local operator SID: {sid}");
    Ok(())
}

pub fn current_user_sid() -> anyhow::Result<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = std::process::Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !output.status.success() {
        anyhow::bail!("whoami could not determine the current Windows SID")
    }
    let line = String::from_utf8(output.stdout)?;
    let sid = line
        .trim()
        .trim_matches('"')
        .split("\",\"")
        .nth(1)
        .map(|value| value.trim_matches('"').trim().to_string())
        .filter(|value| value.starts_with("S-"))
        .ok_or_else(|| anyhow::anyhow!("whoami returned an invalid SID record"))?;
    Ok(sid)
}

fn build_service_info(exe_path: &std::path::Path) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.to_path_buf(),
        launch_arguments: vec![OsString::from("--daemon")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    }
}

/// Description, recovery policy, and the service log directory — applied
/// identically on fresh installs and upgrades, and reapplied after a
/// rollback restores an earlier launch command.
fn apply_service_policy(service: &windows_service::service::Service) -> anyhow::Result<()> {
    service.set_description(SERVICE_DESCRIPTION)?;
    let failure_actions = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(RECOVERY_RESET_SECS),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: RECOVERY_DELAY_FIRST,
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: RECOVERY_DELAY_SECOND,
            },
            ServiceAction {
                action_type: ServiceActionType::None,
                delay: Duration::ZERO,
            },
        ]),
    };
    service.update_failure_actions(failure_actions)?;
    println!(
        "  Recovery policy: restart after {}s, {}s, then stop (resets after 24h)",
        RECOVERY_DELAY_FIRST.as_secs(),
        RECOVERY_DELAY_SECOND.as_secs()
    );
    // Also trigger recovery on non-crash failures (e.g. non-zero exit)
    service.set_failure_actions_on_non_crash_failures(true)?;
    let log_dir = service_log_dir();
    koi_common::persist::create_dir_all_durable(&log_dir)?;
    println!("  Log directory: {}", log_dir.display());
    Ok(())
}

// ── Transactional install (SCM recipe) ───────────────────────────────

/// The fixed product-owned binary path. SCM must never point into a source
/// checkout: the checkout moves, gets cleaned, and is not a product surface.
pub fn install_bin_path() -> PathBuf {
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    PathBuf::from(program_files).join("Koi").join("koi.exe")
}

fn transaction_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("state").join(TRANSACTION_FILENAME)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum TransactionPhase {
    Preparing,
    Armed,
    Settled,
}

/// The prior SCM registration, captured before the first mutation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ServiceSnapshot {
    existed: bool,
    /// Complete descriptor for the Koi-owned registration. Strings are kept
    /// as UTF-16 code units so paths and quoted arguments round-trip without
    /// lossy UTF-8 conversion.
    descriptor: Option<ServiceDescriptorSnapshot>,
    /// Version-1 compatibility fields. A new transaction never writes these,
    /// but the upgrader must still recover an older interrupted manifest.
    #[serde(
        default,
        rename = "executable_path",
        skip_serializing_if = "Option::is_none"
    )]
    legacy_executable_path: Option<String>,
    #[serde(
        default,
        rename = "launch_arguments",
        skip_serializing_if = "Option::is_none"
    )]
    legacy_launch_arguments: Option<Vec<String>>,
    #[serde(
        default,
        rename = "start_type",
        skip_serializing_if = "Option::is_none"
    )]
    legacy_start_type: Option<String>,
    was_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ServiceDescriptorSnapshot {
    executable_path: Vec<u16>,
    launch_arguments: Vec<Vec<u16>>,
    display_name: Vec<u16>,
    service_type: u32,
    start_type: u32,
    error_control: u32,
    dependencies: Vec<Vec<u16>>,
    account_name: Option<Vec<u16>>,
}

impl ServiceSnapshot {
    /// Inspection fails closed: any SCM answer other than a decisive
    /// "service does not exist" aborts the install. A snapshot that guessed
    /// `existed: false` on a transient SCM error would make rollback destroy
    /// a healthy service registration.
    fn capture() -> anyhow::Result<Self> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|error| {
            anyhow::anyhow!("could not open the service manager to inspect koi: {error}")
        })?;
        let service = match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
        ) {
            Ok(service) => service,
            Err(windows_service::Error::Winapi(ref e))
                if e.raw_os_error() == Some(ERROR_SERVICE_NOT_FOUND) =>
            {
                return Ok(Self {
                    existed: false,
                    descriptor: None,
                    legacy_executable_path: None,
                    legacy_launch_arguments: None,
                    legacy_start_type: None,
                    was_active: false,
                });
            }
            Err(error) => anyhow::bail!("could not inspect the koi service registration: {error}"),
        };
        let status = service
            .query_status()
            .map_err(|error| anyhow::anyhow!("could not query the koi service state: {error}"))?;
        let was_active = status.current_state == ServiceState::Running;
        let config = service.query_config().map_err(|error| {
            anyhow::anyhow!("could not query the koi service configuration: {error}")
        })?;
        ensure_koi_owned_service(&config)?;
        let (executable_path, launch_arguments) =
            split_launch_command(config.executable_path.as_os_str())?;
        Ok(Self {
            existed: true,
            descriptor: Some(ServiceDescriptorSnapshot {
                executable_path: encode_os(&executable_path),
                launch_arguments: launch_arguments.iter().map(|arg| encode_os(arg)).collect(),
                display_name: encode_os(&config.display_name),
                service_type: config.service_type.bits(),
                start_type: config.start_type.to_raw(),
                error_control: config.error_control.to_raw(),
                dependencies: config
                    .dependencies
                    .iter()
                    .map(|dependency| encode_os(&dependency.to_system_identifier()))
                    .collect(),
                account_name: config.account_name.as_deref().map(encode_os),
            }),
            legacy_executable_path: None,
            legacy_launch_arguments: None,
            legacy_start_type: None,
            was_active,
        })
    }
}

fn ensure_koi_owned_service(
    config: &windows_service::service::ServiceConfig,
) -> anyhow::Result<()> {
    let account_is_local_system = config.account_name.as_deref().is_none_or(|account| {
        let account = account.to_string_lossy();
        account.eq_ignore_ascii_case("LocalSystem")
            || account.eq_ignore_ascii_case(r"NT AUTHORITY\SYSTEM")
    });
    if config.display_name != OsStr::new(DISPLAY_NAME)
        || config.service_type != ServiceType::OWN_PROCESS
        || config.load_order_group.is_some()
        || config.tag_id != 0
        || !account_is_local_system
    {
        anyhow::bail!(
            "the existing 'koi' SCM object is not the canonical Koi-owned LocalSystem service; refusing to replace it"
        );
    }
    Ok(())
}

fn encode_os(value: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().collect()
}

fn decode_os(value: &[u16]) -> OsString {
    use std::os::windows::ffi::OsStringExt;
    OsString::from_wide(value)
}

/// Decode the native SCM command line with CommandLineToArgvW so quoted
/// arguments, embedded spaces, and backslashes survive rollback semantically.
fn split_launch_command(command: &OsStr) -> anyhow::Result<(OsString, Vec<OsString>)> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

    let mut wide = command.encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let mut argc = 0;
    // SAFETY: `wide` is NUL-terminated for the call and `argc` is a valid
    // output pointer. CommandLineToArgvW owns the returned LocalAlloc block.
    let argv = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut argc) };
    if argv.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut values = Vec::with_capacity(argc.max(0) as usize);
    for index in 0..argc.max(0) as usize {
        // SAFETY: argv contains `argc` pointers to NUL-terminated strings.
        let ptr = unsafe { *argv.add(index) };
        let len = (0..)
            .take_while(|&offset| unsafe { *ptr.add(offset) } != 0)
            .count();
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        values.push(OsString::from_wide(slice));
    }
    // SAFETY: argv is the exact allocation returned by CommandLineToArgvW.
    unsafe { LocalFree(argv.cast()) };
    let executable = values
        .first()
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("the SCM launch command has no executable"))?;
    Ok((executable, values.into_iter().skip(1).collect()))
}

/// One file the installer may replace, with its prior bytes parked beside it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FileSnapshot {
    path: PathBuf,
    backup: PathBuf,
    existed: bool,
    /// Secret-bearing targets must have their replacement stage hardened
    /// before any restored bytes are copied into it.
    #[serde(default)]
    private: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    integrity: Option<koi_common::persist::FileIntegrity>,
}

impl FileSnapshot {
    fn inspect(path: PathBuf, private: bool) -> anyhow::Result<Self> {
        let backup = backup_path(&path);
        if backup.try_exists()? {
            let outcome = koi_common::persist::remove_file_durable(&backup)?;
            koi_common::persist::require_durable(outcome, "removing a stale SCM installer backup")?;
        }
        let existed = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => true,
            Ok(_) => anyhow::bail!(
                "refusing to replace non-regular installation target {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            path,
            backup,
            existed,
            private,
            integrity: None,
        })
    }

    /// Park the prior bytes. A stale backup can only be debris after a
    /// committed transaction; the manifest is the rollback authority.
    fn prepare(&mut self) -> anyhow::Result<()> {
        if !self.existed {
            return Ok(());
        }
        let (outcome, integrity) =
            koi_common::persist::copy_file_atomic_new_with_options_and_prepare_stage(
                &self.path,
                &self.backup,
                koi_common::persist::AtomicWriteOptions::new(),
                koi_common::persist::restrict_windows_local_secret_acl,
            )?;
        koi_common::persist::require_durable(outcome, "checkpointing an SCM installer backup")?;
        self.integrity = Some(integrity);
        Ok(())
    }

    fn validate_backup(&self, require_integrity: bool) -> anyhow::Result<()> {
        if !self.existed {
            return Ok(());
        }
        if !std::fs::symlink_metadata(&self.backup)
            .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            anyhow::bail!(
                "installer recovery is incomplete: expected backup {} for {}",
                self.backup.display(),
                self.path.display()
            );
        }
        match &self.integrity {
            Some(expected) => {
                let actual = koi_common::persist::file_integrity(&self.backup)?;
                if &actual != expected {
                    anyhow::bail!(
                        "installer recovery is unsafe: backup {} for {} changed (expected {} bytes / {}, found {} bytes / {})",
                        self.backup.display(),
                        self.path.display(),
                        expected.len,
                        expected.sha256,
                        actual.len,
                        actual.sha256
                    );
                }
            }
            None if require_integrity => anyhow::bail!(
                "installer recovery is unsafe: backup {} for {} has no recorded integrity",
                self.backup.display(),
                self.path.display()
            ),
            None => {}
        }
        Ok(())
    }

    fn restore(&self) -> anyhow::Result<()> {
        if !self.existed {
            let outcome = koi_common::persist::remove_file_durable(&self.path)?;
            koi_common::persist::require_durable(
                outcome,
                "removing a newly installed file during SCM rollback",
            )?;
            return Ok(());
        }
        let options = koi_common::persist::AtomicWriteOptions::new();
        let outcome = if let Some(expected) = &self.integrity {
            koi_common::persist::copy_file_atomic_verified_with_options_and_prepare_stage(
                &self.backup,
                &self.path,
                expected,
                options,
                |stage| self.prepare_restore_stage(stage),
            )?
        } else {
            koi_common::persist::copy_file_atomic_with_options_and_prepare_stage(
                &self.backup,
                &self.path,
                options,
                |stage| self.prepare_restore_stage(stage),
            )?
            .0
        };
        koi_common::persist::require_durable(outcome, "restoring an SCM installer backup")?;
        Ok(())
    }

    fn prepare_restore_stage(&self, stage: &std::path::Path) -> std::io::Result<()> {
        if self.private {
            koi_common::persist::restrict_windows_local_secret_acl(stage)
        } else {
            Ok(())
        }
    }

    fn cleanup(&self) -> anyhow::Result<()> {
        for path in [&self.backup, &staged_path(&self.path)] {
            let outcome = koi_common::persist::remove_file_durable(path)?;
            koi_common::persist::require_durable(outcome, "removing SCM installer debris")?;
        }
        Ok(())
    }
}

/// The durable record of an in-flight installation. Present on disk with
/// `Armed` = mutations may have started; the next `koi install` recovers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InstallManifest {
    version: u16,
    phase: TransactionPhase,
    http_port: u16,
    service: ServiceSnapshot,
    files: Vec<FileSnapshot>,
    firewall: Vec<FirewallRuleSnapshot>,
    /// Rule names this installation created that did not exist before.
    added_rules: Vec<String>,
    /// Persisted before CreateService is attempted for a service that did not
    /// exist. Deleting a still-missing object during recovery is harmless.
    created_service: bool,
    temporary_paths: Vec<PathBuf>,
}

struct ScmInstallTransaction {
    path: PathBuf,
    manifest: InstallManifest,
}

impl ScmInstallTransaction {
    fn begin(
        data_dir: &std::path::Path,
        bin_path: &std::path::Path,
        config_path: &std::path::Path,
        policy_path: &std::path::Path,
        http_port: u16,
        service: ServiceSnapshot,
    ) -> anyhow::Result<Self> {
        let path = transaction_path(data_dir);
        let firewall = windows_firewall::snapshot_managed()?;
        let files = [
            (bin_path.to_path_buf(), false),
            (config_path.to_path_buf(), false),
            (policy_path.to_path_buf(), true),
        ]
        .into_iter()
        .map(|(path, private)| FileSnapshot::inspect(path, private))
        .collect::<anyhow::Result<Vec<_>>>()?;
        let mut manifest = InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Preparing,
            http_port,
            service,
            files,
            firewall,
            added_rules: Vec::new(),
            created_service: false,
            temporary_paths: Vec::new(),
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
                    "could not disarm the failed SCM checkpoint ({cleanup_error}); re-run `koi install` to retry recovery"
                )));
            }
            return Err(error);
        }
        Ok(Self { path, manifest })
    }

    fn persist_transition(
        &mut self,
        update: impl FnOnce(&mut InstallManifest),
    ) -> anyhow::Result<()> {
        let mut next = self.manifest.clone();
        update(&mut next);
        write_manifest(&self.path, &next)?;
        self.manifest = next;
        Ok(())
    }

    /// Rule names created by this install (tracked for exact rollback).
    fn mark_rule_created(&mut self, name: &str) -> anyhow::Result<()> {
        if !self.manifest.added_rules.iter().any(|n| n == name)
            && !self.manifest.firewall.iter().any(|rule| rule.name == name)
        {
            self.persist_transition(|manifest| manifest.added_rules.push(name.to_string()))?;
        }
        Ok(())
    }

    fn mark_service_created(&mut self) -> anyhow::Result<()> {
        if !self.manifest.created_service {
            self.persist_transition(|manifest| manifest.created_service = true)?;
        }
        Ok(())
    }

    fn commit(&mut self) -> anyhow::Result<()> {
        self.persist_transition(|manifest| manifest.phase = TransactionPhase::Settled)?;
        cleanup_settled(&self.path, &self.manifest)
    }

    fn rollback(mut self) -> anyhow::Result<()> {
        self.persist_transition(|manifest| manifest.phase = TransactionPhase::Armed)?;
        restore_manifest(&self.path, &self.manifest)
    }
}

fn write_manifest(path: &std::path::Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(manifest)?;
    let outcome = koi_common::persist::write_bytes_atomic_with_options_and_prepare_stage(
        path,
        &json,
        koi_common::persist::AtomicWriteOptions::new(),
        koi_common::persist::restrict_windows_local_secret_acl,
    )?;
    koi_common::persist::require_durable(outcome, "persisting the SCM install manifest")?;
    Ok(())
}

fn backup_path(path: &std::path::Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

fn staged_path(path: &std::path::Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".koi-install-staged");
    PathBuf::from(name)
}

/// Recover an interrupted installation before starting a new one.
fn recover_interrupted(path: &std::path::Path) -> anyhow::Result<()> {
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
        TransactionPhase::Settled => cleanup_settled(path, &manifest),
        TransactionPhase::Armed => {
            println!(
                "  Recovering an interrupted SCM installation from {}...",
                path.display()
            );
            restore_manifest(path, &manifest)?;
            println!(" done.");
            Ok(())
        }
    }
}

/// Prove that an armed transaction contains everything needed for exact
/// recovery before touching files, the SCM object, or firewall policy.
fn validate_recovery_boundary(
    path: &std::path::Path,
    manifest: &InstallManifest,
) -> anyhow::Result<()> {
    if let Some(rule) = manifest.firewall.iter().find(|rule| {
        rule.profile
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    }) {
        let generation = if manifest.version == 1 {
            "version-1 manifests predate firewall profile capture"
        } else {
            "the firewall snapshot is incomplete"
        };
        anyhow::bail!(
            "cannot recover interrupted installation safely: {generation}; rule '{}' has no provable prior profile. Recovery stopped before any mutation; manifest and backups remain at {}",
            rule.name,
            path.display()
        );
    }
    windows_firewall::validate_snapshots(&manifest.firewall)
        .context("cannot recover interrupted installation safely from its firewall snapshot")
}

/// Restore the exact prior installation: service registration and lifecycle,
/// product binary, operator policy, config substrate, and Koi-owned
/// firewall rules.
fn restore_manifest(path: &std::path::Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    validate_recovery_boundary(path, manifest)?;
    for file in &manifest.files {
        file.validate_backup(manifest.version >= 3)?;
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS
            | ServiceAccess::QUERY_CONFIG
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::START
            | ServiceAccess::DELETE,
    );

    if let Ok(service) = &service {
        // A crash-looping replacement restarts behind the SCM recovery
        // manager while we restore; clear the policy first so the stop
        // below is final, then reapply it after the config is back.
        let no_actions = ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::ZERO),
            reboot_msg: None,
            command: None,
            actions: Some(Vec::new()),
        };
        service.update_failure_actions(no_actions)?;
        service.set_failure_actions_on_non_crash_failures(false)?;
        stop_service_for_restore(service)?;
    }

    for file in &manifest.files {
        file.restore()?;
    }

    // Service registration restore. Handles are always dropped before a
    // delete wait: SCM does not purge a marked object while any handle to it
    // remains open.
    let mut live_service = None;
    match service {
        // The service existed before and still exists: point it back at the
        // prior semantic launch configuration (binary and arguments
        // separately) and start type.
        Ok(service) if manifest.service.existed => {
            let info = restored_service_info(manifest)?;
            service.change_config(&info)?;
            apply_service_policy(&service)?;
            live_service = Some(service);
        }
        // We created the service and the prior state had none: remove it.
        Ok(service) if manifest.created_service => {
            service.delete()?;
            drop(service);
            wait_for_delete(&manager)?;
        }
        Ok(service) => drop(service),
        // Prior service is gone but the complete manifest expects one:
        // recreate exactly that Koi-owned descriptor and lifecycle policy.
        Err(windows_service::Error::Winapi(ref error))
            if error.raw_os_error() == Some(ERROR_SERVICE_NOT_FOUND)
                && manifest.service.existed =>
        {
            let info = restored_service_info(manifest)?;
            let recreated = manager.create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG
                    | ServiceAccess::START
                    | ServiceAccess::QUERY_STATUS
                    | ServiceAccess::QUERY_CONFIG,
            )?;
            apply_service_policy(&recreated)?;
            live_service = Some(recreated);
        }
        Err(windows_service::Error::Winapi(ref error))
            if error.raw_os_error() == Some(ERROR_SERVICE_NOT_FOUND) => {}
        Err(error) => return Err(error.into()),
    }

    // Firewall restoration is convergent: validate every prior semantic
    // snapshot, delete the complete target-name set, then recreate. Any
    // delete/add failure retains the transaction for a safe retry.
    windows_firewall::restore_snapshot_set(&manifest.added_rules, &manifest.firewall)?;

    // Restart the restored registration BEFORE committing: the manifest and
    // backups stay on disk until the restored start, identity, and health
    // all pass, so an incomplete restoration can still be recovered by the
    // next `koi install`.
    if manifest.service.was_active {
        if let Some(service) = live_service.as_ref() {
            if let Err(start_error) = start_with_retry(service) {
                // The observed SCM wedge signature: the launch is denied with
                // access-denied while the restored binary bytes are verified
                // by the snapshots above and the same bytes ran under a fresh
                // service object when the signature was first isolated
                // (fleet/windows/issues/001; not reproducible on demand
                // across six controlled experiments, so the fallback keys on
                // the discriminating signature, not a mechanism theory).
                let wedged = matches!(
                    &start_error,
                    windows_service::Error::Winapi(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED)
                );
                if wedged {
                    eprintln!(
                        "  Restored service refuses to start (access denied);                          recreating the service object from the complete descriptor"
                    );
                    let wedged_service = live_service.take().ok_or_else(|| {
                        anyhow::anyhow!("restored service handle disappeared before recreation")
                    })?;
                    wedged_service.delete()?;
                    drop(wedged_service);
                    wait_for_delete(&manager)?;
                    let info = restored_service_info(manifest)?;
                    let recreated = manager.create_service(
                        &info,
                        ServiceAccess::CHANGE_CONFIG
                            | ServiceAccess::START
                            | ServiceAccess::QUERY_STATUS
                            | ServiceAccess::QUERY_CONFIG,
                    )?;
                    apply_service_policy(&recreated)?;
                    start_with_retry(&recreated)?;
                    live_service = Some(recreated);
                } else {
                    return Err(anyhow::anyhow!(
                        "restored service did not start: {start_error}"
                    ));
                }
            }
        }
        let service = live_service
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("restored service has no live SCM handle"))?;
        let expected = restored_executable_path(manifest)?;
        let pid = verify_service_process(service, &expected)?;
        println!(
            "  Restored SCM process: PID {pid}, image {}",
            expected.display()
        );
        if !crate::platform::recipes::healthz_wait(manifest.http_port, Duration::from_secs(20)) {
            anyhow::bail!(
                "restored service did not answer /healthz on {}",
                manifest.http_port
            );
        }
    }

    settle_and_cleanup(path, manifest)
}

/// The complete SCM descriptor for the prior registration, rebuilt from the
/// semantic snapshot. Fails closed when the snapshot is incomplete — a
/// partial descriptor must never back a delete/recreate.
fn restored_service_info(manifest: &InstallManifest) -> anyhow::Result<ServiceInfo> {
    let descriptor = restored_descriptor(&manifest.service)?;
    let executable_path = decode_os(&descriptor.executable_path);
    if executable_path.is_empty() {
        anyhow::bail!("snapshot has no prior service executable; refusing to guess");
    }
    let service_type = ServiceType::from_bits(descriptor.service_type).ok_or_else(|| {
        anyhow::anyhow!(
            "snapshot has unsupported prior service type bits: {}",
            descriptor.service_type
        )
    })?;
    let start_type = ServiceStartType::from_raw(descriptor.start_type)
        .map_err(|error| anyhow::anyhow!("snapshot has invalid prior start type: {error}"))?;
    let error_control = ServiceErrorControl::from_raw(descriptor.error_control)
        .map_err(|error| anyhow::anyhow!("snapshot has invalid prior error control: {error}"))?;
    Ok(ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: decode_os(&descriptor.display_name),
        service_type,
        start_type,
        error_control,
        executable_path: PathBuf::from(executable_path),
        launch_arguments: descriptor
            .launch_arguments
            .iter()
            .map(|argument| decode_os(argument))
            .collect(),
        dependencies: descriptor
            .dependencies
            .iter()
            .map(|dependency| ServiceDependency::from_system_identifier(decode_os(dependency)))
            .collect(),
        account_name: descriptor.account_name.as_deref().map(decode_os),
        account_password: None,
    })
}

fn restored_executable_path(manifest: &InstallManifest) -> anyhow::Result<PathBuf> {
    let descriptor = restored_descriptor(&manifest.service)?;
    let executable = decode_os(&descriptor.executable_path);
    if executable.is_empty() {
        anyhow::bail!("snapshot has no prior service executable; refusing to guess");
    }
    Ok(PathBuf::from(executable))
}

fn restored_descriptor(snapshot: &ServiceSnapshot) -> anyhow::Result<ServiceDescriptorSnapshot> {
    if let Some(descriptor) = &snapshot.descriptor {
        return Ok(descriptor.clone());
    }
    let executable = snapshot
        .legacy_executable_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("snapshot has no prior service descriptor"))?;
    let start_type = match snapshot.legacy_start_type.as_deref().unwrap_or("auto") {
        "auto" => ServiceStartType::AutoStart,
        "demand" => ServiceStartType::OnDemand,
        "disabled" => ServiceStartType::Disabled,
        other => anyhow::bail!("unsupported legacy service start type: {other}"),
    };
    Ok(ServiceDescriptorSnapshot {
        executable_path: encode_os(OsStr::new(executable)),
        launch_arguments: snapshot
            .legacy_launch_arguments
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|argument| encode_os(OsStr::new(argument)))
            .collect(),
        display_name: encode_os(OsStr::new(DISPLAY_NAME)),
        service_type: ServiceType::OWN_PROCESS.bits(),
        start_type: start_type.to_raw(),
        error_control: ServiceErrorControl::Normal.to_raw(),
        dependencies: Vec::new(),
        account_name: None,
    })
}

fn settle_and_cleanup(path: &std::path::Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    let mut settled = manifest.clone();
    settled.version = TRANSACTION_VERSION;
    settled.phase = TransactionPhase::Settled;
    write_manifest(path, &settled)?;
    cleanup_settled(path, &settled)
}

fn cleanup_settled(path: &std::path::Path, manifest: &InstallManifest) -> anyhow::Result<()> {
    debug_assert!(matches!(manifest.phase, TransactionPhase::Settled));
    for file in &manifest.files {
        if let Err(error) = file.cleanup() {
            eprintln!(
                "  Warning: committed SCM installer backup {} remains for cleanup: {error}",
                file.backup.display()
            );
            return Ok(());
        }
    }
    if let Err(error) = cleanup_temporary_paths(&manifest.temporary_paths) {
        eprintln!("  Warning: committed SCM installer staging remains for cleanup: {error}");
        return Ok(());
    }
    match koi_common::persist::remove_file_durable(path) {
        Ok(outcome) => {
            if let Err(error) = koi_common::persist::require_durable(
                outcome,
                "removing the settled SCM install manifest",
            ) {
                eprintln!("  Warning: settled SCM manifest cleanup is uncertain: {error}");
            }
        }
        Err(error) => eprintln!(
            "  Warning: settled SCM manifest {} remains for cleanup: {error}",
            path.display()
        ),
    }
    Ok(())
}

fn cleanup_temporary_paths(paths: &[PathBuf]) -> anyhow::Result<()> {
    for path in paths {
        let outcome = koi_common::persist::remove_file_durable(path)?;
        koi_common::persist::require_durable(outcome, "removing SCM installer staging debris")?;
    }
    Ok(())
}

/// Stage the installer's binary into the product path. Returns false when
/// source and destination are the same file (upgrade from the installed
/// path). A destination another process holds fails with the precise cause.
fn stage_binary(exe: &std::path::Path, bin: &std::path::Path) -> anyhow::Result<bool> {
    let same = exe
        .canonicalize()
        .ok()
        .zip(bin.canonicalize().ok())
        .is_some_and(|(s, d)| s == d);
    if same {
        return Ok(false);
    }
    let (outcome, _) = koi_common::persist::copy_file_atomic_with_options(
        exe,
        bin,
        koi_common::persist::AtomicWriteOptions::new(),
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "could not stage {} (a running process may hold it — stop the koi service first): {error}",
            bin.display()
        )
    })?;
    koi_common::persist::require_durable(outcome, "installing the Koi executable")?;
    Ok(true)
}

// ── Uninstall ───────────────────────────────────────────────────────

/// Check if the Koi service is installed (read-only, no elevation needed).
fn is_service_installed() -> bool {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return false;
    };
    manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .is_ok()
}

/// Uninstall the Koi Windows Service and clean up all artifacts.
///
/// Stops the service if running, removes firewall rules, deletes
/// breadcrumb, and cleans up empty log/data directories.
pub fn uninstall() -> anyhow::Result<()> {
    // Check if installed BEFORE requiring elevation
    if !is_service_installed() {
        println!("Koi is not installed as a service. Nothing to uninstall.");
        return Ok(());
    }

    ensure_elevated("uninstall")?;
    println!("Uninstalling Koi service...");

    // Resolve and remove the complete owned firewall set before stopping or
    // deleting the service. Query/delete failures abort uninstall explicitly;
    // they cannot be reported as a successful teardown.
    let firewall = windows_firewall::snapshot_managed()?;
    let mut seen = HashSet::new();
    let mut removed = 0usize;
    for name in firewall.iter().map(|rule| rule.name.as_str()) {
        if seen.insert(name) && windows_firewall::remove(name)? == Removal::Removed {
            removed += 1;
        }
    }
    if removed > 0 {
        println!("  Firewall rules removed ({removed})");
    }

    // Best-effort graceful shutdown via HTTP (before SCM stop)
    if let Some(bc) = koi_config::breadcrumb::read_breadcrumb()? {
        let client = crate::client::KoiClient::with_token(&bc.endpoint, &bc.token);
        if client.shutdown().is_ok() {
            // Give the service a moment to begin shutting down
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => {
            // Stop if still running (fallback after graceful shutdown)
            if let Ok(status) = service.query_status() {
                if status.current_state != ServiceState::Stopped {
                    print!("  Stopping service...");
                    let _ = service.stop();
                    wait_for_stop(&service)?;
                    println!(" done.");
                }
            }

            service.delete()?;
            println!("  Service removed");
        }
        Err(windows_service::Error::Winapi(ref e))
            if e.raw_os_error() == Some(ERROR_SERVICE_NOT_FOUND) =>
        {
            println!("  Service not found, cleaning up remaining files...");
        }
        Err(e) => return Err(e.into()),
    }

    // Daemon discovery file
    koi_config::breadcrumb::delete_breadcrumb()?;

    // Product-owned binary from the transactional installer. Older installs
    // registered a path elsewhere; those binaries stay where they are.
    let bin = install_bin_path();
    if bin.is_file() {
        match std::fs::remove_file(&bin) {
            Ok(()) => println!("  Binary removed: {}", bin.display()),
            Err(e) => println!(
                "  Warning: could not remove {} (a process may hold it): {e}",
                bin.display()
            ),
        }
    }
    if let Some(parent) = bin.parent() {
        // Remove the product directory only when the installer owns it
        // entirely; anything else placed there stays.
        let _ = std::fs::remove_dir(parent);
    }

    // An interrupted transaction cannot outlive the installation it belonged
    // to; its backups are inert but should not outlive it either.
    let manifest = transaction_path(&service_data_dir());
    if manifest.is_file() {
        if let Ok(record) = koi_common::persist::read_json::<InstallManifest>(&manifest) {
            for file in &record.files {
                let _ = file.cleanup();
            }
            let _ = cleanup_temporary_paths(&record.temporary_paths);
        }
        let _ = std::fs::remove_file(&manifest);
    }

    // Log directory - remove only if empty, otherwise inform the user
    let log_dir = service_log_dir();
    match std::fs::remove_dir(&log_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => println!("  Logs preserved at: {}", log_dir.display()),
    }

    // Parent data directory - remove only if empty
    let data_dir = service_data_dir();
    let _ = std::fs::remove_dir(&data_dir); // silent - either empty or has logs

    println!();
    println!("Koi service uninstalled.");

    Ok(())
}

// ── Service runtime ─────────────────────────────────────────────────

/// Check if we're running as a Windows Service and dispatch if so.
pub fn try_run_as_service() -> bool {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).is_ok()
}

// The actual service entry point.
fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        tracing::error!(error = %e, "Service failed");
        if let Err(log_error) = append_service_failure(&service_log_path(), &e) {
            eprintln!("Koi service failed: {e:#}; could not persist the failure: {log_error}");
        }
        // The SCM owns this process. Returning normally from a failed service
        // entry point would publish a successful process exit after startup
        // failed, defeating recovery policy and operator diagnostics.
        std::process::exit(1);
    }
}

/// Persist a startup failure synchronously. `run_service` owns non-blocking
/// logging guards, so they are gone before an error reaches `service_main`, and
/// `process::exit` cannot flush a replacement asynchronous writer.
fn append_service_failure(path: &std::path::Path, error: &anyhow::Error) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "Koi Windows service startup failed: {error:#}")?;
    file.flush()
}

fn run_service(_arguments: Vec<OsString>) -> anyhow::Result<()> {
    // Initialize logging to the well-known service log file.
    let log_path = service_log_path();
    let env_filter = tracing_subscriber::EnvFilter::try_new(
        std::env::var("KOI_LOG").unwrap_or_else(|_| "info".to_string()),
    )
    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _log_guards = crate::infra::init_logging(env_filter, Some(&log_path))
        .context("initializing the Windows service log boundary")?;

    // Service mode resolves the SAME precedence as the foreground daemon
    // (CLI > env > file > default) by parsing the SCM launch line through the
    // normal Cli. The retired environment-only path ignored config.toml and
    // silently bound defaults; this one strict path fails startup on bad input.
    let config = crate::cli::Config::from_service_launch().map_err(anyhow::Error::msg)?;
    let webhook_sinks = config.webhook_sinks()?;
    koi_config::dirs::prepare_data_root(&config.data_dir)
        .context("preparing the configured Windows service data root")?;
    let host = koi_compose::host::HostIdentity::observe()
        .context("observing the machine identity for this Koi composition")?;
    // Resolve the install-time authorization policy while `run_service` can
    // still report startup failure to the SCM. A malformed policy must not
    // silently broaden local-control access inside the async serving loop.
    let local_operator = crate::platform::daemon_local_operator(&config.data_dir)?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

    // Register SCM handler - report StartPending while we spin up
    let status_handle =
        service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Ok(mut guard) = shutdown_tx.lock() {
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(());
                        }
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    let rt = tokio::runtime::Runtime::new()?;
    let runtime_result: anyhow::Result<()> = rt.block_on(async {
        let cancel = tokio_util::sync::CancellationToken::new();
        // Start the uptime clock before build_cores (as daemon_mode does), so `/v1/status`
        // uptime matches the foreground daemon — build_cores can take seconds (the certmesh
        // CA Argon2 auto-unlock), which would otherwise be silently undercounted.
        let started_at = std::time::Instant::now();

        // ── Build all domain cores + bridges + domain background tasks ──
        // Shared with daemon_mode via koi-compose, so `koi install` constructs the identical
        // daemon (P07) — the fix for the verified parity defect. (An mDNS init failure is now
        // non-fatal, matching the foreground daemon, rather than stopping the service.)
        let cores = koi_compose::cores::build_cores(
            &koi_compose::cores::CoreSpec {
                no_mdns: config.no_mdns,
                no_certmesh: config.no_certmesh,
                no_dns: config.no_dns,
                no_health: config.no_health,
                no_proxy: config.no_proxy,
                no_udp: config.no_udp,
                no_runtime: config.no_runtime,
                data_dir: Some(config.data_dir.clone()),
                dns_config: config.dns_config(),
                runtime: config.runtime.clone(),
                http_port: config.http_port,
                runtime_scope: std::env::var("KOI_SCOPE").ok().filter(|s| !s.is_empty()),
                ..koi_compose::cores::CoreSpec::daemon_defaults()
            },
            &host,
            &cancel,
        )
        .await
        .context("constructing Koi domain graph")?;

        // Generate a Daemon Access Token (DAT) for authenticating mutation requests
        let dat_token = crate::infra::mint_dat();

        // Resolve the HTTP bind address through the same strict startup boundary
        // as the foreground daemon. Binding somewhere other than configured is
        // not a safe recovery; SCM receives a failed startup instead.
        let http_bind_ip = if config.no_http {
            None
        } else {
            Some(crate::infra::resolve_http_bind_ip(&config.http_bind)?)
        };

        // Startup diagnostics (logged to file)
        crate::infra::startup_diagnostics(&config, http_bind_ip, &host);

        // ── Enrollment-approval pump ──
        // The certmesh role loops + orchestrator are spawned by build_cores (shared with
        // daemon_mode). Only the approval pump is host-specific: with no interactive console
        // under the SCM, enrollment requests auto-deny (visibly logged), never block.
        if let Some(ref certmesh) = cores.certmesh {
            koi_compose::certmesh::spawn_enrollment_approval(
                certmesh,
                koi_compose::certmesh::deny_and_log_decider(),
                &cancel,
                &cores,
            )
            .await;
        }

        // ── Serving stack (shared verbatim with daemon_mode via koi-serve) ──
        // The SAME stack the foreground daemon spawns (ADR-020 P4c / ADR-016 §2), so the
        // two boot paths cannot drift — fixing prior parity defects where the service
        // started mTLS but silently omitted ACME and announced the CA only at boot. The
        // service always serves the dashboard.
        let serving = match koi_serve::serve(
            &cores,
            started_at,
            koi_serve::ServeConfig {
                host: host.clone(),
                bind_ip: http_bind_ip
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                http_port: config.http_port,
                no_http: config.no_http,
                no_ipc: config.no_ipc,
                no_mcp_http: config.no_mcp_http,
                pipe_path: config.pipe_path.clone(),
                local_operator: local_operator.clone(),
                data_root: config.data_dir.clone(),
                config_path: config.config_path.clone(),
                mtls_port: config.mtls_port,
                acme_port: config.acme_port,
                no_acme: config.no_acme,
                dns_zone: config.dns_zone.clone(),
                announce_http: config.announce_http,
                dashboard: true,
                mode: "daemon",
                dat_token: dat_token.clone(),
                webhooks: webhook_sinks,
                no_mgmt_mcp: config.no_mgmt_mcp,
                ui_dir: Some(config.data_dir.join("ui")),
            },
            &cancel,
        )
        .await
        {
            Ok(ready) => ready,
            Err(error) => {
                koi_compose::cores::ordered_shutdown(
                    &cancel,
                    &cores,
                    SHUTDOWN_TIMEOUT,
                    SHUTDOWN_DRAIN,
                )
                .await;
                return Err(error.context("starting Koi serving stack"));
            }
        };

        // Publish only the endpoint whose listener crossed the startup fence.
        if let Some(endpoint) = &serving.local_endpoint {
            if let Err(error) = koi_config::breadcrumb::write_breadcrumb(endpoint, &dat_token) {
                koi_compose::cores::ordered_shutdown(
                    &cancel,
                    &cores,
                    SHUTDOWN_TIMEOUT,
                    SHUTDOWN_DRAIN,
                )
                .await;
                return Err(error).context("publishing the local daemon ownership breadcrumb");
            }
        }

        // Report Running to SCM
        if let Err(error) = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }) {
            koi_compose::cores::ordered_shutdown(&cancel, &cores, SHUTDOWN_TIMEOUT, SHUTDOWN_DRAIN)
                .await;
            let _ = koi_config::breadcrumb::delete_breadcrumb();
            return Err(error).context("publishing Windows service readiness to the SCM");
        }

        tracing::info!("Ready.");

        // Wait for SCM/admin stop or an owned serving adapter's terminal failure.
        tokio::select! {
            _ = shutdown_rx => {}
            _ = cancel.cancelled() => {}
        }
        tracing::info!("Shutting down...");

        // Record the lifecycle publication failure, but never let it skip the
        // actual resource teardown.
        let stop_pending_error = status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::StopPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 1,
                wait_hint: SHUTDOWN_TIMEOUT,
                process_id: None,
            })
            .err();

        // Ordered shutdown (shared with daemon_mode via koi-compose).
        koi_compose::cores::ordered_shutdown(&cancel, &cores, SHUTDOWN_TIMEOUT, SHUTDOWN_DRAIN)
            .await;

        koi_config::breadcrumb::delete_breadcrumb()
            .context("removing the local daemon ownership breadcrumb")?;
        if let Some(error) = stop_pending_error {
            return Err(error).context("publishing Windows service shutdown to the SCM");
        }
        Ok(())
    });

    if let Err(error) = runtime_result {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(1),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
        return Err(error);
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

// ── Firewall helpers ────────────────────────────────────────────────

fn firewall_ports_for_config(
    config: &crate::cli::Config,
) -> Vec<koi_common::firewall::FirewallPort> {
    use koi_common::firewall::{FirewallPort, FirewallProtocol};

    let mut ports = Vec::new();
    if !config.no_mdns {
        ports.extend(koi_mdns::firewall_ports());
    }
    // The HTTP adapter binds loopback by default — loopback traffic never
    // crosses the firewall, so only open the port when actually exposed
    // (--http-bind bridge/<ip>/0.0.0.0). Explicit loopback IPs stay closed.
    let http_exposed = config.http_bind != "loopback"
        && config
            .http_bind
            .parse::<std::net::IpAddr>()
            .map(|ip| !ip.is_loopback())
            .unwrap_or(true);
    if !config.no_http && http_exposed {
        ports.push(FirewallPort::new(
            "HTTP",
            FirewallProtocol::Tcp,
            config.http_port,
        ));
    }
    // Pond is separately operator-armed, but its listener is intentionally LAN-bound.
    // Provision the managed rule at install time so activation never needs elevation or
    // mutates host policy. With Pond disabled there is no socket behind the open port.
    if !config.no_http {
        if let Some(port) = koi_serve::pond::port_for_http(config.http_port) {
            ports.push(FirewallPort::new("Pond", FirewallProtocol::Tcp, port));
        }
    }
    if !config.no_dns {
        ports.extend(koi_dns::firewall_ports(&config.dns_config()));
    }

    let mut seen = HashSet::new();
    ports
        .into_iter()
        .filter(|port| seen.insert((port.protocol, port.port)))
        .collect()
}

fn firewall_rule_name(port: &koi_common::firewall::FirewallPort) -> String {
    format!(
        "Koi {} ({} {})",
        port.name,
        port.protocol.as_str(),
        port.port
    )
}

fn firewall_ports_summary(ports: &[koi_common::firewall::FirewallPort]) -> String {
    ports
        .iter()
        .map(|port| format!("{} {} ({})", port.protocol.as_str(), port.port, port.name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Check firewall status for enabled capability ports.
/// Called by startup_diagnostics in daemon mode.
pub(crate) fn check_firewall(config: &crate::cli::Config) {
    let ports = firewall_ports_for_config(config);
    if ports.is_empty() {
        return;
    }

    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Firewall: could not resolve the running executable"
            );
            return;
        }
    };

    let rule_names = ports.iter().map(firewall_rule_name).collect::<Vec<_>>();
    let requests = ports
        .iter()
        .zip(&rule_names)
        .map(|(port, rule_name)| (rule_name.as_str(), port.protocol.as_str(), port.port))
        .collect::<Vec<_>>();
    let assessments = match windows_firewall::assess_managed_rules(&requests, &executable) {
        Ok(assessments) => assessments,
        Err(error) => {
            tracing::warn!(
                error = %error,
                rule_count = requests.len(),
                "Firewall: could not query Windows Firewall"
            );
            return;
        }
    };

    for (port, assessment) in ports.iter().zip(assessments) {
        let protocol = port.protocol.as_str();
        match assessment {
            windows_firewall::Assessment::Open => tracing::info!(
                "Firewall: managed rule admits {protocol} {} ({})",
                port.port,
                port.name
            ),
            windows_firewall::Assessment::Inactive => tracing::info!(
                "Firewall: no enabled Windows Firewall profile applies to an active network for {protocol} {} ({})",
                port.port,
                port.name
            ),
            windows_firewall::Assessment::Blocked(
                windows_firewall::BlockReason::MissingOrMismatchedRule,
            ) => tracing::warn!(
                "Firewall: managed rule for {protocol} {} ({}) is absent, disabled, or not scoped to the running executable",
                port.port,
                port.name
            ),
            windows_firewall::Assessment::Blocked(
                windows_firewall::BlockReason::ActiveProfileNotCovered,
            ) => tracing::warn!(
                "Firewall: managed rule for {protocol} {} ({}) does not cover every active Windows Firewall profile",
                port.port,
                port.name
            ),
        }
    }
}

// ── Elevation check ─────────────────────────────────────────────────

/// Bail early with a clear message when not running as Administrator.
fn ensure_elevated(verb: &str) -> anyhow::Result<()> {
    use std::process::Command;

    // `net session` succeeds only in an elevated context.
    let ok = Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if ok {
        Ok(())
    } else {
        anyhow::bail!(
            "koi {verb} requires Administrator privileges \u{2014} \
             right-click your terminal and choose \"Run as administrator\""
        );
    }
}

// ── Service lifecycle helpers ───────────────────────────────────────

/// Poll a service until it reaches the Stopped state or the timeout expires.
fn wait_for_stop(service: &windows_service::service::Service) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + SERVICE_STOP_TIMEOUT;
    loop {
        std::thread::sleep(SERVICE_STOP_POLL);
        match service.query_status() {
            Ok(status) if status.current_state == ServiceState::Stopped => return Ok(()),
            Ok(_) if std::time::Instant::now() >= deadline => {
                anyhow::bail!("Service did not stop within {:?}", SERVICE_STOP_TIMEOUT);
            }
            Ok(_) => continue,
            Err(e) => anyhow::bail!("Could not query service status: {e}"),
        }
    }
}

/// Quiesce a replacement before restoring its files and descriptor.
///
/// A candidate can fail before registering its control handler. SCM then
/// reports `StartPending`, but `ControlService(STOP)` returns 1052 or 1061 and
/// can leave the transaction blocked for the manager's full start timeout.
/// Failure actions are already disabled by the caller. In that one state we
/// verify the process image from the same handle we terminate, then retain the
/// normal bounded wait for SCM to publish `Stopped`.
fn stop_service_for_restore(service: &windows_service::service::Service) -> anyhow::Result<()> {
    print!("  Stopping service for restore...");
    let deadline = std::time::Instant::now() + SERVICE_STOP_TIMEOUT;
    loop {
        let status = service.query_status()?;
        if status.current_state == ServiceState::Stopped {
            println!(" done.");
            return Ok(());
        }

        match service.stop() {
            Ok(_) => break,
            Err(windows_service::Error::Winapi(ref error))
                if error.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE) =>
            {
                break
            }
            Err(error) if start_pending_rejected_stop(status.current_state, &error) => {
                // SCM can expose StartPending before it publishes the process
                // id. Poll rather than guessing; forced recovery remains
                // unavailable until the same status record names a process we
                // can verify against the fixed product image.
                if let Some(pid) = query_start_pending_process_id()? {
                    terminate_verified_process(pid, &install_bin_path())?;
                    println!(" terminated verified start-pending PID {pid}.");
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "SCM did not publish a process id for the start-pending replacement within {:?}; refusing to terminate an unverified process",
                        SERVICE_STOP_TIMEOUT
                    );
                }
                std::thread::sleep(SERVICE_STOP_POLL);
            }
            Err(windows_service::Error::Winapi(ref error))
                if status.current_state == ServiceState::StopPending
                    && error.raw_os_error() == Some(ERROR_SERVICE_CANNOT_ACCEPT_CONTROL) =>
            {
                break
            }
            Err(error) => return Err(error.into()),
        }
    }
    wait_for_stop(service)?;
    println!(" done.");
    Ok(())
}

/// Read the raw `SERVICE_STATUS_PROCESS` because windows-service 0.8 omits
/// `dwProcessId` from its safe status value unless the state is `Running`.
/// A pending-state PID is explicitly untrusted until `terminate_verified_process`
/// opens it and proves the image through that same handle.
fn query_start_pending_process_id() -> anyhow::Result<Option<u32>> {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_START_PENDING, SERVICE_STATUS_PROCESS,
    };

    let mut service_name = encode_os(OsStr::new(SERVICE_NAME));
    service_name.push(0);
    // SAFETY: both names are valid NUL-terminated inputs and every successful
    // SCM/service handle is closed before returning.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("could not open SCM while querying a start-pending replacement");
    }

    let result = (|| -> anyhow::Result<Option<u32>> {
        // SAFETY: `manager` is an open SCM handle and `service_name` remains
        // alive and NUL-terminated for this call.
        let service = unsafe { OpenServiceW(manager, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("could not open Koi service for raw process-status query");
        }

        let query_result = (|| -> anyhow::Result<Option<u32>> {
            let mut status = unsafe { std::mem::zeroed::<SERVICE_STATUS_PROCESS>() };
            let mut needed = 0;
            // SAFETY: `service` has SERVICE_QUERY_STATUS access, and the output
            // buffer exactly describes `status` for SC_STATUS_PROCESS_INFO (0).
            let ok = unsafe {
                QueryServiceStatusEx(
                    service,
                    0,
                    &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
                    std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                    &mut needed,
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error())
                    .context("could not query raw Koi service process status");
            }
            Ok(
                (status.dwCurrentState == SERVICE_START_PENDING && status.dwProcessId != 0)
                    .then_some(status.dwProcessId),
            )
        })();
        // SAFETY: `service` is the handle returned by OpenServiceW above.
        unsafe { CloseServiceHandle(service) };
        query_result
    })();
    // SAFETY: `manager` is the handle returned by OpenSCManagerW above.
    unsafe { CloseServiceHandle(manager) };
    result
}

fn start_pending_rejected_stop(state: ServiceState, error: &windows_service::Error) -> bool {
    state == ServiceState::StartPending
        && matches!(
            error,
            windows_service::Error::Winapi(error)
                if matches!(
                    error.raw_os_error(),
                    Some(ERROR_INVALID_SERVICE_CONTROL | ERROR_SERVICE_CANNOT_ACCEPT_CONTROL)
                )
        )
}

/// Terminate only the process whose already-open handle proves it is the
/// transaction's fixed product image. Holding one handle across query and
/// termination prevents PID reuse from widening this recovery boundary.
fn terminate_verified_process(pid: u32, expected_image: &std::path::Path) -> anyhow::Result<()> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    // SAFETY: OpenProcess receives the SCM-provided PID. The returned handle
    // is closed on every path below.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            0,
            pid,
        )
    };
    if process.is_null() {
        return Err(std::io::Error::last_os_error()).context(format!(
            "could not open start-pending service PID {pid} for verified termination"
        ));
    }

    let result = (|| -> anyhow::Result<()> {
        let actual_image = process_image_path_from_handle(process)?;
        let actual = std::fs::canonicalize(&actual_image).map_err(|error| {
            anyhow::anyhow!(
                "could not resolve start-pending process image {} for PID {pid}: {error}",
                actual_image.display()
            )
        })?;
        let expected = std::fs::canonicalize(expected_image).map_err(|error| {
            anyhow::anyhow!(
                "could not resolve expected service image {}: {error}",
                expected_image.display()
            )
        })?;
        if actual != expected {
            anyhow::bail!(
                "SCM start-pending PID {pid} runs {} instead of {}; refusing forced recovery",
                actual.display(),
                expected.display()
            );
        }

        // SAFETY: `process` is an owned handle with PROCESS_TERMINATE access,
        // and it was verified above against the transaction-owned image.
        if unsafe { TerminateProcess(process, 1) } == 0 {
            return Err(std::io::Error::last_os_error()).context(format!(
                "could not terminate start-pending service PID {pid}"
            ));
        }
        Ok(())
    })();
    // SAFETY: `process` is the handle returned by OpenProcess above.
    unsafe { CloseHandle(process) };
    result
}

/// Start a service, tolerating the SCM's transient states after a failed
/// replacement: a queued auto-restart can race the explicit start and
/// surface as a spurious error or already-running.
fn start_with_retry(
    service: &windows_service::service::Service,
) -> std::result::Result<(), windows_service::Error> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match service.start::<OsString>(&[]) {
            Ok(()) => return Ok(()),
            Err(windows_service::Error::Winapi(ref e))
                if e.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING) =>
            {
                return Ok(());
            }
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(SERVICE_STOP_POLL);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Require SCM to report a real running process and verify that process is
/// executing the expected product image. HTTP health alone could be answered
/// by a stale or unrelated listener after a failed replacement.
fn verify_service_process(
    service: &windows_service::service::Service,
    expected_image: &std::path::Path,
) -> anyhow::Result<u32> {
    let deadline = std::time::Instant::now() + SERVICE_START_TIMEOUT;
    let pid = loop {
        let status = service.query_status()?;
        if status.current_state == ServiceState::Running {
            if let Some(pid) = status.process_id.filter(|pid| *pid != 0) {
                break pid;
            }
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "SCM did not report a running {SERVICE_NAME} process within {:?}",
                SERVICE_START_TIMEOUT
            );
        }
        std::thread::sleep(SERVICE_STOP_POLL);
    };

    let actual_image = process_image_path(pid)?;
    let actual = std::fs::canonicalize(&actual_image).map_err(|error| {
        anyhow::anyhow!(
            "could not resolve SCM process image {} for PID {pid}: {error}",
            actual_image.display()
        )
    })?;
    let expected = std::fs::canonicalize(expected_image).map_err(|error| {
        anyhow::anyhow!(
            "could not resolve expected service image {}: {error}",
            expected_image.display()
        )
    })?;
    if actual != expected {
        anyhow::bail!(
            "SCM started {} as PID {pid} instead of {}",
            actual.display(),
            expected.display()
        );
    }
    Ok(pid)
}

fn process_image_path(pid: u32) -> anyhow::Result<PathBuf> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: these Win32 APIs receive a process id and owned output buffer;
    // the opened handle is closed on every exit path below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = process_image_path_from_handle(process);
    unsafe { CloseHandle(process) };
    result
}

fn process_image_path_from_handle(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> anyhow::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;

    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    // SAFETY: `process` is open for query access and the mutable buffer and
    // length describe its complete allocation.
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

/// Poll until a deleted service is fully purged from the SCM database.
/// The SCM defers actual removal until all handles are closed and the
/// internal state is flushed; attempting to recreate before that fails.
fn wait_for_delete(manager: &ServiceManager) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + SERVICE_STOP_TIMEOUT;
    loop {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Err(windows_service::Error::Winapi(ref error))
                if error.raw_os_error() == Some(ERROR_SERVICE_NOT_FOUND) =>
            {
                return Ok(());
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "could not verify deletion of the old service entry: {error}"
                ));
            }
            Ok(_) if std::time::Instant::now() >= deadline => {
                anyhow::bail!(
                    "Old service entry not purged within {:?}",
                    SERVICE_STOP_TIMEOUT
                );
            }
            Ok(_) => std::thread::sleep(SERVICE_STOP_POLL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_failure_is_persisted_without_an_async_guard() {
        let dir = std::env::temp_dir().join(format!(
            "koi-service-failure-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = dir.join("logs").join("koi.log");
        append_service_failure(&path, &anyhow::anyhow!("outer").context("startup boundary"))
            .unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("Koi Windows service startup failed"));
        assert!(contents.contains("startup boundary: outer"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn service_paths_respect_data_dir_override() {
        let _ = koi_common::test::ensure_data_dir("koi-win-path-tests");
        let data_dir = service_data_dir();
        let log_dir = service_log_dir();
        let log_path = service_log_path();

        assert!(log_dir.starts_with(&data_dir));
        assert!(log_path.starts_with(&log_dir));
        assert!(log_path.ends_with("koi.log"));
    }

    #[test]
    fn install_bin_path_is_product_owned_not_a_checkout() {
        let bin = install_bin_path();
        let text = bin.to_string_lossy().to_ascii_lowercase();
        assert!(text.contains("program files"), "got {}", bin.display());
        assert!(text.ends_with(r"\koi\koi.exe"), "got {}", bin.display());
    }

    #[test]
    fn launch_command_lines_preserve_quoted_arguments_losslessly() {
        assert_eq!(
            split_launch_command(OsStr::new(
                r#""C:\Program Files\Koi\koi.exe" --daemon "--label=Koi Alpha" "C:\path with spaces\leaf""#
            ))
            .unwrap(),
            (
                OsString::from(r"C:\Program Files\Koi\koi.exe"),
                vec![
                    OsString::from("--daemon"),
                    OsString::from("--label=Koi Alpha"),
                    OsString::from(r"C:\path with spaces\leaf"),
                ]
            )
        );
        assert_eq!(
            split_launch_command(OsStr::new(r"F:\bin\koi.exe --daemon --extra arg")).unwrap(),
            (
                OsString::from(r"F:\bin\koi.exe"),
                vec![
                    OsString::from("--daemon"),
                    OsString::from("--extra"),
                    OsString::from("arg")
                ]
            )
        );
        assert_eq!(
            split_launch_command(OsStr::new(r"F:\bare\koi.exe")).unwrap(),
            (OsString::from(r"F:\bare\koi.exe"), Vec::new())
        );
    }

    #[test]
    fn only_start_pending_control_rejection_allows_verified_termination() {
        for raw in [
            ERROR_INVALID_SERVICE_CONTROL,
            ERROR_SERVICE_CANNOT_ACCEPT_CONTROL,
        ] {
            let error = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(raw));
            assert!(start_pending_rejected_stop(
                ServiceState::StartPending,
                &error
            ));
            assert!(!start_pending_rejected_stop(ServiceState::Running, &error));
            assert!(!start_pending_rejected_stop(
                ServiceState::StopPending,
                &error
            ));
        }

        let unrelated = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5));
        assert!(!start_pending_rejected_stop(
            ServiceState::StartPending,
            &unrelated
        ));
    }

    #[test]
    fn complete_service_descriptor_rebuilds_for_recreation() {
        let manifest = test_manifest(PathBuf::from(r"F:\repo\koi.exe"));
        let info = restored_service_info(&manifest).unwrap();
        assert_eq!(info.name, OsStr::new(SERVICE_NAME));
        assert_eq!(info.display_name, OsStr::new(DISPLAY_NAME));
        assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(info.start_type, ServiceStartType::OnDemand);
        assert_eq!(info.error_control, ServiceErrorControl::Severe);
        assert_eq!(info.executable_path, PathBuf::from(r"F:\repo\koi.exe"));
        assert_eq!(
            info.launch_arguments,
            vec![
                OsString::from("--daemon"),
                OsString::from("--label=Koi Alpha")
            ]
        );
        assert_eq!(
            info.dependencies,
            vec![ServiceDependency::Service(OsString::from("Tcpip"))]
        );
        assert_eq!(info.account_name, Some(OsString::from("LocalSystem")));
    }

    #[test]
    fn actual_version_one_json_deserializes_but_missing_profile_blocks_armed_recovery() {
        // Exact v1 wire fields from a34be05: there is no service descriptor
        // and firewall snapshots have no profile member.
        let raw = r#"{
  "version": 1,
  "phase": "Armed",
  "http_port": 5641,
  "service": {
    "existed": true,
    "executable_path": "F:\\legacy path\\koi.exe",
    "launch_arguments": ["--daemon", "--label=Koi Alpha"],
    "start_type": "demand",
    "was_active": true
  },
  "files": [],
  "firewall": [{
    "name": "Koi Pond (TCP 5644)",
    "enabled": true,
    "direction": "inbound",
    "action": "allow",
    "protocol": "tcp",
    "local_port": "5644",
    "program": "F:\\legacy path\\koi.exe"
  }],
  "added_rules": [],
  "created_service": false,
  "temporary_paths": []
}"#;
        let manifest: InstallManifest = serde_json::from_str(raw).unwrap();
        assert_eq!(manifest.version, 1);
        assert!(manifest.service.descriptor.is_none());
        assert_eq!(manifest.firewall[0].profile, None);
        let info = restored_service_info(&manifest).unwrap();
        assert_eq!(
            info.executable_path,
            PathBuf::from(r"F:\legacy path\koi.exe")
        );
        assert_eq!(info.start_type, ServiceStartType::OnDemand);
        assert_eq!(
            info.launch_arguments,
            vec![
                OsString::from("--daemon"),
                OsString::from("--label=Koi Alpha")
            ]
        );

        let path = PathBuf::from(r"F:\ProgramData\koi\state\scm-install-transaction.json");
        let error = validate_recovery_boundary(&path, &manifest).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("version-1 manifests predate firewall profile capture"));
        assert!(message.contains("stopped before any mutation"));
        assert!(message.contains("manifest and backups remain"));

        let mut provable = manifest;
        provable.firewall.clear();
        validate_recovery_boundary(&path, &provable).unwrap();
    }

    fn test_manifest(executable: PathBuf) -> InstallManifest {
        InstallManifest {
            version: TRANSACTION_VERSION,
            phase: TransactionPhase::Armed,
            http_port: 5641,
            service: ServiceSnapshot {
                existed: true,
                descriptor: Some(ServiceDescriptorSnapshot {
                    executable_path: encode_os(executable.as_os_str()),
                    launch_arguments: vec![
                        encode_os(OsStr::new("--daemon")),
                        encode_os(OsStr::new("--label=Koi Alpha")),
                    ],
                    display_name: encode_os(OsStr::new(DISPLAY_NAME)),
                    service_type: ServiceType::OWN_PROCESS.bits(),
                    start_type: ServiceStartType::OnDemand.to_raw(),
                    error_control: ServiceErrorControl::Severe.to_raw(),
                    dependencies: vec![encode_os(OsStr::new("Tcpip"))],
                    account_name: Some(encode_os(OsStr::new("LocalSystem"))),
                }),
                legacy_executable_path: None,
                legacy_launch_arguments: None,
                legacy_start_type: None,
                was_active: true,
            },
            files: Vec::new(),
            firewall: Vec::new(),
            added_rules: Vec::new(),
            created_service: false,
            temporary_paths: Vec::new(),
        }
    }

    #[test]
    fn install_manifest_round_trips_through_the_state_file() {
        let dir = std::env::temp_dir().join(format!(
            "koi-scm-transaction-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = dir.join("state").join(TRANSACTION_FILENAME);
        let mut manifest = test_manifest(PathBuf::from(r"F:\repo\koi.exe"));
        manifest.files =
            vec![FileSnapshot::inspect(dir.join("bin").join("koi.exe"), false).unwrap()];
        manifest.firewall = vec![FirewallRuleSnapshot {
            name: "Koi mDNS (UDP 5353)".to_string(),
            enabled: true,
            direction: "in".to_string(),
            action: "allow".to_string(),
            protocol: "udp".to_string(),
            local_port: "5353".to_string(),
            program: r"F:\repo\koi.exe".to_string(),
            profile: Some("private".to_string()),
        }];
        manifest.added_rules = vec!["Koi Pond (TCP 5644)".to_string()];
        write_manifest(&path, &manifest).unwrap();
        let loaded: InstallManifest = koi_common::persist::read_json(&path).unwrap();
        assert_eq!(loaded.version, TRANSACTION_VERSION);
        assert_eq!(
            decode_os(&loaded.service.descriptor.as_ref().unwrap().executable_path),
            OsString::from(r"F:\repo\koi.exe")
        );
        assert_eq!(
            decode_os(&loaded.service.descriptor.as_ref().unwrap().launch_arguments[1]),
            OsString::from("--label=Koi Alpha")
        );
        assert_eq!(loaded.files.len(), 1);
        assert!(!loaded.files[0].existed);
        assert_eq!(loaded.firewall[0].local_port, "5353");
        assert_eq!(loaded.added_rules, vec!["Koi Pond (TCP 5644)".to_string()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scm_backup_integrity_rejects_changed_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "koi-scm-integrity-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("koi.exe");
        std::fs::write(&target, b"prior binary").unwrap();
        let mut snapshot = FileSnapshot::inspect(target, false).unwrap();
        snapshot.prepare().unwrap();
        std::fs::write(&snapshot.backup, b"changed backup").unwrap();

        let error = snapshot.validate_backup(true).unwrap_err().to_string();
        assert!(error.contains("backup"));
        assert!(error.contains("changed"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn settled_scm_recovery_never_restores_old_files() {
        let dir = std::env::temp_dir().join(format!(
            "koi-scm-settled-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("koi.exe");
        let manifest_path = dir.join(TRANSACTION_FILENAME);
        std::fs::write(&target, b"prior binary").unwrap();
        let mut snapshot = FileSnapshot::inspect(target.clone(), false).unwrap();
        snapshot.prepare().unwrap();
        std::fs::write(&target, b"committed binary").unwrap();
        let mut manifest = test_manifest(target.clone());
        manifest.phase = TransactionPhase::Settled;
        manifest.files = vec![snapshot.clone()];
        write_manifest(&manifest_path, &manifest).unwrap();

        recover_interrupted(&manifest_path).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"committed binary");
        assert!(!snapshot.backup.exists());
        assert!(!manifest_path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn manifest_transitions_are_durable_before_in_memory_state_changes() {
        let dir =
            std::env::temp_dir().join(format!("koi-scm-transition-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(TRANSACTION_FILENAME);
        let manifest = test_manifest(PathBuf::from(r"F:\repo\koi.exe"));
        write_manifest(&path, &manifest).unwrap();
        let mut transaction = ScmInstallTransaction { path, manifest };

        transaction
            .mark_rule_created("Koi Pond (TCP 5654)")
            .unwrap();
        let persisted: InstallManifest = koi_common::persist::read_json(&transaction.path).unwrap();
        assert_eq!(persisted.added_rules, vec!["Koi Pond (TCP 5654)"]);

        transaction.mark_service_created().unwrap();
        let persisted: InstallManifest = koi_common::persist::read_json(&transaction.path).unwrap();
        assert!(persisted.created_service);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_manifest_transition_cannot_advance_recovery_state() {
        let dir = std::env::temp_dir().join(format!(
            "koi-scm-transition-failure-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(TRANSACTION_FILENAME);
        let manifest = test_manifest(PathBuf::from(r"F:\repo\koi.exe"));
        write_manifest(&path, &manifest).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let mut transaction = ScmInstallTransaction { path, manifest };

        assert!(transaction.mark_rule_created("Koi test rule").is_err());
        assert!(transaction.manifest.added_rules.is_empty());
        assert!(transaction.mark_service_created().is_err());
        assert!(!transaction.manifest.created_service);
        let _ = std::fs::remove_dir_all(dir);
    }
}
