use std::ffi::OsString;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "koi";
const DISPLAY_NAME: &str = "Koi mDNS Service";
const SERVICE_DESCRIPTION: &str =
    "Koi mDNS/DNS-SD daemon \u{2014} local service discovery for HTTP, IPC, and CLI clients";

const FIREWALL_RULE_MDNS: &str = "Koi mDNS (UDP)";
const FIREWALL_RULE_HTTP: &str = "Koi HTTP (TCP)";
const MDNS_PORT: u16 = 5353;

const RECOVERY_DELAY_FIRST: Duration = Duration::from_secs(5);
const RECOVERY_DELAY_SECOND: Duration = Duration::from_secs(10);
/// Reset failure count after 24 hours of clean running.
const RECOVERY_RESET_SECS: Duration = Duration::from_secs(86_400);

const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_STOP_POLL: Duration = Duration::from_millis(500);

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);
const SHUTDOWN_DRAIN: Duration = Duration::from_millis(500);

// Generate the extern "system" function that the SCM expects.
define_windows_service!(ffi_service_main, service_main);

// ── Install ─────────────────────────────────────────────────────────

/// Install Koi as a Windows Service.
///
/// Handles fresh installs and upgrades (different exe path, service
/// already running). Configures recovery policy, description, firewall
/// rules, and the service log directory.
pub fn install() -> anyhow::Result<()> {
    let exe_path = std::env::current_exe()?;
    println!("Installing Koi mDNS service...");
    println!("  Binary: {}", exe_path.display());

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )?;
    let mut needs_restart = false;

    // Try to open an existing service for upgrade
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS
            | ServiceAccess::STOP
            | ServiceAccess::DELETE
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::START,
    ) {
        Ok(existing) => {
            println!("  Existing service found, updating...");

            // Stop if running
            if let Ok(status) = existing.query_status() {
                if status.current_state != ServiceState::Stopped {
                    print!("  Stopping running service...");
                    let _ = existing.stop();
                    wait_for_stop(&existing)?;
                    println!(" done.");
                    needs_restart = true;
                }
            }

            existing.delete()?;
            drop(existing);

            // Re-create with updated config
            let info = build_service_info(&exe_path);
            let svc = manager.create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )?;
            println!("  Service updated");
            svc
        }
        Err(_) => {
            // Fresh install
            let info = build_service_info(&exe_path);
            let svc = manager.create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )?;
            println!("  Service installed (AutoStart)");
            svc
        }
    };

    // Description (best-effort, non-critical)
    if let Err(e) = service.set_description(SERVICE_DESCRIPTION) {
        println!("  Warning: could not set description: {e}");
    }

    // Recovery policy: restart after 5s, restart after 10s, then nothing
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
    match service.update_failure_actions(failure_actions) {
        Ok(()) => println!(
            "  Recovery policy: restart after {}s, {}s, then stop (resets after 24h)",
            RECOVERY_DELAY_FIRST.as_secs(),
            RECOVERY_DELAY_SECOND.as_secs()
        ),
        Err(e) => println!("  Warning: could not set recovery policy: {e}"),
    }
    // Also trigger recovery on non-crash failures (e.g. non-zero exit)
    let _ = service.set_failure_actions_on_non_crash_failures(true);

    // Log directory
    let log_dir = crate::config::service_log_dir();
    match std::fs::create_dir_all(&log_dir) {
        Ok(()) => println!("  Log directory: {}", log_dir.display()),
        Err(e) => println!("  Warning: could not create log directory: {e}"),
    }

    // Firewall rules (best-effort, never abort)
    let http_port = std::env::var("KOI_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(crate::config::DEFAULT_HTTP_PORT);
    let fw_mdns = create_firewall_rule(FIREWALL_RULE_MDNS, "UDP", MDNS_PORT, &exe_path);
    let fw_http = create_firewall_rule(FIREWALL_RULE_HTTP, "TCP", http_port, &exe_path);
    if fw_mdns && fw_http {
        println!(
            "  Firewall rules set: {} (UDP {}) and {} (TCP {})",
            FIREWALL_RULE_MDNS, MDNS_PORT, FIREWALL_RULE_HTTP, http_port
        );
    } else {
        if !fw_mdns {
            println!(
                "  Warning: could not set firewall rule {} (UDP {})",
                FIREWALL_RULE_MDNS, MDNS_PORT
            );
        }
        if !fw_http {
            println!(
                "  Warning: could not set firewall rule {} (TCP {})",
                FIREWALL_RULE_HTTP, http_port
            );
        }
    }

    // Start the service
    match service.start::<OsString>(&[]) {
        Ok(()) => {
            if needs_restart {
                println!("  Service restarted");
            } else {
                println!("  Service started");
            }
        }
        Err(e) => println!("  Warning: could not start service: {e}"),
    }

    println!();
    println!("Koi mDNS service installed.");

    Ok(())
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

// ── Uninstall ───────────────────────────────────────────────────────

/// Uninstall the Koi Windows Service and clean up all artifacts.
///
/// Stops the service if running, removes firewall rules, deletes
/// breadcrumb, and cleans up empty log/data directories.
/// Idempotent — safe to run even if the service was never installed.
pub fn uninstall() -> anyhow::Result<()> {
    println!("Uninstalling Koi mDNS service...");

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => {
            // Stop if running
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
        Err(_) => {
            println!("  Service not found, cleaning up remaining files...");
        }
    }

    // Firewall rules (best-effort)
    let rm_mdns = remove_firewall_rule(FIREWALL_RULE_MDNS);
    let rm_http = remove_firewall_rule(FIREWALL_RULE_HTTP);
    if rm_mdns || rm_http {
        println!(
            "  Firewall rules removed: {} (UDP {}) and {} (TCP {})",
            FIREWALL_RULE_MDNS,
            MDNS_PORT,
            FIREWALL_RULE_HTTP,
            crate::config::DEFAULT_HTTP_PORT
        );
    }

    // Daemon discovery file
    crate::config::delete_breadcrumb();

    // Log directory — remove only if empty, otherwise inform the user
    let log_dir = crate::config::service_log_dir();
    match std::fs::remove_dir(&log_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => println!("  Logs preserved at: {}", log_dir.display()),
    }

    // Parent data directory — remove only if empty
    let data_dir = crate::config::service_data_dir();
    let _ = std::fs::remove_dir(&data_dir); // silent — either empty or has logs

    println!();
    println!("Koi mDNS service uninstalled.");

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
    }
}

fn run_service(_arguments: Vec<OsString>) -> anyhow::Result<()> {
    // Initialize logging to the well-known service log file.
    let log_path = crate::config::service_log_path();
    let env_filter = tracing_subscriber::EnvFilter::try_new(
        std::env::var("KOI_LOG").unwrap_or_else(|_| "info".to_string()),
    )
    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _log_guards = crate::init_logging(env_filter, Some(&log_path)).unwrap_or_else(|_| vec![]); // Fall back to no logging rather than crashing

    let config = crate::config::Config::from_env();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

    // Register SCM handler — report StartPending while we spin up
    let status_handle =
        service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Some(tx) = shutdown_tx.lock().unwrap().take() {
                        let _ = tx.send(());
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
    rt.block_on(async {
        let cancel = tokio_util::sync::CancellationToken::new();
        let core = match crate::core::MdnsCore::with_cancel(cancel.clone()) {
            Ok(c) => std::sync::Arc::new(c),
            Err(e) => {
                tracing::error!(error = %e, "Failed to start mDNS core");
                let _ = status_handle.set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(1),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                });
                return;
            }
        };

        // Startup diagnostics (logged to file)
        crate::startup_diagnostics(&config);

        let mut tasks = Vec::new();

        // HTTP adapter
        if !config.no_http {
            let c = core.clone();
            let port = config.http_port;
            let token = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = crate::adapters::http::start(c, port, token).await {
                    tracing::error!(error = %e, "HTTP adapter failed");
                }
            }));
        }

        // IPC adapter
        if !config.no_ipc {
            let c = core.clone();
            let path = config.pipe_path.clone();
            let token = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = crate::adapters::pipe::start(c, path, token).await {
                    tracing::error!(error = %e, "IPC adapter failed");
                }
            }));
        }

        // Write breadcrumb for client discovery
        if !config.no_http {
            let endpoint = format!("http://localhost:{}", config.http_port);
            crate::config::write_breadcrumb(&endpoint);
        }

        // Report Running to SCM
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        tracing::info!("Ready.");

        // Wait for SCM stop signal
        let _ = shutdown_rx.await;
        tracing::info!("Shutting down...");

        // Report StopPending
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: SHUTDOWN_TIMEOUT,
            process_id: None,
        });

        // Ordered shutdown: cancel → drain → wait tasks → core goodbye
        let shutdown = async {
            cancel.cancel();
            tokio::time::sleep(SHUTDOWN_DRAIN).await;
            for task in tasks {
                let _ = task.await;
            }
            if let Err(e) = core.shutdown().await {
                tracing::warn!(error = %e, "Error during shutdown");
            }
        };

        if tokio::time::timeout(SHUTDOWN_TIMEOUT, shutdown)
            .await
            .is_err()
        {
            tracing::warn!(
                "Shutdown timed out after {:?} — forcing exit",
                SHUTDOWN_TIMEOUT
            );
        }

        crate::config::delete_breadcrumb();
    });

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

/// Create a firewall rule. Returns `true` on success.
fn create_firewall_rule(name: &str, protocol: &str, port: u16, exe_path: &std::path::Path) -> bool {
    use std::process::Command;

    // Delete first for idempotency (ignore errors — rule may not exist)
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule"])
        .arg(format!("name={name}"))
        .output();

    let result = Command::new("netsh")
        .args(["advfirewall", "firewall", "add", "rule"])
        .arg(format!("name={name}"))
        .args(["dir=in", "action=allow"])
        .arg(format!("protocol={protocol}"))
        .arg(format!("localport={port}"))
        .arg(format!("program={}", exe_path.display()))
        .output();

    matches!(result, Ok(output) if output.status.success())
}

/// Remove a firewall rule. Returns `true` if the rule was found and removed.
fn remove_firewall_rule(name: &str) -> bool {
    use std::process::Command;

    let result = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule"])
        .arg(format!("name={name}"))
        .output();

    matches!(result, Ok(output) if output.status.success())
}

/// Check firewall status for mDNS and HTTP ports.
/// Called by startup_diagnostics in daemon mode.
pub(crate) fn check_firewall(http_port: u16) {
    use std::process::Command;

    let result = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
            "dir=in",
        ])
        .output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mdns_str = MDNS_PORT.to_string();
            if stdout.contains(&mdns_str) && stdout.contains("UDP") {
                tracing::info!("Firewall: UDP {MDNS_PORT} rule found");
            } else {
                tracing::warn!(
                    "Koi may not receive mDNS traffic \u{2014} no UDP {MDNS_PORT} inbound rule found."
                );
                tracing::warn!("Run as administrator or execute:");
                tracing::warn!(
                    "  netsh advfirewall firewall add rule name=\"{FIREWALL_RULE_MDNS}\" dir=in action=allow protocol=UDP localport={MDNS_PORT}"
                );
            }
            if stdout.contains(&http_port.to_string()) && stdout.contains("TCP") {
                tracing::info!("Firewall: TCP {} rule found", http_port);
            } else {
                tracing::warn!(
                    "  netsh advfirewall firewall add rule name=\"{FIREWALL_RULE_HTTP}\" dir=in action=allow protocol=TCP localport={}",
                    http_port
                );
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "Could not check firewall rules");
        }
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
