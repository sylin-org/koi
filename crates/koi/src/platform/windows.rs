use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use std::collections::HashSet;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

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

pub fn service_data_dir() -> PathBuf {
    koi_common::paths::koi_data_dir()
}

/// Win32 ERROR_SERVICE_DOES_NOT_EXIST (1060).
const ERROR_SERVICE_NOT_FOUND: i32 = 1060;

// Generate the extern "system" function that the SCM expects.
define_windows_service!(ffi_service_main, service_main);

// ── Install ─────────────────────────────────────────────────────────

/// Install Koi as a Windows Service.
///
/// Handles fresh installs and upgrades (different exe path, service
/// already running). Configures recovery policy, description, firewall
/// rules, and the service log directory.
pub fn install() -> anyhow::Result<()> {
    ensure_elevated("install")?;
    let exe_path = std::env::current_exe()?;
    println!("Installing Koi service...");
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

            // The SCM marks deleted services for deferred removal.
            // Poll until the old entry is fully purged before recreating.
            wait_for_delete(&manager)?;

            // Re-create with updated config
            let info = build_service_info(&exe_path);
            let svc = manager.create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )?;
            println!("  Service updated");
            svc
        }
        Err(windows_service::Error::Winapi(ref e))
            if e.raw_os_error() == Some(ERROR_SERVICE_NOT_FOUND) =>
        {
            // Fresh install
            let info = build_service_info(&exe_path);
            let svc = manager.create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )?;
            println!("  Service installed (AutoStart)");
            svc
        }
        Err(e) => return Err(e.into()),
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
    let log_dir = service_log_dir();
    match std::fs::create_dir_all(&log_dir) {
        Ok(()) => println!("  Log directory: {}", log_dir.display()),
        Err(e) => println!("  Warning: could not create log directory: {e}"),
    }

    // Firewall rules (best-effort, never abort)
    let config = crate::cli::Config::from_env();
    let ports = firewall_ports_for_config(&config);
    let mut ok = Vec::new();
    let mut failed = Vec::new();

    // Clean up legacy rule names so we don't leave duplicates behind.
    let _ = remove_firewall_rule(FIREWALL_RULE_MDNS_LEGACY);
    let _ = remove_firewall_rule(FIREWALL_RULE_HTTP_LEGACY);

    for port in &ports {
        let rule_name = firewall_rule_name(port);
        if create_firewall_rule(&rule_name, port.protocol.as_str(), port.port, &exe_path) {
            ok.push(port.clone());
        } else {
            failed.push(port.clone());
        }
    }

    if !ok.is_empty() {
        println!("  Firewall rules set ({})", firewall_ports_summary(&ok));
    }
    for port in &failed {
        println!(
            "  Warning: could not set firewall rule for {} {} ({})",
            port.protocol.as_str(),
            port.port,
            port.name
        );
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
        Err(e) => {
            println!("  Warning: could not start service: {e}");
            // Query status to help diagnose the failure
            match service.query_status() {
                Ok(status) => println!(
                    "  Service state: {:?}, exit code: {:?}",
                    status.current_state, status.exit_code
                ),
                Err(qe) => println!("  Could not query status: {qe}"),
            }
            println!("  Binary: {}", exe_path.display());
            println!("  Try: sc start koi  (or check Event Viewer > Windows Logs > System)");
        }
    }

    println!();
    println!("Koi service installed.");
    println!("  \u{b0}\u{2027} \u{1f41f} \u{b7}\u{ff61} the local waters are calm");
    println!();
    println!("  Modules enabled:");
    println!("    mDNS        service discovery (active)");
    println!("    DNS         static + certmesh entries (ready)");
    println!("    CertMesh    certificate mesh CA (ready \u{2014} run certmesh create)");
    println!("    Health      endpoint health checks (ready)");
    println!("    Proxy       TLS reverse proxy (ready)");
    println!();
    println!("  Use `koi status` to see module state.");

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

    // Best-effort graceful shutdown via HTTP (before SCM stop)
    if let Some(ep) = koi_config::breadcrumb::read_breadcrumb() {
        let client = crate::client::KoiClient::new(&ep);
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

    // Firewall rules (best-effort)
    let config = crate::cli::Config::from_env();
    let ports = firewall_ports_for_config(&config);
    let mut removed = Vec::new();
    for port in &ports {
        if remove_firewall_rule(&firewall_rule_name(port)) {
            removed.push(port.clone());
        }
    }
    let legacy_removed = remove_firewall_rule(FIREWALL_RULE_MDNS_LEGACY)
        | remove_firewall_rule(FIREWALL_RULE_HTTP_LEGACY);
    if !removed.is_empty() {
        println!(
            "  Firewall rules removed ({})",
            firewall_ports_summary(&removed)
        );
    } else if legacy_removed {
        println!("  Firewall rules removed");
    }

    // Daemon discovery file
    koi_config::breadcrumb::delete_breadcrumb();

    // Log directory — remove only if empty, otherwise inform the user
    let log_dir = service_log_dir();
    match std::fs::remove_dir(&log_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => println!("  Logs preserved at: {}", log_dir.display()),
    }

    // Parent data directory — remove only if empty
    let data_dir = service_data_dir();
    let _ = std::fs::remove_dir(&data_dir); // silent — either empty or has logs

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
    }
}

fn run_service(_arguments: Vec<OsString>) -> anyhow::Result<()> {
    // Initialize logging to the well-known service log file.
    let log_path = service_log_path();
    let env_filter = tracing_subscriber::EnvFilter::try_new(
        std::env::var("KOI_LOG").unwrap_or_else(|_| "info".to_string()),
    )
    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _log_guards = crate::init_logging(env_filter, Some(&log_path)).unwrap_or_else(|_| vec![]); // Fall back to no logging rather than crashing

    let config = crate::cli::Config::from_env();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

    // Register SCM handler — report StartPending while we spin up
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
    rt.block_on(async {
        let cancel = tokio_util::sync::CancellationToken::new();

        // Conditionally create domain cores based on config
        let mdns_core = if !config.no_mdns {
            match koi_mdns::MdnsCore::with_cancel(cancel.clone()) {
                Ok(c) => Some(std::sync::Arc::new(c)),
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
            }
        } else {
            tracing::info!("mDNS capability disabled");
            None
        };

        let certmesh_core = if !config.no_certmesh {
            crate::init_certmesh_core()
        } else {
            tracing::info!("Certmesh capability disabled");
            None
        };

        let dns_runtime = if !config.no_dns {
            match koi_dns::DnsCore::new(
                config.dns_config(),
                mdns_core.clone(),
                certmesh_core.clone(),
            )
            .await
            {
                Ok(core) => {
                    let runtime = std::sync::Arc::new(koi_dns::DnsRuntime::new(core));
                    if let Err(e) = runtime.start().await {
                        tracing::error!(error = %e, "Failed to start DNS server");
                    }
                    Some(runtime)
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to initialize DNS core");
                    None
                }
            }
        } else {
            tracing::info!("DNS capability disabled");
            None
        };

        let health_runtime = if !config.no_health {
            let core = std::sync::Arc::new(
                koi_health::HealthCore::new(mdns_core.clone(), dns_runtime.clone()).await,
            );
            let runtime = std::sync::Arc::new(koi_health::HealthRuntime::new(core));
            if let Err(e) = runtime.start().await {
                tracing::error!(error = %e, "Failed to start health checks");
            }
            Some(runtime)
        } else {
            tracing::info!("Health capability disabled");
            None
        };

        let proxy_runtime = if !config.no_proxy {
            match koi_proxy::ProxyCore::new() {
                Ok(core) => {
                    let runtime = std::sync::Arc::new(koi_proxy::ProxyRuntime::new(
                        std::sync::Arc::new(core),
                    ));
                    if let Err(e) = runtime.start_all().await {
                        tracing::error!(error = %e, "Failed to start proxy listeners");
                    }
                    Some(runtime)
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to initialize proxy core");
                    None
                }
            }
        } else {
            tracing::info!("Proxy capability disabled");
            None
        };

        let cores = crate::DaemonCores {
            mdns: mdns_core,
            certmesh: certmesh_core,
            dns: dns_runtime.clone(),
            health: health_runtime.clone(),
            proxy: proxy_runtime.clone(),
        };

        // Ensure data directory exists
        koi_config::dirs::ensure_data_dir();

        // Startup diagnostics (logged to file)
        crate::startup_diagnostics(&config);

        let mut tasks = Vec::new();
        let started_at = std::time::Instant::now();

        // HTTP adapter
        if !config.no_http {
            let c = cores.clone();
            let port = config.http_port;
            let token = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = crate::adapters::http::start(c, port, token, started_at).await {
                    tracing::error!(error = %e, "HTTP adapter failed");
                }
            }));
        }

        // IPC adapter (mDNS only — skip if mDNS disabled)
        if !config.no_ipc {
            if let Some(ref mdns) = cores.mdns {
                let c = mdns.clone();
                let path = config.pipe_path.clone();
                let token = cancel.clone();
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = crate::adapters::pipe::start(c, path, token).await {
                        tracing::error!(error = %e, "IPC adapter failed");
                    }
                }));
            } else {
                tracing::info!("IPC adapter skipped (mDNS disabled)");
            }
        }

        // Write breadcrumb for client discovery
        if !config.no_http {
            let endpoint = format!("http://localhost:{}", config.http_port);
            koi_config::breadcrumb::write_breadcrumb(&endpoint);
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
            if let Some(mdns) = &cores.mdns {
                if let Err(e) = mdns.shutdown().await {
                    tracing::warn!(error = %e, "mDNS shutdown error");
                }
            }
            if let Some(dns) = dns_runtime {
                dns.stop().await;
            }
            if let Some(health) = health_runtime {
                let _ = health.stop().await;
            }
            if let Some(proxy) = proxy_runtime {
                let _ = proxy.stop_all().await;
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

        koi_config::breadcrumb::delete_breadcrumb();
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

fn firewall_ports_for_config(
    config: &crate::cli::Config,
) -> Vec<koi_common::firewall::FirewallPort> {
    use koi_common::firewall::{FirewallPort, FirewallProtocol};

    let mut ports = Vec::new();
    if !config.no_mdns {
        ports.extend(koi_mdns::firewall_ports());
    }
    if !config.no_http {
        ports.push(FirewallPort::new(
            "HTTP",
            FirewallProtocol::Tcp,
            config.http_port,
        ));
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
    use std::process::Command;

    let ports = firewall_ports_for_config(config);
    if ports.is_empty() {
        return;
    }

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
            for port in &ports {
                let port_str = port.port.to_string();
                let proto = port.protocol.as_str();
                if stdout.contains(&port_str) && stdout.contains(proto) {
                    tracing::info!("Firewall: {} {} rule found", proto, port.port);
                } else {
                    let rule_name = firewall_rule_name(port);
                    tracing::warn!(
                        "Koi may not receive {} traffic \u{2014} no {} {} inbound rule found.",
                        port.name,
                        proto,
                        port.port
                    );
                    tracing::warn!("Run as administrator or execute:");
                    tracing::warn!(
                        "  netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=allow protocol={proto} localport={}",
                        port.port
                    );
                }
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "Could not check firewall rules");
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

/// Poll until a deleted service is fully purged from the SCM database.
/// The SCM defers actual removal until all handles are closed and the
/// internal state is flushed; attempting to recreate before that fails.
fn wait_for_delete(manager: &ServiceManager) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + SERVICE_STOP_TIMEOUT;
    loop {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Err(_) => return Ok(()), // gone
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn with_temp_data_dir<F, T>(f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("koi-win-path-test-{nanos}"));
        let prev = std::env::var("KOI_DATA_DIR").ok();
        std::env::set_var("KOI_DATA_DIR", &dir);
        let result = f();
        match prev {
            Some(v) => std::env::set_var("KOI_DATA_DIR", v),
            None => std::env::remove_var("KOI_DATA_DIR"),
        }
        result
    }

    #[test]
    fn service_paths_respect_data_dir_override() {
        with_temp_data_dir(|| {
            let data_dir = service_data_dir();
            let log_dir = service_log_dir();
            let log_path = service_log_path();

            assert!(log_dir.starts_with(&data_dir));
            assert!(log_path.starts_with(&log_dir));
            assert!(log_path.ends_with("koi.log"));
        });
    }
}
