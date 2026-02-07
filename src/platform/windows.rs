use std::ffi::OsString;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "koi";
const DISPLAY_NAME: &str = "Koi mDNS Service";

// Generate the extern "system" function that the SCM expects.
define_windows_service!(ffi_service_main, service_main);

/// Install Koi as a Windows Service.
pub fn install() -> anyhow::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let exe_path = std::env::current_exe()?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![OsString::from("--daemon")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    println!("Service '{DISPLAY_NAME}' installed successfully.");
    println!("Start it with: sc start {SERVICE_NAME}");
    Ok(())
}

/// Uninstall the Koi Windows Service.
pub fn uninstall() -> anyhow::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    println!("Service '{DISPLAY_NAME}' uninstalled successfully.");
    Ok(())
}

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
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

    let status_handle = service_control_handler::register(
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
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let core =
            std::sync::Arc::new(crate::core::MdnsCore::new().expect("Failed to start mDNS core"));
        let config = crate::config::Config::default();

        let mut tasks = Vec::new();

        {
            let c = core.clone();
            let port = config.http_port;
            tasks.push(tokio::spawn(async move {
                if let Err(e) = crate::adapters::http::start(c, port).await {
                    tracing::error!(error = %e, "HTTP adapter failed");
                }
            }));
        }

        {
            let c = core.clone();
            let path = config.pipe_path.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = crate::adapters::pipe::start(c, path).await {
                    tracing::error!(error = %e, "IPC adapter failed");
                }
            }));
        }

        let _ = shutdown_rx.await;
        let _ = core.shutdown();
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
