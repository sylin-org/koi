use std::path::PathBuf;
use std::process::Command;

/// Send sd_notify(READY=1) for systemd Type=notify services.
/// No-op if NOTIFY_SOCKET is not set (i.e., not running under systemd).
pub fn notify_ready() -> anyhow::Result<()> {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        let socket = UnixDatagram::unbound()?;
        socket.send_to(b"READY=1", &socket_path)?;
        tracing::info!("Sent sd_notify READY=1");
    }
    Ok(())
}

// ── Service paths (Linux) ────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn unit_file_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/koi.service")
}

#[cfg(target_os = "linux")]
pub fn install_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/koi")
}

// ── Install / Uninstall (Linux only — systemd) ──────────────────────

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "koi";

/// Install Koi as a systemd service.
///
/// Handles fresh installs and upgrades (stops existing service, copies
/// new binary, rewrites unit file). Mirrors the Windows install UX.
#[cfg(target_os = "linux")]
pub fn install() -> anyhow::Result<()> {
    check_root("install")?;

    let exe_path = std::env::current_exe()?;
    let install_path = install_bin_path();
    let unit_path = unit_file_path();

    println!("Installing Koi mDNS service...");
    println!("  Binary: {}", exe_path.display());

    // Check for existing service
    let was_active = systemctl_check("is-active");
    if was_active || systemctl_check("is-enabled") {
        println!("  Existing service found, updating...");
        if was_active {
            print!("  Stopping service...");
            let _ = Command::new("systemctl")
                .args(["stop", SERVICE_NAME])
                .output();
            println!(" done.");
        }
    }

    // Copy binary to install path
    print!("  Copying to {}...", install_path.display());
    std::fs::copy(&exe_path, &install_path)?;
    // Ensure executable permission
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&install_path, perms)?;
    }
    println!(" done.");

    // Write systemd unit file
    let unit_contents = generate_unit_file(&install_path);
    print!("  Writing {}...", unit_path.display());
    std::fs::write(&unit_path, unit_contents)?;
    println!(" done.");

    // Reload systemd
    print!("  Reloading systemd...");
    let reload = Command::new("systemctl").args(["daemon-reload"]).output();
    match reload {
        Ok(o) if o.status.success() => println!(" done."),
        Ok(o) => println!(" warning: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => println!(" warning: {e}"),
    }

    // Enable (start on boot)
    match Command::new("systemctl")
        .args(["enable", SERVICE_NAME])
        .output()
    {
        Ok(o) if o.status.success() => println!("  Service enabled (start on boot)"),
        Ok(o) => println!(
            "  Warning: could not enable service: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => println!("  Warning: could not enable service: {e}"),
    }

    // Start (or restart)
    match Command::new("systemctl")
        .args(["start", SERVICE_NAME])
        .output()
    {
        Ok(o) if o.status.success() => {
            if was_active {
                println!("  Service restarted");
            } else {
                println!("  Service started");
            }
        }
        Ok(o) => println!(
            "  Warning: could not start service: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => println!("  Warning: could not start service: {e}"),
    }

    println!();
    println!("Koi mDNS service installed.");
    println!("  \u{b0}\u{2027} \u{1f41f} \u{b7}\u{ff61} the local waters are calm");
    println!();
    println!("  Logs: journalctl -u {SERVICE_NAME}");
    println!("  Config: systemctl edit {SERVICE_NAME}");

    Ok(())
}

// ── Uninstall ───────────────────────────────────────────────────────

/// Uninstall the Koi systemd service and clean up artifacts.
///
/// Stops the service if running, removes the unit file, and cleans up
/// the breadcrumb file. Idempotent — safe to run even if never installed.
#[cfg(target_os = "linux")]
pub fn uninstall() -> anyhow::Result<()> {
    check_root("uninstall")?;

    let unit_path = unit_file_path();
    let install_path = install_bin_path();

    println!("Uninstalling Koi mDNS service...");

    let service_exists = unit_path.exists();

    if service_exists {
        // Stop if running
        if systemctl_check("is-active") {
            print!("  Stopping service...");
            let _ = Command::new("systemctl")
                .args(["stop", SERVICE_NAME])
                .output();
            println!(" done.");
        }

        // Disable
        match Command::new("systemctl")
            .args(["disable", SERVICE_NAME])
            .output()
        {
            Ok(o) if o.status.success() => println!("  Service disabled"),
            _ => {}
        }

        // Remove unit file
        print!("  Removing {}...", unit_path.display());
        match std::fs::remove_file(&unit_path) {
            Ok(()) => println!(" done."),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!(" already removed."),
            Err(e) => println!(" warning: {e}"),
        }

        // Reload systemd
        print!("  Reloading systemd...");
        match Command::new("systemctl").args(["daemon-reload"]).output() {
            Ok(o) if o.status.success() => println!(" done."),
            _ => println!(" warning."),
        }
    } else {
        println!("  Service not found, cleaning up remaining files...");
    }

    // Daemon discovery file
    koi_config::breadcrumb::delete_breadcrumb();

    // Note about binary
    if install_path.exists() {
        println!("  Binary preserved at: {}", install_path.display());
    }

    println!();
    println!("Koi mDNS service uninstalled.");

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
use super::check_root;

/// Check a systemctl boolean query (is-active, is-enabled).
#[cfg(target_os = "linux")]
fn systemctl_check(query: &str) -> bool {
    Command::new("systemctl")
        .args([query, SERVICE_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn generate_unit_file(bin_path: &std::path::Path) -> String {
    format!(
        "\
[Unit]
Description=Koi mDNS Service
Documentation=https://github.com/sylin-org/koi
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart={} --daemon
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
",
        bin_path.display()
    )
}
