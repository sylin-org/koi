//! systemd recipe (ADR-036): system and `--user` installs.
//!
//! Covers Debian/Ubuntu/Fedora/Arch and their derivatives — every systemd
//! machine on the fleet. Port decisions are honored from drop-ins or
//! `config.toml`; a shifted plan persists in the config substrate.

use std::path::PathBuf;
use std::process::Command;

use super::{
    healthz_wait, honor_existing_config, honor_existing_linux, persist_plan, plan_ports, Existing,
};

const SERVICE_NAME: &str = "koi";

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
    template.replace("{{BIN}}", &bin.display().to_string())
}

/// Install as a system service (root).
pub fn install_system() -> anyhow::Result<()> {
    super::super::check_root("install")?;

    let exe = std::env::current_exe()?;
    let bin = install_bin_path();
    let unit = system_unit_path();
    println!("Installing Koi service (systemd)...");
    println!("  Binary: {}", exe.display());

    let was_active = systemctl(&["is-active", SERVICE_NAME]);
    let was_enabled = systemctl(&["is-enabled", SERVICE_NAME]);
    if was_active || was_enabled {
        println!("  Existing service found, updating...");
        if was_active {
            print!("  Stopping service...");
            let _ = systemctl_output(&["stop", SERVICE_NAME]);
            println!(" done.");
        }
    }

    // Stage after the stop: upgrading from the installed path must work
    // (ETXTBSY fix — same-file staging is a no-op, rename is atomic).
    print!("  Staging {}...", bin.display());
    if super::stage_binary(&exe, &bin)? {
        println!(" done.");
    } else {
        println!(" already in place.");
    }

    // Ports: existing decisions win; plan only when nothing is declared.
    let existing = honor_existing_linux();
    let planned = match &existing {
        Existing::Declared(plan, _) => *plan,
        _ => plan_ports(),
    };
    let persisted = persist_plan(&existing, &planned, &PathBuf::from("/etc/koi/config.toml"));

    print!("  Writing {}...", unit.display());
    std::fs::write(&unit, render(UNIT_TEMPLATE, &bin))?;
    println!(" done.");

    let _ = systemctl_output(&["daemon-reload"]);
    match systemctl_output(&["enable", SERVICE_NAME]) {
        Ok(o) if o.status.success() => println!("  Service enabled (start on boot)"),
        Ok(o) => println!(
            "  Warning: could not enable: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => println!("  Warning: could not enable: {e}"),
    }
    match systemctl_output(&["start", SERVICE_NAME]) {
        Ok(o) if o.status.success() => println!(
            "  Service {}",
            if was_active { "restarted" } else { "started" }
        ),
        Ok(o) => println!(
            "  Warning: could not start: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => println!("  Warning: could not start: {e}"),
    }

    print!("  Verifying (healthz on {})...", planned.http);
    if healthz_wait(planned.http, std::time::Duration::from_secs(20)) {
        println!(" healthy.");
    } else {
        println!(" NOT answering yet — check journalctl -u {SERVICE_NAME}");
    }

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
}
