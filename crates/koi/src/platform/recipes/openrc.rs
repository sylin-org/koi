//! OpenRC recipe (ADR-036): Alpine, Gentoo, Artix-openrc.
//!
//! The measured Alpine gap: the old installer copied the binary and died
//! writing `/etc/systemd/system/koi.service` (ENOENT). This recipe installs
//! an `openrc-run` service instead, with the same pipeline as systemd:
//! honored port decisions, config-substrate persistence, self-verification.

use std::path::PathBuf;
use std::process::Command;

use super::{healthz_wait, honor_existing_config, persist_plan, plan_ports, Existing};

const INITD_TEMPLATE: &str = include_str!("templates/koi-openrc.initd");

pub fn initd_path() -> PathBuf {
    PathBuf::from("/etc/init.d/koi")
}

pub fn install_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/koi")
}

fn render(bin: &std::path::Path) -> String {
    // LF regardless of checkout (a CRLF shebang breaks the script and the
    // shell that sources it — the measured Alpine failure).
    INITD_TEMPLATE
        .replace("\r\n", "\n")
        .replace("{{BIN}}", &bin.display().to_string())
}

pub fn install_system() -> anyhow::Result<()> {
    super::super::check_root("install")?;

    let exe = std::env::current_exe()?;
    let bin = install_bin_path();
    let initd = initd_path();
    println!("Installing Koi service (OpenRC)...");
    println!("  Binary: {}", exe.display());

    let was_started = rc_service_status();
    if was_started {
        println!("  Existing service found, updating...");
        print!("  Stopping service...");
        let _ = Command::new("rc-service").args(["koi", "stop"]).output();
        println!(" done.");
    }

    print!("  Staging {}...", bin.display());
    if super::stage_binary(&exe, &bin)? {
        println!(" done.");
    } else {
        println!(" already in place.");
    }

    // Port decisions: honor the config file, else plan.
    let config = PathBuf::from("/etc/koi/config.toml");
    let existing = honor_existing_config(&config);
    let planned = match &existing {
        Existing::Declared(plan, _) => *plan,
        _ => plan_ports(),
    };
    let persisted = persist_plan(&existing, &planned, &config);

    std::fs::create_dir_all("/var/log/koi")?;
    print!("  Writing {}...", initd.display());
    std::fs::write(&initd, render(&bin))?;
    make_executable(&initd);
    println!(" done.");

    match Command::new("rc-update")
        .args(["add", "koi", "default"])
        .output()
    {
        Ok(o) if o.status.success() => println!("  Service enabled (default runlevel)"),
        Ok(o) => println!(
            "  Warning: could not enable: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => println!("  Warning: could not enable: {e}"),
    }
    match Command::new("rc-service").args(["koi", "start"]).output() {
        Ok(o) if o.status.success() => println!("  Service started"),
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
        println!(" NOT answering yet — check /var/log/koi/daemon.log");
    }

    println!();
    println!("Koi service installed.");
    println!("  Ports: {}", planned.describe());
    if !persisted.is_empty() {
        println!("  {persisted}");
    }
    println!("  Config: /etc/koi/config.toml (koi config show)");
    println!("  Logs: /var/log/koi/daemon.log");
    println!("  Status: rc-status | grep koi");
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
        let _ = Command::new("rc-service").args(["koi", "stop"]).output();
        println!(" done.");
    }
    let _ = Command::new("rc-update").args(["delete", "koi"]).output();
    match std::fs::remove_file(&initd) {
        Ok(()) => println!("  Removed {}", initd.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("  already removed."),
        Err(e) => println!("  warning: {e}"),
    }
    let _ = std::fs::remove_file("/run/koi.pid");
    koi_config::breadcrumb::delete_breadcrumb();
    if install_bin_path().exists() {
        println!("  Binary preserved at: {}", install_bin_path().display());
    }
    println!();
    println!("Koi service uninstalled.");
    Ok(())
}

fn rc_service_status() -> bool {
    Command::new("rc-service")
        .args(["koi", "status"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initd_golden() {
        let script = render(&PathBuf::from("/usr/local/bin/koi"));
        assert!(script.starts_with("#!/sbin/openrc-run"));
        assert!(
            script.contains("command_args=\"XDG_CONFIG_HOME=/etc /usr/local/bin/koi --daemon\""),
            "the daemon process must resolve config at /etc/koi/config.toml"
        );
        assert!(script.contains("command_background=\"yes\""));
        assert!(script.contains("need net"));
        assert!(!script.contains("{{"));
    }
}
