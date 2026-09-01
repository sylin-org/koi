use std::path::PathBuf;
use std::process::Command;

const LABEL: &str = "org.sylin.koi";

// ── Service paths ───────────────────────────────────────────────────

pub fn plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons/org.sylin.koi.plist")
}

pub fn install_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/koi")
}

/// Install Koi as a macOS LaunchDaemon.
///
/// Handles fresh installs and upgrades (unloads existing daemon, stages
/// the new binary atomically, rewrites plist). Port planning follows
/// ADR-036 (config honored; occupied trio shifts and persists in the
/// config substrate the plist points the daemon at).
pub fn install(
    user: bool,
    operator: Option<&str>,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    if user {
        anyhow::bail!(
            "--user installs aren't supported on macOS yet (a LaunchAgent shape \
             is known but unverified); use `koi install` for the system daemon"
        );
    }
    check_root("install")?;
    super::record_unix_operator(false, operator, data_dir)?;

    let exe_path = std::env::current_exe()?;
    let install_path = install_bin_path();
    let plist_path = plist_path();

    println!("Installing Koi service...");
    println!("  Binary: {}", exe_path.display());

    let was_loaded = launchctl_is_loaded();
    if was_loaded {
        println!("  Existing daemon found, updating...");
        print!("  Unloading daemon...");
        let _ = launchctl_bootout();
        println!(" done.");
    }

    // Stage atomically (ADR-036): rename(2) over the old binary — an
    // upgrade running from the installed path no longer hits ETXTBSY.
    print!("  Staging {}...", install_path.display());
    if crate::platform::recipes::stage_binary(&exe_path, &install_path)? {
        println!(" done.");
    } else {
        println!(" already in place.");
    }
    let _ = Command::new("chown")
        .args(["root:wheel", &install_path.display().to_string()])
        .output();

    // Port planning per ADR-036; the plist resolves config at /etc/koi.
    let config_path = std::path::PathBuf::from("/etc/koi/config.toml");
    let existing = crate::platform::recipes::honor_existing_config(&config_path);
    let planned = match &existing {
        crate::platform::recipes::Existing::Declared(plan, _) => *plan,
        _ => crate::platform::recipes::plan_ports(),
    };
    let persisted = crate::platform::recipes::persist_plan(&existing, &planned, &config_path);

    let plist_contents = generate_plist(&install_path);
    print!("  Writing {}...", plist_path.display());
    std::fs::write(&plist_path, plist_contents)?;
    let _ = Command::new("chown")
        .args(["root:wheel", &plist_path.display().to_string()])
        .output();
    let _ = Command::new("chmod")
        .args(["644", &plist_path.display().to_string()])
        .output();
    println!(" done.");

    match launchctl_bootstrap(&plist_path) {
        true => {
            if was_loaded {
                println!("  Daemon reloaded");
            } else {
                println!("  Daemon loaded (starts at boot)");
            }
        }
        false => println!("  Warning: could not load daemon"),
    }

    print!("  Verifying (healthz on {})...", planned.http);
    if crate::platform::recipes::healthz_wait(planned.http, std::time::Duration::from_secs(20)) {
        println!(" healthy.");
    } else {
        println!(" NOT answering yet — check /var/log/koi.err");
    }

    println!();
    println!("Koi service installed.");
    println!("  Ports: {}", planned.describe());
    if !persisted.is_empty() {
        println!("  {persisted}");
    }
    println!("  Config: {} (koi config show)", config_path.display());
    println!("  Logs: /var/log/koi.log");
    println!("  Status: sudo launchctl list | grep {LABEL}");
    println!("  Use `koi status` to see module state.");

    Ok(())
}

/// Uninstall the Koi LaunchDaemon and clean up artifacts.
///
/// Checks if installed before requiring root. Sends a graceful shutdown
/// signal via HTTP before unloading the daemon.
pub fn uninstall() -> anyhow::Result<()> {
    let plist = plist_path();
    let install_path = install_bin_path();

    // Check if installed BEFORE requiring elevation
    if !plist.exists() {
        println!("Koi is not installed as a launchd daemon. Nothing to uninstall.");
        return Ok(());
    }

    check_root("uninstall")?;
    println!("Uninstalling Koi service...");

    // Best-effort graceful shutdown via HTTP
    if let Some(bc) = koi_config::breadcrumb::read_breadcrumb() {
        let client = crate::client::KoiClient::with_token(&bc.endpoint, &bc.token);
        if client.shutdown().is_ok() {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    // Unload if loaded
    if launchctl_is_loaded() {
        print!("  Unloading daemon...");
        let _ = launchctl_bootout();
        println!(" done.");
    }

    // Remove plist
    print!("  Removing {}...", plist.display());
    match std::fs::remove_file(&plist) {
        Ok(()) => println!(" done."),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!(" already removed."),
        Err(e) => println!(" warning: {e}"),
    }

    // Daemon discovery file
    koi_config::breadcrumb::delete_breadcrumb();

    // Note about binary
    if install_path.exists() {
        println!("  Binary preserved at: {}", install_path.display());
    }

    // Clean up log files if empty
    for log in &["/var/log/koi.log", "/var/log/koi.err"] {
        let path = std::path::Path::new(log);
        if let Ok(meta) = path.metadata() {
            if meta.len() == 0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    println!();
    println!("Koi service uninstalled.");

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

use super::check_root;

/// Check if the daemon is loaded in launchd.
fn launchctl_is_loaded() -> bool {
    Command::new("launchctl")
        .args(["list", LABEL])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Load the daemon using modern `bootstrap` with legacy `load -w` fallback.
fn launchctl_bootstrap(plist_path: &std::path::Path) -> bool {
    let plist_str = plist_path.display().to_string();

    // Try modern command first (macOS 10.11+)
    let result = Command::new("launchctl")
        .args(["bootstrap", "system", &plist_str])
        .output();
    if matches!(&result, Ok(o) if o.status.success()) {
        return true;
    }

    // Fall back to legacy command
    let result = Command::new("launchctl")
        .args(["load", "-w", &plist_str])
        .output();
    matches!(result, Ok(o) if o.status.success())
}

/// Unload the daemon using modern `bootout` with legacy `unload -w` fallback.
fn launchctl_bootout() -> bool {
    let domain_target = format!("system/{LABEL}");

    // Try modern command first
    let result = Command::new("launchctl")
        .args(["bootout", &domain_target])
        .output();
    if matches!(&result, Ok(o) if o.status.success()) {
        return true;
    }

    // Fall back to legacy command
    let plist_path = plist_path();
    let plist_str = plist_path.display().to_string();
    let result = Command::new("launchctl")
        .args(["unload", "-w", &plist_str])
        .output();
    matches!(result, Ok(o) if o.status.success())
}

fn generate_plist(bin_path: &std::path::Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>

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
        label = LABEL,
        bin = bin_path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_paths_are_expected() {
        assert!(plist_path().ends_with("org.sylin.koi.plist"));
        assert!(install_bin_path().ends_with("/usr/local/bin/koi"));
    }

    #[test]
    fn plist_contains_label_and_binary() {
        let plist = generate_plist(&std::path::PathBuf::from("/usr/local/bin/koi"));
        assert!(plist.contains("org.sylin.koi"));
        assert!(plist.contains("/usr/local/bin/koi"));
        assert!(
            plist.contains("<string>/etc</string>"),
            "the daemon resolves its config at /etc/koi/config.toml (ADR-036)"
        );
    }
}
