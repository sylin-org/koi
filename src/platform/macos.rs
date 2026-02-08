use std::process::Command;

const LABEL: &str = "org.sylin.koi";

/// Install Koi as a macOS LaunchDaemon.
///
/// Handles fresh installs and upgrades (unloads existing daemon, copies
/// new binary, rewrites plist). Mirrors the Windows/Linux install UX.
pub fn install() -> anyhow::Result<()> {
    check_root("install")?;

    let exe_path = std::env::current_exe()?;
    let install_path = crate::config::install_bin_path();
    let plist_path = crate::config::plist_path();

    println!("Installing Koi mDNS service...");
    println!("  Binary: {}", exe_path.display());

    // Check for existing daemon
    let was_loaded = launchctl_is_loaded();
    if was_loaded {
        println!("  Existing daemon found, updating...");
        print!("  Unloading daemon...");
        let _ = launchctl_bootout();
        println!(" done.");
    }

    // Copy binary to install path
    print!("  Copying to {}...", install_path.display());
    std::fs::copy(&exe_path, &install_path)?;
    // Set ownership and permissions: root:wheel, 755
    let _ = Command::new("chown")
        .args(["root:wheel", &install_path.display().to_string()])
        .output();
    let _ = Command::new("chmod")
        .args(["755", &install_path.display().to_string()])
        .output();
    println!(" done.");

    // Write plist
    let plist_contents = generate_plist(&install_path);
    print!("  Writing {}...", plist_path.display());
    std::fs::write(&plist_path, plist_contents)?;
    // Plist must be owned by root:wheel with 644
    let _ = Command::new("chown")
        .args(["root:wheel", &plist_path.display().to_string()])
        .output();
    let _ = Command::new("chmod")
        .args(["644", &plist_path.display().to_string()])
        .output();
    println!(" done.");

    // Load the daemon
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

    println!();
    println!("Koi mDNS service installed.");
    println!("  \u{b0}\u{2027} \u{1f41f} \u{b7}\u{ff61} the local waters are calm");
    println!();
    println!("  Logs: /var/log/koi.log");
    println!("  Status: sudo launchctl list | grep {LABEL}");

    Ok(())
}

/// Uninstall the Koi LaunchDaemon and clean up artifacts.
///
/// Unloads the daemon if loaded, removes the plist file, and cleans up
/// the breadcrumb file. Idempotent — safe to run even if never installed.
pub fn uninstall() -> anyhow::Result<()> {
    check_root("uninstall")?;

    let plist_path = crate::config::plist_path();
    let install_path = crate::config::install_bin_path();

    println!("Uninstalling Koi mDNS service...");

    let plist_exists = plist_path.exists();

    if plist_exists {
        // Unload if loaded
        if launchctl_is_loaded() {
            print!("  Unloading daemon...");
            let _ = launchctl_bootout();
            println!(" done.");
        }

        // Remove plist
        print!("  Removing {}...", plist_path.display());
        match std::fs::remove_file(&plist_path) {
            Ok(()) => println!(" done."),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!(" already removed."),
            Err(e) => println!(" warning: {e}"),
        }
    } else {
        println!("  Daemon not found, cleaning up remaining files...");
    }

    // Daemon discovery file
    crate::config::delete_breadcrumb();

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
    println!("Koi mDNS service uninstalled.");

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

fn check_root(verb: &str) -> anyhow::Result<()> {
    let output = Command::new("id").arg("-u").output();
    match output {
        Ok(o) if String::from_utf8_lossy(&o.stdout).trim() == "0" => Ok(()),
        _ => anyhow::bail!("koi {verb} requires root \u{2014} try: sudo koi {verb}"),
    }
}

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
    let plist_path = crate::config::plist_path();
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
