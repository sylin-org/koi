//! Manual recipe (ADR-036): no supported init system detected.
//!
//! The honest fallback. No service is pretended: the binary is staged and
//! exact run instructions are printed, but the command exits non-zero so
//! automation cannot mistake guidance for an installation.

use std::path::PathBuf;

use super::systemd;

/// Stage the system binary and print how to run it. Always errors —
/// that is the point.
pub fn install_system() -> anyhow::Result<()> {
    super::super::check_root("install")?;

    let exe = std::env::current_exe()?;
    let bin = systemd::install_bin_path();
    println!("No supported init system was detected (systemd/OpenRC).");
    println!("Staging the binary; NO service will be registered.");
    print!("  Staging {}...", bin.display());
    if super::stage_binary(&exe, &bin)? {
        println!(" done.");
    } else {
        println!(" already in place.");
    }
    println!();
    println!("To run Koi until the next reboot:");
    println!("  sudo mkdir -p /run /var/lib/koi");
    println!("  sudo /usr/local/bin/koi --daemon");
    println!();
    println!("To supervise it yourself (runit/s6/Docker), run that command under");
    println!("your supervisor with KOI_DATA_DIR=/var/lib/koi in the environment.");
    anyhow::bail!(
        "no supported init system: the binary is installed at {} but no \
         service was registered",
        bin.display()
    )
}

/// `--user` with no user service manager: stage under ~/.local/bin and print
/// the user-daemon invocation (the data root must be per-user — machine data
/// roots are root-owned). Always errors.
pub fn install_user() -> anyhow::Result<()> {
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        anyhow::bail!("HOME is not set; cannot stage a user binary");
    }
    let exe = std::env::current_exe()?;
    let bin = PathBuf::from(&home).join(".local/bin/koi");
    println!("No user service manager was detected (systemd --user).");
    println!("Staging the binary; NO service will be registered.");
    if let Some(parent) = bin.parent() {
        std::fs::create_dir_all(parent)?;
    }
    print!("  Staging {}...", bin.display());
    if super::stage_binary(&exe, &bin)? {
        println!(" done.");
    } else {
        println!(" already in place.");
    }
    let data = PathBuf::from(&home).join(".local/share/koi");
    println!();
    println!("To run Koi as your user until reboot:");
    println!("  mkdir -p {}/runtime", data.display());
    println!(
        "  env KOI_DATA_DIR={} XDG_RUNTIME_DIR={}/runtime \\",
        data.display(),
        data.display()
    );
    println!("    {} --daemon", bin.display());
    println!();
    println!("To start at boot, add that line to your crontab with @reboot.");
    anyhow::bail!(
        "no user service manager: the binary is installed at {} but no \
         service was registered",
        bin.display()
    )
}
