#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub mod unix;

#[cfg(target_os = "macos")]
pub mod macos;

/// Platform-specific service registration.
/// On Windows, integrates with the Service Control Manager (SCM).
/// On Linux, sends systemd sd_notify(READY=1).
pub fn register_service() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        // Windows service registration is handled separately via the install subcommand.
        // When running as a service, the SCM handler is set up in windows::run_service().
        Ok(())
    }
    #[cfg(unix)]
    {
        unix::notify_ready()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(())
    }
}

/// Check that the current process is running as root/administrator.
/// Bails with a clear message if not elevated.
#[cfg(unix)]
pub fn check_root(verb: &str) -> anyhow::Result<()> {
    // SAFETY: getuid() is always safe to call and has no preconditions.
    if unsafe { libc::getuid() } == 0 {
        Ok(())
    } else {
        anyhow::bail!(
            "\"koi {verb}\" requires root privileges. Re-run with sudo."
        )
    }
}
