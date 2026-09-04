//! Linux platform surface: sd_notify for systemd plus the ADR-036 installer
//! dispatch (recipes live in [`super::recipes`]).

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

// ── Install / Uninstall (Linux — ADR-036 recipe dispatch) ───────────

/// Install koi for the detected init system. `user` selects the per-user
/// service shape where one exists (ADR-036).
#[cfg(target_os = "linux")]
pub fn install(
    user: bool,
    operator: Option<&str>,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    super::recipes::install(user, operator, data_dir)
}

/// Uninstall every koi service shape found (system unit, user unit, OpenRC).
#[cfg(target_os = "linux")]
pub fn uninstall(data_dir: &std::path::Path) -> anyhow::Result<()> {
    super::recipes::uninstall(data_dir)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn unit_paths_are_expected() {
        assert!(super::super::recipes::systemd::system_unit_path().ends_with("koi.service"));
        assert!(super::super::recipes::systemd::install_bin_path().ends_with("/usr/local/bin/koi"));
    }
}
