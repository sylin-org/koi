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
