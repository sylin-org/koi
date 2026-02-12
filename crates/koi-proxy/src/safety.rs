use std::net::{IpAddr, ToSocketAddrs};

use url::Url;

use crate::ProxyError;

pub fn ensure_backend_allowed(backend: &Url, allow_remote: bool) -> Result<(), ProxyError> {
    if allow_remote {
        return Ok(());
    }

    let host = backend
        .host_str()
        .ok_or_else(|| ProxyError::InvalidConfig("Backend URL missing host".to_string()))?;

    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }

    let port = backend.port_or_known_default().unwrap_or(80);
    let addr = format!("{host}:{port}");
    let addrs = addr
        .to_socket_addrs()
        .map_err(|e| ProxyError::InvalidConfig(format!("Backend resolution failed: {e}")))?;

    let mut any = false;
    for addr in addrs {
        any = true;
        if !is_loopback(addr.ip()) {
            return Err(ProxyError::InvalidConfig(
                "Backend is not loopback; use --backend-remote to allow".to_string(),
            ));
        }
    }

    if !any {
        return Err(ProxyError::InvalidConfig(
            "Backend host did not resolve to any address".to_string(),
        ));
    }

    Ok(())
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}
