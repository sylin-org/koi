use std::net::ToSocketAddrs;

use crate::ProxyError;

/// Parse a backend into `(host, port)`.
///
/// Accepts either a URL with an explicit or scheme-default port
/// (`http://127.0.0.1:3000`, `https://host`) or a bare `host:port`
/// (`127.0.0.1:3000`). The passthrough connects to this TCP endpoint directly;
/// any URL path is irrelevant to a byte-level proxy and is ignored.
pub fn parse_backend(backend: &str) -> Result<(String, u16), ProxyError> {
    if backend.contains("://") {
        let url = url::Url::parse(backend)
            .map_err(|e| ProxyError::InvalidConfig(format!("invalid backend URL: {e}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| ProxyError::InvalidConfig("backend URL missing host".to_string()))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ProxyError::InvalidConfig("backend URL missing port".to_string()))?;
        return Ok((host, port));
    }

    let (host, port) = backend.rsplit_once(':').ok_or_else(|| {
        ProxyError::InvalidConfig("backend must be host:port or a URL".to_string())
    })?;
    let port: u16 = port
        .parse()
        .map_err(|_| ProxyError::InvalidConfig(format!("invalid backend port: {port}")))?;
    if host.is_empty() {
        return Err(ProxyError::InvalidConfig(
            "backend missing host".to_string(),
        ));
    }
    Ok((host.to_string(), port))
}

/// Reject a non-loopback backend unless `allow_remote` is set.
///
/// The plaintext hop from the proxy to its backend is unencrypted, so by default
/// the backend must be loopback. `--backend-remote` / `allow_remote` opts into a
/// remote backend (with a loud warning at the call site).
pub fn ensure_backend_allowed(backend: &str, allow_remote: bool) -> Result<(), ProxyError> {
    let (host, port) = parse_backend(backend)?;

    if allow_remote {
        return Ok(());
    }

    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }

    let addrs = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| ProxyError::InvalidConfig(format!("backend resolution failed: {e}")))?;

    let mut any = false;
    for addr in addrs {
        any = true;
        if !addr.ip().is_loopback() {
            return Err(ProxyError::InvalidConfig(
                "backend is not loopback; use --backend-remote to allow".to_string(),
            ));
        }
    }

    if !any {
        return Err(ProxyError::InvalidConfig(
            "backend host did not resolve to any address".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_url_form_with_explicit_port() {
        let (host, port) = parse_backend("http://127.0.0.1:3000").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 3000);
    }

    #[test]
    fn parses_url_form_with_default_port() {
        let (host, port) = parse_backend("https://example.test").unwrap();
        assert_eq!(host, "example.test");
        assert_eq!(port, 443);
    }

    #[test]
    fn parses_bare_host_port() {
        let (host, port) = parse_backend("127.0.0.1:8080").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn rejects_missing_port() {
        assert!(parse_backend("127.0.0.1").is_err());
    }

    #[test]
    fn loopback_backend_allowed_without_remote() {
        assert!(ensure_backend_allowed("127.0.0.1:3000", false).is_ok());
        assert!(ensure_backend_allowed("http://localhost:3000", false).is_ok());
    }

    #[test]
    fn non_loopback_backend_rejected_without_remote() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737), never loopback.
        assert!(ensure_backend_allowed("192.0.2.10:3000", false).is_err());
    }

    #[test]
    fn non_loopback_backend_allowed_with_remote() {
        assert!(ensure_backend_allowed("192.0.2.10:3000", true).is_ok());
    }
}
