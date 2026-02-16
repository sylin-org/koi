//! Networking utilities - Happy Eyeballs endpoint resolution.
//!
//! When a URL contains `localhost`, the OS may resolve it to both `[::1]` (IPv6)
//! and `127.0.0.1` (IPv4). If the server only listens on one protocol, the client
//! stalls for ~2 s on every request while the first SYN times out. This module
//! races a TCP connect to both addresses in parallel and rewrites the URL to use
//! whichever responds first - eliminating that per-request penalty.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use tracing::{debug, trace};

/// Timeout for the parallel TCP race.  Kept short - we're probing loopback.
const RACE_TIMEOUT: Duration = Duration::from_millis(300);

/// If `endpoint` contains `localhost`, race IPv4 vs IPv6 TCP connects and
/// return a rewritten URL using the winning literal address.  If both fail (or
/// the URL doesn't use `localhost`), the original endpoint is returned unchanged.
///
/// # Examples
/// ```
/// use koi_common::net::resolve_localhost;
///
/// // Non-localhost URLs pass through unchanged.
/// assert_eq!(
///     resolve_localhost("http://192.168.1.5:5641"),
///     "http://192.168.1.5:5641"
/// );
/// ```
pub fn resolve_localhost(endpoint: &str) -> String {
    // Only race when the host is literally "localhost".
    let lower = endpoint.to_ascii_lowercase();
    if !lower.contains("://localhost:") && !lower.ends_with("://localhost") {
        return endpoint.to_string();
    }

    // Extract port - default to 80 if not present.
    let port = extract_port(endpoint).unwrap_or(80);

    let v4_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let v6_addr: SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 1], port).into();

    debug!(port, "racing IPv4 vs IPv6 on localhost:{port}");

    // Spawn two threads; first successful connect wins.
    let (tx, rx) = std::sync::mpsc::channel::<&str>();

    let tx4 = tx.clone();
    std::thread::spawn(move || {
        trace!(%v4_addr, "probing IPv4");
        if TcpStream::connect_timeout(&v4_addr, RACE_TIMEOUT).is_ok() {
            let _ = tx4.send("127.0.0.1");
        }
    });

    let tx6 = tx;
    std::thread::spawn(move || {
        trace!(%v6_addr, "probing IPv6");
        if TcpStream::connect_timeout(&v6_addr, RACE_TIMEOUT).is_ok() {
            let _ = tx6.send("[::1]");
        }
    });

    // Wait for the first winner or timeout.
    match rx.recv_timeout(RACE_TIMEOUT + Duration::from_millis(50)) {
        Ok(winner) => {
            let resolved = replace_localhost(endpoint, winner, port);
            debug!(winner, %resolved, "localhost resolved via Happy Eyeballs");
            resolved
        }
        Err(_) => {
            debug!("neither IPv4 nor IPv6 responded - keeping original endpoint");
            endpoint.to_string()
        }
    }
}

/// Extract the port number from an HTTP endpoint URL.
fn extract_port(endpoint: &str) -> Option<u16> {
    // Strip scheme
    let after_scheme = endpoint
        .find("://")
        .map(|i| &endpoint[i + 3..])
        .unwrap_or(endpoint);

    // Strip path
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);

    // Port is after the last colon (handles IPv6 bracket notation)
    host_port.rsplit(':').next()?.parse().ok()
}

/// Replace "localhost" in the endpoint with the winning address literal.
fn replace_localhost(endpoint: &str, winner: &str, port: u16) -> String {
    // Build a case-insensitive replacement.  The URL could say "Localhost",
    // "LOCALHOST", etc., so we locate it by position.
    let lower = endpoint.to_ascii_lowercase();
    if let Some(pos) = lower.find("localhost") {
        let before = &endpoint[..pos];
        let after_host = &endpoint[pos + "localhost".len()..];
        // If winner is IPv6 literal and we're writing a URL, use bracket form.
        format!("{before}{winner}{after_host}")
    } else {
        // Shouldn't happen given the guard in resolve_localhost, but be safe.
        endpoint.replace("localhost", &format!("{winner}:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_localhost_passthrough() {
        let ep = "http://192.168.1.5:5641";
        assert_eq!(resolve_localhost(ep), ep);
    }

    #[test]
    fn extract_port_simple() {
        assert_eq!(extract_port("http://localhost:5641"), Some(5641));
    }

    #[test]
    fn extract_port_with_path() {
        assert_eq!(extract_port("http://localhost:8080/foo"), Some(8080));
    }

    #[test]
    fn extract_port_none() {
        assert_eq!(extract_port("http://localhost"), None);
    }

    #[test]
    fn replace_localhost_ipv4() {
        assert_eq!(
            replace_localhost("http://localhost:5641", "127.0.0.1", 5641),
            "http://127.0.0.1:5641"
        );
    }

    #[test]
    fn replace_localhost_ipv6() {
        assert_eq!(
            replace_localhost("http://localhost:5641", "[::1]", 5641),
            "http://[::1]:5641"
        );
    }

    #[test]
    fn replace_localhost_with_path() {
        assert_eq!(
            replace_localhost("http://localhost:5641/v1/foo", "127.0.0.1", 5641),
            "http://127.0.0.1:5641/v1/foo"
        );
    }

    #[test]
    fn replace_localhost_case_insensitive() {
        assert_eq!(
            replace_localhost("http://Localhost:5641", "127.0.0.1", 5641),
            "http://127.0.0.1:5641"
        );
    }
}
