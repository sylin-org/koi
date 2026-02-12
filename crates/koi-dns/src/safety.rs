use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Simple global rate limiter for DNS queries.
pub struct RateLimiter {
    max_per_sec: u32,
    state: Mutex<RateState>,
}

struct RateState {
    window_start: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            state: Mutex::new(RateState {
                window_start: Instant::now(),
                count: 0,
            }),
        }
    }

    pub fn allow(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(state.window_start) >= Duration::from_secs(1) {
            state.window_start = now;
            state.count = 0;
        }
        if state.count >= self.max_per_sec {
            return false;
        }
        state.count += 1;
        true
    }
}

/// True if the IP is private or link-local.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(*v4),
        IpAddr::V6(v6) => is_private_ipv6(*v6),
    }
}

pub fn is_local_client(addr: &SocketAddr) -> bool {
    is_private_ip(&addr.ip())
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    match octets {
        [10, ..] => true,
        [127, ..] => true,
        [169, 254, ..] => true,
        [172, b, ..] if (16..=31).contains(&b) => true,
        [192, 168, ..] => true,
        _ => false,
    }
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // Unique local addresses fc00::/7
    let ula = (segments[0] & 0xfe00) == 0xfc00;
    // Link-local fe80::/10
    let link_local = (segments[0] & 0xffc0) == 0xfe80;
    ula || link_local || ip.is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv4_ranges() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
