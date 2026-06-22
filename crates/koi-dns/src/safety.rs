use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The rate-limit window. Counts reset once a window elapses.
const WINDOW: Duration = Duration::from_secs(1);

/// The global backstop is this multiple of the per-client budget: a single
/// client is capped at `max_per_sec`, but the whole resolver tolerates up to
/// `factor × max_per_sec` across all clients before shedding load.
const GLOBAL_QPS_FACTOR: u32 = 10;

/// Upper bound on tracked per-client buckets. DNS-over-UDP source addresses are
/// spoofable, so an attacker could otherwise mint unbounded buckets; past this
/// size we evict idle entries (and the global backstop still protects the rest).
const MAX_TRACKED_CLIENTS: usize = 4096;

/// Per-client DNS query rate limiter with a global backstop.
///
/// Each source IP gets its own `max_per_sec` budget, so one noisy (or hostile)
/// LAN peer can no longer starve every other client — the failure mode of a
/// single global bucket. A whole-resolver backstop (`GLOBAL_QPS_FACTOR ×
/// max_per_sec`) still caps aggregate load, which is the only meaningful guard
/// against spoofed-source floods where per-client accounting is moot.
pub struct RateLimiter {
    per_client_max: u32,
    global_max: u32,
    inner: Mutex<RateInner>,
}

struct RateInner {
    clients: HashMap<IpAddr, RateState>,
    global: RateState,
}

struct RateState {
    window_start: Instant,
    count: u32,
}

impl RateState {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            count: 0,
        }
    }

    /// Reset the counter if the current window has elapsed.
    fn roll(&mut self, now: Instant) {
        if now.duration_since(self.window_start) >= WINDOW {
            self.window_start = now;
            self.count = 0;
        }
    }
}

impl RateLimiter {
    pub fn new(max_per_sec: u32) -> Self {
        let now = Instant::now();
        Self {
            per_client_max: max_per_sec,
            global_max: max_per_sec.saturating_mul(GLOBAL_QPS_FACTOR),
            inner: Mutex::new(RateInner {
                clients: HashMap::new(),
                global: RateState::new(now),
            }),
        }
    }

    /// Returns `true` if a query from `client` is within both the per-client and
    /// the global budget for the current window (and consumes one token from
    /// each when so).
    pub fn allow(&self, client: IpAddr) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Global backstop first: roll the window and reject if the whole-resolver
        // cap is already hit (this is what stops spoofed-source floods).
        inner.global.roll(now);
        if inner.global.count >= self.global_max {
            return false;
        }

        // Bound memory: when the map is large, drop buckets whose window has gone
        // idle so a burst of distinct (spoofable) source IPs cannot grow it without
        // limit. If it is STILL full of active buckets and this is a NEW client, we
        // cannot give it its own bucket — fall back to the global backstop only
        // (already checked above), keeping the map hard-capped regardless of qps.
        if inner.clients.len() >= MAX_TRACKED_CLIENTS {
            inner
                .clients
                .retain(|_, st| now.duration_since(st.window_start) < WINDOW);
            if inner.clients.len() >= MAX_TRACKED_CLIENTS && !inner.clients.contains_key(&client) {
                inner.global.count += 1;
                return true;
            }
        }

        // Per-client bucket in its own scope so the borrow ends before we touch
        // the global counter again.
        {
            let per_client_max = self.per_client_max;
            let entry = inner
                .clients
                .entry(client)
                .or_insert_with(|| RateState::new(now));
            entry.roll(now);
            if entry.count >= per_client_max {
                return false;
            }
            entry.count += 1;
        }

        // Both buckets had headroom — consume one global token.
        inner.global.count += 1;
        true
    }

    #[cfg(test)]
    fn tracked_clients(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clients
            .len()
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

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn per_client_budget_is_independent() {
        // Two clients each get their own per-second budget.
        let rl = RateLimiter::new(3);
        let a = ip(192, 168, 1, 10);
        let b = ip(192, 168, 1, 11);
        for _ in 0..3 {
            assert!(rl.allow(a));
            assert!(rl.allow(b));
        }
        // Each is now at its own cap, independently.
        assert!(!rl.allow(a));
        assert!(!rl.allow(b));
    }

    #[test]
    fn one_noisy_client_does_not_starve_others() {
        // The single-global-bucket failure mode: a flood from one peer must not
        // deny a well-behaved peer its own budget.
        let rl = RateLimiter::new(5);
        let noisy = ip(192, 168, 1, 50);
        let quiet = ip(192, 168, 1, 51);
        for _ in 0..5 {
            assert!(rl.allow(noisy));
        }
        assert!(!rl.allow(noisy), "noisy client capped at its own budget");
        assert!(rl.allow(quiet), "a different client still has headroom");
    }

    #[test]
    fn global_backstop_caps_aggregate_load() {
        // With many distinct clients (e.g. spoofed sources), the global backstop
        // (GLOBAL_QPS_FACTOR × per_client) still bounds total throughput.
        let per_client = 2u32;
        let rl = RateLimiter::new(per_client);
        let global_cap = per_client * GLOBAL_QPS_FACTOR;
        let mut allowed = 0u32;
        // Each fresh client can spend up to `per_client`; the global cap is hit
        // first because there are far more clients than headroom.
        for n in 0..1000u32 {
            let client = ip(10, 0, (n >> 8) as u8, (n & 0xff) as u8);
            if rl.allow(client) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, global_cap, "aggregate load capped at the backstop");
    }

    #[test]
    fn client_map_is_hard_bounded() {
        // With qps high enough that global_max (qps * GLOBAL_QPS_FACTOR) exceeds
        // MAX_TRACKED_CLIENTS, a flood of distinct (spoofable) source IPs must NOT
        // grow the tracked-client map past its hard cap — new IPs fall back to the
        // global backstop once the table is full.
        let per_client = 500u32; // global_max = 5000 > MAX_TRACKED_CLIENTS (4096)
        let rl = RateLimiter::new(per_client);
        for n in 0..(MAX_TRACKED_CLIENTS as u32 + 2000) {
            let client = ip(10, (n >> 16) as u8, (n >> 8) as u8, (n & 0xff) as u8);
            let _ = rl.allow(client);
        }
        assert!(
            rl.tracked_clients() <= MAX_TRACKED_CLIENTS,
            "tracked-client map exceeded its hard cap: {}",
            rl.tracked_clients()
        );
    }
}
