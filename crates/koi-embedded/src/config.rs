use std::net::IpAddr;
use std::path::PathBuf;

use koi_common::firewall::{FirewallPort, FirewallProtocol};
use koi_dns::DnsConfig;
use koi_runtime::RuntimeBackendKind;

#[derive(Debug, Clone)]
pub struct KoiConfig {
    pub data_dir: Option<PathBuf>,
    pub service_endpoint: String,
    pub service_mode: ServiceMode,
    pub http_enabled: bool,
    pub mdns_enabled: bool,
    pub dns_enabled: bool,
    pub health_enabled: bool,
    pub certmesh_enabled: bool,
    pub proxy_enabled: bool,
    pub udp_enabled: bool,
    pub runtime_enabled: bool,
    pub runtime_backend: RuntimeBackendKind,
    pub http_port: u16,
    pub dashboard_enabled: bool,
    pub api_docs_enabled: bool,
    pub mdns_browser_enabled: bool,
    pub announce_http: bool,
    pub dns_config: DnsConfig,
    pub dns_auto_start: bool,
    pub health_auto_start: bool,
    pub proxy_auto_start: bool,
}

impl KoiConfig {
    /// Collect firewall ports required by the currently-enabled capabilities.
    ///
    /// This mirrors the logic in the standalone Koi daemon's
    /// `firewall_ports_for_config`, but derives from the embedded config.
    pub fn firewall_ports(&self) -> Vec<FirewallPort> {
        use std::collections::HashSet;

        let mut ports = Vec::new();
        if self.mdns_enabled {
            ports.extend(koi_mdns::firewall_ports());
        }
        if self.http_enabled {
            ports.push(FirewallPort::new(
                "HTTP",
                FirewallProtocol::Tcp,
                self.http_port,
            ));
        }
        if self.dns_enabled {
            ports.extend(koi_dns::firewall_ports(&self.dns_config));
        }

        // Deduplicate by (protocol, port)
        let mut seen = HashSet::new();
        ports
            .into_iter()
            .filter(|p| seen.insert((p.protocol, p.port)))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    Auto,
    EmbeddedOnly,
    ClientOnly,
}

impl Default for KoiConfig {
    fn default() -> Self {
        Self {
            data_dir: None,
            service_endpoint: "http://127.0.0.1:5641".to_string(),
            service_mode: ServiceMode::Auto,
            http_enabled: false,
            mdns_enabled: true,
            dns_enabled: true,
            health_enabled: false,
            certmesh_enabled: false,
            proxy_enabled: false,
            udp_enabled: false,
            runtime_enabled: false,
            runtime_backend: RuntimeBackendKind::Auto,
            http_port: 5641,
            dashboard_enabled: false,
            api_docs_enabled: false,
            mdns_browser_enabled: false,
            announce_http: false,
            dns_config: DnsConfig::default(),
            dns_auto_start: false,
            health_auto_start: false,
            proxy_auto_start: false,
        }
    }
}

pub struct DnsConfigBuilder {
    config: DnsConfig,
}

impl DnsConfigBuilder {
    pub fn new(config: DnsConfig) -> Self {
        Self { config }
    }

    pub fn bind_addr(mut self, addr: IpAddr) -> Self {
        self.config.bind_addr = addr;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    pub fn zone(mut self, zone: impl Into<String>) -> Self {
        self.config.zone = zone.into();
        self
    }

    pub fn local_ttl(mut self, ttl: u32) -> Self {
        self.config.local_ttl = ttl;
        self
    }

    pub fn allow_public_clients(mut self, allow: bool) -> Self {
        self.config.allow_public_clients = allow;
        self
    }

    pub fn max_qps(mut self, max_qps: u32) -> Self {
        self.config.max_qps = max_qps;
        self
    }

    pub fn local_zone(mut self, enabled: bool) -> Self {
        self.config.local_zone = enabled;
        self
    }

    pub fn build(self) -> DnsConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // ── KoiConfig defaults ─────────────────────────────────────────

    #[test]
    fn default_config_has_expected_values() {
        let cfg = KoiConfig::default();
        assert_eq!(cfg.service_endpoint, "http://127.0.0.1:5641");
        assert_eq!(cfg.service_mode, ServiceMode::Auto);
        assert!(!cfg.http_enabled);
        assert!(cfg.mdns_enabled);
        assert!(cfg.dns_enabled);
        assert!(!cfg.health_enabled);
        assert!(!cfg.certmesh_enabled);
        assert!(!cfg.proxy_enabled);
        assert!(!cfg.udp_enabled);
        assert!(!cfg.runtime_enabled);
        assert_eq!(cfg.runtime_backend, RuntimeBackendKind::Auto);
        assert_eq!(cfg.http_port, 5641);
        assert!(!cfg.dashboard_enabled);
        assert!(!cfg.api_docs_enabled);
        assert!(!cfg.mdns_browser_enabled);
        assert!(!cfg.announce_http);
        assert!(!cfg.dns_auto_start);
        assert!(!cfg.health_auto_start);
        assert!(!cfg.proxy_auto_start);
        assert!(cfg.data_dir.is_none());
    }

    #[test]
    fn default_config_clone_is_equal() {
        let cfg = KoiConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cfg.http_port, cloned.http_port);
        assert_eq!(cfg.mdns_enabled, cloned.mdns_enabled);
        assert_eq!(cfg.service_endpoint, cloned.service_endpoint);
    }

    #[test]
    fn default_config_debug_does_not_panic() {
        let cfg = KoiConfig::default();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("KoiConfig"));
    }

    // ── Firewall ports ─────────────────────────────────────────────

    #[test]
    fn firewall_ports_includes_http_when_enabled() {
        let mut cfg = KoiConfig::default();
        cfg.http_enabled = true;
        cfg.mdns_enabled = false;
        cfg.dns_enabled = false;
        let ports = cfg.firewall_ports();
        assert!(
            ports.iter().any(|p| p.port == 5641),
            "expected HTTP port 5641 in firewall ports"
        );
    }

    #[test]
    fn firewall_ports_respects_custom_http_port() {
        let mut cfg = KoiConfig::default();
        cfg.http_enabled = true;
        cfg.http_port = 9999;
        cfg.mdns_enabled = false;
        cfg.dns_enabled = false;
        let ports = cfg.firewall_ports();
        assert!(
            ports.iter().any(|p| p.port == 9999),
            "expected custom HTTP port 9999"
        );
        assert!(
            !ports.iter().any(|p| p.port == 5641),
            "should not have default port when overridden"
        );
    }

    #[test]
    fn firewall_ports_empty_when_all_disabled() {
        let mut cfg = KoiConfig::default();
        cfg.http_enabled = false;
        cfg.mdns_enabled = false;
        cfg.dns_enabled = false;
        let ports = cfg.firewall_ports();
        assert!(ports.is_empty(), "all disabled should yield no ports");
    }

    #[test]
    fn firewall_ports_deduplicates() {
        let mut cfg = KoiConfig::default();
        // DNS default port is 53 (TCP+UDP), mDNS is 5353 (UDP).
        // With both enabled we should not have duplicate (protocol, port) pairs.
        cfg.http_enabled = false;
        cfg.mdns_enabled = true;
        cfg.dns_enabled = true;
        let ports = cfg.firewall_ports();
        let mut seen = std::collections::HashSet::new();
        for p in &ports {
            assert!(
                seen.insert((p.protocol, p.port)),
                "duplicate firewall port: {:?} {}",
                p.protocol,
                p.port
            );
        }
    }

    // ── ServiceMode ────────────────────────────────────────────────

    #[test]
    fn service_mode_equality() {
        assert_eq!(ServiceMode::Auto, ServiceMode::Auto);
        assert_eq!(ServiceMode::EmbeddedOnly, ServiceMode::EmbeddedOnly);
        assert_eq!(ServiceMode::ClientOnly, ServiceMode::ClientOnly);
        assert_ne!(ServiceMode::Auto, ServiceMode::EmbeddedOnly);
        assert_ne!(ServiceMode::Auto, ServiceMode::ClientOnly);
    }

    #[test]
    fn service_mode_is_copy() {
        let mode = ServiceMode::Auto;
        let copy = mode;
        assert_eq!(mode, copy);
    }

    #[test]
    fn service_mode_debug() {
        let debug = format!("{:?}", ServiceMode::EmbeddedOnly);
        assert!(debug.contains("EmbeddedOnly"));
    }

    // ── DnsConfigBuilder ───────────────────────────────────────────

    #[test]
    fn dns_config_builder_defaults_match_dns_config() {
        let dns_default = DnsConfig::default();
        let built = DnsConfigBuilder::new(DnsConfig::default()).build();
        assert_eq!(built.port, dns_default.port);
        assert_eq!(built.zone, dns_default.zone);
        assert_eq!(built.local_ttl, dns_default.local_ttl);
        assert_eq!(built.allow_public_clients, dns_default.allow_public_clients);
        assert_eq!(built.max_qps, dns_default.max_qps);
        assert_eq!(built.local_zone, dns_default.local_zone);
    }

    #[test]
    fn dns_config_builder_port() {
        let cfg = DnsConfigBuilder::new(DnsConfig::default())
            .port(5353)
            .build();
        assert_eq!(cfg.port, 5353);
    }

    #[test]
    fn dns_config_builder_bind_addr() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let cfg = DnsConfigBuilder::new(DnsConfig::default())
            .bind_addr(addr)
            .build();
        assert_eq!(cfg.bind_addr, addr);
    }

    #[test]
    fn dns_config_builder_zone() {
        let cfg = DnsConfigBuilder::new(DnsConfig::default())
            .zone("home")
            .build();
        assert_eq!(cfg.zone, "home");
    }

    #[test]
    fn dns_config_builder_local_ttl() {
        let cfg = DnsConfigBuilder::new(DnsConfig::default())
            .local_ttl(120)
            .build();
        assert_eq!(cfg.local_ttl, 120);
    }

    #[test]
    fn dns_config_builder_allow_public_clients() {
        let cfg = DnsConfigBuilder::new(DnsConfig::default())
            .allow_public_clients(true)
            .build();
        assert!(cfg.allow_public_clients);
    }

    #[test]
    fn dns_config_builder_max_qps() {
        let cfg = DnsConfigBuilder::new(DnsConfig::default())
            .max_qps(500)
            .build();
        assert_eq!(cfg.max_qps, 500);
    }

    #[test]
    fn dns_config_builder_local_zone() {
        let cfg = DnsConfigBuilder::new(DnsConfig::default())
            .local_zone(false)
            .build();
        assert!(!cfg.local_zone);
    }

    #[test]
    fn dns_config_builder_chaining() {
        let cfg = DnsConfigBuilder::new(DnsConfig::default())
            .port(5353)
            .zone("office")
            .local_ttl(300)
            .allow_public_clients(true)
            .max_qps(1000)
            .local_zone(false)
            .build();
        assert_eq!(cfg.port, 5353);
        assert_eq!(cfg.zone, "office");
        assert_eq!(cfg.local_ttl, 300);
        assert!(cfg.allow_public_clients);
        assert_eq!(cfg.max_qps, 1000);
        assert!(!cfg.local_zone);
    }
}
