use std::net::IpAddr;
use std::path::PathBuf;

use koi_dns::DnsConfig;

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
    pub dns_config: DnsConfig,
    pub dns_auto_start: bool,
    pub health_auto_start: bool,
    pub proxy_auto_start: bool,
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

    pub fn build(self) -> DnsConfig {
        self.config
    }
}
