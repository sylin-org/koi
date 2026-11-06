//! Presentation input for operational screens.
//!
//! This is a read projection, never a second state owner. `koi-serve` builds it
//! from one captured composition status; the desktop decodes the same endpoint.

use koi_certmesh::CertmeshStatus;
use koi_common::{capability::CapabilityStatus, pond::PondStatus};
use koi_dns::{DnsCatalogSnapshot, DnsRuntimeStatus};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSnapshot {
    pub revision: u64,
    /// Authenticated inspection projection; never supplied by public Pond.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mdns: Option<koi_common::mdns_browser::BrowserSnapshot>,
    #[serde(default)]
    pub capabilities: Vec<CapabilityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certmesh: Option<CertmeshStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsRuntimeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_catalog: Option<DnsCatalogSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pond: Option<PondStatus>,
    /// Native host integration is supplied by the desktop adapter. Browser and
    /// LAN presentations leave it absent rather than guessing OS state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostIntegrationStatus>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIntegrationStatus {
    pub service_installed: bool,
    pub service_running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autostart_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autostart_detail: Option<String>,
}

impl OperatorSnapshot {
    pub fn capability(&self, name: &str) -> Option<&CapabilityStatus> {
        self.capabilities.iter().find(|item| item.name == name)
    }
}
