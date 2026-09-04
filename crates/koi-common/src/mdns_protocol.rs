//! mDNS registration/admin **wire-contract** types.
//!
//! These are the shapes exchanged between the daemon (which produces them in
//! `koi-mdns`'s HTTP/NDJSON handlers) and clients that consume them (`koi-client`,
//! external API consumers). They live in the kernel — alongside [`crate::types`] and
//! [`crate::pipeline`] — so a client can speak the contract without depending on the
//! mDNS engine. `koi-mdns` re-exports them from its `protocol` module.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Native API surface used by an mDNS provider.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderApi {
    Embedded,
    SystemDbus,
    Win32DnsApi,
    BonjourDnsSd,
}

impl fmt::Display for ProviderApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Embedded => "embedded",
            Self::SystemDbus => "system-dbus",
            Self::Win32DnsApi => "win32-dns-sd",
            Self::BonjourDnsSd => "bonjour-dns-sd",
        })
    }
}

/// One read-only environmental fact reported by a provider adapter.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProbeFact {
    Yes,
    No,
    Unknown,
    NotApplicable,
}

impl fmt::Display for ProbeFact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Unknown => "unknown",
            Self::NotApplicable => "n/a",
        })
    }
}

/// Whether an adapter can open a provider session in the current environment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProviderAvailability {
    Ready,
    Absent,
    Unavailable,
}

impl fmt::Display for ProviderAvailability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready => "ready",
            Self::Absent => "absent",
            Self::Unavailable => "unavailable",
        })
    }
}

/// Runtime condition of an already-open provider session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProviderSessionState {
    Ready,
    Recovering,
    Lost,
}

impl fmt::Display for ProviderSessionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready => "ready",
            Self::Recovering => "recovering",
            Self::Lost => "lost",
        })
    }
}

/// Operations a provider can perform with real native resources.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct MdnsCapabilities {
    pub publish: bool,
    pub withdraw: bool,
    pub continuous_browse: bool,
    pub browse_resolves: bool,
    pub direct_resolve: bool,
    pub explicit_address: bool,
}

impl MdnsCapabilities {
    pub const FULL_PROVIDER: Self = Self {
        publish: true,
        withdraw: true,
        continuous_browse: true,
        browse_resolves: true,
        direct_resolve: false,
        explicit_address: true,
    };

    pub const FULL_PROVIDER_WITH_DIRECT_RESOLVE: Self = Self {
        direct_resolve: true,
        ..Self::FULL_PROVIDER
    };

    pub fn supports(self, required: Self) -> bool {
        (!required.publish || self.publish)
            && (!required.withdraw || self.withdraw)
            && (!required.continuous_browse || self.continuous_browse)
            && (!required.browse_resolves || self.browse_resolves)
            && (!required.direct_resolve || self.direct_resolve)
            && (!required.explicit_address || self.explicit_address)
    }

    pub fn intersect(self, maximum: Self) -> Self {
        Self {
            publish: self.publish && maximum.publish,
            withdraw: self.withdraw && maximum.withdraw,
            continuous_browse: self.continuous_browse && maximum.continuous_browse,
            browse_resolves: self.browse_resolves && maximum.browse_resolves,
            direct_resolve: self.direct_resolve && maximum.direct_resolve,
            explicit_address: self.explicit_address && maximum.explicit_address,
        }
    }

    pub fn union(self, other: Self) -> Self {
        Self {
            publish: self.publish || other.publish,
            withdraw: self.withdraw || other.withdraw,
            continuous_browse: self.continuous_browse || other.continuous_browse,
            browse_resolves: self.browse_resolves || other.browse_resolves,
            direct_resolve: self.direct_resolve || other.direct_resolve,
            explicit_address: self.explicit_address || other.explicit_address,
        }
    }

    pub fn satisfies_provider_contract(self) -> bool {
        self.supports(Self::FULL_PROVIDER)
    }

    pub fn summary(self) -> String {
        let mut operations = Vec::new();
        if self.publish {
            operations.push("publish");
        }
        if self.withdraw {
            operations.push("withdraw");
        }
        if self.continuous_browse {
            operations.push("browse");
        }
        if self.browse_resolves {
            operations.push("browse-resolve");
        }
        if self.direct_resolve {
            operations.push("direct-resolve");
        }
        if self.explicit_address {
            operations.push("explicit-address");
        }
        if operations.is_empty() {
            "none".to_string()
        } else {
            operations.join("+")
        }
    }
}

/// Adapter evidence plus the state of its currently open session, when any.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct MdnsProviderReport {
    pub name: String,
    pub priority: u16,
    pub api: ProviderApi,
    pub availability: ProviderAvailability,
    pub installed: ProbeFact,
    pub configured: ProbeFact,
    pub running: ProbeFact,
    pub capabilities: MdnsCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<ProviderSessionState>,
    pub detail: String,
}

/// Provider currently responsible for each independent mDNS route.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct MdnsRoutes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_publish: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browse: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolve: Option<String>,
}

/// Registry intent compared with real provider-owned publication resources.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct PublicationSync {
    pub desired: usize,
    pub established: usize,
    pub pending: usize,
    pub failed: usize,
}

/// Top-level condition of the mDNS control plane.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ControlPlaneState {
    Ready,
    Reconciling,
    Degraded,
    #[default]
    Stopped,
}

impl fmt::Display for ControlPlaneState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready => "ready",
            Self::Reconciling => "reconciling",
            Self::Degraded => "degraded",
            Self::Stopped => "stopped",
        })
    }
}

/// Structured mDNS orchestration snapshot. Human summaries are projections of
/// this value and are never parsed back into policy or integration decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct MdnsControlPlaneStatus {
    pub state: ControlPlaneState,
    pub generation: u64,
    pub routes: MdnsRoutes,
    pub providers: Vec<MdnsProviderReport>,
    pub publications: PublicationSync,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition: Option<String>,
}

/// Payload for registering a new service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct RegisterPayload {
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub port: u16,
    /// Pin the A/AAAA record to a specific IP address.
    /// When absent, all machine IPs are advertised (auto-detect).
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u64>,
    #[serde(default)]
    pub txt: HashMap<String, String>,
}

/// Result of a successful registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct RegistrationResult {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub port: u16,
    pub mode: LeaseMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u64>,
}

/// Result of a successful lease renewal (heartbeat).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct RenewalResult {
    pub id: String,
    pub lease_secs: u64,
}

/// How a registration stays alive (wire representation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LeaseMode {
    Session,
    Heartbeat,
    Permanent,
}

/// Wire-level registration state (display-only projection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LeaseState {
    Alive,
    Draining,
}

/// Full registration state as exposed to admin queries.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdminRegistration {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub port: u16,
    pub mode: LeaseMode,
    pub state: LeaseState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_secs: Option<u64>,
    pub grace_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub registered_at: String,
    pub last_seen: String,
    #[serde(default)]
    pub txt: HashMap<String, String>,
}

/// Daemon status overview for admin queries.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DaemonStatus {
    pub version: String,
    pub uptime_secs: u64,
    pub platform: String,
    pub registrations: RegistrationCounts,
    /// Runtime provider routes and their concrete synchronization state.
    #[serde(default)]
    pub control_plane: MdnsControlPlaneStatus,
}

/// Registration counts by state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct RegistrationCounts {
    pub alive: usize,
    pub draining: usize,
    pub permanent: usize,
    pub total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plane_status_round_trips_without_text_parsing() {
        let status = MdnsControlPlaneStatus {
            state: ControlPlaneState::Ready,
            generation: 7,
            routes: MdnsRoutes {
                publish: Some("avahi".to_string()),
                explicit_publish: Some("native".to_string()),
                browse: Some("avahi".to_string()),
                resolve: Some("systemd-resolved".to_string()),
            },
            providers: vec![MdnsProviderReport {
                name: "avahi".to_string(),
                priority: 300,
                api: ProviderApi::SystemDbus,
                availability: ProviderAvailability::Ready,
                installed: ProbeFact::Yes,
                configured: ProbeFact::Yes,
                running: ProbeFact::Yes,
                capabilities: MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
                session: Some(ProviderSessionState::Ready),
                detail: "live system D-Bus owner".to_string(),
            }],
            publications: PublicationSync {
                desired: 2,
                established: 2,
                pending: 0,
                failed: 0,
            },
            transition: None,
        };

        let json = serde_json::to_value(&status).expect("serialize status");
        assert_eq!(json["routes"]["browse"], "avahi");
        assert_eq!(json["providers"][0]["session"], "ready");
        assert_eq!(json["publications"]["established"], 2);
        let decoded: MdnsControlPlaneStatus =
            serde_json::from_value(json).expect("deserialize status");
        assert_eq!(decoded, status);
    }

    #[test]
    fn old_daemon_status_without_control_plane_gets_stopped_default() {
        let json = serde_json::json!({
            "version": "1.0.0",
            "uptime_secs": 4,
            "platform": "linux",
            "registrations": {"alive": 0, "draining": 0, "permanent": 0, "total": 0}
        });
        let decoded: DaemonStatus = serde_json::from_value(json).expect("legacy status");
        assert_eq!(decoded.control_plane.state, ControlPlaneState::Stopped);
    }
}
