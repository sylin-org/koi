//! Runtime adapter discovery for the mDNS bounded context.
//!
//! An adapter owns every platform-specific question required to decide whether
//! it can participate: presence, configuration, liveness, capability shape,
//! and arming. The supervisor consumes reports; it never reaches around an
//! adapter with process, socket, service-manager, or D-Bus checks of its own.

use std::fmt;
use std::sync::Arc;

use crate::provider::MdnsProvider;
use crate::Result;

/// One observed environmental fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Whether an adapter can participate in the current reconciliation round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterReadiness {
    /// The resource is usable for the role reported by the adapter.
    Ready,
    /// The resource is definitely not running/present right now.
    Absent,
    /// The resource exists, but an observed failure makes it unusable.
    Unavailable,
}

impl fmt::Display for AdapterReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready => "ready",
            Self::Absent => "absent",
            Self::Unavailable => "unavailable",
        })
    }
}

/// Native API surface used by an adapter. Selection never branches on this;
/// it is evidence for operators and conformance tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterApi {
    Orchestrated,
    Embedded,
    SystemDbus,
    Win32DnsApi,
    BonjourDnsSd,
}

impl fmt::Display for AdapterApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Orchestrated => "orchestrated",
            Self::Embedded => "embedded",
            Self::SystemDbus => "system-dbus",
            Self::Win32DnsApi => "win32-dns-sd",
            Self::BonjourDnsSd => "bonjour-dns-sd",
        })
    }
}

/// Operations exposed by the inspected platform facility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MdnsCapabilities {
    pub publish: bool,
    pub withdraw: bool,
    pub continuous_browse: bool,
    /// Browse observations include resolved SRV/TXT/address data.
    pub browse_resolves: bool,
    /// The provider offers a point-resolution operation independent of browse.
    pub direct_resolve: bool,
    pub explicit_address: bool,
}

impl MdnsCapabilities {
    /// Koi's current provider contract. Partial facilities are collaborators,
    /// never silently selected as if they implemented missing operations.
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
        self.publish
            && self.withdraw
            && self.continuous_browse
            && self.browse_resolves
            && self.explicit_address
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

/// A read-only adapter observation. This is evidence, not policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterReport {
    pub name: &'static str,
    pub priority: u16,
    pub api: AdapterApi,
    pub readiness: AdapterReadiness,
    pub installed: ProbeFact,
    pub configured: ProbeFact,
    pub running: ProbeFact,
    pub capabilities: MdnsCapabilities,
    pub detail: String,
}

impl AdapterReport {
    /// Whether this report satisfies the complete Koi mDNS provider contract by
    /// itself. Partial adapters can still be selected for individual routes.
    pub fn satisfies_full_contract(&self) -> bool {
        self.readiness == AdapterReadiness::Ready && self.capabilities.satisfies_provider_contract()
    }

    pub(crate) fn failed_inspection(
        adapter: &dyn MdnsAdapter,
        readiness: AdapterReadiness,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            name: adapter.name(),
            priority: adapter.priority(),
            api: adapter.api(),
            readiness,
            installed: ProbeFact::Unknown,
            configured: ProbeFact::Unknown,
            running: ProbeFact::Unknown,
            capabilities: MdnsCapabilities::default(),
            detail: detail.into(),
        }
    }

    pub(crate) fn concise(&self) -> String {
        format!(
            "{}={} (api {}; installed {}, configured {}, running {}; capabilities {}; {})",
            self.name,
            self.readiness,
            self.api,
            self.installed,
            self.configured,
            self.running,
            self.capabilities.summary(),
            self.detail
        )
    }
}

/// Platform adapter boundary consumed by the runtime supervisor.
///
/// `inspect` must be read-only and must not activate a stopped system service.
/// `arm` is called only when at least one operation from a ready report appears
/// in the selected capability plan. Partial providers are valid participants;
/// the supervisor never routes them an operation they did not declare.
#[async_trait::async_trait]
pub trait MdnsAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u16;
    fn api(&self) -> AdapterApi;
    fn capabilities(&self) -> MdnsCapabilities;

    async fn inspect(&self) -> AdapterReport;
    async fn arm(&self) -> Result<Arc<dyn MdnsProvider>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(
        name: &'static str,
        priority: u16,
        api: AdapterApi,
        readiness: AdapterReadiness,
        capabilities: MdnsCapabilities,
    ) -> AdapterReport {
        AdapterReport {
            name,
            priority,
            api,
            readiness,
            installed: ProbeFact::Yes,
            configured: ProbeFact::Yes,
            running: ProbeFact::Yes,
            capabilities,
            detail: "test evidence".to_string(),
        }
    }

    #[test]
    fn capability_flags_are_composable() {
        let publication = MdnsCapabilities {
            publish: true,
            withdraw: true,
            ..MdnsCapabilities::default()
        };
        let browse = MdnsCapabilities {
            continuous_browse: true,
            browse_resolves: true,
            ..MdnsCapabilities::default()
        };
        let combined = publication.union(browse);
        assert!(combined.supports(publication));
        assert!(combined.supports(browse));
        assert!(!combined.supports(MdnsCapabilities {
            explicit_address: true,
            ..MdnsCapabilities::default()
        }));
    }

    #[test]
    fn full_provider_report_satisfies_full_contract() {
        let report = report(
            "avahi",
            300,
            AdapterApi::SystemDbus,
            AdapterReadiness::Ready,
            MdnsCapabilities::FULL_PROVIDER_WITH_DIRECT_RESOLVE,
        );
        assert!(report.satisfies_full_contract());
    }

    #[test]
    fn partial_provider_is_truthful_about_the_full_contract() {
        let partial = MdnsCapabilities {
            publish: true,
            withdraw: true,
            direct_resolve: true,
            ..MdnsCapabilities::default()
        };
        let report = report(
            "systemd-resolved",
            200,
            AdapterApi::SystemDbus,
            AdapterReadiness::Ready,
            partial,
        );
        assert!(!report.satisfies_full_contract());
        assert!(report.capabilities.publish);
        assert!(report.capabilities.direct_resolve);
    }
}
