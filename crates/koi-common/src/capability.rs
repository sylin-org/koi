use serde::Serialize;

/// Summary of a capability's current state for the unified dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityStatus {
    pub name: String,
    pub summary: String,
    pub healthy: bool,
}

/// Trait implemented by each domain to participate in `koi status`.
pub trait Capability: Send + Sync {
    fn name(&self) -> &str;
    fn status(&self) -> CapabilityStatus;
}
