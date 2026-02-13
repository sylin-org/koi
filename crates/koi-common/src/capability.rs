use serde::Serialize;
use utoipa::ToSchema;

/// Summary of a capability's current state for the unified dashboard.
#[derive(Debug, Clone, Serialize, ToSchema)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_status_serializes_expected_fields() {
        let cs = CapabilityStatus {
            name: "mdns".to_string(),
            summary: "3 registered".to_string(),
            healthy: true,
        };
        let json = serde_json::to_value(&cs).unwrap();
        assert_eq!(json.get("name").unwrap(), "mdns");
        assert_eq!(json.get("summary").unwrap(), "3 registered");
        assert_eq!(json.get("healthy").unwrap(), true);
    }

    #[test]
    fn capability_status_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CapabilityStatus>();
    }
}
