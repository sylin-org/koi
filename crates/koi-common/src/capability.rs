use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Composition-owned summary projected from a domain's authoritative typed status.
///
/// This is a presentation/wire type, never a domain state source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CapabilityStatus {
    pub name: String,
    pub summary: String,
    pub healthy: bool,
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
