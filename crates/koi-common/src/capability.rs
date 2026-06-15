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
///
/// `status` is async so cores can read their internal `tokio` locks directly (the runtime
/// adapter needs this; the others read sync locks but stay uniform). `name` is sync.
#[async_trait::async_trait]
pub trait Capability: Send + Sync {
    fn name(&self) -> &str;
    async fn status(&self) -> CapabilityStatus;
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
