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

/// A declaration of why a capability is not mounted. Recorded once during
/// daemon assembly (ADR-035: "yield, but declare") and merged into the
/// capability ladder by the status endpoint, so a client can ask WHY a
/// surface is absent instead of scraping logs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CapabilityNote {
    pub capability: String,
    /// "skipped" (coexistence or dependency), "disabled" (operator flag), or
    /// "error" (initialization failed and the daemon continued without it).
    pub state: String,
    pub reason: String,
    /// Capabilities this surface was waiting on (e.g. `["mdns"]` for IPC).
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// Process-global note registry. The daemon assembles its capability notes
/// once during startup and the status endpoint reads them for the lifetime of
/// the process — a singleton world, deliberately: these notes describe THIS
/// process's assembly, not per-request state.
static NOTES: std::sync::OnceLock<std::sync::RwLock<Vec<CapabilityNote>>> =
    std::sync::OnceLock::new();

fn notes_cell() -> &'static std::sync::RwLock<Vec<CapabilityNote>> {
    NOTES.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// Record assembly notes (idempotent per call site; appends).
pub fn record_notes(notes: Vec<CapabilityNote>) {
    let mut cell = notes_cell().write().expect("capability note lock");
    cell.extend(notes);
}

/// Snapshot the recorded notes.
pub fn notes_snapshot() -> Vec<CapabilityNote> {
    notes_cell().read().expect("capability note lock").clone()
}

/// Clear all recorded notes (tests; and recovery paths that re-assemble).
pub fn clear_notes() {
    notes_cell().write().expect("capability note lock").clear();
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
    fn capability_notes_round_trip_and_record() {
        let note = CapabilityNote {
            capability: "ipc".to_string(),
            state: "skipped".to_string(),
            reason: "depends on mdns: 5353 held by systemd-resolved".to_string(),
            depends_on: vec!["mdns".to_string()],
        };
        let json = serde_json::to_value(&note).unwrap();
        assert_eq!(json.get("state").unwrap(), "skipped");
        assert_eq!(json.get("depends_on").unwrap().as_array().unwrap().len(), 1);

        record_notes(vec![note.clone()]);
        let snap = notes_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].capability, "ipc");
    }

    #[test]
    fn capability_status_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CapabilityStatus>();
    }
}
