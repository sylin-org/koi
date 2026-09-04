//! Dependency-neutral status vocabulary for the Pond serving component.
//!
//! Pond's behavior and transports remain in `koi-serve`. These value types live in the
//! shared kernel because the lower `koi-compose` layer retains the exact Pond snapshot in
//! the product-wide status without depending back on the serving layer.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PondState {
    Disabled,
    Reconciling,
    Running,
    Waiting,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PondFirewallState {
    /// A known active firewall confirmed the port is admitted.
    Open,
    /// No active supported host firewall was found.
    Inactive,
    /// A known active firewall rejects the port.
    Blocked,
    /// The host policy could not be assessed without guessing.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondFirewallStatus {
    pub state: PondFirewallState,
    pub detail: String,
}

/// The exact durable UI bundle currently served by Pond.
///
/// The revision is a content digest, not a filesystem timestamp. `available = true`
/// therefore means every public asset comes from one completely committed bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondUiStatus {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// Exact desired and observed state of the Pond listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondStatus {
    /// Monotonic semantic status revision within this process.
    #[serde(default)]
    pub revision: u64,
    /// Lifecycle epoch used to reject observations from a superseded listener task.
    #[serde(default)]
    pub generation: u64,
    /// Whether this process can still admit lifecycle commands. This becomes
    /// false before terminal daemon shutdown can reject a command and never
    /// becomes true again for the same runtime instance.
    #[serde(default = "accepting_commands_default")]
    pub accepting_commands: bool,
    pub desired: bool,
    /// Whether the listener socket is currently bound, independent of LAN reachability.
    pub running: bool,
    /// `Running` means the bound listener has a LAN endpoint and no known supported
    /// firewall block; `Waiting` may still have `running = true` when an interface or
    /// firewall prevents reachability.
    pub state: PondState,
    pub port: u16,
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub firewall: PondFirewallStatus,
    /// Atomic five-file presentation bundle selected by the Pond domain.
    #[serde(default)]
    pub ui: PondUiStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PondStatus {
    pub fn disabled(port: u16) -> Self {
        Self {
            revision: 0,
            generation: 0,
            accepting_commands: true,
            desired: false,
            running: false,
            state: PondState::Disabled,
            port,
            urls: Vec::new(),
            url: None,
            firewall: PondFirewallStatus {
                state: PondFirewallState::Unknown,
                detail: "not assessed while Pond is disabled".to_string(),
            },
            ui: PondUiStatus::default(),
            reason: None,
        }
    }

    /// Initial truth when durable intent requests Pond before supervision has begun.
    pub fn awaiting_reconciliation(port: u16) -> Self {
        Self {
            revision: 0,
            generation: 0,
            accepting_commands: true,
            desired: true,
            running: false,
            state: PondState::Waiting,
            port,
            urls: Vec::new(),
            url: None,
            firewall: PondFirewallStatus {
                state: PondFirewallState::Unknown,
                detail: "firewall not assessed before a listener bind".to_string(),
            },
            ui: PondUiStatus::default(),
            reason: Some("persisted desire awaits listener reconciliation".to_string()),
        }
    }
}

const fn accepting_commands_default() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_wire_round_trips_with_generation() {
        let mut status = PondStatus::awaiting_reconciliation(5644);
        status.revision = 7;
        status.generation = 3;

        let encoded = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<PondStatus>(&encoded).unwrap(),
            status
        );
    }

    #[test]
    fn older_status_without_ui_metadata_defaults_to_unavailable() {
        let status = PondStatus::disabled(5644);
        let mut value = serde_json::to_value(status).unwrap();
        value.as_object_mut().unwrap().remove("ui");
        value.as_object_mut().unwrap().remove("accepting_commands");

        let decoded: PondStatus = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.ui, PondUiStatus::default());
        assert!(decoded.accepting_commands);
    }

    #[test]
    fn lifecycle_state_vocabulary_is_exact_and_exhaustive() {
        fn pinned_wire_name(state: PondState) -> &'static str {
            match state {
                PondState::Disabled => "disabled",
                PondState::Reconciling => "reconciling",
                PondState::Running => "running",
                PondState::Waiting => "waiting",
                PondState::Error => "error",
            }
        }

        let states = [
            PondState::Disabled,
            PondState::Reconciling,
            PondState::Running,
            PondState::Waiting,
            PondState::Error,
        ];
        for state in states {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{}\"", pinned_wire_name(state))
            );
        }
        assert!(serde_json::from_str::<PondState>("\"stopping\"").is_err());
    }
}
