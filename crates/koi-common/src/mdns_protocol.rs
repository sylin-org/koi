//! mDNS registration/admin **wire-contract** types.
//!
//! These are the shapes exchanged between the daemon (which produces them in
//! `koi-mdns`'s HTTP/NDJSON handlers) and clients that consume them (`koi-client`,
//! external API consumers). They live in the kernel — alongside [`crate::types`] and
//! [`crate::pipeline`] — so a client can speak the contract without depending on the
//! mDNS engine. `koi-mdns` re-exports them from its `protocol` module.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
}

/// Registration counts by state.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegistrationCounts {
    pub alive: usize,
    pub draining: usize,
    pub permanent: usize,
    pub total: usize,
}
