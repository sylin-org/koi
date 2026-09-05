//! Shared service-catalog vocabulary.
//!
//! These values are product read models. Domain snapshots remain authoritative;
//! composition projects them into this dependency-light schema.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::error::ErrorCode;

pub const CATALOG_SCHEMA: u32 = 1;
pub const PREFERENCES_SCHEMA: u32 = 1;
pub const INSTALLATION_ID_TXT_KEY: &str = "koi.installation_id";
pub const SERVICE_ID_TXT_KEY: &str = "koi.service_id";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("identifier must be a non-empty lowercase ASCII string")]
pub struct InvalidCatalogId;

macro_rules! catalog_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, ToSchema)]
        #[serde(transparent)]
        #[schema(value_type = String)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, InvalidCatalogId> {
                let value = value.into();
                if value.is_empty()
                    || !value.is_ascii()
                    || value
                        .bytes()
                        .any(|byte| byte.is_ascii_uppercase() || byte.is_ascii_whitespace())
                {
                    return Err(InvalidCatalogId);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

catalog_id!(InstallationId);
catalog_id!(DeviceId);
catalog_id!(ServiceId);
catalog_id!(EndpointId);
catalog_id!(ObservationId);
catalog_id!(OperationId);
catalog_id!(NetworkScopeId);

impl InstallationId {
    pub fn new_uuid_v7() -> Self {
        Self::new(uuid::Uuid::now_v7().to_string()).expect("UUIDv7 is lowercase ASCII")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CatalogSnapshot {
    pub schema: u32,
    pub epoch: String,
    pub revision: u64,
    pub generated_at: DateTime<Utc>,
    pub devices: Vec<Device>,
    pub services: Vec<Service>,
    pub local_candidates: Vec<LocalCandidate>,
}

#[derive(Deserialize)]
struct CatalogSnapshotWire {
    schema: u32,
    epoch: String,
    revision: u64,
    generated_at: DateTime<Utc>,
    devices: Vec<Device>,
    services: Vec<Service>,
    local_candidates: Vec<LocalCandidate>,
}

impl<'de> Deserialize<'de> for CatalogSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CatalogSnapshotWire::deserialize(deserializer)?;
        if wire.schema != CATALOG_SCHEMA {
            return Err(serde::de::Error::custom(format!(
                "unsupported catalog schema {}; supported schema is {}",
                wire.schema, CATALOG_SCHEMA
            )));
        }
        Ok(Self {
            schema: wire.schema,
            epoch: wire.epoch,
            revision: wire.revision,
            generated_at: wire.generated_at,
            devices: wire.devices,
            services: wire.services,
            local_candidates: wire.local_candidates,
        })
    }
}

impl Default for CatalogSnapshot {
    fn default() -> Self {
        Self {
            schema: CATALOG_SCHEMA,
            epoch: "unobserved".to_string(),
            revision: 0,
            generated_at: DateTime::UNIX_EPOCH,
            devices: Vec::new(),
            services: Vec::new(),
            local_candidates: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Device {
    pub schema: u32,
    pub id: DeviceId,
    pub names: Vec<NameEvidence>,
    pub addresses: Vec<AddressEvidence>,
    pub koi_presence: KoiPresence,
    pub mesh_identity: MeshIdentity,
    pub condition: DeviceCondition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NameEvidence {
    pub value: String,
    pub observation_ids: Vec<ObservationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AddressEvidence {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_scope_id: Option<NetworkScopeId>,
    pub observation_ids: Vec<ObservationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum KoiPresence {
    Absent,
    Observed,
    Identified { installation_id: InstallationId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MeshIdentity {
    pub state: MeshIdentityState,
    pub observation_ids: Vec<ObservationId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeshIdentityState {
    Open,
    Member,
    Authenticated,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCondition {
    Present,
    Stale,
    Absent,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Service {
    pub schema: u32,
    pub id: ServiceId,
    pub device_id: DeviceId,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub kind: ServiceKind,
    pub condition: ServiceCondition,
    pub endpoints: Vec<Endpoint>,
    pub observations: Vec<Observation>,
    pub checks: Vec<CheckEvidence>,
    pub available_actions: Vec<AvailableAction>,
    pub favorite: bool,
    pub local_only: bool,
    pub managed: bool,
    pub active_operations: Vec<OperationSummary>,
    pub identity_confidence: IdentityConfidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ambiguity: Option<Ambiguity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known: Option<LastKnownService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    Web,
    Api,
    Printer,
    Database,
    Runtime,
    Proxy,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCondition {
    Starting,
    Found,
    Responding,
    NotResponding,
    Absent,
    Stale,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityConfidence {
    Explicit,
    Correlated,
    Observed,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Endpoint {
    pub schema: u32,
    pub id: EndpointId,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_scope: Option<NetworkScope>,
    pub source_observation_ids: Vec<ObservationId>,
    pub owner: EndpointOwner,
    pub browser_usable: bool,
    pub transport_encryption: TransportEncryption,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_service_name: Option<String>,
    pub authority_needs: Vec<AuthorityNeed>,
    pub reachability: Vec<CheckEvidence>,
    pub client_tls: Vec<CheckEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NetworkScope {
    pub id: NetworkScopeId,
    pub family: AddressFamily,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
    pub route_source: String,
    pub classification: NetworkClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_scope: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
    Hostname,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkClassification {
    Loopback,
    Private,
    LinkLocal,
    Public,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EndpointOwner {
    Foreign,
    Domain { name: String },
    Share { operation_id: OperationId },
    Secure { operation_id: OperationId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportEncryption {
    None,
    Tls,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityNeed {
    DataAccessToken,
    LocalOperator,
    NativeAuthorization,
    ClientCertificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Observation {
    pub schema: u32,
    pub id: ObservationId,
    pub kind: ObservationKind,
    pub source: String,
    pub provider: String,
    pub source_revision: u64,
    pub source_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_scope_id: Option<NetworkScopeId>,
    pub observer_installation_id: InstallationId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observer_device_id: Option<DeviceId>,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub state: ObservationState,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw_reference: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Mdns,
    Dns,
    Runtime,
    LocalListener,
    Share,
    Proxy,
    Health,
    Certmesh,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Current,
    Withdrawn,
    Stale,
    SourceUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CheckEvidence {
    pub schema: u32,
    pub kind: CheckKind,
    pub observer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_identity: Option<String>,
    pub target_endpoint_id: EndpointId,
    pub checked_at: DateTime<Utc>,
    pub deadline_ms: u64,
    pub timeout_ms: u64,
    pub valid_until: DateTime<Utc>,
    pub result: CheckResult,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    NameResolution,
    TcpConnect,
    HttpResponse,
    BackendHealth,
    ProxyListener,
    FirewallAssessment,
    Certificate,
    OsRootPresence,
    ClientTls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Passed,
    Failed,
    Unknown,
    NotRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AvailableAction {
    Open,
    CopyEndpoint,
    ViewDetails,
    Favorite,
    SetFriendlyAlias,
    DismissCandidate,
    Diagnose,
    Share,
    StopSharing,
    SetUpSecureAccess,
    StopSecureAccess,
    InstallRoot,
    JoinDevice,
    RepairIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OperationSummary {
    pub id: OperationId,
    pub kind: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Ambiguity {
    pub reason: String,
    pub candidates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LastKnownService {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub kind: ServiceKind,
}

/// Stable key for personal intent attached to a Koi service identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServicePreferenceKey {
    KoiService { id: ServiceId },
}

impl ServicePreferenceKey {
    pub fn service_id(&self) -> &ServiceId {
        match self {
            Self::KoiService { id } => id,
        }
    }
}

/// Safe context retained for a favorite that is no longer observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreferredServiceContext {
    pub device_id: DeviceId,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub kind: ServiceKind,
    pub last_condition: ServiceCondition,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ServicePreference {
    pub service_key: ServicePreferenceKey,
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known: Option<PreferredServiceContext>,
}

/// A local candidate is recognized by its detector and source-owned stable key.
/// A port or display label alone is deliberately insufficient.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct CandidatePreferenceKey {
    pub recognizer: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CandidatePreference {
    pub candidate_id: ServiceId,
    pub candidate_key: CandidatePreferenceKey,
    pub dismissed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PreferencesMode {
    Writable,
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreferencesProblem {
    pub error: ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_schema: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_schema: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_schema: Option<u32>,
}

/// Latest authoritative personal-preference state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreferencesStatus {
    pub schema: u32,
    pub epoch: String,
    pub revision: u64,
    pub mode: PreferencesMode,
    pub services: Vec<ServicePreference>,
    pub candidates: Vec<CandidatePreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<PreferencesProblem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SetServicePreferenceRequest {
    pub schema: u32,
    pub expected_revision: u64,
    pub service_key: ServicePreferenceKey,
    pub favorite: bool,
    #[serde(default)]
    pub friendly_alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SetCandidatePreferenceRequest {
    pub schema: u32,
    pub expected_revision: u64,
    pub candidate_key: CandidatePreferenceKey,
    pub dismissed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreferenceErrorBody {
    pub error: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_schema: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_schema: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_schema: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LocalCandidate {
    pub schema: u32,
    pub id: ServiceId,
    pub key: CandidatePreferenceKey,
    pub display_name: String,
    pub kind: ServiceKind,
    pub endpoints: Vec<Endpoint>,
    pub observations: Vec<Observation>,
    pub available_actions: Vec<AvailableAction>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_reject_uppercase_empty_and_whitespace() {
        assert!(ServiceId::new("svc_0199").is_ok());
        assert!(ServiceId::new("").is_err());
        assert!(ServiceId::new("SVC_0199").is_err());
        assert!(ServiceId::new("svc 0199").is_err());
        assert!(serde_json::from_str::<ServiceId>(r#""SVC_0199""#).is_err());
    }

    #[test]
    fn catalog_schema_round_trips() {
        let snapshot = CatalogSnapshot {
            schema: CATALOG_SCHEMA,
            epoch: "0199a".into(),
            revision: 4,
            generated_at: Utc::now(),
            devices: Vec::new(),
            services: Vec::new(),
            local_candidates: Vec::new(),
        };
        let json = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(
            serde_json::from_slice::<CatalogSnapshot>(&json).unwrap(),
            snapshot
        );
        let mut future: serde_json::Value = serde_json::from_slice(&json).unwrap();
        future["schema"] = serde_json::json!(CATALOG_SCHEMA + 1);
        assert!(serde_json::from_value::<CatalogSnapshot>(future).is_err());
    }

    #[test]
    fn preference_contract_round_trips_with_stable_tagged_keys() {
        let status = PreferencesStatus {
            schema: PREFERENCES_SCHEMA,
            epoch: "epoch-1".into(),
            revision: 7,
            mode: PreferencesMode::Writable,
            services: vec![ServicePreference {
                service_key: ServicePreferenceKey::KoiService {
                    id: ServiceId::new("svc_0199").unwrap(),
                },
                favorite: true,
                friendly_alias: Some("Workshop dashboard".into()),
                last_known: None,
            }],
            candidates: Vec::new(),
            problem: None,
        };
        let value = serde_json::to_value(&status).unwrap();
        assert_eq!(value["services"][0]["service_key"]["kind"], "koi_service");
        assert_eq!(
            serde_json::from_value::<PreferencesStatus>(value).unwrap(),
            status
        );
    }
}
