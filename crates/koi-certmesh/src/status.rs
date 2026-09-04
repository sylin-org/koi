//! Authoritative, immutable Certmesh status projection.
//!
//! Certmesh owns this projection and publishes it only after successful domain
//! transitions. Boundaries consume it directly (cheap [`Arc`](std::sync::Arc)
//! reads) or subscribe to its coalescing watch feed; they never reconstruct
//! membership, posture, CA state, or diagnosis from persistence.

use chrono::{DateTime, Utc};
use koi_common::diagnosis::TrustDiagnosis;
use koi_common::posture::Posture;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::roster::{CertPolicy, EnrollmentState, ProxyConfigEntry, Roster};
use crate::{ca, diagnosis, member, CertmeshPaths, Identity, IdentityInfo, RenewalHealth};

/// Sensitive in-process projection of Certmesh's authoritative verification
/// anchor. It is intentionally separate from serializable status so raw PEM can
/// feed the Trust domain without ever reaching HTTP, dashboard, or logs.
#[derive(Clone, PartialEq, Eq)]
pub struct CertmeshCaAnchor {
    pub fingerprint: String,
    pub certificate_pem: String,
}

impl std::fmt::Debug for CertmeshCaAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertmeshCaAnchor")
            .field("fingerprint", &self.fingerprint)
            .field("certificate_pem", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertmeshCaAnchorSnapshot {
    pub revision: u64,
    pub state: CertmeshCaAnchorState,
}

/// Result of observing the verification anchor owned by this Certmesh role.
///
/// `Absent` is a positive domain fact and may drive removal from a consuming
/// trust store. `Unavailable` is an observation failure and must preserve the
/// consumer's last accepted desire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertmeshCaAnchorState {
    Absent,
    Available(CertmeshCaAnchor),
    Unavailable { reason: String },
}

impl CertmeshCaAnchorSnapshot {
    pub fn absent(revision: u64) -> Self {
        Self {
            revision,
            state: CertmeshCaAnchorState::Absent,
        }
    }

    pub fn anchor(&self) -> Result<Option<&CertmeshCaAnchor>, &str> {
        match &self.state {
            CertmeshCaAnchorState::Absent => Ok(None),
            CertmeshCaAnchorState::Available(anchor) => Ok(Some(anchor)),
            CertmeshCaAnchorState::Unavailable { reason } => Err(reason),
        }
    }
}

pub(crate) fn build_ca_anchor(
    paths: &CertmeshPaths,
    local_hostname: Option<&str>,
    role: CertmeshRole,
    revision: u64,
) -> CertmeshCaAnchorSnapshot {
    let state = match observe_ca_anchor(paths, local_hostname, role) {
        Ok(None) => CertmeshCaAnchorState::Absent,
        Ok(Some(anchor)) => CertmeshCaAnchorState::Available(anchor),
        Err(reason) => CertmeshCaAnchorState::Unavailable { reason },
    };
    CertmeshCaAnchorSnapshot { revision, state }
}

pub(crate) fn observe_ca_anchor(
    paths: &CertmeshPaths,
    local_hostname: Option<&str>,
    role: CertmeshRole,
) -> Result<Option<CertmeshCaAnchor>, String> {
    let path = match role {
        CertmeshRole::Open => return Ok(None),
        CertmeshRole::Authority => {
            // On an authority the CA artifact is the aggregate's source of
            // truth; a stale leaf-local copy may not mask damage to it.
            paths.ca_cert_path()
        }
        CertmeshRole::Member => {
            let hostname = local_hostname.ok_or_else(|| {
                "cannot observe the member CA anchor without the configured local hostname"
                    .to_string()
            })?;
            paths.certs_dir().join(hostname).join("ca.pem")
        }
    };
    let certificate_pem = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read CA anchor {}: {error}", path.display()))?;
    let certificate = pem::parse(&certificate_pem)
        .map_err(|error| format!("CA anchor {} is invalid PEM: {error}", path.display()))?;
    Ok(Some(CertmeshCaAnchor {
        fingerprint: koi_crypto::pinning::fingerprint_sha256(certificate.contents()),
        certificate_pem,
    }))
}

/// This node's durable relationship to Certmesh.
///
/// Role is deliberately independent from [`Posture`]. A member whose identity
/// is missing, corrupt, expired, or revoked remains a member and therefore keeps
/// enforcing authentication; it does not fail open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CertmeshRole {
    /// No CA ownership or joined-mesh marker exists.
    Open,
    /// The node joined a CA owned elsewhere (including embedded installations
    /// that deliberately keep only their leaf and pinned CA anchor).
    Member,
    /// The node owns the mesh CA, whether its private key is locked or unlocked.
    Authority,
}

impl CertmeshRole {
    /// Whether consumers must enforce authenticated operation.
    pub const fn requires_authentication(self) -> bool {
        !matches!(self, Self::Open)
    }
}

/// Health of this node's local Certmesh identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCondition {
    /// No identity is expected or installed on an open node.
    Absent,
    /// The leaf, key, and CA anchor are coherent and current.
    Healthy,
    /// Identity material exists but is expired.
    Expired,
    /// The node is a member/authority but its identity is absent or incoherent.
    Invalid,
    /// The authority has revoked this node.
    Revoked,
}

/// Key-redacting local identity status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertmeshIdentityStatus {
    pub condition: IdentityCondition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<IdentityInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A roster member projected at the Certmesh boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertmeshMemberStatus {
    pub hostname: String,
    pub role: String,
    pub status: String,
    pub cert_fingerprint: String,
    pub cert_expires: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_sans: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_entries: Vec<ProxyConfigEntry>,
}

/// Authority-only status. It is absent on open and member-only nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertmeshAuthorityStatus {
    pub locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    pub enrollment_open: bool,
    pub requires_approval: bool,
    pub enrollment_state: EnrollmentState,
    pub member_count: usize,
    pub seq: u64,
    pub policy: CertPolicy,
    pub members: Vec<CertmeshMemberStatus>,
}

/// Observable delivery state for the local post-certificate reload hook.
/// Presence means the new certificate is already authoritative, but its local
/// consumer has not yet acknowledged a successful reload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertmeshReloadStatus {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_fingerprint: Option<String>,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Process-local outcome of this node's automatic or operator-triggered local
/// certificate renewal attempts. Certificate deadline health remains on the
/// identity; this facet owns execution failure truth that cannot be derived
/// from certificate files or best-effort events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertmeshRenewalStatus {
    pub consecutive_failures: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The single, domain-owned Certmesh read model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertmeshStatus {
    /// Monotonic process-local revision, incremented only for semantic changes.
    pub revision: u64,
    pub role: CertmeshRole,
    /// What the node can safely do now. This can be Open while `role` remains
    /// Member/Authority, which represents a fail-closed broken identity.
    pub posture: Posture,
    pub identity: CertmeshIdentityStatus,
    pub diagnosis: TrustDiagnosis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<CertmeshAuthorityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload: Option<CertmeshReloadStatus>,
    #[serde(default)]
    pub renewal: CertmeshRenewalStatus,
}

/// Qualify the public read model while a visible repository generation awaits
/// durability confirmation. The aggregate remains authoritative in memory;
/// the RED finding prevents boundaries from mistaking it for settled success.
pub(crate) fn qualify_repository_durability(status: &mut CertmeshStatus, reason: &str) {
    status
        .diagnosis
        .checks
        .push(koi_common::diagnosis::DiagnosisCheck::red(
            "repository_durability",
            format!(
                "the current Certmesh generation is visible, but crash durability could not be confirmed: {reason}"
            ),
        ));
    status.diagnosis = TrustDiagnosis::from_checks(status.posture, status.diagnosis.checks.clone());
}

impl CertmeshStatus {
    /// Minimal discovery/join information safe to expose without the management
    /// token. Full status (identity health, diagnosis, roster) remains protected.
    pub fn bootstrap(&self) -> CertmeshBootstrapStatus {
        let authority = self.authority.as_ref();
        CertmeshBootstrapStatus {
            revision: self.revision,
            authority_available: authority.is_some(),
            ca_fingerprint: authority.and_then(|a| a.ca_fingerprint.clone()),
            enrollment_open: authority.is_some_and(|a| a.enrollment_open),
            requires_approval: authority.is_some_and(|a| a.requires_approval),
        }
    }
}

/// Project only the active-member facts promised by the cross-domain roster
/// port. Keeping this mapper in Certmesh makes the domain the sole authority
/// over what membership means and gives consumers stable ordering.
pub(crate) fn active_members(
    status: &CertmeshStatus,
) -> Vec<koi_common::integration::MemberSummary> {
    let mut members = status
        .authority
        .as_ref()
        .into_iter()
        .flat_map(|authority| authority.members.iter())
        .filter(|member| member.status == "active")
        .map(|member| koi_common::integration::MemberSummary {
            hostname: member.hostname.clone(),
            sans: member.cert_sans.clone(),
            cert_expires: chrono::DateTime::parse_from_rfc3339(&member.cert_expires)
                .ok()
                .map(|value| value.with_timezone(&chrono::Utc)),
            last_seen: member.last_seen,
            status: member.status.clone(),
            proxy_entries: member
                .proxy_entries
                .iter()
                .map(|entry| koi_common::integration::ProxyConfigSummary {
                    name: entry.name.clone(),
                    listen_port: entry.listen_port,
                    backend: entry.backend.clone(),
                    allow_remote: entry.allow_remote,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    members.sort_by(|left, right| left.hostname.cmp(&right.hostname));
    members
}

/// Public, non-sensitive CA preflight used by discovery and enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CertmeshBootstrapStatus {
    pub revision: u64,
    pub authority_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
    pub enrollment_open: bool,
    pub requires_approval: bool,
}

/// Assemble the initial or refreshed projection from domain-owned state.
pub(crate) fn build(
    paths: &CertmeshPaths,
    local_hostname: Option<&str>,
    ca_unlocked: bool,
    in_memory_ca_fingerprint: Option<String>,
    roster: &Roster,
    auth_method: Option<String>,
    revision: u64,
) -> CertmeshStatus {
    build_with_tls(
        paths,
        local_hostname,
        ca_unlocked,
        in_memory_ca_fingerprint,
        roster,
        auth_method,
        revision,
    )
    .0
}

/// Assemble both public status and sensitive TLS material from one coherent
/// aggregate read. Callers publish them while retaining the transition gate.
pub(crate) fn build_with_tls(
    paths: &CertmeshPaths,
    local_hostname: Option<&str>,
    ca_unlocked: bool,
    in_memory_ca_fingerprint: Option<String>,
    roster: &Roster,
    auth_method: Option<String>,
    revision: u64,
) -> (
    CertmeshStatus,
    Option<koi_common::integration::TlsIdentityMaterial>,
) {
    let member_path = paths.member_state_path();
    let member_marker_exists = member_path.exists();
    let member_observation = member::load(&member_path);
    let member_load_error = member_observation.as_ref().err().map(ToString::to_string);
    let member_state = member_observation.ok().flatten();
    let role = detect_role(
        paths,
        local_hostname,
        member_state.is_some() || member_load_error.is_some(),
    );
    let policy = member_state
        .as_ref()
        .map(|state| state.policy.clone())
        .unwrap_or_else(|| roster.metadata.policy.clone());
    let self_revoked = local_self_revoked(local_hostname, member_state.as_ref(), roster);
    let expected_pin = member_state
        .as_ref()
        .map(|state| state.ca_fingerprint.as_str());
    let (raw_identity, identity_error) =
        load_identity(paths, local_hostname, &policy, expected_pin);
    let integrity_ok = raw_identity.as_ref().map(|identity| {
        diagnosis::identity_material_is_usable(
            &identity.cert_pem,
            &identity.key_pem,
            &identity.ca_cert_pem,
        )
    });

    let member_record_error = if role == CertmeshRole::Member {
        match (member_load_error.as_ref(), member_state.as_ref()) {
            (Some(error), _) => Some(error.clone()),
            (None, None) if member_marker_exists => {
                Some("member state exists but is unreadable or corrupt".to_string())
            }
            (None, Some(state)) if local_hostname != Some(state.hostname.as_str()) => {
                Some(format!(
                    "member state belongs to '{}' but this node is '{}'",
                    state.hostname,
                    local_hostname.unwrap_or("<unavailable>")
                ))
            }
            (None, Some(_)) => None,
            (None, None) => None,
        }
    } else {
        None
    };

    // Revocation is an independent, authoritative mesh decision and takes
    // precedence over local identity damage. A revoked node must never regain
    // its outbound signer merely because its member marker or key material is
    // also incoherent.
    let condition = if self_revoked {
        IdentityCondition::Revoked
    } else if member_record_error.is_some() {
        IdentityCondition::Invalid
    } else if matches!(role, CertmeshRole::Open) && raw_identity.is_none() {
        IdentityCondition::Absent
    } else if raw_identity.is_none() || integrity_ok == Some(false) {
        IdentityCondition::Invalid
    } else if raw_identity
        .as_ref()
        .is_some_and(|identity| identity.renewal.expired)
    {
        IdentityCondition::Expired
    } else {
        IdentityCondition::Healthy
    };
    let posture = Posture {
        signed: condition == IdentityCondition::Healthy,
        encrypted: false,
    };
    let reason = match condition {
        IdentityCondition::Invalid => {
            Some(member_record_error.or(identity_error).unwrap_or_else(|| {
                "local certificate, key, and CA anchor are not a coherent identity".to_string()
            }))
        }
        IdentityCondition::Expired => Some("local certificate has expired".to_string()),
        IdentityCondition::Revoked => Some("this node has been revoked by the mesh CA".to_string()),
        IdentityCondition::Absent | IdentityCondition::Healthy => None,
    };
    let mut diagnosis = diagnosis::build_diagnosis(
        posture,
        raw_identity.as_ref(),
        integrity_ok,
        self_revoked,
        role.requires_authentication(),
        reason.as_deref(),
    );
    if paths.credential_cleanup_pending() {
        diagnosis.checks.push(
            koi_common::diagnosis::DiagnosisCheck::warn(
                "credential_cleanup",
                "Certmesh is removed, but retirement of an unusable platform credential is pending",
            )
            .with_remedy("retry cleanup: `koi certmesh destroy --yes`"),
        );
        diagnosis = koi_common::diagnosis::TrustDiagnosis::from_checks(posture, diagnosis.checks);
    }
    let reload = crate::lifecycle::status(paths);
    if let Some(reload) = reload.as_ref() {
        let summary = reload.last_error.as_deref().unwrap_or(
            "a new certificate is active, but its configured reload hook is still pending",
        );
        diagnosis.checks.push(
            koi_common::diagnosis::DiagnosisCheck::warn("certificate_reload", summary)
                .with_remedy("fix the configured reload command, then restart Koi to retry it"),
        );
        diagnosis = koi_common::diagnosis::TrustDiagnosis::from_checks(posture, diagnosis.checks);
    }
    let identity = CertmeshIdentityStatus {
        condition,
        info: raw_identity.as_ref().map(IdentityInfo::from),
        reason,
    };

    let authority = matches!(role, CertmeshRole::Authority).then(|| {
        let ca_fingerprint =
            in_memory_ca_fingerprint.or_else(|| ca::ca_fingerprint_from_disk(paths).ok());
        CertmeshAuthorityStatus {
            locked: !ca_unlocked,
            ca_fingerprint,
            auth_method,
            enrollment_open: roster.metadata.enrollment_open,
            requires_approval: roster.metadata.requires_approval,
            enrollment_state: roster.enrollment_state(),
            member_count: roster.active_count(),
            seq: roster.metadata.seq,
            policy: roster.metadata.policy.clone(),
            members: roster
                .members
                .iter()
                .map(|member| CertmeshMemberStatus {
                    hostname: member.hostname.clone(),
                    role: format!("{:?}", member.role).to_lowercase(),
                    status: format!("{:?}", member.status).to_lowercase(),
                    cert_fingerprint: member.cert_fingerprint.clone(),
                    cert_expires: member.cert_expires.to_rfc3339(),
                    cert_sans: member.cert_sans.clone(),
                    last_seen: member.last_seen,
                    proxy_entries: member.proxy_entries.clone(),
                })
                .collect(),
        }
    });

    let tls_material = (condition == IdentityCondition::Healthy)
        .then_some(raw_identity.as_ref())
        .flatten()
        .map(|identity| koi_common::integration::TlsIdentityMaterial {
            hostname: identity.hostname.clone(),
            certificate_chain_pem: std::sync::Arc::<str>::from(format!(
                "{}{}",
                identity.cert_pem, identity.ca_cert_pem
            )),
            private_key_pem: std::sync::Arc::<str>::from(identity.key_pem.clone()),
            trust_anchor_pem: std::sync::Arc::<str>::from(identity.ca_cert_pem.clone()),
        });

    (
        CertmeshStatus {
            revision,
            role,
            posture,
            identity,
            diagnosis,
            authority,
            reload,
            renewal: CertmeshRenewalStatus::default(),
        },
        tls_material,
    )
}

fn detect_role(
    paths: &CertmeshPaths,
    local_hostname: Option<&str>,
    has_member_state: bool,
) -> CertmeshRole {
    if paths.is_ca_initialized() {
        return CertmeshRole::Authority;
    }
    // Existence is the durable membership marker. A corrupt member record must
    // degrade to an invalid, authentication-required Member — never Open.
    if has_member_state || paths.member_state_path().exists() {
        return CertmeshRole::Member;
    }
    let anchored_leaf = local_hostname.is_some_and(|hostname| {
        let leaf = paths.certs_dir().join(hostname);
        leaf.join("ca.pem").exists()
            && (leaf.join("cert.pem").exists() || leaf.join("key.pem").exists())
    });
    if anchored_leaf {
        CertmeshRole::Member
    } else {
        CertmeshRole::Open
    }
}

fn load_identity(
    paths: &CertmeshPaths,
    local_hostname: Option<&str>,
    policy: &CertPolicy,
    expected_pin: Option<&str>,
) -> (Option<Identity>, Option<String>) {
    let Some(hostname) = local_hostname else {
        return (
            None,
            Some("local hostname was not supplied by the application composition".to_string()),
        );
    };
    let hostname = hostname.to_string();
    let leaf = paths.certs_dir().join(&hostname);
    let read = |name: &str| {
        std::fs::read_to_string(leaf.join(name))
            .map_err(|error| format!("cannot read {}: {error}", leaf.join(name).display()))
    };
    let cert_pem = match read("cert.pem") {
        Ok(value) => value,
        Err(error) => return (None, Some(error)),
    };
    let key_pem = match read("key.pem") {
        Ok(value) => value,
        Err(error) => return (None, Some(error)),
    };
    let ca_cert_pem = match read("ca.pem").or_else(|_| {
        std::fs::read_to_string(paths.ca_cert_path()).map_err(|error| error.to_string())
    }) {
        Ok(value) => value,
        Err(error) => return (None, Some(format!("cannot read local CA anchor: {error}"))),
    };
    let ca_der = match pem::parse(&ca_cert_pem) {
        Ok(value) => value,
        Err(error) => {
            return (
                None,
                Some(format!("local CA anchor is invalid PEM: {error}")),
            )
        }
    };
    let renewal = match RenewalHealth::from_leaf(&cert_pem, policy) {
        Some(value) => value,
        None => {
            return (
                None,
                Some("local certificate is invalid or has no usable expiry".into()),
            )
        }
    };
    let ca_fingerprint = koi_crypto::pinning::fingerprint_sha256(ca_der.contents());
    if expected_pin
        .is_some_and(|pin| !koi_crypto::pinning::fingerprints_match(pin, &ca_fingerprint))
    {
        return (
            None,
            Some("local CA anchor does not match the member's pinned CA fingerprint".into()),
        );
    }
    (
        Some(Identity {
            hostname,
            cert_pem,
            key_pem,
            ca_cert_pem,
            ca_fingerprint,
            renewal,
        }),
        None,
    )
}

fn local_self_revoked(
    local_hostname: Option<&str>,
    member_state: Option<&member::MemberState>,
    roster: &Roster,
) -> bool {
    if member_state.is_some_and(|state| state.self_revoked) {
        return true;
    }
    local_hostname.is_some_and(|hostname| roster.is_revoked(hostname))
}
