//! Enrollment flow logic.
//!
//! Processes join requests: verifies auth (TOTP/FIDO2), issues certificate,
//! adds member to roster, writes cert files, appends audit log.

use chrono::Utc;
use koi_crypto::auth::{AuthChallenge, AuthState};
use koi_crypto::totp::RateLimiter;

use crate::audit;
use crate::ca::{self, CaState, IssuedCert};
use crate::certfiles;
use crate::error::CertmeshError;
use crate::protocol::{JoinRequest, JoinResponse};
use crate::roster::{MemberRole, MemberStatus, Roster, RosterMember, RosterMetadata};

/// Validate hostname against scope constraints (domain and subnet).
///
/// If `allowed_domain` is set, the hostname must end with that domain suffix
/// (or match exactly). If `allowed_subnet` is set, the caller IP would be
/// checked (subnet validation is deferred to the HTTP layer where IP is
/// available — see `validate_subnet()`).
pub fn validate_scope(hostname: &str, metadata: &RosterMetadata) -> Result<(), CertmeshError> {
    if let Some(ref domain) = metadata.allowed_domain {
        let domain_lower = domain.to_lowercase();
        let host_lower = hostname.to_lowercase();
        // Hostname must either match the domain exactly or end with ".domain"
        if host_lower != domain_lower && !host_lower.ends_with(&format!(".{domain_lower}")) {
            let reason = format!("hostname '{}' outside domain '{}'", hostname, domain);
            let _ = audit::append_entry(
                "scope_violation",
                &[("hostname", hostname), ("reason", &reason)],
            );
            return Err(CertmeshError::ScopeViolation(reason));
        }
    }
    Ok(())
}

/// Validate an IP address against a CIDR subnet constraint.
///
/// Returns `Ok(())` if no subnet constraint is set or the IP is within range.
/// Uses `ipnet::IpNet` for correct CIDR parsing and containment checks.
pub fn validate_subnet(ip: &str, metadata: &RosterMetadata) -> Result<(), CertmeshError> {
    if let Some(ref cidr) = metadata.allowed_subnet {
        let network: ipnet::IpNet = cidr
            .parse()
            .map_err(|_| CertmeshError::ScopeViolation(format!("invalid subnet CIDR: {cidr}")))?;
        let client_ip: std::net::IpAddr = ip
            .parse()
            .map_err(|_| CertmeshError::ScopeViolation(format!("invalid IP address: {ip}")))?;
        if !network.contains(&client_ip) {
            let reason = format!("IP '{}' outside subnet '{}'", ip, cidr);
            let _ = audit::append_entry("scope_violation", &[("ip", ip), ("reason", &reason)]);
            return Err(CertmeshError::ScopeViolation(reason));
        }
    }
    Ok(())
}

/// Parse and validate a CIDR string. Returns the canonical form.
///
/// Used at policy-set time so invalid CIDRs are rejected early.
pub fn parse_cidr(cidr: &str) -> Result<ipnet::IpNet, CertmeshError> {
    cidr.parse()
        .map_err(|_| CertmeshError::ScopeViolation(format!("invalid CIDR format: {cidr}")))
}

/// Process an enrollment request from a joining member.
///
/// 1. Check enrollment is open (including deadline)
/// 2. Verify auth response (TOTP or FIDO2)
/// 3. Validate scope constraints
/// 4. Check not already enrolled
/// 5. Approval (handled by caller)
/// 6. Issue certificate
/// 7. Write cert files
/// 8. Add to roster
/// 9. Audit log
#[allow(clippy::too_many_arguments)]
pub fn process_enrollment(
    ca: &CaState,
    roster: &mut Roster,
    auth_state: &AuthState,
    challenge: &AuthChallenge,
    rate_limiter: &mut RateLimiter,
    request: &JoinRequest,
    hostname: &str,
    sans: &[String],
    approved_by: Option<String>,
) -> Result<(JoinResponse, IssuedCert), CertmeshError> {
    // 1. Check enrollment is open (includes deadline auto-close)
    if !roster.is_enrollment_open() {
        return Err(CertmeshError::EnrollmentClosed);
    }

    // 2. Verify auth response (adapter-dispatched)
    let adapter = koi_crypto::auth::adapter_for(auth_state);
    let valid = adapter
        .verify(auth_state, challenge, &request.auth)
        .unwrap_or(false);

    match rate_limiter.check_and_record(valid) {
        Ok(()) => {} // Valid, proceed
        Err(koi_crypto::totp::RateLimitError::LockedOut { remaining_secs }) => {
            return Err(CertmeshError::RateLimited { remaining_secs });
        }
        Err(koi_crypto::totp::RateLimitError::InvalidCode { .. }) => {
            return Err(CertmeshError::InvalidAuth);
        }
    }

    // 3. Validate scope constraints
    validate_scope(hostname, &roster.metadata)?;

    // 3b. Reject revoked members
    if roster.is_revoked(hostname) {
        return Err(CertmeshError::Revoked(hostname.to_string()));
    }

    // 4. Check not already enrolled
    if roster.is_enrolled(hostname) {
        return Err(CertmeshError::AlreadyEnrolled(hostname.to_string()));
    }

    // 5. Approval handled by caller when required
    if roster.requires_approval() && approved_by.as_deref().unwrap_or("").is_empty() {
        return Err(CertmeshError::ApprovalDenied);
    }

    // 6. Issue certificate
    let issued = ca::issue_certificate(ca, hostname, sans)?;

    // 6. Write cert files
    let cert_dir = certfiles::write_cert_files(hostname, &issued)?;

    // 7. Add to roster
    let is_primary = roster.members.is_empty();
    let role = if is_primary {
        MemberRole::Primary
    } else {
        MemberRole::Member
    };
    let role_str = if is_primary { "primary" } else { "member" };

    let ca_fp = ca::ca_fingerprint(ca);
    let member = RosterMember {
        hostname: hostname.to_string(),
        role,
        enrolled_at: Utc::now(),
        enrolled_by: approved_by
            .clone()
            .or_else(|| roster.metadata.operator.clone()),
        cert_fingerprint: issued.fingerprint.clone(),
        cert_expires: issued.expires,
        cert_sans: sans.to_vec(),
        cert_path: cert_dir.display().to_string(),
        status: MemberStatus::Active,
        reload_hook: None,
        last_seen: Some(Utc::now()),
        pinned_ca_fingerprint: Some(ca_fp),
        proxy_entries: Vec::new(),
    };
    roster.members.push(member);

    // 9. Audit log
    let operator_str = approved_by
        .as_deref()
        .or(roster.metadata.operator.as_deref())
        .unwrap_or("self");
    let _ = audit::append_entry(
        "member_joined",
        &[
            ("hostname", hostname),
            ("fingerprint", &issued.fingerprint),
            ("role", role_str),
            ("approved_by", operator_str),
        ],
    );

    let ca_fingerprint = ca::ca_fingerprint(ca);

    let response = JoinResponse {
        hostname: hostname.to_string(),
        ca_cert: issued.ca_pem.clone(),
        service_cert: issued.cert_pem.clone(),
        service_key: issued.key_pem.clone(),
        ca_fingerprint,
        cert_path: cert_dir.display().to_string(),
    };

    Ok((response, issued))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::TrustProfile;
    use crate::roster::EnrollmentState;
    use koi_crypto::totp;

    fn make_test_ca() -> CaState {
        let _ = koi_common::test::ensure_data_dir("koi-certmesh-enrollment-tests");
        let entropy = vec![42u8; 32];
        ca::create_ca("test-pass", &entropy).unwrap().0
    }

    fn make_auth_and_code(
        secret: &totp::TotpSecret,
        valid: bool,
    ) -> (AuthState, AuthChallenge, koi_crypto::auth::AuthResponse) {
        let state = AuthState::Totp(totp::TotpSecret::from_bytes(secret.as_bytes().to_vec()));
        let challenge = AuthChallenge::Totp;
        let code = if valid {
            koi_crypto::totp::current_code(secret).expect("current_code")
        } else {
            let v = koi_crypto::totp::current_code(secret).expect("current_code");
            if v != "000000" {
                "000000".to_string()
            } else {
                "111111".to_string()
            }
        };
        let response = koi_crypto::auth::AuthResponse::Totp { code };
        (state, challenge, response)
    }

    #[test]
    fn enrollment_with_invalid_totp_fails() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let secret = totp::generate_secret();
        let mut rl = RateLimiter::new();

        let (auth_state, challenge, bad_response) = make_auth_and_code(&secret, false);

        let request = JoinRequest {
            hostname: "stone-05".to_string(),
            auth: bad_response,
            sans: vec![],
        };

        let result = process_enrollment(
            &ca,
            &mut roster,
            &auth_state,
            &challenge,
            &mut rl,
            &request,
            "stone-05",
            &["stone-05".to_string(), "stone-05.local".to_string()],
            None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            CertmeshError::InvalidAuth => {}
            other => panic!("expected InvalidAuth, got: {other}"),
        }
    }

    #[test]
    fn enrollment_closed_rejects() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::MyOrganization, Some("Admin".into()));
        // Explicitly close enrollment so the test doesn't depend on constructor defaults
        roster.metadata.enrollment_state = EnrollmentState::Closed;
        assert_eq!(roster.metadata.enrollment_state, EnrollmentState::Closed);

        let secret = totp::generate_secret();
        let mut rl = RateLimiter::new();

        let (auth_state, challenge, _) = make_auth_and_code(&secret, true);
        let request = JoinRequest {
            hostname: "stone-05".to_string(),
            auth: koi_crypto::auth::AuthResponse::Totp {
                code: "123456".to_string(),
            },
            sans: vec![],
        };

        let result = process_enrollment(
            &ca,
            &mut roster,
            &auth_state,
            &challenge,
            &mut rl,
            &request,
            "stone-05",
            &["stone-05".to_string()],
            None,
        );

        assert!(matches!(result, Err(CertmeshError::EnrollmentClosed)));
    }

    #[test]
    fn rate_limit_after_failures() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let secret = totp::generate_secret();
        let mut rl = RateLimiter::new();

        let (auth_state, challenge, _) = make_auth_and_code(&secret, false);
        let bad_request = JoinRequest {
            hostname: "stone-05".to_string(),
            auth: koi_crypto::auth::AuthResponse::Totp {
                code: "000000".to_string(),
            },
            sans: vec![],
        };

        // Fail 3 times to trigger lockout
        for _ in 0..3 {
            let _ = process_enrollment(
                &ca,
                &mut roster,
                &auth_state,
                &challenge,
                &mut rl,
                &bad_request,
                "stone-05",
                &["stone-05".to_string()],
                None,
            );
        }

        // 4th attempt should be rate limited
        let result = process_enrollment(
            &ca,
            &mut roster,
            &auth_state,
            &challenge,
            &mut rl,
            &bad_request,
            "stone-05",
            &["stone-05".to_string()],
            None,
        );

        assert!(matches!(result, Err(CertmeshError::RateLimited { .. })));
    }

    // ── Scope validation tests ──────────────────────────────────────

    #[test]
    fn validate_scope_no_constraints_allows_any() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::JustMe,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: None,
        };
        assert!(validate_scope("anything.example.com", &metadata).is_ok());
    }

    #[test]
    fn validate_scope_domain_exact_match() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::MyTeam,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: Some("lab.local".to_string()),
            allowed_subnet: None,
        };
        assert!(validate_scope("lab.local", &metadata).is_ok());
    }

    #[test]
    fn validate_scope_domain_suffix_match() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::MyTeam,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: Some("lab.local".to_string()),
            allowed_subnet: None,
        };
        assert!(validate_scope("host-01.lab.local", &metadata).is_ok());
        assert!(validate_scope("deep.nest.lab.local", &metadata).is_ok());
    }

    #[test]
    fn validate_scope_domain_case_insensitive() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::MyTeam,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: Some("Lab.Local".to_string()),
            allowed_subnet: None,
        };
        assert!(validate_scope("HOST.lab.local", &metadata).is_ok());
    }

    #[test]
    fn validate_scope_domain_rejects_outside() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::MyOrganization,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: Some("school.local".to_string()),
            allowed_subnet: None,
        };
        let result = validate_scope("attacker.evil.com", &metadata);
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[test]
    fn validate_scope_domain_rejects_partial_suffix() {
        // "notschool.local" should NOT match "school.local"
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::MyOrganization,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: Some("school.local".to_string()),
            allowed_subnet: None,
        };
        let result = validate_scope("notschool.local", &metadata);
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[test]
    fn validate_subnet_allows_in_range() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::JustMe,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: Some("192.168.1.0/24".to_string()),
        };
        assert!(validate_subnet("192.168.1.42", &metadata).is_ok());
        assert!(validate_subnet("192.168.1.255", &metadata).is_ok());
    }

    #[test]
    fn validate_subnet_rejects_outside() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::JustMe,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: Some("192.168.1.0/24".to_string()),
        };
        let result = validate_subnet("10.0.0.1", &metadata);
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[test]
    fn validate_subnet_no_constraint_allows_any() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::JustMe,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: None,
        };
        assert!(validate_subnet("10.0.0.1", &metadata).is_ok());
    }

    #[test]
    fn validate_subnet_rejects_invalid_cidr() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::JustMe,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: Some("not-a-cidr".to_string()),
        };
        // ipnet rejects malformed CIDR strings
        let result = validate_subnet("10.0.0.1", &metadata);
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[test]
    fn validate_subnet_ipv6() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::JustMe,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: Some("fd00::/16".to_string()),
        };
        assert!(validate_subnet("fd00::1", &metadata).is_ok());
        let result = validate_subnet("fe80::1", &metadata);
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[test]
    fn validate_subnet_prefix_32_exact_match() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::JustMe,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: Some("10.0.0.1/32".to_string()),
        };
        assert!(validate_subnet("10.0.0.1", &metadata).is_ok());
        let result = validate_subnet("10.0.0.2", &metadata);
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[test]
    fn validate_subnet_mixed_versions_rejects() {
        let metadata = RosterMetadata {
            created_at: chrono::Utc::now(),
            trust_profile: TrustProfile::JustMe,
            operator: None,
            requires_approval: Some(false),
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: Some("10.0.0.0/8".to_string()),
        };
        // IPv6 address should not match IPv4 CIDR
        let result = validate_subnet("fd00::1", &metadata);
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[test]
    fn parse_cidr_valid() {
        assert!(parse_cidr("192.168.1.0/24").is_ok());
        assert!(parse_cidr("fd00::/16").is_ok());
        assert!(parse_cidr("10.0.0.0/8").is_ok());
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-a-cidr").is_err());
        assert!(parse_cidr("300.0.0.0/24").is_err());
        assert!(parse_cidr("10.0.0.0/99").is_err());
    }
}
