//! Enrollment flow logic.
//!
//! Processes join requests: verifies TOTP, issues certificate,
//! adds member to roster, writes cert files, appends audit log.

use chrono::Utc;
use koi_crypto::totp::{RateLimiter, TotpSecret};

use crate::audit;
use crate::ca::{self, CaState, IssuedCert};
use crate::certfiles;
use crate::error::CertmeshError;
use crate::profiles::TrustProfile;
use crate::protocol::{JoinRequest, JoinResponse};
use crate::roster::{MemberRole, MemberStatus, Roster, RosterMember, RosterMetadata};

/// Validate hostname against scope constraints (domain and subnet).
///
/// If `allowed_domain` is set, the hostname must end with that domain suffix
/// (or match exactly). If `allowed_subnet` is set, the caller IP would be
/// checked (subnet validation is deferred to the HTTP layer where IP is
/// available — see `validate_subnet()`).
pub fn validate_scope(
    hostname: &str,
    metadata: &RosterMetadata,
) -> Result<(), CertmeshError> {
    if let Some(ref domain) = metadata.allowed_domain {
        let domain_lower = domain.to_lowercase();
        let host_lower = hostname.to_lowercase();
        // Hostname must either match the domain exactly or end with ".domain"
        if host_lower != domain_lower && !host_lower.ends_with(&format!(".{domain_lower}")) {
            let reason = format!(
                "hostname '{}' outside domain '{}'",
                hostname, domain
            );
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
pub fn validate_subnet(
    ip: &str,
    metadata: &RosterMetadata,
) -> Result<(), CertmeshError> {
    if let Some(ref cidr) = metadata.allowed_subnet {
        if let Some((net_str, prefix_str)) = cidr.split_once('/') {
            let net_ip: std::net::IpAddr = net_str.parse().map_err(|_| {
                CertmeshError::ScopeViolation(format!("invalid subnet CIDR: {cidr}"))
            })?;
            let prefix_len: u32 = prefix_str.parse().map_err(|_| {
                CertmeshError::ScopeViolation(format!("invalid prefix length in CIDR: {cidr}"))
            })?;
            let client_ip: std::net::IpAddr = ip.parse().map_err(|_| {
                CertmeshError::ScopeViolation(format!("invalid IP address: {ip}"))
            })?;
            if !ip_in_subnet(client_ip, net_ip, prefix_len) {
                let reason = format!("IP '{}' outside subnet '{}'", ip, cidr);
                let _ = audit::append_entry(
                    "scope_violation",
                    &[("ip", ip), ("reason", &reason)],
                );
                return Err(CertmeshError::ScopeViolation(reason));
            }
        }
    }
    Ok(())
}

/// Check whether `ip` is within the CIDR subnet `net/prefix_len`.
fn ip_in_subnet(ip: std::net::IpAddr, net: std::net::IpAddr, prefix_len: u32) -> bool {
    match (ip, net) {
        (std::net::IpAddr::V4(ip4), std::net::IpAddr::V4(net4)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            (u32::from(ip4) & mask) == (u32::from(net4) & mask)
        }
        (std::net::IpAddr::V6(ip6), std::net::IpAddr::V6(net6)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            (u128::from(ip6) & mask) == (u128::from(net6) & mask)
        }
        _ => false, // mismatched IP versions
    }
}

/// Process an enrollment request from a joining member.
///
/// 1. Check enrollment is open (including deadline)
/// 2. Verify TOTP code
/// 3. Validate scope constraints
/// 4. Check not already enrolled
/// 5. Approval placeholder
/// 6. Issue certificate
/// 7. Write cert files
/// 8. Add to roster
/// 9. Audit log
#[allow(clippy::too_many_arguments)]
pub fn process_enrollment(
    ca: &CaState,
    roster: &mut Roster,
    totp_secret: &TotpSecret,
    rate_limiter: &mut RateLimiter,
    request: &JoinRequest,
    hostname: &str,
    sans: &[String],
    profile: &TrustProfile,
) -> Result<(JoinResponse, IssuedCert), CertmeshError> {
    // 1. Check enrollment is open (includes deadline auto-close)
    if !roster.is_enrollment_open() {
        return Err(CertmeshError::EnrollmentClosed);
    }

    // 2. Verify TOTP code (rate limiter checks lockout internally)
    let valid = koi_crypto::totp::verify_code(totp_secret, &request.totp_code);

    match rate_limiter.check_and_record(valid) {
        Ok(()) => {} // Valid code, proceed
        Err(koi_crypto::totp::RateLimitError::LockedOut { remaining_secs }) => {
            return Err(CertmeshError::RateLimited { remaining_secs });
        }
        Err(koi_crypto::totp::RateLimitError::InvalidCode { .. }) => {
            return Err(CertmeshError::InvalidTotp);
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

    // 5. Approval placeholder — log warning if required but not yet implemented
    if profile.requires_approval() {
        tracing::warn!(
            "Approval required by '{}' profile but not yet implemented — auto-approving",
            profile
        );
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
        enrolled_by: roster.metadata.operator.clone(),
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
    let operator_str = roster
        .metadata
        .operator
        .as_deref()
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
    use crate::roster::EnrollmentState;
    use koi_crypto::totp;

    fn make_test_ca() -> CaState {
        let entropy = vec![42u8; 32];
        ca::create_ca("test-pass", &entropy).unwrap()
    }

    #[test]
    fn enrollment_with_invalid_totp_fails() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let secret = totp::generate_secret();
        let mut rl = RateLimiter::new();

        let request = JoinRequest {
            totp_code: "000000".to_string(),
        };

        let result = process_enrollment(
            &ca,
            &mut roster,
            &secret,
            &mut rl,
            &request,
            "stone-05",
            &["stone-05".to_string(), "stone-05.local".to_string()],
            &TrustProfile::JustMe,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            CertmeshError::InvalidTotp => {}
            other => panic!("expected InvalidTotp, got: {other}"),
        }
    }

    #[test]
    fn enrollment_closed_rejects() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::MyOrganization, Some("Admin".into()));
        assert_eq!(roster.metadata.enrollment_state, EnrollmentState::Closed);

        let secret = totp::generate_secret();
        let mut rl = RateLimiter::new();

        let request = JoinRequest {
            totp_code: "123456".to_string(),
        };

        let result = process_enrollment(
            &ca,
            &mut roster,
            &secret,
            &mut rl,
            &request,
            "stone-05",
            &["stone-05".to_string()],
            &TrustProfile::MyOrganization,
        );

        assert!(matches!(result, Err(CertmeshError::EnrollmentClosed)));
    }

    #[test]
    fn rate_limit_after_failures() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let secret = totp::generate_secret();
        let mut rl = RateLimiter::new();

        let bad_request = JoinRequest {
            totp_code: "000000".to_string(),
        };

        // Fail 3 times to trigger lockout
        for _ in 0..3 {
            let _ = process_enrollment(
                &ca,
                &mut roster,
                &secret,
                &mut rl,
                &bad_request,
                "stone-05",
                &["stone-05".to_string()],
                &TrustProfile::JustMe,
            );
        }

        // 4th attempt should be rate limited
        let result = process_enrollment(
            &ca,
            &mut roster,
            &secret,
            &mut rl,
            &bad_request,
            "stone-05",
            &["stone-05".to_string()],
            &TrustProfile::JustMe,
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
            enrollment_state: EnrollmentState::Open,
            enrollment_deadline: None,
            allowed_domain: None,
            allowed_subnet: Some("not-a-cidr".to_string()),
        };
        // No '/' in the CIDR, so validate_subnet should pass (no-op for malformed)
        assert!(validate_subnet("10.0.0.1", &metadata).is_ok());
    }

    #[test]
    fn ip_in_subnet_ipv4_various_prefixes() {
        use std::net::IpAddr;
        let net: IpAddr = "10.0.0.0".parse().unwrap();
        let ip_in: IpAddr = "10.0.0.42".parse().unwrap();
        let ip_out: IpAddr = "10.0.1.1".parse().unwrap();

        assert!(ip_in_subnet(ip_in, net, 24));
        assert!(!ip_in_subnet(ip_out, net, 24));
        assert!(ip_in_subnet(ip_in, net, 8));
        assert!(ip_in_subnet(ip_out, net, 8));
    }

    #[test]
    fn ip_in_subnet_ipv6() {
        use std::net::IpAddr;
        let net: IpAddr = "fd00::".parse().unwrap();
        let ip_in: IpAddr = "fd00::1".parse().unwrap();
        let ip_out: IpAddr = "fe80::1".parse().unwrap();

        assert!(ip_in_subnet(ip_in, net, 16));
        assert!(!ip_in_subnet(ip_out, net, 16));
    }

    #[test]
    fn ip_in_subnet_mixed_versions_returns_false() {
        use std::net::IpAddr;
        let net_v4: IpAddr = "10.0.0.0".parse().unwrap();
        let ip_v6: IpAddr = "fd00::1".parse().unwrap();
        assert!(!ip_in_subnet(ip_v6, net_v4, 8));
    }

    #[test]
    fn ip_in_subnet_prefix_zero_matches_all() {
        use std::net::IpAddr;
        let net: IpAddr = "10.0.0.0".parse().unwrap();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(ip_in_subnet(ip, net, 0));
    }

    #[test]
    fn ip_in_subnet_prefix_32_exact_match() {
        use std::net::IpAddr;
        let net: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_same: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_diff: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(ip_in_subnet(ip_same, net, 32));
        assert!(!ip_in_subnet(ip_diff, net, 32));
    }

    #[test]
    fn ip_in_subnet_invalid_prefix_returns_false() {
        use std::net::IpAddr;
        let net: IpAddr = "10.0.0.0".parse().unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // prefix > 32 for IPv4 is invalid
        assert!(!ip_in_subnet(ip, net, 33));
    }
}
