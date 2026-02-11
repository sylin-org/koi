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
use crate::roster::{
    EnrollmentState, MemberRole, MemberStatus, Roster, RosterMember,
};

/// Process an enrollment request from a joining member.
///
/// 1. Check enrollment is open
/// 2. Check rate limit
/// 3. Verify TOTP code
/// 4. Check not already enrolled
/// 5. Issue certificate
/// 6. Write cert files
/// 7. Add to roster
/// 8. Audit log
#[allow(clippy::too_many_arguments)]
pub fn process_enrollment(
    ca: &CaState,
    roster: &mut Roster,
    totp_secret: &TotpSecret,
    rate_limiter: &mut RateLimiter,
    request: &JoinRequest,
    hostname: &str,
    sans: &[String],
    _profile: &TrustProfile,
) -> Result<(JoinResponse, IssuedCert), CertmeshError> {
    // 1. Check enrollment is open
    if roster.metadata.enrollment_state != EnrollmentState::Open {
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

    // 4. Check not already enrolled
    if roster.is_enrolled(hostname) {
        return Err(CertmeshError::AlreadyEnrolled(hostname.to_string()));
    }

    // 5. Issue certificate
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
    };
    roster.members.push(member);

    // 8. Audit log
    let _ = audit::append_entry(
        "member_joined",
        &[
            ("hostname", hostname),
            ("fingerprint", &issued.fingerprint),
            ("role", role_str),
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
}
