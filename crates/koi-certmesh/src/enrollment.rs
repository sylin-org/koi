//! Enrollment flow logic.
//!
//! Processes join requests: verifies auth (TOTP), issues certificate,
//! adds member to roster, writes cert files, appends audit log.

use chrono::Utc;
use koi_crypto::auth::{AuthChallenge, AuthState};
use koi_crypto::totp::RateLimiter;

use crate::audit;
use crate::ca::{self, CaState, IssuedCert};
use crate::certfiles;
use crate::error::CertmeshError;
use crate::protocol::{JoinRequest, JoinResponse};
use crate::roster::{MemberRole, MemberStatus, Roster, RosterMember};

/// Process an enrollment request from a joining member.
///
/// 1. Check enrollment is open
/// 2. Verify auth response (TOTP)
/// 3. Reject revoked members
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
    paths: &crate::CertmeshPaths,
) -> Result<(JoinResponse, IssuedCert), CertmeshError> {
    // 1. Check enrollment is open
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

    // 3. Reject revoked members
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
    let cert_dir = certfiles::write_cert_files_to(&paths.certs_dir().join(hostname), &issued)?;

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
    let _ = audit::append_entry_to(
        &paths.audit_log_path(),
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
    use koi_crypto::totp;

    // Posture booleans for the named presets (UX labels only).
    const JUST_ME: (bool, bool) = (true, false);
    const MY_ORG: (bool, bool) = (false, true);

    fn test_paths() -> crate::CertmeshPaths {
        crate::CertmeshPaths::with_data_dir(koi_common::test::ensure_data_dir(
            "koi-certmesh-enrollment-tests",
        ))
    }

    fn make_test_ca() -> CaState {
        ca::create_ca("test-pass", &[42u8; 32], &test_paths())
            .unwrap()
            .0
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
        let mut roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
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
            &test_paths(),
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
        let mut roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".into()));
        // My Organization starts closed; assert it so the test is explicit.
        roster.close_enrollment();
        assert!(!roster.is_enrollment_open());

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
            &test_paths(),
        );

        assert!(matches!(result, Err(CertmeshError::EnrollmentClosed)));
    }

    #[test]
    fn rate_limit_after_failures() {
        let ca = make_test_ca();
        let mut roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
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
                &test_paths(),
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
            &test_paths(),
        );

        assert!(matches!(result, Err(CertmeshError::RateLimited { .. })));
    }
}
