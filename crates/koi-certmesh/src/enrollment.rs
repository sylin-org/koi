//! Enrollment flow logic.
//!
//! Processes join requests: verifies auth (TOTP), issues certificate,
//! adds member to roster, writes cert files, appends audit log.

use chrono::{Duration, Utc};
use koi_crypto::auth::{AuthChallenge, AuthState};
use koi_crypto::totp::RateLimiter;

use crate::audit;
use crate::ca::{self, CaState, IssuedCert};
use crate::error::CertmeshError;
use crate::protocol::{JoinRequest, JoinResponse};
use crate::roster::{MemberRole, MemberStatus, Roster, RosterMember};

/// Process an enrollment request from a joining member.
///
/// 1. Check enrollment is open
/// 2. Verify the join credential (invite token OR TOTP)
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
    auth_state: Option<&AuthState>,
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

    // 2. Verify the join credential. Two mutually exclusive paths (ADR-015 F2):
    //
    //    - invite_token: per-host, single-use, hostname-bound — the automatable
    //      path. The token IS the credential; it does not depend on the
    //      enrollment auth credential being loaded in memory. Single-use is
    //      enforced by burning the token on a successful match.
    //    - auth (TOTP): the interactive mesh-wide enrollment secret, rate-limited.
    //
    // The posture booleans (`enrollment_open` above, `requires_approval` at
    // step 5) gate both paths identically — the invite only swaps the credential.
    if let Some(token) = request.invite_token.as_deref() {
        if !crate::invite::verify_and_consume(&paths.invites_path(), token, hostname) {
            return Err(CertmeshError::InvalidAuth);
        }
    } else {
        let auth = request.auth.as_ref().ok_or(CertmeshError::InvalidAuth)?;
        let auth_state = auth_state.ok_or(CertmeshError::CaLocked)?;
        let adapter = koi_crypto::auth::adapter_for(auth_state);
        let valid = adapter.verify(auth_state, challenge, auth).unwrap_or(false);

        match rate_limiter.check_and_record(valid) {
            Ok(()) => {} // Valid, proceed
            Err(koi_crypto::totp::RateLimitError::LockedOut { remaining_secs }) => {
                return Err(CertmeshError::RateLimited { remaining_secs });
            }
            Err(koi_crypto::totp::RateLimitError::InvalidCode { .. }) => {
                return Err(CertmeshError::InvalidAuth);
            }
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

    // 6. Sign the member's CSR (ADR-015 F1). The member generated its own keypair
    //    and sent ONLY this CSR; the CA signs a leaf and never sees the private
    //    key. Remote enrollment REQUIRES a CSR — the CA refuses to generate and
    //    ship member keys (the key-custody fault this fixes).
    let csr_pem = request.csr.as_deref().ok_or_else(|| {
        CertmeshError::InvalidPayload(
            "a CSR is required to enroll; the CA does not generate member keys".to_string(),
        )
    })?;
    // Leaf lifetime is the CA-held policy (ADR-017), not a hardcoded constant.
    let lifetime_days = roster.metadata.policy.leaf_lifetime_days;
    let leaf_pem = crate::csr::sign_csr(ca, csr_pem, sans, lifetime_days)?;

    // Fingerprint + expiry derived from the issued leaf. The member persists its
    // own cert files locally; the CA records membership only (no cert_path here).
    let leaf_der = pem::parse(&leaf_pem)
        .map_err(|e| CertmeshError::Certificate(format!("issued leaf parse: {e}")))?;
    let fingerprint = koi_crypto::pinning::fingerprint_sha256(leaf_der.contents());
    let expires = Utc::now() + Duration::days(i64::from(lifetime_days));

    // 7. Add to roster (cert_path empty — the member holds the files, not the CA).
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
        cert_fingerprint: fingerprint.clone(),
        cert_expires: expires,
        cert_sans: sans.to_vec(),
        cert_path: String::new(),
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
            ("fingerprint", &fingerprint),
            ("role", role_str),
            ("approved_by", operator_str),
        ],
    );

    let ca_fingerprint = ca::ca_fingerprint(ca);
    let ca_pem = ca.cert_pem.clone();
    let fullchain_pem = format!("{leaf_pem}{ca_pem}");

    let response = JoinResponse {
        hostname: hostname.to_string(),
        ca_cert: ca_pem.clone(),
        service_cert: leaf_pem.clone(),
        // CSR flow: the CA has no member key to return — the member kept it.
        service_key: String::new(),
        ca_fingerprint,
        cert_path: String::new(),
        // The member persists this to drive its pull-renewal loop (ADR-017 F6).
        policy: roster.metadata.policy.clone(),
    };

    let issued = IssuedCert {
        cert_pem: leaf_pem,
        key_pem: String::new(),
        ca_pem,
        fullchain_pem,
        fingerprint,
        expires,
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

    /// A per-test data dir so invite-store / cert-file state never races with
    /// other parallel tests sharing the suite-wide `test_paths()`.
    fn unique_test_paths(name: &str) -> crate::CertmeshPaths {
        crate::CertmeshPaths::with_data_dir(
            koi_common::test::ensure_data_dir("koi-certmesh-enrollment-tests").join(name),
        )
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
            auth: Some(bad_response),
            invite_token: None,
            csr: None,
            sans: vec![],
        };

        let result = process_enrollment(
            &ca,
            &mut roster,
            Some(&auth_state),
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
            auth: Some(koi_crypto::auth::AuthResponse::Totp {
                code: "123456".to_string(),
            }),
            invite_token: None,
            csr: None,
            sans: vec![],
        };

        let result = process_enrollment(
            &ca,
            &mut roster,
            Some(&auth_state),
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
            auth: Some(koi_crypto::auth::AuthResponse::Totp {
                code: "000000".to_string(),
            }),
            invite_token: None,
            csr: None,
            sans: vec![],
        };

        // Fail 3 times to trigger lockout
        for _ in 0..3 {
            let _ = process_enrollment(
                &ca,
                &mut roster,
                Some(&auth_state),
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
            Some(&auth_state),
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

    #[test]
    fn enrollment_with_invite_token_succeeds() {
        let paths = unique_test_paths("invite-ok");
        let ca = make_test_ca();
        let mut roster = Roster::new(JUST_ME.0, JUST_ME.1, None); // enrollment open
        let mut rl = RateLimiter::new();

        // Mint an invite bound to the joining hostname. No TOTP auth is supplied
        // (auth_state = None) — the invite is the sole credential. The joiner also
        // supplies its own CSR (ADR-015 F1); the CA never generates the key.
        let token = crate::invite::mint(&paths.invites_path(), "stone-invited", 60)
            .unwrap()
            .token;
        let (_key_pem, csr_pem) =
            crate::csr::generate_keypair_and_csr("stone-invited", &["stone-invited".to_string()])
                .unwrap();
        let request = JoinRequest {
            hostname: "stone-invited".to_string(),
            auth: None,
            invite_token: Some(token.clone()),
            csr: Some(csr_pem),
            sans: vec![],
        };

        let result = process_enrollment(
            &ca,
            &mut roster,
            None,
            &AuthChallenge::Totp,
            &mut rl,
            &request,
            "stone-invited",
            &["stone-invited".to_string()],
            None,
            &paths,
        );
        let (resp, issued) = result.expect("invite enrollment should succeed");
        assert!(
            resp.service_key.is_empty(),
            "CSR flow: the CA must NOT return a member private key"
        );
        assert!(resp.service_cert.contains("BEGIN CERTIFICATE"));
        // Leaf lifetime comes from the CA-held policy default (90 days, ADR-017).
        let days = (issued.expires - Utc::now()).num_days();
        assert!(
            (89..=90).contains(&days),
            "expected ~90-day leaf, got {days}"
        );

        // Single-use: the now-spent token is rejected on a second attempt.
        let mut roster2 = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let request2 = JoinRequest {
            hostname: "stone-invited".to_string(),
            auth: None,
            invite_token: Some(token),
            csr: None,
            sans: vec![],
        };
        let result2 = process_enrollment(
            &ca,
            &mut roster2,
            None,
            &AuthChallenge::Totp,
            &mut rl,
            &request2,
            "stone-invited",
            &["stone-invited".to_string()],
            None,
            &paths,
        );
        assert!(
            matches!(result2, Err(CertmeshError::InvalidAuth)),
            "spent invite token must be rejected, got: {result2:?}"
        );
    }

    #[test]
    fn enrollment_without_csr_is_rejected() {
        // Even with a valid credential, the CA refuses to enroll without a CSR —
        // it never generates member keys server-side (ADR-015 F1).
        let paths = unique_test_paths("no-csr");
        let ca = make_test_ca();
        let mut roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let mut rl = RateLimiter::new();

        let token = crate::invite::mint(&paths.invites_path(), "no-csr-host", 60)
            .unwrap()
            .token;
        let request = JoinRequest {
            hostname: "no-csr-host".to_string(),
            auth: None,
            invite_token: Some(token),
            csr: None, // no CSR supplied
            sans: vec![],
        };
        let result = process_enrollment(
            &ca,
            &mut roster,
            None,
            &AuthChallenge::Totp,
            &mut rl,
            &request,
            "no-csr-host",
            &["no-csr-host".to_string()],
            None,
            &paths,
        );
        assert!(
            matches!(result, Err(CertmeshError::InvalidPayload(_))),
            "enrollment without a CSR must be rejected, got: {result:?}"
        );
    }
}
