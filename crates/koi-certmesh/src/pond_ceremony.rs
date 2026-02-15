//! Pond ceremony rules — the domain-specific bag→prompts logic
//! for certmesh ceremonies (init, join, invite, unlock).
//!
//! These rules implement [`CeremonyRules`] from koi-common. They
//! inspect the session bag and return prompts, messages, or completion.
//! The actual CA/roster/enrollment operations are triggered by the
//! HTTP handler after receiving [`EvalResult::Complete`].

use koi_common::ceremony::{
    CeremonyRules, EvalResult, Message, Prompt, RenderHints, SelectOption,
};
use koi_common::encoding::{hex_decode, hex_encode};

use crate::profiles::TrustProfile;

// ── Pond rules ──────────────────────────────────────────────────────

/// Ceremony rules for pond operations.
///
/// Stateless — all state lives in the session bag. The host (and the
/// HTTP handler above it) hold the `CertmeshCore` needed to execute
/// the terminal action.
pub struct PondCeremonyRules;

impl CeremonyRules for PondCeremonyRules {
    fn validate_ceremony_type(&self, ceremony: &str) -> Result<(), String> {
        match ceremony {
            "init" | "join" | "invite" | "unlock" => Ok(()),
            other => Err(format!("unknown pond ceremony: {other}")),
        }
    }

    fn evaluate(
        &self,
        ceremony_type: &str,
        bag: &mut serde_json::Map<String, serde_json::Value>,
        render: &RenderHints,
    ) -> EvalResult {
        match ceremony_type {
            "init" => eval_init(bag, render),
            "join" => eval_join(bag, render),
            "invite" => eval_invite(bag, render),
            "unlock" => eval_unlock(bag, render),
            _ => EvalResult::Fatal(format!("unhandled ceremony: {ceremony_type}")),
        }
    }
}

// ── Init ceremony ───────────────────────────────────────────────────
//
// Required bag keys (in priority order):
//   profile       – "just_me" | "my_team" | "my_organization"
//   passphrase    – string, min 8 chars
//   entropy       – raw text from user (keyboard mashing, etc.)
//   auth_mode     – "totp" (fido2 future)
//   verification_code – 6-digit TOTP code (only when auth_mode=totp)
//
// Internal bag keys (underscore prefix, set by rules, never prompted):
//   _totp_secret_hex – hex-encoded TOTP secret bytes
//   _totp_uri        – otpauth:// URI
//   _server_entropy  – hex-encoded 32 bytes of server entropy
//   _entropy_seed    – hex-encoded 32-byte final seed (server ⊕ client)

fn eval_init(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    render: &RenderHints,
) -> EvalResult {
    // ── 1. Profile ──────────────────────────────────────────────────
    let profile = match bag.get("profile").and_then(|v| v.as_str()).map(String::from) {
        None => {
            return EvalResult::NeedInput {
                prompts: vec![Prompt::select_one(
                    "profile",
                    "Select a trust profile for your pond",
                    vec![
                        SelectOption::with_description(
                            "just_me",
                            "Just Me",
                            "Single admin, personal garden. No approval needed.",
                        ),
                        SelectOption::with_description(
                            "my_team",
                            "My Team",
                            "Small group with shared trust. Enrollment requires approval.",
                        ),
                        SelectOption::with_description(
                            "my_organization",
                            "My Organization",
                            "Structured admin. Enrollment closed by default, operator required.",
                        ),
                    ],
                )],
                messages: vec![Message::info(
                    "Initialize Pond",
                    "A pond is a private certificate authority for your garden. \
                     Choose a trust profile that matches how you'll use it.",
                )],
            };
        }
        Some(p) => {
            // Validate the profile value
            if TrustProfile::from_str_loose(&p).is_none() {
                bag.remove("profile");
                return EvalResult::ValidationError {
                    prompts: vec![profile_prompt()],
                    messages: Vec::new(),
                    error: format!(
                        "Unknown profile: '{p}'. Choose just_me, my_team, or my_organization."
                    ),
                };
            }
            p
        }
    };

    // ── 2. Passphrase ───────────────────────────────────────────────
    match bag.get("passphrase").and_then(|v| v.as_str()) {
        None => {
            return EvalResult::NeedInput {
                prompts: vec![Prompt::secret_confirm(
                    "passphrase",
                    "Choose a passphrase to protect the pond keystone",
                )],
                messages: vec![Message::info(
                    "Passphrase",
                    "This passphrase encrypts the CA private key. You'll need it to \
                     unlock the pond after a restart. Minimum 8 characters.",
                )],
            };
        }
        Some(pp) => {
            if pp.len() < 8 {
                bag.remove("passphrase");
                return EvalResult::ValidationError {
                    prompts: vec![Prompt::secret_confirm(
                        "passphrase",
                        "Choose a passphrase to protect the pond keystone",
                    )],
                    messages: Vec::new(),
                    error: "Passphrase must be at least 8 characters.".into(),
                };
            }
        }
    }

    // ── 3. Entropy ──────────────────────────────────────────────────
    if !bag.contains_key("entropy") {
        // Generate server-side entropy contribution (transparent to user)
        let server_entropy = generate_server_entropy_hex();
        bag.insert(
            "_server_entropy".into(),
            serde_json::Value::String(server_entropy),
        );

        return EvalResult::NeedInput {
            prompts: vec![Prompt::entropy(
                "entropy",
                "Contribute additional entropy for key generation",
            )],
            messages: vec![Message::info(
                "Entropy Collection",
                "Type random characters, move your mouse, or paste random text. \
                 This is mixed with server-generated randomness for defense in depth.",
            )],
        };
    }

    // Combine server + client entropy if not already done
    if !bag.contains_key("_entropy_seed") {
        let client_entropy = bag
            .get("entropy")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let server_entropy = bag
            .get("_server_entropy")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let seed = combine_entropy(server_entropy, client_entropy);
        bag.insert(
            "_entropy_seed".into(),
            serde_json::Value::String(hex_encode(&seed)),
        );
    }

    // ── 4. Auth mode ────────────────────────────────────────────────
    let auth_mode = match bag.get("auth_mode").and_then(|v| v.as_str()).map(String::from) {
        None => {
            return EvalResult::NeedInput {
                prompts: vec![Prompt::select_one(
                    "auth_mode",
                    "Choose how stones will authenticate when joining the pond",
                    vec![
                        SelectOption::with_description(
                            "totp",
                            "TOTP (Authenticator App)",
                            "6-digit codes from any TOTP-compatible app \
                             (Google Authenticator, Authy, etc.)",
                        ),
                        // FIDO2 future:
                        // SelectOption::with_description(
                        //     "fido2",
                        //     "FIDO2 (Hardware Key)",
                        //     "WebAuthn hardware security key (YubiKey, etc.)",
                        // ),
                    ],
                )],
                messages: Vec::new(),
            };
        }
        Some(mode) => {
            if mode != "totp" {
                bag.remove("auth_mode");
                return EvalResult::ValidationError {
                    prompts: vec![Prompt::select_one(
                        "auth_mode",
                        "Choose how stones will authenticate when joining the pond",
                        vec![SelectOption::new("totp", "TOTP (Authenticator App)")],
                    )],
                    messages: Vec::new(),
                    error: format!(
                        "Unsupported auth mode: '{mode}'. Currently only TOTP is supported."
                    ),
                };
            }
            mode
        }
    };

    // ── 5. TOTP setup + verification ────────────────────────────────
    if auth_mode == "totp" {
        // Generate TOTP secret if not yet done
        if !bag.contains_key("_totp_secret_hex") {
            let secret = koi_crypto::totp::generate_secret();
            let secret_hex = hex_encode(secret.as_bytes());

            let account = bag
                .get("_self_hostname")
                .and_then(|v| v.as_str())
                .unwrap_or("pond");
            let uri = koi_crypto::totp::build_totp_uri(&secret, "ZenGarden", account);

            bag.insert(
                "_totp_secret_hex".into(),
                serde_json::Value::String(secret_hex),
            );
            bag.insert(
                "_totp_uri".into(),
                serde_json::Value::String(uri),
            );
        }

        // Need verification code
        if !bag.contains_key("verification_code") {
            let uri = bag["_totp_uri"].as_str().unwrap_or("");
            let qr_content = render_qr(uri, render);

            return EvalResult::NeedInput {
                prompts: vec![Prompt::code(
                    "verification_code",
                    "Enter the 6-digit code from your authenticator app",
                )],
                messages: vec![Message::qr_code(
                    "Scan this QR code with your authenticator app",
                    &qr_content,
                )],
            };
        }

        // Validate verification code
        let code = bag
            .get("verification_code")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let secret_hex = bag
            .get("_totp_secret_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let valid = if let Ok(secret_bytes) = hex_decode(secret_hex) {
            let secret = koi_crypto::totp::TotpSecret::from_bytes(secret_bytes);
            koi_crypto::totp::verify_code(&secret, code)
        } else {
            false
        };

        if !valid {
            bag.remove("verification_code");
            let uri = bag.get("_totp_uri").and_then(|v| v.as_str()).unwrap_or("");
            let qr_content = render_qr(uri, render);

            return EvalResult::ValidationError {
                prompts: vec![Prompt::code(
                    "verification_code",
                    "Enter the 6-digit code from your authenticator app",
                )],
                messages: vec![Message::qr_code(
                    "Scan this QR code with your authenticator app",
                    &qr_content,
                )],
                error: "Invalid verification code. Check your authenticator app and try again."
                    .into(),
            };
        }
    }

    // ── All data collected — ceremony is complete ────────────────────
    //
    // The actual CA creation, self-enrollment, trust store install, etc.
    // is executed by the HTTP handler after receiving Complete.
    // The bag contains everything needed: profile, passphrase,
    // _entropy_seed, auth_mode, _totp_secret_hex.

    let summary = format!(
        "Profile: {profile}\nAuth mode: {auth_mode}\n\
         The pond will be created with these settings.",
    );

    EvalResult::Complete {
        messages: vec![Message::summary("Pond initialization ready", &summary)],
    }
}

// ── Join ceremony ───────────────────────────────────────────────────
//
// Required: join_code (from invite), plus verification_code (TOTP).

fn eval_join(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    _render: &RenderHints,
) -> EvalResult {
    if !bag.contains_key("join_code") {
        return EvalResult::NeedInput {
            prompts: vec![Prompt::code(
                "join_code",
                "Enter the join code from your invitation",
            )],
            messages: vec![Message::info(
                "Join Pond",
                "Enter the join code you received from the pond administrator.",
            )],
        };
    }

    if !bag.contains_key("verification_code") {
        return EvalResult::NeedInput {
            prompts: vec![Prompt::code(
                "verification_code",
                "Enter the 6-digit code from your authenticator app",
            )],
            messages: Vec::new(),
        };
    }

    // Validation of join_code + verification_code is done by the
    // HTTP handler via enrollment::process_enrollment.

    EvalResult::Complete {
        messages: vec![Message::summary(
            "Join ready",
            "Your stone will be enrolled in the pond.",
        )],
    }
}

// ── Invite ceremony ─────────────────────────────────────────────────
//
// Requires: passphrase (to prove admin authority).

fn eval_invite(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    _render: &RenderHints,
) -> EvalResult {
    if !bag.contains_key("passphrase") {
        return EvalResult::NeedInput {
            prompts: vec![Prompt::secret(
                "passphrase",
                "Enter the pond passphrase to generate an invitation",
            )],
            messages: vec![Message::info(
                "Create Invitation",
                "You'll need the pond passphrase to prove administrator authority.",
            )],
        };
    }

    // Passphrase verification and invite code generation done by HTTP handler.
    EvalResult::Complete {
        messages: vec![Message::summary(
            "Invitation ready",
            "The HTTP handler will generate the join code and QR.",
        )],
    }
}

// ── Unlock ceremony ─────────────────────────────────────────────────
//
// Requires: passphrase (to decrypt CA key).

fn eval_unlock(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    _render: &RenderHints,
) -> EvalResult {
    if !bag.contains_key("passphrase") {
        return EvalResult::NeedInput {
            prompts: vec![Prompt::secret(
                "passphrase",
                "Enter the pond passphrase to unlock",
            )],
            messages: vec![Message::info(
                "Unlock Pond",
                "The pond CA is locked. Enter the passphrase to decrypt the CA key \
                 and resume operations.",
            )],
        };
    }

    // Passphrase validation and CA unlock done by HTTP handler.
    EvalResult::Complete {
        messages: vec![Message::summary(
            "Unlock ready",
            "The HTTP handler will attempt to decrypt the CA key.",
        )],
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn profile_prompt() -> Prompt {
    Prompt::select_one(
        "profile",
        "Select a trust profile for your pond",
        vec![
            SelectOption::with_description(
                "just_me",
                "Just Me",
                "Single admin, personal garden.",
            ),
            SelectOption::with_description(
                "my_team",
                "My Team",
                "Small group with shared trust.",
            ),
            SelectOption::with_description(
                "my_organization",
                "My Organization",
                "Structured admin, operator required.",
            ),
        ],
    )
}

/// Generate 32 bytes of server-side entropy, hex-encoded.
fn generate_server_entropy_hex() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    hex_encode(&buf)
}

/// Combine server and client entropy into a 32-byte seed via SHA-256.
fn combine_entropy(server_hex: &str, client_raw: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(server_hex.as_bytes());
    hasher.update(client_raw.as_bytes());
    hasher.finalize().into()
}

/// Render a QR code based on the client's render hints.
fn render_qr(payload: &str, render: &RenderHints) -> String {
    use koi_common::ceremony::QrFormat;

    match render.qr.unwrap_or_default() {
        QrFormat::PngBase64 => koi_crypto::totp::qr_code_png_base64_raw(payload),
        QrFormat::Utf8 => koi_crypto::totp::qr_code_unicode_raw(payload),
        QrFormat::UriOnly => payload.to_string(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::ceremony::{CeremonyHost, CeremonyRequest, InputType};

    fn make_host() -> CeremonyHost<PondCeremonyRules> {
        CeremonyHost::new(PondCeremonyRules)
    }

    #[test]
    fn init_starts_with_profile_prompt() {
        let host = make_host();
        let resp = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();

        assert!(!resp.complete);
        assert_eq!(resp.prompts.len(), 1);
        assert_eq!(resp.prompts[0].key, "profile");
        assert_eq!(resp.prompts[0].input_type, InputType::SelectOne);
        assert_eq!(resp.prompts[0].options.len(), 3);
    }

    #[test]
    fn init_profile_then_passphrase() {
        let host = make_host();

        // Start
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();

        // Submit profile
        let mut data = serde_json::Map::new();
        data.insert("profile".into(), serde_json::json!("just_me"));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();

        assert!(!r2.complete);
        assert_eq!(r2.prompts[0].key, "passphrase");
        assert_eq!(r2.prompts[0].input_type, InputType::SecretConfirm);
    }

    #[test]
    fn init_rejects_short_passphrase() {
        let host = make_host();

        // Start with profile already set
        let mut data = serde_json::Map::new();
        data.insert("profile".into(), serde_json::json!("just_me"));
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data,
                render: None,
            })
            .unwrap();

        // Submit short passphrase
        let mut data = serde_json::Map::new();
        data.insert("passphrase".into(), serde_json::json!("short"));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();

        assert!(!r2.complete);
        assert!(r2.error.is_some());
        assert!(r2.error.as_deref().unwrap().contains("8 characters"));
        assert_eq!(r2.prompts[0].key, "passphrase");
    }

    #[test]
    fn init_invalid_profile_reprompts() {
        let host = make_host();

        let mut data = serde_json::Map::new();
        data.insert("profile".into(), serde_json::json!("nonsense"));
        let resp = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data,
                render: None,
            })
            .unwrap();

        assert!(!resp.complete);
        assert!(resp.error.is_some());
        assert_eq!(resp.prompts[0].key, "profile");
    }

    #[test]
    fn unlock_collects_passphrase_then_completes() {
        let host = make_host();

        // Start unlock
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("unlock".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();

        assert!(!r1.complete);
        assert_eq!(r1.prompts[0].key, "passphrase");

        // Submit passphrase
        let mut data = serde_json::Map::new();
        data.insert("passphrase".into(), serde_json::json!("my_secret_pass"));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();

        assert!(r2.complete);
    }

    #[test]
    fn join_collects_code_then_verification() {
        let host = make_host();

        // Start join
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("join".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();
        assert_eq!(r1.prompts[0].key, "join_code");

        // Submit join code
        let mut data = serde_json::Map::new();
        data.insert("join_code".into(), serde_json::json!("ABC123"));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();
        assert_eq!(r2.prompts[0].key, "verification_code");

        // Submit verification code
        let mut data = serde_json::Map::new();
        data.insert("verification_code".into(), serde_json::json!("123456"));
        let r3 = host
            .step(CeremonyRequest {
                session_id: Some(r2.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();
        assert!(r3.complete);
    }

    #[test]
    fn unknown_ceremony_rejected() {
        let host = make_host();
        let err = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("bogus".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap_err();

        assert!(matches!(
            err,
            koi_common::ceremony::CeremonyError::InvalidCeremony(_)
        ));
    }
}
