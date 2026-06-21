//! Certmesh init-ceremony rules - the domain-specific bag→prompts logic
//! for certmesh ceremonies (init, join, invite, unlock).
//!
//! These rules implement [`CeremonyRules`] from koi-common. They
//! inspect the session bag and return prompts, messages, or completion.
//! The actual CA/roster/enrollment operations are triggered by the
//! caller (HTTP handler or CLI) after receiving [`EvalResult::Complete`].
//!
//! # Init ceremony bag keys
//!
//! **User-facing** (prompted):
//!   - `profile`              – "just_me" | "my_team" | "my_organization" | "custom"
//!   - `enrollment_open`      – "open" | "closed"   (only if profile=custom)
//!   - `requires_approval`    – "yes" | "no"         (only if profile=custom)
//!   - `operator`             – string               (when approval required)
//!   - `entropy`              – raw user input (keyboard mashing) for key-gen entropy
//!   - `passphrase_choice`    – "keep" | "again" | "own" (after seeing suggestion)
//!   - `passphrase`           – string, min 8 chars (set from suggestion or manual)
//!   - `auto_unlock`           – "auto" | "token" | "passphrase" (only if profile=custom)
//!   - `auth_mode`            – "totp"
//!   - `verification_code`    – 6-digit TOTP code
//!   - `unlock_token_type`    - "totp" (only if unlock_method=token)
//!   - `unlock_totp_code`     - 6-digit code to verify unlock TOTP registration
//!
//! **Internal** (underscore prefix, set by rules):
//!   - `_effective_profile`   – preset display label after custom→baseline mapping
//!   - `_enrollment_open`     – bool (effective enrollment state)
//!   - `_requires_approval`   – bool (effective approval state)
//!   - `_auto_unlock`         – bool (auto-unlock CA on boot - derived from _unlock_method)
//!   - `_unlock_method`       – "auto" | "token" | "passphrase"
//!   - `_unlock_totp_secret`  – hex-encoded TOTP secret for unlock slot
//!   - `_unlock_totp_uri`     – otpauth:// URI for unlock TOTP QR
//!   - `_server_entropy`      – hex-encoded 32 bytes of server entropy
//!   - `_entropy_seed`        – hex-encoded 32-byte final seed
//!   - `_suggested_passphrase`– XKCD-style passphrase derived from entropy
//!   - `_totp_secret_hex`     – hex-encoded TOTP secret bytes
//!   - `_totp_uri`            – otpauth:// URI

use koi_common::ceremony::{CeremonyRules, EvalResult, Message, Prompt, RenderHints, SelectOption};
use koi_common::encoding::{hex_decode, hex_encode};

use crate::profiles::preset_bools;

// ── Certmesh ceremony rules ─────────────────────────────────────────

/// Ceremony rules for certmesh operations (init, join, invite, unlock).
///
/// Session state lives in the bag; the only instance state is the resolved
/// data `paths`, injected once at the composition root (the CLI entry) so the
/// unlock ceremony reads the slot table from the right place with no ambient
/// default. The host (and the HTTP handler above it) hold the `CertmeshCore`
/// needed to execute the terminal action.
pub struct InitCeremonyRules {
    paths: crate::CertmeshPaths,
}

impl InitCeremonyRules {
    /// Construct the rules with the resolved data paths.
    pub fn new(paths: crate::CertmeshPaths) -> Self {
        Self { paths }
    }
}

impl CeremonyRules for InitCeremonyRules {
    fn validate_ceremony_type(&self, ceremony: &str) -> Result<(), String> {
        match ceremony {
            "init" | "join" | "invite" | "unlock" => Ok(()),
            other => Err(format!("unknown certmesh ceremony: {other}")),
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
            "unlock" => eval_unlock(bag, render, &self.paths),
            _ => EvalResult::Fatal(format!("unhandled ceremony: {ceremony_type}")),
        }
    }
}

// ── Init ceremony ───────────────────────────────────────────────────

fn eval_init(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    render: &RenderHints,
) -> EvalResult {
    // Each step helper returns `Some(result)` to stop the flow (need input,
    // validation error, or a recursive restart) or `None` when the step is
    // satisfied and the flow should continue. The final summary step is the
    // only one that returns a terminal `EvalResult` directly. The observable
    // prompt sequence is identical to the original monolithic evaluator.
    if let Some(r) = eval_init_profile(bag) {
        return r;
    }
    if let Some(r) = eval_init_operator(bag) {
        return r;
    }
    if let Some(r) = eval_init_entropy(bag) {
        return r;
    }
    if let Some(r) = eval_init_passphrase(bag, render) {
        return r;
    }
    if let Some(r) = eval_init_unlock_method(bag) {
        return r;
    }
    let auth_mode = match eval_init_auth_mode(bag) {
        Ok(mode) => mode,
        Err(r) => return r,
    };
    if let Some(r) = eval_init_totp(bag, render, &auth_mode) {
        return r;
    }
    if let Some(r) = eval_init_token(bag, render) {
        return r;
    }
    eval_init_summary(bag, &auth_mode)
}

/// Step 1: trust-profile / posture selection.
///
/// Resolves `profile` (preset or `custom`) into the effective posture booleans
/// (`_enrollment_open`, `_requires_approval`, `_effective_profile`, and — for
/// presets — `_unlock_method` / `_auto_unlock`). Custom profiles ask the
/// enrollment and approval sub-prompts first.
fn eval_init_profile(bag: &mut serde_json::Map<String, serde_json::Value>) -> Option<EvalResult> {
    let profile_raw = match bag
        .get("profile")
        .and_then(|v| v.as_str())
        .map(String::from)
    {
        None => {
            return Some(EvalResult::NeedInput {
                prompts: vec![Prompt::select_one(
                    "profile",
                    "Who is this certificate authority for?",
                    vec![
                        SelectOption::with_description(
                            "just_me",
                            "Just me",
                            "You control every machine on the network. \
                             Anyone with the authenticator code can join.",
                        ),
                        SelectOption::with_description(
                            "my_team",
                            "My team",
                            "A small group. An operator name is recorded \
                             in the audit log for accountability.",
                        ),
                        SelectOption::with_description(
                            "my_organization",
                            "My organization",
                            "Strict access control. Enrollment starts \
                             closed - each machine must be approved.",
                        ),
                        SelectOption::with_description(
                            "custom",
                            "Custom",
                            "Choose each policy individually.",
                        ),
                    ],
                )],
                messages: vec![Message::info(
                    "Initialize Certificate Authority",
                    "This is a private certificate authority for your network. \
                     Choose a trust profile that matches how you'll use it.",
                )],
            });
        }
        Some(p) => p,
    };

    if profile_raw == "custom" {
        eval_init_custom_posture(bag)
    } else {
        eval_init_preset_posture(bag, &profile_raw)
    }
}

/// Step 1a: custom-profile enrollment + approval sub-prompts → posture bools.
fn eval_init_custom_posture(
    bag: &mut serde_json::Map<String, serde_json::Value>,
) -> Option<EvalResult> {
    if !bag.contains_key("enrollment_open") {
        return Some(EvalResult::NeedInput {
            prompts: vec![Prompt::select_one(
                "enrollment_open",
                "Enrollment when the CA is created",
                vec![
                    SelectOption::with_description(
                        "open",
                        "Open (default)",
                        "Any machine with a valid TOTP code can join immediately. \
                         You can close enrollment later.",
                    ),
                    SelectOption::with_description(
                        "closed",
                        "Closed",
                        "Machines cannot join until you explicitly open enrollment.",
                    ),
                ],
            )],
            messages: Vec::new(),
        });
    }

    if !bag.contains_key("requires_approval") {
        return Some(EvalResult::NeedInput {
            prompts: vec![Prompt::select_one(
                "requires_approval",
                "Require approval for each join request?",
                vec![
                    SelectOption::with_description(
                        "no",
                        "No (default)",
                        "TOTP code is sufficient. Machine joins immediately after verification.",
                    ),
                    SelectOption::with_description(
                        "yes",
                        "Yes",
                        "After TOTP verification, an operator must approve \
                         the request before a certificate is issued.",
                    ),
                ],
            )],
            messages: Vec::new(),
        });
    }

    let enroll_open = bag
        .get("enrollment_open")
        .and_then(|v| v.as_str())
        .unwrap_or("open")
        == "open";
    let approval = bag
        .get("requires_approval")
        .and_then(|v| v.as_str())
        .unwrap_or("no")
        == "yes";

    // Label the resulting posture with the nearest preset name (display only).
    let baseline_label = match (enroll_open, approval) {
        (true, false) => "Just Me",
        (true, true) => "My Team",
        (false, true) => "My Organization",
        (false, false) => "Just Me",
    };

    bag.insert(
        "_effective_profile".into(),
        serde_json::json!(baseline_label),
    );
    bag.insert("_enrollment_open".into(), serde_json::json!(enroll_open));
    bag.insert("_requires_approval".into(), serde_json::json!(approval));
    // Custom profiles get auto_unlock from a separate prompt (eval_init_unlock_method).
    None
}

/// Step 1a': standard-preset posture resolution.
fn eval_init_preset_posture(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    profile_raw: &str,
) -> Option<EvalResult> {
    let (enroll_open, approval, auto_unlock) = match preset_bools(profile_raw) {
        Some(bools) => bools,
        None => {
            bag.remove("profile");
            return Some(EvalResult::ValidationError {
                prompts: vec![profile_prompt()],
                messages: Vec::new(),
                error: format!(
                    "Unknown profile: '{profile_raw}'. \
                     Choose just_me, my_team, my_organization, or custom.",
                ),
            });
        }
    };

    let unlock_method = if auto_unlock { "auto" } else { "passphrase" };

    bag.insert(
        "_effective_profile".into(),
        serde_json::json!(preset_label(profile_raw)),
    );
    bag.insert("_enrollment_open".into(), serde_json::json!(enroll_open));
    bag.insert("_requires_approval".into(), serde_json::json!(approval));
    bag.insert("_unlock_method".into(), serde_json::json!(unlock_method));
    bag.insert("_auto_unlock".into(), serde_json::json!(auto_unlock));
    None
}

/// Step 1b: operator name prompt (only when approval is required).
fn eval_init_operator(bag: &mut serde_json::Map<String, serde_json::Value>) -> Option<EvalResult> {
    let requires_approval = bag
        .get("_requires_approval")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if requires_approval && !bag.contains_key("operator") {
        return Some(EvalResult::NeedInput {
            prompts: vec![Prompt::text("operator", "Operator name (for audit trails)")],
            messages: vec![Message::info(
                "Operator",
                "This name will be recorded in the audit log alongside \
                 administrative actions.",
            )],
        });
    }
    None
}

/// Step 2: entropy collection ("mash the keyboard") + seed derivation.
fn eval_init_entropy(bag: &mut serde_json::Map<String, serde_json::Value>) -> Option<EvalResult> {
    if !bag.contains_key("entropy") {
        let server_entropy = generate_server_entropy_hex();
        bag.insert(
            "_server_entropy".into(),
            serde_json::Value::String(server_entropy),
        );

        return Some(EvalResult::NeedInput {
            prompts: vec![Prompt::entropy("entropy", "Mash your keyboard!")],
            messages: vec![Message::info(
                "Entropy Collection",
                "Type random characters - go wild! This will be mixed with \
                 server-generated randomness to create your passphrase.",
            )],
        });
    }

    if !bag.contains_key("_entropy_seed") {
        let client_entropy = bag.get("entropy").and_then(|v| v.as_str()).unwrap_or("");
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
    None
}

/// Step 3: passphrase — suggest from entropy, choice (keep/again/own), manual
/// entry, and minimum-length validation.
fn eval_init_passphrase(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    render: &RenderHints,
) -> Option<EvalResult> {
    if !bag.contains_key("passphrase") {
        ensure_suggested_passphrase(bag);

        match bag
            .get("passphrase_choice")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            None => return Some(passphrase_choice_prompt(bag)),
            Some(choice) => match choice.as_str() {
                "keep" => {
                    let suggested = bag
                        .get("_suggested_passphrase")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    bag.insert("passphrase".into(), serde_json::json!(suggested));
                }
                "again" => {
                    // Clear entropy state and loop back to mashing.
                    bag.remove("entropy");
                    bag.remove("_server_entropy");
                    bag.remove("_entropy_seed");
                    bag.remove("_suggested_passphrase");
                    bag.remove("_passphrase_hint");
                    bag.remove("passphrase_choice");
                    return Some(eval_init(bag, render));
                }
                "own" => {
                    // Fall through to manual prompt below.
                }
                _ => {
                    bag.remove("passphrase_choice");
                    return Some(eval_init(bag, render));
                }
            },
        }

        // Manual passphrase entry ("own" choice).
        if !bag.contains_key("passphrase") {
            return Some(EvalResult::NeedInput {
                prompts: vec![Prompt::secret_confirm(
                    "passphrase",
                    "Enter your passphrase (minimum 8 characters)",
                )],
                messages: vec![Message::info(
                    "Custom Passphrase",
                    "This passphrase protects your CA's private key. \
                     Write it down - you'll need it if the CA host reboots.\n\n\
                     Minimum 8 characters.",
                )],
            });
        }
    }

    // Validate passphrase length.
    if let Some(pp) = bag.get("passphrase").and_then(|v| v.as_str()) {
        if pp.len() < 8 {
            bag.remove("passphrase");
            bag.remove("passphrase_choice");
            return Some(EvalResult::ValidationError {
                prompts: vec![Prompt::secret_confirm(
                    "passphrase",
                    "Enter your passphrase (minimum 8 characters)",
                )],
                messages: Vec::new(),
                error: "Passphrase must be at least 8 characters.".into(),
            });
        }
    }
    None
}

/// Derive and store the XKCD-style suggested passphrase (and its memorization
/// hint) from the entropy seed, if not already present. No-op on decode failure.
fn ensure_suggested_passphrase(bag: &mut serde_json::Map<String, serde_json::Value>) {
    if bag.contains_key("_suggested_passphrase") {
        return;
    }
    let seed_hex = bag["_entropy_seed"].as_str().unwrap_or("");
    if let Ok(seed_bytes) = hex_decode(seed_hex) {
        let mut seed_arr = [0u8; 32];
        let len = seed_bytes.len().min(32);
        seed_arr[..len].copy_from_slice(&seed_bytes[..len]);
        let suggested = crate::entropy::generate_passphrase(&seed_arr);
        let hint = crate::entropy::memorization_hint(&suggested);
        bag.insert("_suggested_passphrase".into(), serde_json::json!(suggested));
        if !hint.is_empty() {
            bag.insert("_passphrase_hint".into(), serde_json::json!(hint));
        }
    }
}

/// Build the keep/again/own passphrase-choice prompt with the suggested
/// passphrase and memorization hint.
fn passphrase_choice_prompt(bag: &serde_json::Map<String, serde_json::Value>) -> EvalResult {
    let suggested = bag
        .get("_suggested_passphrase")
        .and_then(|v| v.as_str())
        .unwrap_or("(generation failed)");
    let hint = bag
        .get("_passphrase_hint")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut hint_text = format!("Your suggested passphrase:\n\n## {}\n", suggested);
    if !hint.is_empty() {
        hint_text.push_str(&format!("\nMemorization hint: *{hint}*"));
    }
    hint_text.push_str(
        "\n\nThis passphrase protects your CA's private key. \
         Write it down somewhere safe - you'll need it if the \
         CA host reboots.",
    );

    EvalResult::NeedInput {
        prompts: vec![Prompt::select_one(
            "passphrase_choice",
            "What would you like to do?",
            vec![
                SelectOption::with_description(
                    "keep",
                    "Keep this passphrase",
                    "Use the generated passphrase. Write it down!",
                ),
                SelectOption::with_description(
                    "again",
                    "Mash again",
                    "Collect new entropy and generate a different passphrase.",
                ),
                SelectOption::with_description(
                    "own",
                    "Enter my own",
                    "Type a custom passphrase (minimum 8 characters).",
                ),
            ],
        )],
        messages: vec![
            Message::info("Your Passphrase", &hint_text),
            Message::info(
                "⚠ No recovery",
                "If you lose this passphrase, the certificate authority must be \
                 recreated from scratch. There is no reset.",
            ),
        ],
    }
}

/// Step 3b: unlock-method choice (custom profiles only).
fn eval_init_unlock_method(
    bag: &mut serde_json::Map<String, serde_json::Value>,
) -> Option<EvalResult> {
    if bag.contains_key("_unlock_method") {
        return None;
    }
    match bag
        .get("auto_unlock")
        .and_then(|v| v.as_str())
        .map(String::from)
    {
        None => Some(EvalResult::NeedInput {
            prompts: vec![Prompt::select_one(
                "auto_unlock",
                "Unlock behavior after reboot",
                vec![
                    SelectOption::with_description(
                        "auto",
                        "Auto-unlock (recommended)",
                        "The passphrase is saved locally so the CA \
                         unlocks automatically when the member reboots. \
                         Best for headless machines.",
                    ),
                    SelectOption::with_description(
                        "token",
                        "Token authentication",
                        "Register an authenticator app or security key. \
                         An operator authenticates to unlock after reboot.",
                    ),
                    SelectOption::with_description(
                        "passphrase",
                        "Manual passphrase",
                        "Enter the passphrase on every boot. \
                         Most secure, least convenient.",
                    ),
                ],
            )],
            messages: Vec::new(),
        }),
        Some(choice) => {
            let method = match choice.as_str() {
                "auto" | "yes" => "auto",
                "token" => "token",
                "passphrase" | "no" => "passphrase",
                _ => "auto",
            };
            bag.insert("_unlock_method".into(), serde_json::json!(method));
            bag.insert("_auto_unlock".into(), serde_json::json!(method == "auto"));
            None
        }
    }
}

/// Step 4: authentication mode (currently TOTP only).
///
/// Returns the resolved auth mode on success, or the stop `EvalResult` on a
/// missing/invalid selection.
fn eval_init_auth_mode(
    bag: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<String, EvalResult> {
    match bag
        .get("auth_mode")
        .and_then(|v| v.as_str())
        .map(String::from)
    {
        None => Err(EvalResult::NeedInput {
            prompts: vec![Prompt::select_one(
                "auth_mode",
                "Choose how members will authenticate when joining the mesh",
                vec![SelectOption::with_description(
                    "totp",
                    "TOTP (Authenticator App)",
                    "6-digit codes from any TOTP-compatible app \
                         (Google Authenticator, Authy, etc.)",
                )],
            )],
            messages: Vec::new(),
        }),
        Some(mode) => {
            if mode != "totp" {
                bag.remove("auth_mode");
                return Err(EvalResult::ValidationError {
                    prompts: vec![Prompt::select_one(
                        "auth_mode",
                        "Choose how members will authenticate when joining the mesh",
                        vec![SelectOption::new("totp", "TOTP (Authenticator App)")],
                    )],
                    messages: Vec::new(),
                    error: format!(
                        "Unsupported auth mode: '{mode}'. Currently only TOTP is supported."
                    ),
                });
            }
            Ok(mode)
        }
    }
}

/// Step 5: TOTP enrollment-secret setup + 6-digit verification.
fn eval_init_totp(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    render: &RenderHints,
    auth_mode: &str,
) -> Option<EvalResult> {
    if auth_mode != "totp" {
        return None;
    }
    if !bag.contains_key("_totp_secret_hex") {
        let secret = koi_crypto::totp::generate_secret();
        let secret_hex = hex_encode(secret.as_bytes());

        let account = bag
            .get("_self_hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("certmesh");
        let uri = koi_crypto::totp::build_totp_uri(&secret, "Koi Certmesh", account);

        bag.insert(
            "_totp_secret_hex".into(),
            serde_json::Value::String(secret_hex),
        );
        bag.insert("_totp_uri".into(), serde_json::Value::String(uri));
    }

    if !bag.contains_key("verification_code") {
        let uri = bag["_totp_uri"].as_str().unwrap_or("");
        let qr_content = render_qr(uri, render);

        return Some(EvalResult::NeedInput {
            prompts: vec![Prompt::code(
                "verification_code",
                "Enter the 6-digit code from your authenticator app",
            )],
            messages: vec![
                Message::qr_code("Scan this QR code with your authenticator app", &qr_content),
                Message::info(
                    "Save this now",
                    "This secret will not be shown again after CA creation. \
                     You can rotate it later with the rotate-auth command.",
                ),
            ],
        });
    }

    let code = bag
        .get("verification_code")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let secret_hex = bag
        .get("_totp_secret_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !totp_code_valid(secret_hex, code) {
        bag.remove("verification_code");
        let uri = bag.get("_totp_uri").and_then(|v| v.as_str()).unwrap_or("");
        return Some(totp_invalid_code_result(
            "verification_code",
            "Enter the 6-digit code from your authenticator app",
            uri,
            render,
            "Scan this QR code with your authenticator app",
            "Invalid verification code. Check your authenticator app and try again.",
        ));
    }
    None
}

/// Step 6: token-registration sub-flow (only when `_unlock_method == "token"`).
fn eval_init_token(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    render: &RenderHints,
) -> Option<EvalResult> {
    let unlock_method = bag
        .get("_unlock_method")
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
        .to_string();

    if unlock_method != "token" {
        return None;
    }

    // The only supported unlock token type is TOTP. Record it so the
    // completion summary can label the boot behavior.
    bag.insert("unlock_token_type".into(), serde_json::json!("totp"));

    ensure_unlock_totp_secret(bag);

    if !bag.contains_key("unlock_totp_code") {
        let uri = bag["_unlock_totp_uri"].as_str().unwrap_or("");
        let qr_content = render_qr(uri, render);

        return Some(EvalResult::NeedInput {
            prompts: vec![Prompt::code(
                "unlock_totp_code",
                "Enter the 6-digit code to verify your unlock token",
            )],
            messages: vec![
                Message::qr_code(
                    "Scan this QR code with your authenticator app (unlock token)",
                    &qr_content,
                ),
                Message::info(
                    "Separate Token",
                    "This is a **separate** token from your enrollment code. \
                     Add it as a second entry in your authenticator app. \
                     It will be labeled 'Koi Certmesh Unlock'.",
                ),
            ],
        });
    }

    let code = bag
        .get("unlock_totp_code")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let secret_hex = bag
        .get("_unlock_totp_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !totp_code_valid(secret_hex, code) {
        bag.remove("unlock_totp_code");
        let uri = bag
            .get("_unlock_totp_uri")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        return Some(totp_invalid_code_result(
            "unlock_totp_code",
            "Enter the 6-digit code to verify your unlock token",
            uri,
            render,
            "Scan this QR code with your authenticator app (unlock token)",
            "Invalid code. Check your authenticator app and try again.",
        ));
    }
    None
}

/// Generate and store the unlock-token TOTP secret + QR URI, if not present.
fn ensure_unlock_totp_secret(bag: &mut serde_json::Map<String, serde_json::Value>) {
    if bag.contains_key("_unlock_totp_secret") {
        return;
    }
    let secret = koi_crypto::totp::generate_secret();
    let secret_hex = hex_encode(secret.as_bytes());

    let account = bag
        .get("_self_hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("certmesh");
    let uri = koi_crypto::totp::build_totp_uri(&secret, "Koi Certmesh Unlock", account);

    bag.insert(
        "_unlock_totp_secret".into(),
        serde_json::Value::String(secret_hex),
    );
    bag.insert("_unlock_totp_uri".into(), serde_json::Value::String(uri));
}

/// Final step: build the readiness summary and complete the ceremony.
fn eval_init_summary(
    bag: &serde_json::Map<String, serde_json::Value>,
    auth_mode: &str,
) -> EvalResult {
    let profile_raw = bag.get("profile").and_then(|v| v.as_str()).unwrap_or("");
    let effective_profile = bag
        .get("_effective_profile")
        .and_then(|v| v.as_str())
        .unwrap_or(profile_raw);
    let enrollment_label = if bag
        .get("_enrollment_open")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
    {
        "Open"
    } else {
        "Closed"
    };
    let requires_approval = bag
        .get("_requires_approval")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let approval_label = if requires_approval {
        "Required"
    } else {
        "Not required"
    };
    let unlock_method = bag
        .get("_unlock_method")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let unlock_label = match unlock_method {
        "auto" => "Auto-unlock on boot",
        "token" => "Authenticator code (TOTP) required after reboot",
        _ => "Passphrase required after reboot",
    };

    let mut summary_lines = vec![
        format!("Profile: {effective_profile}"),
        format!("Enrollment: {enrollment_label}"),
        format!("Approval: {approval_label}"),
    ];
    if let Some(op) = bag.get("operator").and_then(|v| v.as_str()) {
        summary_lines.push(format!("Operator: {op}"));
    }
    summary_lines.push(format!("Auth: {auth_mode}"));
    summary_lines.push(format!("Boot: {unlock_label}"));
    summary_lines.push(String::new());
    summary_lines.push("This will:".into());
    summary_lines.push("• Generate an ECDSA P-256 CA keypair".into());
    summary_lines.push("• Encrypt the private key with envelope encryption (key slots)".into());
    summary_lines.push("• Install the CA in the system trust store".into());
    summary_lines.push(format!(
        "• {enrollment_label} enrollment for other machines"
    ));
    match unlock_method {
        "auto" => {
            summary_lines.push("• Save passphrase locally for auto-unlock on reboot".into());
        }
        "token" => {
            summary_lines.push("• Register unlock token for boot authentication".into());
        }
        _ => {}
    }

    EvalResult::Complete {
        messages: vec![Message::summary(
            "Certificate authority ready",
            summary_lines.join("\n"),
        )],
    }
}

// ── Join ceremony ───────────────────────────────────────────────────

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
                "Join Certmesh",
                "Enter the join code you received from the certmesh administrator.",
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

    EvalResult::Complete {
        messages: vec![Message::summary(
            "Join ready",
            "Your member will be enrolled in the certmesh.",
        )],
    }
}

// ── Invite ceremony ─────────────────────────────────────────────────

fn eval_invite(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    _render: &RenderHints,
) -> EvalResult {
    if !bag.contains_key("passphrase") {
        return EvalResult::NeedInput {
            prompts: vec![Prompt::secret(
                "passphrase",
                "Enter the CA passphrase to generate an invitation",
            )],
            messages: vec![Message::info(
                "Create Invitation",
                "You'll need the CA passphrase to prove administrator authority.",
            )],
        };
    }

    EvalResult::Complete {
        messages: vec![Message::summary(
            "Invitation ready",
            "The invitation will be generated with a fresh TOTP secret.",
        )],
    }
}

// ── Unlock ceremony ─────────────────────────────────────────────────

fn eval_unlock(
    bag: &mut serde_json::Map<String, serde_json::Value>,
    _render: &RenderHints,
    paths: &crate::CertmeshPaths,
) -> EvalResult {
    // Step 1: Choose unlock method (only when TOTP is also available).
    if unlock_totp_available(paths) && !bag.contains_key("_unlock_choice") {
        return eval_unlock_method_choice();
    }

    let method = bag
        .get("_unlock_choice")
        .and_then(|v| v.as_str())
        .unwrap_or("passphrase");

    // Step 2: Collect the credential for the chosen method.
    if let Some(r) = eval_unlock_collect_credential(bag, method) {
        return r;
    }

    let summary = match method {
        "totp" => "The CA key will be decrypted using your authenticator code.",
        _ => "The CA key will be decrypted and certmesh operations resumed.",
    };

    EvalResult::Complete {
        messages: vec![Message::summary("Unlock ready", summary)],
    }
}

/// Whether the slot table advertises a TOTP unlock method.
fn unlock_totp_available(paths: &crate::CertmeshPaths) -> bool {
    let slot_table_path = paths.slot_table_path();
    let available_methods = if slot_table_path.exists() {
        match koi_crypto::unlock_slots::SlotTable::load(&slot_table_path) {
            Ok(table) => table
                .available_methods()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            Err(_) => vec!["passphrase".to_string()],
        }
    } else {
        vec!["passphrase".to_string()]
    };
    available_methods.contains(&"totp".to_string())
}

/// Build the passphrase-vs-TOTP unlock-method selection prompt.
fn eval_unlock_method_choice() -> EvalResult {
    let options = vec![
        SelectOption::with_description("passphrase", "Passphrase", "Enter your CA passphrase"),
        SelectOption::with_description(
            "totp",
            "Authenticator code",
            "Enter a code from your authenticator app",
        ),
    ];
    EvalResult::NeedInput {
        prompts: vec![Prompt::select_one(
            "_unlock_choice",
            "How do you want to unlock the CA?",
            options,
        )],
        messages: vec![Message::info(
            "Unlock Certificate Authority",
            "The CA is locked. Choose how to unlock it.",
        )],
    }
}

/// Collect the credential for the chosen unlock method. Returns `Some` when more
/// input is needed, `None` once the credential is present.
fn eval_unlock_collect_credential(
    bag: &serde_json::Map<String, serde_json::Value>,
    method: &str,
) -> Option<EvalResult> {
    match method {
        "totp" => {
            if !bag.contains_key("_unlock_totp_input") {
                return Some(EvalResult::NeedInput {
                    prompts: vec![Prompt::code(
                        "_unlock_totp_input",
                        "Enter the 6-digit code from your authenticator app",
                    )],
                    messages: vec![Message::info(
                        "TOTP Unlock",
                        "Enter the current code from the authenticator app you \
                         registered during CA setup.",
                    )],
                });
            }
        }
        _ => {
            // Passphrase path (original behavior).
            if !bag.contains_key("passphrase") {
                return Some(EvalResult::NeedInput {
                    prompts: vec![Prompt::secret(
                        "passphrase",
                        "Enter the CA passphrase to unlock",
                    )],
                    messages: vec![Message::info(
                        "Unlock Certificate Authority",
                        "The CA is locked. Enter the passphrase to decrypt the CA key \
                         and resume operations.",
                    )],
                });
            }
        }
    }
    None
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Human-readable display label for a preset name (UX only).
fn preset_label(profile_raw: &str) -> &'static str {
    match profile_raw.to_lowercase().as_str() {
        "my_team" | "my-team" | "myteam" | "team" | "2" => "My Team",
        "my_organization" | "my-organization" | "myorganization" | "organization" | "org" | "3" => {
            "My Organization"
        }
        // just_me and anything else that resolved as a preset defaults to Just Me
        _ => "Just Me",
    }
}

fn profile_prompt() -> Prompt {
    Prompt::select_one(
        "profile",
        "Who is this certificate authority for?",
        vec![
            SelectOption::with_description("just_me", "Just me", "Single admin, personal network."),
            SelectOption::with_description("my_team", "My team", "Small group with shared trust."),
            SelectOption::with_description(
                "my_organization",
                "My organization",
                "Structured admin, operator required.",
            ),
            SelectOption::with_description("custom", "Custom", "Choose each policy individually."),
        ],
    )
}

fn generate_server_entropy_hex() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    hex_encode(&buf)
}

fn combine_entropy(server_hex: &str, client_raw: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(server_hex.as_bytes());
    hasher.update(client_raw.as_bytes());
    hasher.finalize().into()
}

fn render_qr(payload: &str, render: &RenderHints) -> String {
    use koi_common::ceremony::QrFormat;

    match render.qr.unwrap_or_default() {
        QrFormat::PngBase64 => koi_crypto::totp::qr_code_png_base64_raw(payload),
        QrFormat::Utf8 => koi_crypto::totp::qr_code_unicode_raw(payload),
        QrFormat::UriOnly => payload.to_string(),
    }
}

/// Verify a 6-digit `code` against a hex-encoded TOTP `secret_hex`.
/// Returns `false` on any decoding failure.
fn totp_code_valid(secret_hex: &str, code: &str) -> bool {
    match hex_decode(secret_hex) {
        Ok(secret_bytes) => {
            let secret = koi_crypto::totp::TotpSecret::from_bytes(secret_bytes);
            koi_crypto::totp::verify_code(&secret, code)
        }
        Err(_) => false,
    }
}

/// Build the "invalid TOTP code" re-prompt (QR + code prompt) shared by the
/// enrollment-secret and unlock-token verification steps.
fn totp_invalid_code_result(
    code_key: &str,
    code_prompt: &str,
    uri: &str,
    render: &RenderHints,
    qr_caption: &str,
    error: &str,
) -> EvalResult {
    let qr_content = render_qr(uri, render);
    EvalResult::ValidationError {
        prompts: vec![Prompt::code(code_key, code_prompt)],
        messages: vec![Message::qr_code(qr_caption, &qr_content)],
        error: error.into(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::ceremony::{CeremonyHost, CeremonyRequest, InputType};

    fn make_host() -> CeremonyHost<InitCeremonyRules> {
        let paths = crate::CertmeshPaths::with_data_dir(koi_common::test::ensure_data_dir(
            "koi-certmesh-ceremony-tests",
        ));
        CeremonyHost::new(InitCeremonyRules::new(paths))
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
        // 4 options now: just_me, my_team, my_organization, custom
        assert_eq!(resp.prompts[0].options.len(), 4);
    }

    #[test]
    fn init_profile_then_entropy() {
        let host = make_host();

        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();

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
        assert_eq!(r2.prompts[0].key, "entropy");
        assert_eq!(r2.prompts[0].input_type, InputType::Entropy);
    }

    #[test]
    fn init_entropy_then_passphrase_suggestion() {
        let host = make_host();

        // Step 1: start with profile
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

        // Step 2: provide entropy
        let mut data = serde_json::Map::new();
        data.insert("entropy".into(), serde_json::json!("asdfghjklqwertyuiop"));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();

        // Should show passphrase_choice with keep/again/own
        assert!(!r2.complete);
        assert_eq!(r2.prompts[0].key, "passphrase_choice");
        assert_eq!(r2.prompts[0].input_type, InputType::SelectOne);
        assert_eq!(r2.prompts[0].options.len(), 3);
        assert_eq!(r2.prompts[0].options[0].value, "keep");
        assert_eq!(r2.prompts[0].options[1].value, "again");
        assert_eq!(r2.prompts[0].options[2].value, "own");

        // Should have a message containing the suggested passphrase
        let has_passphrase_msg = r2
            .messages
            .iter()
            .any(|m| m.content.contains('-') && m.title.contains("Passphrase"));
        assert!(
            has_passphrase_msg,
            "Expected passphrase suggestion in messages"
        );
    }

    #[test]
    fn init_custom_profile_asks_enrollment_then_approval() {
        let host = make_host();

        let mut data = serde_json::Map::new();
        data.insert("profile".into(), serde_json::json!("custom"));
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data,
                render: None,
            })
            .unwrap();

        assert!(!r1.complete);
        assert_eq!(r1.prompts[0].key, "enrollment_open");

        let mut data = serde_json::Map::new();
        data.insert("enrollment_open".into(), serde_json::json!("open"));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();

        assert!(!r2.complete);
        assert_eq!(r2.prompts[0].key, "requires_approval");
    }

    #[test]
    fn init_custom_with_approval_asks_operator() {
        let host = make_host();

        let mut data = serde_json::Map::new();
        data.insert("profile".into(), serde_json::json!("custom"));
        data.insert("enrollment_open".into(), serde_json::json!("open"));
        data.insert("requires_approval".into(), serde_json::json!("yes"));
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data,
                render: None,
            })
            .unwrap();

        assert!(!r1.complete);
        assert_eq!(r1.prompts[0].key, "operator");
        assert_eq!(r1.prompts[0].input_type, InputType::Text);
    }

    #[test]
    fn init_my_team_asks_operator() {
        let host = make_host();

        let mut data = serde_json::Map::new();
        data.insert("profile".into(), serde_json::json!("my_team"));
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data,
                render: None,
            })
            .unwrap();

        assert!(!r1.complete);
        assert_eq!(r1.prompts[0].key, "operator");
    }

    #[test]
    fn init_rejects_short_passphrase() {
        let host = make_host();

        // Pre-fill profile + entropy + own choice + short passphrase
        let mut data = serde_json::Map::new();
        data.insert("profile".into(), serde_json::json!("just_me"));
        data.insert("entropy".into(), serde_json::json!("keyboard mashing"));
        data.insert("passphrase_choice".into(), serde_json::json!("own"));
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data,
                render: None,
            })
            .unwrap();

        // Should now prompt for manual passphrase
        assert!(!r1.complete);
        assert_eq!(r1.prompts[0].key, "passphrase");
        assert_eq!(r1.prompts[0].input_type, InputType::SecretConfirm);

        // Provide a short one
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

        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("join".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();
        assert_eq!(r1.prompts[0].key, "join_code");

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
        assert!(r3.result_data.is_some());
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

    #[test]
    fn init_complete_returns_result_data() {
        let host = make_host();

        // Provide everything needed except verification_code
        let mut data = serde_json::Map::new();
        data.insert("profile".into(), serde_json::json!("just_me"));
        data.insert("passphrase".into(), serde_json::json!("my-long-passphrase"));
        data.insert("entropy".into(), serde_json::json!("asdfghjkl"));
        data.insert("auth_mode".into(), serde_json::json!("totp"));
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("init".into()),
                data,
                render: None,
            })
            .unwrap();

        // Should ask for verification_code now
        assert!(!r1.complete);
        assert_eq!(r1.prompts[0].key, "verification_code");

        // We can't provide a valid TOTP code in a unit test since the
        // secret was just generated, but we can verify the structure.
        // The actual TOTP verification is tested via integration tests.
    }
}
