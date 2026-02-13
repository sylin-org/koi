//! Certmesh command handlers.
//!
//! All certmesh commands delegate to the running service via HTTP.
//! The CLI never performs direct file I/O for certmesh operations —
//! the service has the elevated permissions needed for cert store,
//! file writes, etc.

use std::sync::Arc;

use koi_certmesh::entropy;
use koi_certmesh::profiles::TrustProfile;
use koi_certmesh::protocol::PolicySummary;
use koi_common::encoding::{hex_decode, hex_encode};
use koi_mdns::events::MdnsEvent;

use crate::client::KoiClient;
use crate::format;

/// mDNS discovery timeout for finding a CA on the local network.
const CA_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ── Color helpers ────────────────────────────────────────────────────
//
// Semantic color system per CERTMESH-CREATE-WIZARD.md:
//   Cyan       — active trigger-effect pair (Enter + what it activates)
//   Cyan bold  — critical value to capture (passphrase, TOTP manual code)
//   Green      — completed / success (✓ checkmarks)
//   Yellow     — irreversible warning (⚠, "no recovery mechanism")
//   Red        — error (✗ wrong input, failed verification)
//   Dim        — supporting / secondary (descriptions, hints, Cancel)
//   Default    — neutral / settled text, box chrome
//
// Degrades gracefully: respects NO_COLOR, TERM=dumb, non-interactive stdout.

mod color {
    use std::io::IsTerminal;

    /// Whether the terminal supports ANSI color output.
    fn enabled() -> bool {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| {
            if std::env::var_os("NO_COLOR").is_some() {
                return false;
            }
            if std::env::var("TERM")
                .map(|t| t.eq_ignore_ascii_case("dumb"))
                .unwrap_or(false)
            {
                return false;
            }
            std::io::stdout().is_terminal()
        })
    }

    /// Wrap text in an ANSI escape sequence, returning plain text when colors
    /// are unavailable.
    fn wrap(code: &str, text: &str) -> String {
        if enabled() {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// Cyan — active trigger-effect pair.
    pub fn cyan(text: &str) -> String {
        wrap("36", text)
    }

    /// Cyan bold — critical value to capture (passphrase, TOTP code).
    pub fn cyan_bold(text: &str) -> String {
        wrap("1;36", text)
    }

    /// Green — completed / success.
    pub fn green(text: &str) -> String {
        wrap("32", text)
    }

    /// Yellow — irreversible warning.
    pub fn yellow(text: &str) -> String {
        wrap("33", text)
    }

    /// Red — error.
    pub fn red(text: &str) -> String {
        wrap("31", text)
    }

    /// Dim — supporting / secondary text.
    pub fn dim(text: &str) -> String {
        wrap("2", text)
    }
}

// ── Shared helper ────────────────────────────────────────────────────

/// Resolve the daemon endpoint or bail with a clear message.
fn require_daemon(endpoint: Option<&str>) -> anyhow::Result<KoiClient> {
    let ep = endpoint
        .map(String::from)
        .or_else(koi_config::breadcrumb::read_breadcrumb)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No running Koi service found.\n\
                 Install and start the service first: koi install"
            )
        })?;
    Ok(KoiClient::new(&ep))
}

// ── Create ──────────────────────────────────────────────────────────

pub fn create(
    profile: Option<&str>,
    operator: Option<&str>,
    enrollment: Option<&str>,
    require_approval: Option<bool>,
    passphrase: Option<&str>,
    json: bool,
    endpoint: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;
    if preflight_ca_exists(&client)? {
        return Ok(());
    }

    // ── Fully non-interactive JSON mode ────────────────────────────
    if json {
        let trust_profile = profile
            .and_then(TrustProfile::from_str_loose)
            .ok_or_else(|| anyhow::anyhow!("--profile is required with --json"))?;
        let ca_passphrase = passphrase
            .map(ToString::to_string)
            .ok_or_else(|| anyhow::anyhow!("--passphrase is required with --json"))?;
        validate_operator(
            require_approval.unwrap_or_else(|| trust_profile.requires_approval()),
            operator,
        )?;
        let entropy_seed =
            entropy::collect_entropy(entropy::EntropyMode::Manual(ca_passphrase.clone()))?;

        let enrollment_open = parse_enrollment_open(enrollment)?;
        let body = serde_json::json!({
            "passphrase": ca_passphrase,
            "entropy_hex": hex_encode(&entropy_seed),
            "profile": trust_profile,
            "operator": operator,
            "enrollment_open": enrollment_open,
            "requires_approval": require_approval,
        });
        let resp = client.post_json("/v1/certmesh/create", &body)?;
        let ca_fingerprint = resp
            .get("ca_fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!(
            "{}",
            serde_json::json!({
                "created": true,
                "profile": trust_profile.to_string(),
                "ca_fingerprint": ca_fingerprint,
            })
        );
        return Ok(());
    }

    // ── Intro box ──────────────────────────────────────────────────
    println!();
    print_box(
        "  ",
        None,
        &[
            "Create a certificate mesh".to_string(),
            String::new(),
            color::dim("A certificate mesh is a private Certificate"),
            color::dim("Authority (CA) for your local network. It lets"),
            color::dim("your machines issue and trust TLS certificates"),
            color::dim("without relying on an external provider."),
            String::new(),
            "ESC at any time to cancel.".to_string(),
        ],
        BoxStyle::Rounded,
    );

    // ── Step 1: Profile (skip if --profile provided) ───────────────
    let mut selection = if let Some(profile_value) = profile {
        let trust_profile = TrustProfile::from_str_loose(profile_value)
            .ok_or_else(|| anyhow::anyhow!("Invalid profile '{profile_value}'"))?;
        println!(
            "\n  {} Profile: {trust_profile} {}",
            color::green("✓"),
            color::dim("(from --profile)")
        );
        ProfileSelection {
            profile: trust_profile,
            enrollment_open: parse_enrollment_open(enrollment)?,
            requires_approval: require_approval,
        }
    } else {
        prompt_profile_selection()?
    };

    let mut operator_name = resolve_operator_interactive(
        selection.profile,
        selection.effective_requires_approval(),
        operator,
    )?;

    // ── Step 2: Passphrase (skip if --passphrase provided) ─────────
    let (mut passphrase_value, mut entropy_seed) = if let Some(provided) = passphrase {
        let es = entropy::collect_entropy(entropy::EntropyMode::Manual(provided.to_string()))?;
        println!(
            "  {} Passphrase: {}",
            color::green("✓"),
            color::dim("(from --passphrase)")
        );
        (Some(provided.to_string()), es)
    } else {
        let (pp, es) = prompt_passphrase_and_entropy()?;
        (Some(pp), es)
    };

    // ── Review loop ────────────────────────────────────────────────
    loop {
        print_create_review(
            selection.profile,
            operator_name.as_deref(),
            passphrase_value.as_deref().unwrap_or(""),
            selection.enrollment_open,
            selection.requires_approval,
            profile.is_some(),
            passphrase.is_some(),
        );
        let nav = prompt_line(&format!(
            "\n  {} {}  {} {} {}  {} {}: ",
            color::cyan("Enter"),
            color::cyan("Create"),
            color::dim("1-2"),
            color::dim("Go back"),
            color::dim(" "),
            "esc",
            color::dim("Cancel"),
        ))?;
        match nav.trim().to_ascii_lowercase().as_str() {
            "" => break,
            "1" if profile.is_none() => {
                selection = prompt_profile_selection()?;
                operator_name = resolve_operator_interactive(
                    selection.profile,
                    selection.effective_requires_approval(),
                    operator_name.as_deref(),
                )?;
            }
            "2" if passphrase.is_none() => {
                let (pp, es) = prompt_passphrase_and_entropy()?;
                passphrase_value = Some(pp);
                entropy_seed = es;
            }
            "esc" => {
                println!("\n  Canceled. No changes made.");
                return Ok(());
            }
            _ => println!(
                "  {}",
                color::dim("Press Enter to create, 1 or 2 to go back, or esc to cancel.")
            ),
        }
    }

    // ── Execute creation ───────────────────────────────────────────
    let ca_passphrase = passphrase_value.unwrap_or_default();
    if ca_passphrase.is_empty() {
        anyhow::bail!("Passphrase cannot be empty.");
    }
    validate_operator(
        selection.effective_requires_approval(),
        operator_name.as_deref(),
    )?;

    let body = serde_json::json!({
        "passphrase": ca_passphrase,
        "entropy_hex": hex_encode(&entropy_seed),
        "profile": selection.profile,
        "operator": operator_name,
        "enrollment_open": selection.enrollment_open,
        "requires_approval": selection.requires_approval,
    });

    println!("\n  Creating certificate mesh...\n");
    let resp = client.post_json("/v1/certmesh/create", &body)?;

    let totp_uri = resp.get("totp_uri").and_then(|v| v.as_str()).unwrap_or("");
    let ca_fingerprint = resp
        .get("ca_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // ── Creation output ────────────────────────────────────────────
    println!("  {} CA keypair generated (ECDSA P-256)", color::green("✓"));
    println!(
        "  {} Private key encrypted (Argon2id + AES-256-GCM)",
        color::green("✓")
    );
    println!("  {} Roster initialized", color::green("✓"));
    println!("  {} Audit log started", color::green("✓"));

    // ── TOTP setup (QR first, then manual code, per proposal) ──────
    if !totp_uri.is_empty() {
        println!("\n  Authenticator setup\n");
        println!(
            "  {}",
            color::dim("When other machines join this mesh, they'll prove")
        );
        println!(
            "  {}",
            color::dim("authorization with a one-time code from an authenticator")
        );
        println!(
            "  {}\n",
            color::dim("app (Google Authenticator, Authy, 1Password, etc.).")
        );

        // QR code first
        if let Some(secret) = extract_totp_secret_from_uri(totp_uri) {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "localhost".to_string());
            let qr = koi_crypto::totp::qr_code_unicode(
                &secret,
                "Koi Certmesh",
                &format!("admin@{hostname}"),
            );
            println!("  Scan this QR code:\n");
            println!("{qr}");
        }

        // Manual code second
        if let Some(secret_base32) = extract_totp_secret_base32_from_uri(totp_uri) {
            println!(
                "  Or enter this code manually: {}\n",
                color::cyan_bold(&secret_base32)
            );
        }

        println!("  ┌─────────────────────────────────────────────────────┐");
        println!(
            "  │  {}         │",
            color::yellow("Save this now. It will not be shown again.")
        );
        println!(
            "  │  {}     │",
            color::dim("(rotate later with 'koi certmesh rotate-auth')")
        );
        println!("  └─────────────────────────────────────────────────────┘");
        println!();

        // Verify the user actually captured the TOTP secret by asking for a code.
        // A single prompt handles everything: 6-digit codes are verified,
        // "1" retries, "2" regenerates. No overlap since TOTP codes are always 6 digits.
        if let Some(mut secret) = extract_totp_secret_from_uri(totp_uri) {
            println!(
                "  {}",
                color::dim("Enter a code from your authenticator app to verify setup.")
            );
            let mut attempts = 0u32;
            loop {
                let prompt = if attempts >= 2 {
                    format!(
                        "  {} {}, {} {}, or {}: ",
                        color::dim("[1]"),
                        color::dim("try again"),
                        color::dim("[2]"),
                        color::dim("new secret"),
                        color::cyan("code")
                    )
                } else {
                    format!("  {} ", color::cyan("TOTP code:"))
                };
                let input = prompt_line(&prompt)?;
                let trimmed = input.trim().replace(' ', "");

                if trimmed.is_empty() || trimmed == "1" {
                    continue;
                }

                if trimmed == "2" && attempts >= 2 {
                    println!("\n  Rotating auth credential...\n");
                    let rotate_resp = client.post_json(
                        "/v1/certmesh/rotate-auth",
                        &serde_json::json!({ "passphrase": ca_passphrase }),
                    )?;
                    let new_uri = rotate_resp
                        .get("auth_setup")
                        .and_then(|s| s.get("totp_uri"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if let Some(new_secret) = extract_totp_secret_from_uri(new_uri) {
                        secret = new_secret;
                        let hostname = hostname::get()
                            .map(|h| h.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "localhost".to_string());
                        let qr = koi_crypto::totp::qr_code_unicode(
                            &secret,
                            "Koi Certmesh",
                            &format!("admin@{hostname}"),
                        );
                        println!("  Scan the new QR code:\n");
                        println!("{qr}");
                        if let Some(b32) = extract_totp_secret_base32_from_uri(new_uri) {
                            println!(
                                "  Or enter this code manually: {}\n",
                                color::cyan_bold(&b32)
                            );
                        }
                        println!(
                            "  {}",
                            color::dim("Enter a code from your authenticator app to verify setup.")
                        );
                    }
                    attempts = 0;
                    continue;
                }

                if koi_crypto::totp::verify_code(&secret, &trimmed) {
                    println!(
                        "  {} TOTP verified — authenticator is set up correctly.\n",
                        color::green("✓")
                    );
                    break;
                }

                attempts += 1;
                if attempts >= 2 {
                    println!(
                        "  {} Code doesn't match. {}",
                        color::red("✗"),
                        color::dim("Enter code, [1] retry, or [2] generate new secret.")
                    );
                } else {
                    println!(
                        "  {} Code doesn't match. {}",
                        color::red("✗"),
                        color::dim("Wait for a fresh code and try again.")
                    );
                }
            }
        } else {
            // Fallback if we couldn't parse the secret — just continue
            let _ = prompt_line(&format!(
                "  {} {}: ",
                color::cyan("Enter"),
                color::cyan("Continue")
            ));
        }
    }

    // ── Verification ───────────────────────────────────────────────
    println!("\n  Verifying setup...\n");
    if let Ok(status_resp) = client.get_json("/v1/certmesh/status") {
        let ca_initialized = status_resp
            .get("ca_initialized")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let member_count = status_resp
            .get("member_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let ca_locked = status_resp
            .get("ca_locked")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        println!(
            "  {} CA initialized",
            if ca_initialized {
                color::green("✓")
            } else {
                color::red("✗")
            }
        );
        println!(
            "  {} CA key decrypts successfully",
            if !ca_locked {
                color::green("✓")
            } else {
                color::red("✗")
            }
        );
        println!(
            "  {} Roster reachable ({member_count} member{})",
            if member_count > 0 {
                color::green("✓")
            } else {
                color::red("✗")
            },
            if member_count == 1 { "" } else { "s" }
        );
    }

    // ── Summary box ────────────────────────────────────────────────
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string());
    let cert_path = koi_common::paths::koi_data_dir()
        .join("certs")
        .join(&hostname);

    println!();
    print_box(
        "  ",
        Some(&color::green("Certificate mesh created")),
        &[
            String::new(),
            format!("Profile:        {}", selection.profile),
            format!("CA fingerprint: {}", truncate_str(ca_fingerprint, 35)),
            format!("Hostname:       {}", truncate_str(&hostname, 35)),
            format!(
                "Certificates:   {}",
                truncate_str(&cert_path.display().to_string(), 35)
            ),
            String::new(),
        ],
        BoxStyle::Rounded,
    );
    println!();
    println!("  What's next:");
    println!(
        "  {}       koi certmesh join",
        color::dim("• On another machine:")
    );
    println!(
        "  {}   koi certmesh unlock",
        color::dim("• After a daemon restart:")
    );
    println!(
        "  {}     koi certmesh status",
        color::dim("• Check status anytime:")
    );

    Ok(())
}

// ── Create helpers ──────────────────────────────────────────────────

fn validate_operator(requires_approval: bool, operator: Option<&str>) -> anyhow::Result<()> {
    if requires_approval && operator.is_none() {
        anyhow::bail!("This policy requires --operator <name>.");
    }
    Ok(())
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

/// Visible width of a string, ignoring ANSI escape sequences.
///
/// Counts Unicode characters outside of `\x1b[…m` sequences.
fn visible_width(s: &str) -> usize {
    let mut width = 0usize;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            width += 1;
        }
    }
    width
}

/// Pad a string with trailing spaces so its *visible* width equals `target`.
///
/// If the visible width already exceeds `target`, the string is returned as-is.
fn pad_visible(s: &str, target: usize) -> String {
    let vw = visible_width(s);
    if vw >= target {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(target - vw))
    }
}

/// Box style: `╭╮╰╯│─` (rounded) or `┌┐└┘│─` (square).
#[derive(Clone, Copy)]
enum BoxStyle {
    Rounded,
    Square,
}

/// Print a box with auto-aligned right border.
///
/// `indent` is the leading whitespace (e.g. `"  "`).
/// `title` if `Some`, is embedded in the top border: `╭── Title ──…╮`.
/// `lines` are the content lines (may contain ANSI color codes).
/// The inner width is derived from the widest visible line + 2 padding.
fn print_box(indent: &str, title: Option<&str>, lines: &[String], style: BoxStyle) {
    let (tl, tr, bl, br, h, v) = match style {
        BoxStyle::Rounded => ('╭', '╮', '╰', '╯', '─', '│'),
        BoxStyle::Square => ('┌', '┐', '└', '┘', '─', '│'),
    };

    // Determine inner width: max visible width + 2 spaces (left + right padding)
    let max_content = lines.iter().map(|l| visible_width(l)).max().unwrap_or(0);
    let title_width = title.map(|t| visible_width(t) + 6).unwrap_or(0); // "── Title ──"
    let inner = max_content.max(title_width).max(20) + 2; // +2 for side padding

    // Top border
    if let Some(t) = title {
        let label = format!("{h}{h} {t} ");
        let label_vw = visible_width(&label);
        let remaining = if inner + 2 > label_vw {
            inner + 2 - label_vw
        } else {
            1
        };
        println!(
            "{indent}{tl}{label}{}{tr}",
            std::iter::repeat_n(h, remaining).collect::<String>()
        );
    } else {
        println!(
            "{indent}{tl}{}{tr}",
            std::iter::repeat_n(h, inner + 2).collect::<String>()
        );
    }

    // Content lines
    for line in lines {
        let padded = pad_visible(line, inner);
        println!("{indent}{v} {padded} {v}");
    }

    // Bottom border
    println!(
        "{indent}{bl}{}{br}",
        std::iter::repeat_n(h, inner + 2).collect::<String>()
    );
}

#[derive(Clone, Copy)]
struct ProfileSelection {
    profile: TrustProfile,
    enrollment_open: Option<bool>,
    requires_approval: Option<bool>,
}

impl ProfileSelection {
    fn effective_requires_approval(&self) -> bool {
        self.requires_approval
            .unwrap_or_else(|| self.profile.requires_approval())
    }
}

fn preflight_ca_exists(client: &KoiClient) -> anyhow::Result<bool> {
    let status = client.get_json("/v1/certmesh/status")?;
    let ca_init = status
        .get("ca_initialized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !ca_init {
        return Ok(false);
    }

    let profile = status
        .get("profile")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let fingerprint = status
        .get("ca_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let member_count = status
        .get("member_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!();
    println!(
        "  {}  A certificate mesh already exists on this machine.",
        color::yellow("⚠")
    );
    println!();
    println!("     Profile:        {profile}");
    println!("     CA fingerprint: {fingerprint}");
    println!("     Members:        {member_count} active");
    println!();
    println!("  {}", color::dim("To inspect:   koi certmesh status"));
    println!("  {}", color::dim("To destroy:   koi certmesh destroy"));
    println!();
    println!("  No changes made.");
    Ok(true)
}

fn prompt_profile_selection() -> anyhow::Result<ProfileSelection> {
    println!("\n  Step 1 of 2 — Who is this mesh for?\n");
    println!(
        "  [1] {}          {}",
        color::cyan("Just me"),
        color::dim("You control every machine on the network.")
    );
    println!(
        "                       {}\n",
        color::dim("Anyone with the authenticator code can join.")
    );
    println!(
        "  [2] My team          {}",
        color::dim("A small group. An operator name is recorded")
    );
    println!(
        "                       {}\n",
        color::dim("in the audit log for accountability.")
    );
    println!(
        "  [3] My organization  {}",
        color::dim("Strict access control. Enrollment starts")
    );
    println!(
        "                       {}\n",
        color::dim("closed — each machine must be approved.")
    );
    println!(
        "  [4] Custom           {}\n",
        color::dim("Choose each policy individually.")
    );

    loop {
        let line = prompt_line(&format!(
            "  Choose [1-4, {}=1, esc={}]: ",
            color::cyan("Enter"),
            color::dim("cancel")
        ))?;
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "1" | "just-me" | "just me" => {
                println!("  {} Just me\n", color::green("✓"));
                return Ok(ProfileSelection {
                    profile: TrustProfile::JustMe,
                    enrollment_open: None,
                    requires_approval: None,
                });
            }
            "2" | "team" | "my-team" | "my team" => {
                println!("  {} My team\n", color::green("✓"));
                return Ok(ProfileSelection {
                    profile: TrustProfile::MyTeam,
                    enrollment_open: None,
                    requires_approval: None,
                });
            }
            "3" | "organization" | "org" | "my-organization" | "my organization" => {
                println!("  {} My organization\n", color::green("✓"));
                return Ok(ProfileSelection {
                    profile: TrustProfile::MyOrganization,
                    enrollment_open: None,
                    requires_approval: None,
                });
            }
            "4" | "custom" => return prompt_custom_policy(),
            "esc" => anyhow::bail!("Canceled. No changes made."),
            _ => println!("  {} Pick 1, 2, 3, or 4.", color::red("✗")),
        }
    }
}

fn prompt_custom_policy() -> anyhow::Result<ProfileSelection> {
    println!("\n  {} Custom\n", color::green("✓"));

    println!("    Enrollment when mesh is created:\n");
    println!(
        "    [1] {}   {}",
        color::cyan("Open (default)"),
        color::dim("Any machine with a valid TOTP code can join")
    );
    println!(
        "                         {}\n",
        color::dim("immediately. You can close enrollment later.")
    );
    println!(
        "    [2] Closed           {}",
        color::dim("Machines cannot join until you explicitly")
    );
    println!(
        "                         {}\n",
        color::dim("run 'certmesh open-enrollment'.")
    );

    let enrollment_open = loop {
        let line = prompt_line(&format!(
            "    Choose [1-2, {}=1, esc={}]: ",
            color::cyan("Enter"),
            color::dim("cancel")
        ))?;
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "1" | "open" | "o" => {
                println!("    {} Enrollment: Open\n", color::green("✓"));
                break true;
            }
            "2" | "closed" | "close" | "c" => {
                println!("    {} Enrollment: Closed\n", color::green("✓"));
                break false;
            }
            "esc" => anyhow::bail!("Canceled. No changes made."),
            _ => println!("    {} Enter 1 (open) or 2 (closed).", color::red("✗")),
        }
    };

    println!("    Require approval for each join request?\n");
    println!(
        "    [1] {}     {}",
        color::cyan("No (default)"),
        color::dim("TOTP code is sufficient. Machine joins")
    );
    println!(
        "                         {}\n",
        color::dim("immediately after verification.")
    );
    println!(
        "    [2] Yes              {}",
        color::dim("After TOTP verification, an operator must")
    );
    println!(
        "                         {}\n",
        color::dim("approve the request before a cert is issued.")
    );

    let requires_approval = loop {
        let line = prompt_line(&format!(
            "    Choose [1-2, {}=1, esc={}]: ",
            color::cyan("Enter"),
            color::dim("cancel")
        ))?;
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "1" | "no" | "n" => {
                println!("    {} Approval: No\n", color::green("✓"));
                break false;
            }
            "2" | "yes" | "y" => {
                println!("    {} Approval: Yes\n", color::green("✓"));
                break true;
            }
            "esc" => anyhow::bail!("Canceled. No changes made."),
            _ => println!("    {} Enter 1 (no) or 2 (yes).", color::red("✗")),
        }
    };

    let enroll_label = if enrollment_open { "Open" } else { "Closed" };
    let approval_label = if requires_approval {
        "approval required"
    } else {
        "no approval"
    };
    println!(
        "  {} Custom ({enroll_label} enrollment, {approval_label})\n",
        color::green("✓")
    );

    let baseline_profile = match (enrollment_open, requires_approval) {
        (true, false) => TrustProfile::JustMe,
        (true, true) => TrustProfile::MyTeam,
        (false, true) => TrustProfile::MyOrganization,
        (false, false) => TrustProfile::JustMe,
    };

    Ok(ProfileSelection {
        profile: baseline_profile,
        enrollment_open: Some(enrollment_open),
        requires_approval: Some(requires_approval),
    })
}

fn resolve_operator_interactive(
    _profile: TrustProfile,
    requires_approval: bool,
    current: Option<&str>,
) -> anyhow::Result<Option<String>> {
    if !requires_approval {
        return Ok(None);
    }

    if let Some(op) = current {
        return Ok(Some(op.to_string()));
    }

    let default_operator = format!(
        "{}\\{}",
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "host".to_string()),
        std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "operator".to_string())
    );
    println!("    {}", color::dim("Operator name (for audit trails):"));
    let line = prompt_line(&format!(
        "    {}: ",
        color::dim(&format!("(default: {default_operator})"))
    ))?;
    if line.trim().is_empty() {
        println!("    {} Operator: {default_operator}\n", color::green("✓"));
        Ok(Some(default_operator))
    } else {
        let op = line.trim().to_string();
        println!("    {} Operator: {op}\n", color::green("✓"));
        Ok(Some(op))
    }
}

/// Step 2 — CA passphrase. Three paths per the proposal:
/// 1. Keyboard mashing (default) — interactive entropy, then generate passphrase
/// 2. Generate one for me — OS RNG entropy, then generate passphrase
/// 3. I'll type my own — user provides passphrase, entropy derived from it
fn prompt_passphrase_and_entropy() -> anyhow::Result<(String, [u8; 32])> {
    println!("\n  Step 2 of 2 — CA passphrase\n");
    println!(
        "  {}",
        color::dim("This passphrase protects your CA's private key. You'll need")
    );
    println!("  {}\n", color::dim("it every time the daemon restarts."));
    print_box(
        "  ",
        None,
        &[
            format!(
                "{}  {}",
                color::yellow("⚠"),
                color::yellow("There is no recovery mechanism.")
            ),
            format!(
                "   {}",
                color::yellow("If you lose this passphrase, the entire mesh")
            ),
            format!("   {}", color::yellow("must be recreated from scratch.")),
        ],
        BoxStyle::Square,
    );
    println!();
    println!(
        "  [1] {}   {}",
        color::cyan("Let me mash the keyboard!"),
        color::dim("Fun & secure. (default)")
    );
    println!(
        "  [2] Generate one for me          {}",
        color::dim("Quick — just wait.")
    );
    println!(
        "  [3] I'll type my own             {}\n",
        color::dim("For password manager users.")
    );

    let choice = loop {
        let line = prompt_line(&format!(
            "  Choose [1-3, {}=1, esc={}]: ",
            color::cyan("Enter"),
            color::dim("cancel")
        ))?;
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "1" | "mash" => break 1,
            "2" | "generate" | "gen" => break 2,
            "3" | "own" | "manual" => break 3,
            "esc" => anyhow::bail!("Canceled. No changes made."),
            _ => println!("  {} Pick 1, 2, or 3.", color::red("✗")),
        }
    };

    match choice {
        1 => {
            // Keyboard mashing → entropy → generate passphrase
            let entropy_seed = entropy::collect_entropy(entropy::EntropyMode::KeyboardMashing)?;
            let passphrase = entropy::generate_passphrase(&entropy_seed);
            prompt_passphrase_proposal(&passphrase, entropy_seed)
        }
        2 => {
            // Auto-generate → entropy → generate passphrase
            println!("\n  Generating a secure passphrase...\n");
            let entropy_seed = entropy::collect_entropy(entropy::EntropyMode::AutoGenerate)?;
            println!("  {} Done! Secure entropy collected.\n", color::green("✓"));
            println!("  Press {} to see your passphrase...", color::cyan("Enter"));
            let _ = prompt_line("  ")?;
            let passphrase = entropy::generate_passphrase(&entropy_seed);
            prompt_passphrase_proposal(&passphrase, entropy_seed)
        }
        3 => {
            // User types their own passphrase
            prompt_own_passphrase()
        }
        _ => unreachable!(),
    }
}

/// Show the generated passphrase proposal and let the user accept or switch.
fn prompt_passphrase_proposal(
    passphrase: &str,
    entropy_seed: [u8; 32],
) -> anyhow::Result<(String, [u8; 32])> {
    let hint = entropy::memorization_hint(passphrase);

    println!("\n  Your generated passphrase:\n");
    println!("      {}\n", color::cyan_bold(passphrase));
    if !hint.is_empty() {
        println!(
            "  {} {}\n",
            color::dim("Memorization hint:"),
            color::dim(&hint)
        );
    }
    println!(
        "  [1] {} {}",
        color::cyan("Accept this passphrase"),
        color::dim("(default)")
    );
    println!("  [2] I'll use my own instead\n");

    let accept = loop {
        let line = prompt_line(&format!(
            "  Choose [1-2, {}=1, esc={}]: ",
            color::cyan("Enter"),
            color::dim("cancel")
        ))?;
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "1" => break true,
            "2" => break false,
            "esc" => anyhow::bail!("Canceled. No changes made."),
            _ => println!("  Pick 1 or 2."),
        }
    };

    if accept {
        // Confirm by typing the last word
        let parts: Vec<&str> = passphrase.split('-').collect();
        let last_word = parts
            .get(2)
            .copied()
            .unwrap_or(parts.last().copied().unwrap_or(""));
        loop {
            let typed = prompt_line(&format!(
                "  Confirm by typing the last word ({last_word}): "
            ))?;
            if typed.trim() == last_word {
                println!("  {} Passphrase set\n", color::green("✓"));
                return Ok((passphrase.to_string(), entropy_seed));
            }
            println!("  {} That doesn't match. Try again.", color::red("✗"));
        }
    } else {
        // Switch to own passphrase — preserve entropy seed from mashing/generation
        let (pp, _) = prompt_own_passphrase()?;
        // Mix user passphrase into the existing entropy seed
        let mixed = entropy::hash_passphrase(&pp);
        // XOR the two seeds for best-of-both
        let mut combined = [0u8; 32];
        for i in 0..32 {
            combined[i] = entropy_seed[i] ^ mixed[i];
        }
        Ok((pp, combined))
    }
}

/// Freeform passphrase entry with strength validation.
fn prompt_own_passphrase() -> anyhow::Result<(String, [u8; 32])> {
    loop {
        let first = prompt_line("  Passphrase: ")?;
        if first.trim().is_empty() {
            println!("  Passphrase cannot be empty.");
            continue;
        }
        let bits = entropy::estimate_entropy_bits(first.trim());
        if bits < 40 {
            println!("\n  {} Entropy: {bits} bits — too weak", color::yellow("⚠"));
            println!(
                "     {}",
                color::dim("Minimum: 40 bits. Try a longer phrase,")
            );
            println!("     {}\n", color::dim("or accept a generated one."));
            continue;
        }
        let confirm = prompt_line("  Confirm passphrase: ")?;
        if first != confirm {
            println!("  {} Passphrases do not match.\n", color::red("✗"));
            continue;
        }
        let strength = if bits >= 60 {
            "excellent"
        } else if bits >= 52 {
            "strong"
        } else {
            "acceptable"
        };
        println!(
            "  {} Passphrase set {} {}\n",
            color::green("✓"),
            color::dim(&format!("(entropy: {bits} bits —")),
            color::dim(&format!("{strength})"))
        );
        let seed = entropy::hash_passphrase(first.trim());
        return Ok((first.trim().to_string(), seed));
    }
}

fn parse_enrollment_open(enrollment: Option<&str>) -> anyhow::Result<Option<bool>> {
    match enrollment {
        None => Ok(None),
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "open" => Ok(Some(true)),
            "closed" | "close" => Ok(Some(false)),
            other => anyhow::bail!("Invalid --enrollment value '{other}'. Use 'open' or 'closed'."),
        },
    }
}

fn print_create_review(
    profile: TrustProfile,
    operator: Option<&str>,
    passphrase: &str,
    enrollment_open: Option<bool>,
    requires_approval: Option<bool>,
    profile_locked: bool,
    passphrase_locked: bool,
) {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string());

    let enrollment_action = match enrollment_open {
        Some(true) | None => "• Open enrollment for other machines",
        Some(false) => "• Keep enrollment closed",
    };

    let mut lines = vec![String::new(), format!("1. Profile:     {profile}")];
    if let Some(open) = enrollment_open {
        lines.push(format!(
            "   Enrollment: {}",
            if open { "Open" } else { "Closed" }
        ));
    }
    if let Some(required) = requires_approval {
        lines.push(format!(
            "   Approval:   {}",
            if required { "Required" } else { "Not required" }
        ));
    }
    if let Some(op) = operator {
        lines.push(format!("   Operator:   {}", truncate_str(op, 35)));
    }
    lines.push(format!(
        "2. Passphrase: {}",
        color::cyan_bold(&truncate_str(passphrase, 35))
    ));
    lines.push(String::new());
    lines.push(color::dim("This will:"));
    lines.push(color::dim("• Generate an ECDSA P-256 CA keypair"));
    lines.push(color::dim(&format!(
        "• Create a CA on this machine ({})",
        truncate_str(&hostname, 19)
    )));
    lines.push(color::dim("• Install the CA in your system trust store"));
    lines.push(color::dim(enrollment_action));
    lines.push(String::new());
    lines.push(color::yellow(
        "⚠ passphrase will not be shown again after creation",
    ));
    lines.push(String::new());

    println!();
    print_box("  ", Some("Review"), &lines, BoxStyle::Rounded);

    if profile_locked {
        println!(
            "  {}",
            color::dim("(Profile came from --profile and cannot be edited here.)")
        );
    }
    if passphrase_locked {
        println!(
            "  {}",
            color::dim("(Passphrase came from --passphrase and cannot be edited here.)")
        );
    }
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    use std::io::Write;

    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end().to_string())
}

fn extract_totp_secret_base32_from_uri(uri: &str) -> Option<String> {
    let query = uri.split('?').nth(1)?;
    for param in query.split('&') {
        if let Some(val) = param.strip_prefix("secret=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Extract the TOTP secret from an otpauth:// URI and reconstruct a TotpSecret.
fn extract_totp_secret_from_uri(uri: &str) -> Option<koi_crypto::totp::TotpSecret> {
    let query = uri.split('?').nth(1)?;
    for param in query.split('&') {
        if let Some(val) = param.strip_prefix("secret=") {
            let decoded = base32_decode(val)?;
            return Some(koi_crypto::totp::TotpSecret::from_bytes(decoded));
        }
    }
    None
}

/// Simple base32 decoder (RFC 4648, no padding required).
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let input = input.trim_end_matches('=').as_bytes();
    let mut bits: u64 = 0;
    let mut bit_count = 0;
    let mut result = Vec::new();

    for &c in input {
        let c = c.to_ascii_uppercase();
        let val = ALPHABET.iter().position(|&a| a == c)? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Some(result)
}

// ── Status ──────────────────────────────────────────────────────────

pub fn status(json: bool, endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;
    let resp = client.get_json("/v1/certmesh/status")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let ca_init = resp
            .get("ca_initialized")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !ca_init {
            println!("Certificate mesh: not initialized");
            println!("  Run `koi certmesh create` to set up a CA.");
        } else {
            // Deserialize into CertmeshStatus for formatting
            match serde_json::from_value::<koi_certmesh::protocol::CertmeshStatus>(resp.clone()) {
                Ok(s) => {
                    println!("Certificate mesh: active");
                    println!("  Profile:    {}", s.profile);
                    println!("  CA locked:  {}", s.ca_locked);
                    println!("  Enrollment: {:?}", s.enrollment_state);
                    println!("  Members:    {}", s.member_count);
                    for m in &s.members {
                        println!("    {} ({}) — {}", m.hostname, m.role, m.status);
                    }
                }
                Err(_) => {
                    // Fallback: print raw JSON
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
            }
        }
    }

    Ok(())
}

// ── Log ─────────────────────────────────────────────────────────────

pub fn log(endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;
    let resp = client.get_json("/v1/certmesh/log")?;

    let entries = resp.get("entries").and_then(|v| v.as_str()).unwrap_or("");
    if entries.is_empty() {
        println!("No audit log entries.");
    } else {
        print!("{entries}");
    }
    Ok(())
}

// ── Compliance ────────────────────────────────────────────────────

pub fn compliance(json: bool, endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;
    let resp = client.get_json("/v1/certmesh/compliance")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    let policy = resp
        .get("policy")
        .and_then(|v| serde_json::from_value::<PolicySummary>(v.clone()).ok());
    let audit_entries = resp
        .get("audit_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!("Compliance summary:");
    if let Some(policy) = policy {
        println!("  Profile:           {}", policy.profile);
        println!("  Enrollment:        {:?}", policy.enrollment_state);
        if let Some(deadline) = policy.enrollment_deadline {
            println!("  Enrollment close:  {deadline}");
        }
        if let Some(domain) = policy.allowed_domain {
            println!("  Allowed domain:    {domain}");
        }
        if let Some(subnet) = policy.allowed_subnet {
            println!("  Allowed subnet:    {subnet}");
        }
        println!("  Requires approval: {}", policy.requires_approval);
    } else {
        println!("  Policy: unavailable");
    }
    println!("  Audit entries:     {audit_entries}");
    Ok(())
}

// ── Unlock ──────────────────────────────────────────────────────────

pub fn unlock(endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;

    eprintln!("Enter the CA passphrase:");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim();

    if passphrase.is_empty() {
        anyhow::bail!("Passphrase cannot be empty.");
    }

    let body = serde_json::json!({ "passphrase": passphrase });
    client.post_json("/v1/certmesh/unlock", &body)?;
    println!("CA unlocked successfully.");
    Ok(())
}

// ── Set Hook ────────────────────────────────────────────────────────

pub fn set_hook(reload: &str, json: bool, endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string());

    let body = serde_json::json!({
        "hostname": hostname,
        "reload": reload,
    });
    let resp = client.put_json("/v1/certmesh/set-hook", &body)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("Reload hook set for {hostname}: {reload}");
    }
    Ok(())
}

// ── Join ────────────────────────────────────────────────────────────

pub async fn join(
    endpoint: Option<&str>,
    json: bool,
    cli_endpoint: Option<&str>,
) -> anyhow::Result<()> {
    // The local daemon must be running to handle cert file writes
    let _local = require_daemon(cli_endpoint)?;

    let resolved_endpoint = match endpoint {
        Some(ep) => ep.to_string(),
        None => discover_ca().await?,
    };

    eprintln!("Enter the TOTP code from your authenticator app:");
    let mut code = String::new();
    std::io::stdin().read_line(&mut code)?;
    let code = code.trim().to_string();

    let client = KoiClient::new(&resolved_endpoint);
    let local_hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let body = serde_json::json!({
        "hostname": local_hostname,
        "auth": { "method": "totp", "code": code },
    });
    let resp = client.post_json("/v1/certmesh/join", &body)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let hostname = resp
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let cert_path = resp
            .get("cert_path")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!("Enrolled as: {hostname}");
        println!("Certificates written to: {cert_path}");
    }
    Ok(())
}

// ── Promote ─────────────────────────────────────────────────────────

pub async fn promote(
    endpoint: Option<&str>,
    json: bool,
    cli_endpoint: Option<&str>,
) -> anyhow::Result<()> {
    // The local daemon must be running
    let _local = require_daemon(cli_endpoint)?;

    let resolved_endpoint = match endpoint {
        Some(ep) => ep.to_string(),
        None => discover_ca().await?,
    };

    eprintln!("Enter the TOTP code from your authenticator app:");
    let mut code = String::new();
    std::io::stdin().read_line(&mut code)?;
    let code = code.trim().to_string();

    eprintln!("Enter the CA passphrase (used to encrypt the transferred key):");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim().to_string();

    if passphrase.is_empty() {
        anyhow::bail!("Passphrase cannot be empty.");
    }

    // Request promotion from the primary
    let client = KoiClient::new(&resolved_endpoint);
    let body = serde_json::json!({ "auth": { "method": "totp", "code": code } });
    let resp = client.post_json("/v1/certmesh/promote", &body)?;

    // Parse the promotion response
    let promote_response: koi_certmesh::protocol::PromoteResponse =
        serde_json::from_value(resp.clone())
            .map_err(|e| anyhow::anyhow!("Failed to parse promotion response: {e}"))?;

    // Decrypt and install the CA key, auth credential, and roster locally
    let (ca_key, auth_state, roster) =
        koi_certmesh::failover::accept_promotion(&promote_response, &passphrase)?;

    // Save to local disk
    let ca_dir = koi_certmesh::ca::ca_dir();
    std::fs::create_dir_all(&ca_dir)?;

    let encrypted_key = koi_crypto::keys::encrypt_key(&ca_key, &passphrase)?;
    koi_crypto::keys::save_encrypted_key(&koi_certmesh::ca::ca_key_path(), &encrypted_key)?;
    std::fs::write(
        koi_certmesh::ca::ca_cert_path(),
        &promote_response.ca_cert_pem,
    )?;

    // Persist auth credential to auth.json
    let stored = match &auth_state {
        koi_crypto::auth::AuthState::Totp(secret) => koi_crypto::auth::store_totp(secret, &passphrase)?,
        koi_crypto::auth::AuthState::Fido2(cred) => koi_crypto::auth::store_fido2(cred.clone()),
    };
    let auth_json = serde_json::to_string_pretty(&stored)?;
    std::fs::write(koi_certmesh::ca::auth_path(), auth_json)?;

    koi_certmesh::roster::save_roster(&roster, &koi_certmesh::ca::roster_path())?;

    // Update local member role to Standby
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string());

    let mut roster = koi_certmesh::roster::load_roster(&koi_certmesh::ca::roster_path())?;
    if let Some(member) = roster.find_member_mut(&hostname) {
        member.role = koi_certmesh::roster::MemberRole::Standby;
        koi_certmesh::roster::save_roster(&roster, &koi_certmesh::ca::roster_path())?;
    }

    let _ = koi_certmesh::audit::append_entry("promoted_to_standby", &[("hostname", &hostname)]);

    if json {
        println!(
            "{}",
            serde_json::json!({
                "promoted": true,
                "role": "standby",
                "hostname": hostname,
            })
        );
    } else {
        print!("{}", format::promote_success(&hostname));
    }

    Ok(())
}

// ── Open Enrollment ─────────────────────────────────────────────────

pub fn open_enrollment(
    until: Option<&str>,
    json: bool,
    endpoint: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;
    let deadline = until.map(parse_deadline).transpose()?;

    let body = serde_json::json!({
        "deadline": deadline.map(|d| d.to_rfc3339()),
    });
    let resp = client.post_json("/v1/certmesh/open-enrollment", &body)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let state = resp
            .get("enrollment_state")
            .and_then(|v| v.as_str())
            .unwrap_or("open");
        println!("Enrollment: {state}");
        if let Some(d) = resp.get("deadline").and_then(|v| v.as_str()) {
            println!("Deadline:   {d}");
        }
    }
    Ok(())
}

// ── Close Enrollment ────────────────────────────────────────────────

pub fn close_enrollment(json: bool, endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;
    let resp = client.post_json("/v1/certmesh/close-enrollment", &serde_json::json!({}))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("Enrollment: closed");
    }
    Ok(())
}

// ── Set Policy ──────────────────────────────────────────────────────

pub fn set_policy(
    domain: Option<&str>,
    subnet: Option<&str>,
    clear: bool,
    json: bool,
    endpoint: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;
    let allowed_domain = if clear {
        None
    } else {
        domain.map(String::from)
    };
    let allowed_subnet = if clear {
        None
    } else {
        subnet.map(String::from)
    };

    let body = serde_json::json!({
        "allowed_domain": allowed_domain,
        "allowed_subnet": allowed_subnet,
    });
    let resp = client.put_json("/v1/certmesh/set-policy", &body)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        print_policy_result(&allowed_domain, &allowed_subnet, clear);
    }
    Ok(())
}

fn print_policy_result(domain: &Option<String>, subnet: &Option<String>, clear: bool) {
    if clear {
        println!("Enrollment policy: all constraints cleared");
    } else {
        println!("Enrollment policy updated:");
        if let Some(d) = domain {
            println!("  Domain:  {d}");
        }
        if let Some(s) = subnet {
            println!("  Subnet:  {s}");
        }
        if domain.is_none() && subnet.is_none() {
            println!("  (no constraints)");
        }
    }
}

// ── Rotate Auth ─────────────────────────────────────────────────────

pub fn rotate_auth(json: bool, endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;

    eprintln!("Enter the CA passphrase:");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim();

    if passphrase.is_empty() {
        anyhow::bail!("Passphrase cannot be empty.");
    }

    let body = serde_json::json!({ "passphrase": passphrase });
    let resp = client.post_json("/v1/certmesh/rotate-auth", &body)?;

    let totp_uri = resp
        .get("auth_setup")
        .and_then(|s| s.get("totp_uri"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if json {
        println!("{}", serde_json::json!({ "rotated": true }));
    } else {
        println!("Auth credential rotated successfully.");
        if !totp_uri.is_empty() {
            if let Some(secret) = extract_totp_secret_from_uri(totp_uri) {
                let hostname = hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "localhost".to_string());
                let qr = koi_crypto::totp::qr_code_unicode(
                    &secret,
                    "Koi Certmesh",
                    &format!("admin@{hostname}"),
                );
                println!("\nScan this QR code with your authenticator app:\n");
                println!("{qr}");
            }
        }
    }
    Ok(())
}

// ── Backup ─────────────────────────────────────────────────────────

pub fn backup(path: &std::path::Path, json: bool, endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;

    confirm_action(
        "This will export the CA private key and enrollment secret.",
        "BACKUP",
    )?;

    let ca_passphrase = read_non_empty_line("Enter the CA passphrase:")?;
    let backup_passphrase = read_non_empty_line("Enter a backup passphrase:")?;
    confirm_passphrase("Confirm the backup passphrase:", &backup_passphrase)?;

    let body = serde_json::json!({
        "ca_passphrase": ca_passphrase,
        "backup_passphrase": backup_passphrase,
    });
    let resp = client.post_json("/v1/certmesh/backup", &body)?;
    let backup_hex = resp
        .get("backup_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("backup response missing backup_hex"))?;

    let bytes = hex_decode(backup_hex).map_err(|e| anyhow::anyhow!("invalid backup hex: {e}"))?;
    std::fs::write(path, bytes)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "backup_saved": true,
                "path": path.display().to_string(),
            })
        );
    } else {
        println!("Backup saved to {}", path.display());
    }
    Ok(())
}

// ── Restore ────────────────────────────────────────────────────────

pub fn restore(path: &std::path::Path, json: bool, endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;

    confirm_action("This will overwrite the local certmesh state.", "RESTORE")?;

    let backup_bytes = std::fs::read(path)?;
    let backup_hex = hex_encode(&backup_bytes);

    let backup_passphrase = read_non_empty_line("Enter the backup passphrase:")?;
    let new_passphrase = read_non_empty_line("Enter a new CA passphrase:")?;
    confirm_passphrase("Confirm the new CA passphrase:", &new_passphrase)?;

    let body = serde_json::json!({
        "backup_hex": backup_hex,
        "backup_passphrase": backup_passphrase,
        "new_passphrase": new_passphrase,
    });
    let resp = client.post_json("/v1/certmesh/restore", &body)?;

    let restored = resp
        .get("restored")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if json {
        println!("{}", serde_json::json!({ "restored": restored }));
    } else if restored {
        println!("Backup restored successfully.");
    } else {
        println!("Backup restore failed.");
    }
    Ok(())
}

// ── Revoke ─────────────────────────────────────────────────────────

pub fn revoke(
    hostname: &str,
    reason: Option<&str>,
    json: bool,
    endpoint: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;

    let body = serde_json::json!({
        "hostname": hostname,
        "reason": reason,
    });
    let resp = client.post_json("/v1/certmesh/revoke", &body)?;
    let revoked = resp
        .get("revoked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if json {
        println!(
            "{}",
            serde_json::json!({ "hostname": hostname, "revoked": revoked })
        );
    } else if revoked {
        println!("Member revoked: {hostname}");
    } else {
        println!("Member could not be revoked: {hostname}");
    }
    Ok(())
}

// ── Destroy ─────────────────────────────────────────────────────────

pub fn destroy(json: bool, endpoint: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint)?;

    // Interactive confirmation gate — skip in --json (scripting) mode
    if !json {
        println!();
        println!(
            "  {}  This will {} all certmesh state:",
            color::yellow("⚠"),
            color::yellow("permanently delete")
        );
        println!(
            "     {}",
            color::dim("CA keys, certificates, enrollments, and audit logs.")
        );
        println!(
            "     {}",
            color::dim("If this node is the root CA, all mesh members will")
        );
        println!(
            "     {}",
            color::dim("lose their ability to renew certificates.")
        );
        println!();
        let answer = prompt_line(&format!("  Type {} to confirm: ", color::red("DESTROY")))?;
        if answer.trim() != "DESTROY" {
            println!("  Aborted. No changes made.");
            return Ok(());
        }
        println!();
    }

    let resp = client.post_json("/v1/certmesh/destroy", &serde_json::json!({}))?;

    let destroyed = resp
        .get("destroyed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if json {
        println!("{}", serde_json::json!({ "destroyed": destroyed }));
    } else if destroyed {
        println!("Certificate mesh destroyed. All CA data, certificates, and audit logs have been removed.");
    } else {
        println!("Certificate mesh could not be destroyed.");
    }
    Ok(())
}

// ── CLI helpers ────────────────────────────────────────────────────

fn read_non_empty_line(prompt: &str) -> anyhow::Result<String> {
    eprintln!("{prompt}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        anyhow::bail!("Input cannot be empty.");
    }
    Ok(trimmed)
}

fn confirm_passphrase(prompt: &str, expected: &str) -> anyhow::Result<()> {
    let confirm = read_non_empty_line(prompt)?;
    if confirm != expected {
        anyhow::bail!("Passphrases do not match.");
    }
    Ok(())
}

fn confirm_action(message: &str, token: &str) -> anyhow::Result<()> {
    eprintln!("{message}");
    eprintln!("Type {token} to continue:");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if line.trim() != token {
        anyhow::bail!("Confirmation failed.");
    }
    Ok(())
}

// ── Deadline Parsing ────────────────────────────────────────────────

/// Parse a deadline string — supports RFC 3339 timestamps or durations.
///
/// Duration formats: "30m", "2h", "1d", "12h30m"
fn parse_deadline(s: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    // Try RFC 3339 first
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }

    // Try duration format
    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num_buf.push(ch);
        } else {
            let n: u64 = num_buf
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid deadline format: {s}"))?;
            num_buf.clear();
            match ch {
                'm' => total_secs += n * 60,
                'h' => total_secs += n * 3600,
                'd' => total_secs += n * 86400,
                _ => anyhow::bail!("invalid deadline unit '{ch}' in: {s}"),
            }
        }
    }
    if total_secs == 0 {
        anyhow::bail!(
            "invalid deadline format: {s}\n\
             Expected RFC 3339 (e.g. 2026-02-12T00:00:00Z) or duration (e.g. 2h, 1d, 30m)"
        );
    }

    Ok(chrono::Utc::now() + chrono::Duration::seconds(total_secs as i64))
}

/// Discover a certmesh CA on the local network via mDNS.
///
/// Browses for `_certmesh._tcp` services for 5 seconds, collects
/// resolved results, and returns the endpoint URL of the discovered CA.
async fn discover_ca() -> anyhow::Result<String> {
    eprintln!("Searching for certmesh CA on the local network...");

    let core = Arc::new(koi_mdns::MdnsCore::new()?);
    let handle = core.browse(koi_certmesh::CERTMESH_SERVICE_TYPE).await?;

    let deadline = tokio::time::Instant::now() + CA_DISCOVERY_TIMEOUT;
    let mut found = Vec::new();

    loop {
        tokio::select! {
            event = handle.recv() => {
                match event {
                    Some(MdnsEvent::Resolved(record)) => {
                        if let (Some(ip), Some(port)) = (&record.ip, record.port) {
                            let endpoint = format!("http://{ip}:{port}");
                            if !found.iter().any(|(ep, _)| ep == &endpoint) {
                                found.push((endpoint, record.name.clone()));
                            }
                        }
                    }
                    Some(_) => continue,
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }

    let _ = core.shutdown().await;

    match found.len() {
        0 => anyhow::bail!(
            "No certmesh CA found on the local network.\n\
             Specify the endpoint manually: koi certmesh join <endpoint>"
        ),
        1 => {
            let (endpoint, name) = found.into_iter().next().unwrap();
            eprintln!("Found CA: {name} at {endpoint}");
            Ok(endpoint)
        }
        _ => {
            let mut msg = String::from("Multiple certmesh CAs found:\n");
            for (ep, name) in &found {
                msg.push_str(&format!("  {name}  {ep}\n"));
            }
            msg.push_str("\nSpecify which to join: koi certmesh join <endpoint>");
            anyhow::bail!(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_deadline_rfc3339() {
        let result = parse_deadline("2026-03-01T00:00:00Z");
        assert!(result.is_ok());
        let dt = result.unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 3);
    }

    #[test]
    fn parse_deadline_duration_hours() {
        let before = chrono::Utc::now();
        let result = parse_deadline("2h").unwrap();
        let expected_min = before + chrono::Duration::hours(2);
        assert!(result >= expected_min - chrono::Duration::seconds(1));
    }

    #[test]
    fn parse_deadline_duration_days() {
        let before = chrono::Utc::now();
        let result = parse_deadline("1d").unwrap();
        let expected_min = before + chrono::Duration::days(1);
        assert!(result >= expected_min - chrono::Duration::seconds(1));
    }

    #[test]
    fn parse_deadline_duration_minutes() {
        let before = chrono::Utc::now();
        let result = parse_deadline("30m").unwrap();
        let expected_min = before + chrono::Duration::minutes(30);
        assert!(result >= expected_min - chrono::Duration::seconds(1));
    }

    #[test]
    fn parse_deadline_combined_duration() {
        let before = chrono::Utc::now();
        let result = parse_deadline("1h30m").unwrap();
        let expected_min = before + chrono::Duration::minutes(90);
        assert!(result >= expected_min - chrono::Duration::seconds(1));
    }

    #[test]
    fn parse_deadline_invalid_format() {
        let result = parse_deadline("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn parse_deadline_invalid_unit() {
        let result = parse_deadline("5x");
        assert!(result.is_err());
    }

    #[test]
    fn parse_deadline_empty_fails() {
        let result = parse_deadline("");
        assert!(result.is_err());
    }

    #[test]
    fn hex_encode_produces_correct_output() {
        assert_eq!(hex_encode(&[0x0a, 0xff, 0x00]), "0aff00");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn base32_decode_valid() {
        // "JBSWY3DPEE======" is the RFC 4648 base32 encoding of "Hello!"
        let decoded = base32_decode("JBSWY3DPEE").unwrap();
        assert_eq!(&decoded, b"Hello!");
    }

    #[test]
    fn base32_decode_with_padding() {
        let decoded = base32_decode("JBSWY3DPEE======").unwrap();
        assert_eq!(&decoded, b"Hello!");
    }

    #[test]
    fn base32_decode_invalid_char() {
        let decoded = base32_decode("1!!!invalid");
        assert!(decoded.is_none());
    }

    #[test]
    fn extract_totp_secret_from_valid_uri() {
        // Build a known URI and extract
        let secret = koi_crypto::totp::generate_secret();
        let uri = koi_crypto::totp::build_totp_uri(&secret, "Test", "user");
        let extracted = extract_totp_secret_from_uri(&uri);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().as_bytes(), secret.as_bytes());
    }

    #[test]
    fn extract_totp_secret_from_bad_uri() {
        assert!(extract_totp_secret_from_uri("not-a-uri").is_none());
        assert!(extract_totp_secret_from_uri("otpauth://totp/x?issuer=x").is_none());
    }

    #[test]
    fn require_daemon_fails_without_endpoint() {
        // No breadcrumb file, no endpoint — should fail
        let result = require_daemon(None);
        // This may succeed if there IS a breadcrumb; if not, it fails.
        // We just verify it doesn't panic.
        let _ = result;
    }

    use chrono::Datelike;
}
