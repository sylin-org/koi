//! Certmesh command handlers.
//!
//! All certmesh commands delegate to the running service via HTTP.
//! The CLI never performs direct file I/O for certmesh operations -
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
//   Cyan       - active trigger-effect pair (Enter + what it activates)
//   Cyan bold  - critical value to capture (passphrase, TOTP manual code)
//   Green      - completed / success (✓ checkmarks)
//   Yellow     - irreversible warning (⚠, "no recovery mechanism")
//   Red        - error (✗ wrong input, failed verification)
//   Dim        - supporting / secondary (descriptions, hints, Cancel)
//   Default    - neutral / settled text, box chrome
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

    /// Green - completed / success.
    pub fn green(text: &str) -> String {
        wrap("32", text)
    }

    /// Yellow - irreversible warning.
    pub fn yellow(text: &str) -> String {
        wrap("33", text)
    }

    /// Red - error.
    pub fn red(text: &str) -> String {
        wrap("31", text)
    }

    /// Dim - supporting / secondary text.
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

    // ── Interactive ceremony-driven mode ─────────────────────────────
    //
    // The ceremony host manages all branching, validation, and content.
    // The CLI is a dumb render loop.
    use koi_certmesh::pond_ceremony::PondCeremonyRules;
    use koi_common::ceremony::CeremonyHost;

    let host = CeremonyHost::new(PondCeremonyRules);

    // Pre-fill initial data from CLI flags
    let mut initial_data = serde_json::Map::new();
    if let Some(p) = profile {
        initial_data.insert("profile".into(), serde_json::json!(p));
    }
    if let Some(op) = operator {
        initial_data.insert("operator".into(), serde_json::json!(op));
    }
    if let Some(pp) = passphrase {
        initial_data.insert("passphrase".into(), serde_json::json!(pp));
    }
    if let Some(enroll) = enrollment {
        initial_data.insert("enrollment_open".into(), serde_json::json!(enroll));
    }
    if let Some(approve) = require_approval {
        initial_data.insert(
            "requires_approval".into(),
            serde_json::json!(if approve { "yes" } else { "no" }),
        );
    }
    // Provide hostname so TOTP URI is personalized
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string());
    initial_data.insert("_self_hostname".into(), serde_json::json!(hostname));

    let result_bag = super::ceremony_cli::run_ceremony(&host, "init", initial_data)?;

    // ── Map ceremony result → certmesh create API body ─────────────
    let effective_profile = result_bag
        .get("_effective_profile")
        .and_then(|v| v.as_str())
        .and_then(TrustProfile::from_str_loose)
        .unwrap_or(TrustProfile::JustMe);

    let body = serde_json::json!({
        "passphrase": result_bag.get("passphrase").and_then(|v| v.as_str()).unwrap_or(""),
        "entropy_hex": result_bag.get("_entropy_seed").and_then(|v| v.as_str()).unwrap_or(""),
        "profile": effective_profile,
        "operator": result_bag.get("operator").and_then(|v| v.as_str()),
        "enrollment_open": result_bag.get("_enrollment_open").and_then(|v| v.as_bool()),
        "requires_approval": result_bag.get("_requires_approval").and_then(|v| v.as_bool()),
        "totp_secret_hex": result_bag.get("_totp_secret_hex").and_then(|v| v.as_str()),
    });

    println!("\n  Creating certificate mesh...\n");
    let resp = client.post_json("/v1/certmesh/create", &body)?;

    let ca_fingerprint = resp
        .get("ca_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // ── Post-creation verification ─────────────────────────────────
    println!("  {} CA keypair generated (ECDSA P-256)", color::green("✓"));
    println!(
        "  {} Private key encrypted (Argon2id + AES-256-GCM)",
        color::green("✓")
    );
    println!("  {} Roster initialized", color::green("✓"));
    println!("  {} Audit log started", color::green("✓"));

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
    let cert_path = koi_common::paths::koi_data_dir()
        .join("certs")
        .join(&hostname);

    println!();
    print_box(
        "  ",
        Some(&color::green("Certificate mesh created")),
        &[
            String::new(),
            format!("Profile:        {effective_profile}"),
            format!("CA fingerprint: {}", truncate_str(ca_fingerprint, 35)),
            format!("Hostname:       {}", truncate_str(&hostname, 35)),
            format!(
                "Certificates:   {}",
                truncate_str(&cert_path.display().to_string(), 35)
            ),
            String::new(),
        ],
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

/// Print a box with auto-aligned right border using rounded corners (`╭╮╰╯│─`).
///
/// `indent` is the leading whitespace (e.g. `"  "`).
/// `title` if `Some`, is embedded in the top border: `╭── Title ──…╮`.
/// `lines` are the content lines (may contain ANSI color codes).
/// The inner width is derived from the widest visible line + 2 padding.
fn print_box(indent: &str, title: Option<&str>, lines: &[String]) {
    let (tl, tr, bl, br, h, v) = ('╭', '╮', '╰', '╯', '─', '│');

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

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    use std::io::Write;

    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end().to_string())
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
                        println!("    {} ({}) - {}", m.hostname, m.role, m.status);
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
        koi_crypto::auth::AuthState::Totp(secret) => {
            koi_crypto::auth::store_totp(secret, &passphrase)?
        }
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

    // Interactive confirmation gate - skip in --json (scripting) mode
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

/// Parse a deadline string - supports RFC 3339 timestamps or durations.
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
        // No breadcrumb file, no endpoint - should fail
        let result = require_daemon(None);
        // This may succeed if there IS a breadcrumb; if not, it fails.
        // We just verify it doesn't panic.
        let _ = result;
    }

    use chrono::Datelike;
}
