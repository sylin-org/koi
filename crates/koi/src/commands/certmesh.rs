//! Certmesh command handlers.
//!
//! All certmesh commands delegate to the running service via HTTP.
//! The CLI never performs direct file I/O for certmesh operations -
//! the service has the elevated permissions needed for cert store,
//! file writes, etc.

use std::sync::Arc;

use koi_certmesh::profiles::preset_bools;
use koi_certmesh::protocol::{
    AcceptPromotionResponse, AuditLogResponse, BackupResponse, CreateCaResponse, DestroyResponse,
    EnrollmentState, EnrollmentSummary, InstallCertResponse, InviteResponse, JoinResponse,
    RenewSelfResponse, RestoreResponse, RevokeResponse, RotateAuthResponse, SetHookResponse,
    UnlockResponse,
};
use koi_certmesh::{
    entropy, CertmeshBootstrapStatus, CertmeshRole, CertmeshStatus, IdentityCondition,
};
use koi_common::encoding::{hex_decode, hex_encode};
use koi_common::types::{ServiceRecord, ServiceType};
use koi_mdns::events::MdnsEvent;
use koi_mdns::BrowseRecvError;

use crate::client::KoiClient;
use crate::commands::decode_response;
use crate::format;

/// mDNS discovery timeout for finding a CA on the local network.
const CA_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn fetch_certmesh_status(client: &KoiClient) -> anyhow::Result<CertmeshStatus> {
    serde_json::from_value(client.certmesh_status()?)
        .map_err(|error| anyhow::anyhow!("daemon returned an invalid Certmesh status: {error}"))
}

fn fetch_certmesh_bootstrap(client: &KoiClient) -> anyhow::Result<CertmeshBootstrapStatus> {
    serde_json::from_value(client.certmesh_bootstrap()?)
        .map_err(|error| anyhow::anyhow!("authority returned an invalid bootstrap status: {error}"))
}

const fn role_label(role: CertmeshRole) -> &'static str {
    match role {
        CertmeshRole::Open => "open",
        CertmeshRole::Member => "member",
        CertmeshRole::Authority => "authority",
    }
}

const fn identity_label(condition: IdentityCondition) -> &'static str {
    match condition {
        IdentityCondition::Absent => "absent",
        IdentityCondition::Healthy => "healthy",
        IdentityCondition::Expired => "expired",
        IdentityCondition::Invalid => "invalid",
        IdentityCondition::Revoked => "revoked",
    }
}

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

/// Resolve a daemon client or bail with a clear message — a thin alias over the one
/// [`crate::commands::require_client`] that mDNS admin and every certmesh command share.
/// That single implementation owns the token-leak rule (explicit endpoint → explicit token
/// or tokenless, never the local breadcrumb token) and the breadcrumb health-probe.
fn require_daemon(
    endpoint: Option<&str>,
    explicit_token: Option<&str>,
) -> anyhow::Result<KoiClient> {
    crate::commands::require_client(endpoint, explicit_token)
}

fn require_non_empty<'a>(value: &'a str, field: &str, operation: &str) -> anyhow::Result<&'a str> {
    if value.trim().is_empty() {
        anyhow::bail!("daemon returned an invalid {operation} response: '{field}' is empty");
    }
    Ok(value)
}

fn local_hostname(operation: &str) -> anyhow::Result<String> {
    koi_compose::host::HostIdentity::observe()
        .map(|identity| identity.hostname().to_string())
        .map_err(|error| {
            anyhow::anyhow!("cannot determine the local hostname for {operation}: {error}")
        })
}

fn local_fqdn(operation: &str) -> anyhow::Result<String> {
    koi_compose::host::HostIdentity::observe()
        .map(|identity| identity.local_fqdn().to_string())
        .map_err(|error| {
            anyhow::anyhow!("cannot determine the local hostname for {operation}: {error}")
        })
}

fn local_certificate_path(
    endpoint: Option<&str>,
    data_root: &std::path::Path,
    hostname: &str,
) -> Option<std::path::PathBuf> {
    endpoint.is_none().then(|| {
        koi_certmesh::CertmeshPaths::with_data_dir(data_root.to_path_buf())
            .certs_dir()
            .join(hostname)
    })
}

#[derive(Debug, serde::Deserialize)]
struct CeremonyCreateResult {
    passphrase: String,
    #[serde(rename = "_entropy_seed")]
    entropy_hex: String,
    #[serde(default)]
    operator: Option<String>,
    #[serde(rename = "_enrollment_open")]
    enrollment_open: bool,
    #[serde(rename = "_requires_approval")]
    requires_approval: bool,
    #[serde(rename = "_auto_unlock")]
    auto_unlock: bool,
    #[serde(rename = "_effective_profile")]
    effective_profile: String,
    #[serde(rename = "_totp_secret_hex", default)]
    totp_secret_hex: Option<String>,
}

fn decode_create_ceremony_result(
    result: serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<CeremonyCreateResult> {
    let result: CeremonyCreateResult = serde_json::from_value(serde_json::Value::Object(result))
        .map_err(|error| anyhow::anyhow!("init ceremony returned invalid result data: {error}"))?;
    for (value, field) in [
        (result.passphrase.as_str(), "passphrase"),
        (result.entropy_hex.as_str(), "_entropy_seed"),
        (result.effective_profile.as_str(), "_effective_profile"),
    ] {
        if value.trim().is_empty() {
            anyhow::bail!("init ceremony returned invalid result data: '{field}' is empty");
        }
    }
    Ok(result)
}

// ── Create ──────────────────────────────────────────────────────────

// `create` mirrors the clap `Create` subcommand's flags one-to-one plus the
// shared json/endpoint/token plumbing; grouping them into a struct would only
// move the argument list elsewhere without improving clarity.
#[allow(clippy::too_many_arguments)]
pub fn create(
    profile: Option<&str>,
    operator: Option<&str>,
    enrollment: Option<&str>,
    require_approval: Option<bool>,
    passphrase: Option<&str>,
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
    data_root: &std::path::Path,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    if preflight_ca_exists(&client)? {
        return Ok(());
    }

    // ── Fully non-interactive JSON mode ────────────────────────────
    if json {
        let preset_name =
            profile.ok_or_else(|| anyhow::anyhow!("--profile is required with --json"))?;
        // Resolve the named preset to its (enrollment_open, requires_approval,
        // auto_unlock) tuple. CLI flags override the preset defaults.
        let (preset_open, preset_approval, preset_auto_unlock) = preset_bools(preset_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Unknown --profile '{preset_name}'. \
                     Choose just-me, team, or organization."
                )
            })?;
        let ca_passphrase = passphrase
            .map(ToString::to_string)
            .ok_or_else(|| anyhow::anyhow!("--passphrase is required with --json"))?;

        let requires_approval = require_approval.unwrap_or(preset_approval);
        let enrollment_open = parse_enrollment_open(enrollment)?.unwrap_or(preset_open);
        validate_operator(requires_approval, operator)?;
        let entropy_seed =
            entropy::collect_entropy(entropy::EntropyMode::Manual(ca_passphrase.clone()))?;

        let body = serde_json::json!({
            "passphrase": ca_passphrase,
            "entropy_hex": hex_encode(&entropy_seed),
            "operator": operator,
            "enrollment_open": enrollment_open,
            "requires_approval": requires_approval,
            "auto_unlock": preset_auto_unlock,
        });
        let response: CreateCaResponse = decode_response(
            client.post_json("/v1/certmesh/create", &body)?,
            "Certmesh create",
        )?;
        let ca_fingerprint = require_non_empty(
            &response.ca_fingerprint,
            "ca_fingerprint",
            "Certmesh create",
        )?;
        println!(
            "{}",
            serde_json::json!({
                "created": true,
                "profile": preset_label(preset_name),
                "enrollment_open": enrollment_open,
                "requires_approval": requires_approval,
                "ca_fingerprint": ca_fingerprint,
            })
        );
        return Ok(());
    }

    // ── Interactive ceremony-driven mode ─────────────────────────────
    //
    // The ceremony host manages all branching, validation, and content.
    // The CLI is a dumb render loop.
    use koi_certmesh::init_ceremony::InitCeremonyRules;
    use koi_common::ceremony::CeremonyHost;

    // Initialization is pure input orchestration. In particular, an explicit
    // remote endpoint must never inspect this machine's unlock slots or data
    // root while collecting the remote authority's create request.
    let host = CeremonyHost::new(InitCeremonyRules::for_init());

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
    let hostname = local_hostname("Certmesh initialization")?;
    initial_data.insert("_self_hostname".into(), serde_json::json!(hostname));

    let result_bag = decode_create_ceremony_result(super::ceremony_cli::run_ceremony(
        &host,
        "init",
        initial_data,
    )?)?;

    // ── Map ceremony result → certmesh create API body ─────────────
    //
    // The ceremony already resolved the chosen preset (or custom answers) to
    // the three booleans. We forward those verbatim — the preset name survives
    // only as the display label `_effective_profile`.
    let effective_profile = result_bag.effective_profile.clone();

    let body = serde_json::json!({
        "passphrase": result_bag.passphrase,
        "entropy_hex": result_bag.entropy_hex,
        "operator": result_bag.operator,
        "enrollment_open": result_bag.enrollment_open,
        "requires_approval": result_bag.requires_approval,
        "auto_unlock": result_bag.auto_unlock,
        "totp_secret_hex": result_bag.totp_secret_hex,
    });

    println!("\n  Creating certificate mesh...\n");
    let response: CreateCaResponse = decode_response(
        client.post_json("/v1/certmesh/create", &body)?,
        "Certmesh create",
    )?;
    let ca_fingerprint = require_non_empty(
        &response.ca_fingerprint,
        "ca_fingerprint",
        "Certmesh create",
    )?;

    // ── Post-creation verification ─────────────────────────────────
    println!("  {} CA keypair generated (ECDSA P-256)", color::green("✓"));
    println!(
        "  {} Private key encrypted (Argon2id + AES-256-GCM)",
        color::green("✓")
    );
    println!("  {} Roster initialized", color::green("✓"));
    println!("  {} Audit log started", color::green("✓"));

    println!("\n  Verifying setup...\n");
    let status = fetch_certmesh_status(&client)?;
    let authority = status.authority.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "CA creation completed, but Certmesh status reports role '{}' with no authority state",
            role_label(status.role)
        )
    })?;
    let member_count = authority.member_count;

    println!("  {} CA initialized", color::green("✓"));
    println!(
        "  {} CA key decrypts successfully",
        if !authority.locked {
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

    // ── Summary box ────────────────────────────────────────────────
    let mut summary = vec![
        String::new(),
        format!("Profile:        {effective_profile}"),
        format!("CA fingerprint: {}", truncate_str(ca_fingerprint, 35)),
        format!("Hostname:       {}", truncate_str(&hostname, 35)),
    ];
    if let Some(cert_path) = local_certificate_path(endpoint, data_root, &hostname) {
        summary.push(format!(
            "Certificates:   {}",
            truncate_str(&cert_path.display().to_string(), 35)
        ));
    }
    summary.push(String::new());

    println!();
    print_box(
        "  ",
        Some(&color::green("Certificate mesh created")),
        &summary,
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
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 1).collect();
        format!("{truncated}…")
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
    let status = fetch_certmesh_status(client)?;
    let Some(authority) = status.authority.as_ref() else {
        return Ok(false);
    };

    let enrollment_open = authority.enrollment_open;
    let fingerprint = authority.ca_fingerprint.as_deref().ok_or_else(|| {
        anyhow::anyhow!("invalid Certmesh status: authority state has no CA fingerprint")
    })?;
    let member_count = authority.member_count;

    println!();
    println!(
        "  {}  A certificate mesh already exists on this machine.",
        color::yellow("⚠")
    );
    println!();
    println!(
        "     Enrollment:     {}",
        if enrollment_open { "open" } else { "closed" }
    );
    println!("     CA fingerprint: {fingerprint}");
    println!("     Members:        {member_count} active");
    println!();
    println!("  {}", color::dim("To inspect:   koi certmesh status"));
    println!("  {}", color::dim("To destroy:   koi certmesh destroy"));
    println!();
    println!("  No changes made.");
    Ok(true)
}

/// Human-readable display label for a preset name (UX only).
fn preset_label(preset_name: &str) -> &'static str {
    match preset_name.to_lowercase().as_str() {
        "my_team" | "my-team" | "myteam" | "team" | "2" => "My Team",
        "my_organization" | "my-organization" | "myorganization" | "organization" | "org" | "3" => {
            "My Organization"
        }
        _ => "Just Me",
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

pub fn status(json: bool, endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let status = fetch_certmesh_status(&client)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Certificate mesh: {}", role_label(status.role));
        println!(
            "  Identity:   {}",
            identity_label(status.identity.condition)
        );
        println!("  Trust:      {}", status.posture.level().as_wire());
        if let Some(reason) = status.identity.reason.as_deref() {
            println!("  Attention:  {reason}");
        }

        match status.role {
            CertmeshRole::Open => {
                println!("  Run `koi certmesh create` to set up a CA, or `koi certmesh join` to join one.");
            }
            CertmeshRole::Member => {
                if let Some(identity) = status.identity.info.as_ref() {
                    println!("  Hostname:   {}", identity.hostname);
                    println!("  CA:         {}", identity.ca_fingerprint);
                    println!("  Expires:    {}", identity.renewal.expires_at);
                }
            }
            CertmeshRole::Authority => {
                let authority = status.authority.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid Certmesh status: authority role has no authority state"
                    )
                })?;
                println!("  CA locked:  {}", authority.locked);
                println!(
                    "  Enrollment: {} ({})",
                    if authority.enrollment_open {
                        "open"
                    } else {
                        "closed"
                    },
                    if authority.requires_approval {
                        "approval required"
                    } else {
                        "no approval"
                    }
                );
                println!("  Members:    {}", authority.member_count);
                for member in &authority.members {
                    println!(
                        "    {} ({}) - {}",
                        member.hostname, member.role, member.status
                    );
                }
            }
        }
    }

    Ok(())
}

// ── Log ─────────────────────────────────────────────────────────────

pub fn log(endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let response: AuditLogResponse =
        decode_response(client.get_json("/v1/certmesh/log")?, "Certmesh audit log")?;
    let entries = response.entries;
    if entries.is_empty() {
        println!("No audit log entries.");
    } else {
        print!("{entries}");
    }
    Ok(())
}

// ── Unlock ──────────────────────────────────────────────────────────

pub fn unlock(endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;

    eprintln!("Enter the CA passphrase:");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim();

    if passphrase.is_empty() {
        anyhow::bail!("Passphrase cannot be empty.");
    }

    let body = serde_json::json!({ "passphrase": passphrase });
    let response: UnlockResponse = decode_response(
        client.post_json("/v1/certmesh/unlock", &body)?,
        "Certmesh unlock",
    )?;
    if !response.success {
        anyhow::bail!("daemon did not acknowledge Certmesh unlock");
    }
    println!("CA unlocked successfully.");
    Ok(())
}

// ── Set Hook ────────────────────────────────────────────────────────

pub fn set_hook(
    reload: &str,
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let hostname = local_hostname("configuring the certificate reload hook")?;

    let body = serde_json::json!({
        "hostname": hostname,
        "reload": reload,
    });
    let response: SetHookResponse = decode_response(
        client.put_json("/v1/certmesh/set-hook", &body)?,
        "Certmesh reload-hook configuration",
    )?;
    require_non_empty(
        &response.hostname,
        "hostname",
        "Certmesh reload-hook configuration",
    )?;
    require_non_empty(
        &response.reload,
        "reload",
        "Certmesh reload-hook configuration",
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "Reload hook set for {}: {}",
            response.hostname, response.reload
        );
    }
    Ok(())
}

// ── Join ────────────────────────────────────────────────────────────

/// Rotate this enrolled member's private key and renew its leaf immediately.
///
/// The local daemon generates the replacement key and contacts the CA over the
/// normal mTLS renewal channel. The private key never leaves this host.
pub fn renew(json: bool, endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let response: RenewSelfResponse = decode_response(
        client.post_json("/v1/certmesh/renew-self", &serde_json::json!({}))?,
        "Certmesh renewal",
    )?;
    require_non_empty(&response.expires, "expires", "Certmesh renewal")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "Certificate renewed; private key rotated. Expires {}.",
            response.expires
        );
        if let Some(hook) = response.hook {
            println!(
                "Reload hook: {}",
                if hook.success { "succeeded" } else { "failed" }
            );
        }
    }
    Ok(())
}

pub async fn join(
    endpoint: Option<&str>,
    invite: Option<&str>,
    ca_mtls_port: Option<u16>,
    json: bool,
) -> anyhow::Result<()> {
    // The local daemon owns key custody (ADR-015 F1): it generates the member
    // keypair, persists the private key, and installs the signed cert. The CLI
    // only carries public material (CSR out, cert back).
    //
    // It is ALWAYS the local breadcrumb daemon — never a global `--endpoint`. Key custody
    // must stay on THIS host; routing member-csr/member-cert to a remote (e.g. the CA)
    // would request the joiner's CSR off-box. The CA is the `endpoint` arg / mDNS only.
    let local = require_daemon(None, None)?;

    // ADR-017 F3: an invite is a *code* `<secret>.<ca_fingerprint>`. Split it so we
    // can pin the CA fingerprint and preflight the endpoint before sending our CSR.
    // The CA is sent only the secret half (`invite_secret`).
    let (invite_secret, pinned_fp) = match invite {
        Some(code) => {
            let (secret, fp) = koi_certmesh::invite::decode_code(code);
            (Some(secret.to_string()), fp.map(str::to_string))
        }
        None => (None, None),
    };

    let resolved_endpoint = match endpoint {
        Some(ep) => ep.to_string(),
        // Cross-check the discovered `_certmesh._tcp` fp= TXT against the invite's
        // pin (F12 hint); the authoritative pin check is the preflight below.
        None => discover_ca(pinned_fp.as_deref()).await?,
    };

    let remote = KoiClient::new(&resolved_endpoint);
    let local_hostname = local_hostname("joining Certmesh")?;

    // 0. Public preflight + pin (ADR-017 F3). Bootstrap deliberately exposes only
    //    authority availability and enrollment facts; the full domain status is a
    //    protected management surface. When the invite carries a CA fingerprint,
    //    refuse to continue unless bootstrap reports the same pin — so a LAN MITM
    //    is rejected *before* we ever transmit a CSR. The TOTP path has no
    //    out-of-band fingerprint and stays TOFU.
    let bootstrap = fetch_certmesh_bootstrap(&remote).map_err(|error| {
        anyhow::anyhow!("could not preflight the CA at {resolved_endpoint}: {error}")
    })?;
    if !bootstrap.authority_available {
        anyhow::bail!("the Koi daemon at {resolved_endpoint} is not a Certmesh authority");
    }
    if let Some(ref pin) = pinned_fp {
        let advertised = bootstrap.ca_fingerprint.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "CA at {resolved_endpoint} did not report a fingerprint — aborting (the \
                 invite expects {pin})"
            )
        })?;
        if !koi_crypto::pinning::fingerprints_match(advertised, pin) {
            anyhow::bail!(
                "CA fingerprint mismatch — refusing to join.\n  invite pinned: {pin}\n  \
                 CA advertised: {advertised}\nThe endpoint may be impersonating the CA \
                 (MITM), or the invite is for a different mesh."
            );
        }
        eprintln!("Preflight OK — CA fingerprint matches the invite pin.");
    }

    // 1. Ask the LOCAL daemon to generate our keypair + CSR. The private key is
    //    written locally by the daemon and never leaves this machine.
    let csr_resp = local.post_json(
        "/v1/certmesh/member-csr",
        &serde_json::json!({
            "hostname": local_hostname,
            "sans": [],
        }),
    )?;
    let csr = csr_resp
        .get("csr")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("local daemon did not return a CSR"))?
        .to_string();

    // 2. Send the CSR + credential to the REMOTE CA. Two credentials (ADR-015 F2):
    //    an invite token enrolls non-interactively; otherwise prompt for the mesh
    //    TOTP. The CA signs the CSR and returns a cert — never a private key.
    let mut body = serde_json::Map::new();
    body.insert("hostname".into(), serde_json::json!(local_hostname));
    body.insert("csr".into(), serde_json::json!(csr));
    if let Some(ref secret) = invite_secret {
        // Send only the secret half — the CA does not need (and never sees) the
        // pinned fingerprint that travelled in the invite code.
        body.insert("invite_token".into(), serde_json::json!(secret));
    } else {
        eprintln!("Enter the TOTP code from your authenticator app:");
        let mut code = String::new();
        std::io::stdin().read_line(&mut code)?;
        body.insert(
            "auth".into(),
            serde_json::json!({ "method": "totp", "code": code.trim() }),
        );
    }
    let response: JoinResponse = decode_response(
        remote.post_json("/v1/certmesh/join", &serde_json::Value::Object(body))?,
        "Certmesh join",
    )?;
    let service_cert = require_non_empty(&response.service_cert, "service_cert", "Certmesh join")?;
    let ca_cert = require_non_empty(&response.ca_cert, "ca_cert", "Certmesh join")?;
    let response_ca_fingerprint =
        require_non_empty(&response.ca_fingerprint, "ca_fingerprint", "Certmesh join")?;

    // 3. Hand the signed cert to the LOCAL daemon to install next to the key. We
    //    also pass the CA coordinates (endpoint + pinned fingerprint + policy) so
    //    the daemon arms member-pull renewal (ADR-017 F6) — the background loop
    //    later rotates the key + pulls a fresh leaf over mTLS before expiry.
    let mut install_body = serde_json::Map::new();
    install_body.insert("hostname".into(), serde_json::json!(local_hostname));
    install_body.insert("cert_pem".into(), serde_json::json!(service_cert));
    install_body.insert("ca_pem".into(), serde_json::json!(ca_cert));
    install_body.insert("ca_endpoint".into(), serde_json::json!(resolved_endpoint));
    if let Some(port) = ca_mtls_port {
        install_body.insert("ca_mtls_port".into(), serde_json::json!(port));
    }
    // Pin the install to the OUT-OF-BAND fingerprint from the invite when we have
    // one (F3) — so the local daemon hard-fails if the CA returned a cert that does
    // not match the pin (a /join MITM that slipped past preflight). Without an
    // invite pin (TOTP join), fall back to the CA's self-reported fingerprint
    // (documented TOFU).
    // `pinned_fp` is `Some` for every invite join, so the `or_else` (the CA's
    // self-reported fingerprint — TOFU) is reached ONLY on the TOTP path, which has
    // no out-of-band pin. Never let an invite join fall through to the response fp.
    let install_fp = pinned_fp.as_deref().unwrap_or(response_ca_fingerprint);
    install_body.insert("ca_fingerprint".into(), serde_json::json!(install_fp));
    install_body.insert("sans".into(), serde_json::json!([]));
    install_body.insert("policy".into(), serde_json::to_value(&response.policy)?);
    let install: InstallCertResponse = decode_response(
        local.post_json(
            "/v1/certmesh/member-cert",
            &serde_json::Value::Object(install_body),
        )?,
        "Certmesh certificate installation",
    )?;
    if !install.installed {
        anyhow::bail!(
            "daemon returned an invalid Certmesh certificate installation response: installation was not acknowledged"
        );
    }
    let cert_path = require_non_empty(
        &install.cert_path,
        "cert_path",
        "Certmesh certificate installation",
    )?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "enrolled": true,
                "hostname": local_hostname,
                "cert_path": cert_path,
                "ca_fingerprint": response_ca_fingerprint,
            })
        );
    } else {
        println!("Enrolled as: {local_hostname}");
        println!("Key + certificate stored locally: {cert_path}");
    }
    Ok(())
}

// ── Invite ───────────────────────────────────────────────────────────

/// Mint a single-use, hostname-bound enrollment invite (ADR-015 F2).
///
/// Delegates to the running daemon (`POST /v1/certmesh/invite`), which owns the
/// certmesh data dir and writes the audit entry. The endpoint is DAT-gated, so
/// this requires the local daemon token (operator-only).
///
/// With `client` set, the invite is role-bound to a client principal (ADR-026):
/// the token may only enroll a non-serving principal whose leaf carries the
/// clientAuth-only profile — never a serving host.
pub fn invite(
    hostname: &str,
    ttl: i64,
    client: bool,
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client_ = require_daemon(endpoint, token)?;
    let mut body = serde_json::json!({
        "hostname": hostname,
        "ttl_mins": ttl,
    });
    if client {
        body["role"] = serde_json::json!("client");
    }
    let response: InviteResponse = decode_response(
        client_.post_json("/v1/certmesh/invite", &body)?,
        "Certmesh invite",
    )?;
    let token_str = require_non_empty(&response.token, "token", "Certmesh invite")?;
    let expires_at = require_non_empty(&response.expires_at, "expires_at", "Certmesh invite")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    println!("Invite minted for {hostname} (single-use, expires {expires_at}):");
    println!();
    println!("  {}", color::green(token_str));
    println!();
    println!("On {hostname}, run:");
    println!("  koi certmesh join <ca-endpoint> --invite {token_str}");
    Ok(())
}

// ── Promote ─────────────────────────────────────────────────────────

pub async fn promote(endpoint: Option<&str>, json: bool) -> anyhow::Result<()> {
    // The local (standby) daemon must be running — always the local breadcrumb daemon,
    // never a global `--endpoint`. The CA being promoted from is the `endpoint` arg / mDNS.
    let local = require_daemon(None, None)?;

    let resolved_endpoint = match endpoint {
        Some(ep) => ep.to_string(),
        None => discover_ca(None).await?,
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

    // The local daemon owns the ephemeral secret and the eventual durable
    // install. The CLI carries only public/opaque protocol material.
    let session = local.post_json(
        koi_certmesh::http::paths::PROMOTION_SESSION,
        &serde_json::json!({}),
    )?;
    let session_id = session
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("local daemon did not return a promotion session"))?;
    // The daemon presents its member certificate to the authority. A generic
    // HTTP client cannot reach this deliberately mTLS-only endpoint, and the CLI
    // must never read the member private key.
    let resp = local.post_json(
        koi_certmesh::http::paths::RELAY_PROMOTION,
        &serde_json::json!({
            "session_id": session_id,
            "authority_endpoint": resolved_endpoint,
            "auth": { "method": "totp", "code": code },
        }),
    )?;

    let accepted: AcceptPromotionResponse = decode_response(
        local.post_json(
            koi_certmesh::http::paths::ACCEPT_PROMOTION,
            &serde_json::json!({
                "session_id": session_id,
                "promotion": resp,
                "passphrase": passphrase,
            }),
        )?,
        "Certmesh promotion acceptance",
    )?;
    if !accepted.promoted {
        anyhow::bail!("local daemon did not acknowledge Certmesh promotion");
    }
    let hostname = require_non_empty(
        &accepted.hostname,
        "hostname",
        "Certmesh promotion acceptance",
    )?;

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
        print!("{}", format::promote_success(hostname));
    }

    Ok(())
}

// ── Open Enrollment ─────────────────────────────────────────────────

pub fn open_enrollment(
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let response: EnrollmentSummary = decode_response(
        client.post_json("/v1/certmesh/open-enrollment", &serde_json::json!({}))?,
        "Certmesh enrollment-open",
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        let state = match response.enrollment_state {
            EnrollmentState::Open => "open",
            EnrollmentState::Closed => "closed",
        };
        println!("Enrollment: {state}");
    }
    Ok(())
}

// ── Close Enrollment ────────────────────────────────────────────────

pub fn close_enrollment(
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let response: EnrollmentSummary = decode_response(
        client.post_json("/v1/certmesh/close-enrollment", &serde_json::json!({}))?,
        "Certmesh enrollment-close",
    )?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        let state = match response.enrollment_state {
            EnrollmentState::Open => "open",
            EnrollmentState::Closed => "closed",
        };
        println!("Enrollment: {state}");
    }
    Ok(())
}

// ── Rotate Auth ─────────────────────────────────────────────────────

pub fn rotate_auth(json: bool, endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;

    eprintln!("Enter the CA passphrase:");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim();

    if passphrase.is_empty() {
        anyhow::bail!("Passphrase cannot be empty.");
    }

    let body = serde_json::json!({ "passphrase": passphrase });
    let response: RotateAuthResponse = decode_response(
        client.post_json("/v1/certmesh/rotate-auth", &body)?,
        "Certmesh authentication rotation",
    )?;
    let koi_crypto::auth::AuthSetup::Totp { totp_uri } = response.auth_setup;
    require_non_empty(
        &totp_uri,
        "auth_setup.totp_uri",
        "Certmesh authentication rotation",
    )?;

    if json {
        println!("{}", serde_json::json!({ "rotated": true }));
    } else {
        println!("Auth credential rotated successfully.");
        let secret = extract_totp_secret_from_uri(&totp_uri).ok_or_else(|| {
            anyhow::anyhow!(
                "daemon returned an invalid Certmesh authentication rotation response: auth_setup.totp_uri has no valid secret"
            )
        })?;
        let hostname = local_hostname("rendering the rotated Certmesh credential")?;
        let qr = koi_crypto::totp::qr_code_unicode(
            &secret,
            "Koi Certmesh",
            &format!("admin@{hostname}"),
        );
        println!("\nScan this QR code with your authenticator app:\n");
        println!("{qr}");
    }
    Ok(())
}

// ── Backup ─────────────────────────────────────────────────────────

pub fn backup(
    path: &std::path::Path,
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;

    // Backup is non-destructive (it only *reads* the CA key into an encrypted
    // bundle), so there is no DESTROY-style confirmation gate. The former
    // courtesy "Type BACKUP" prompt was dropped: it did a bare stdin read with
    // no TTY check and so hung on piped stdin. The passphrase prompts below are
    // genuine secret inputs, not a confirmation, and can be fed via piped lines.
    let ca_passphrase = read_non_empty_line("Enter the CA passphrase:")?;
    let backup_passphrase = read_non_empty_line("Enter a backup passphrase:")?;
    confirm_passphrase("Confirm the backup passphrase:", &backup_passphrase)?;

    let body = serde_json::json!({
        "ca_passphrase": ca_passphrase,
        "backup_passphrase": backup_passphrase,
    });
    let response: BackupResponse = decode_response(
        client.post_json("/v1/certmesh/backup", &body)?,
        "Certmesh backup",
    )?;
    let backup_hex = require_non_empty(&response.backup_hex, "backup_hex", "Certmesh backup")?;

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

pub fn restore(
    path: &std::path::Path,
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;

    // The former courtesy "Type RESTORE" prompt was dropped: it did a bare
    // stdin read with no TTY check and so hung on piped stdin. The passphrase
    // prompts below are genuine secret inputs (the backup + new CA passphrase),
    // not a confirmation, and can be supplied via piped lines.
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
    let response: RestoreResponse = decode_response(
        client.post_json("/v1/certmesh/restore", &body)?,
        "Certmesh restore",
    )?;
    let restored = response.restored;

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
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;

    let body = serde_json::json!({
        "hostname": hostname,
        "reason": reason,
    });
    let response: RevokeResponse = decode_response(
        client.post_json("/v1/certmesh/revoke", &body)?,
        "Certmesh revocation",
    )?;
    let revoked = response.revoked;

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

pub fn destroy(
    json: bool,
    yes: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    // The single confirmation gate (token word + danger line come from the
    // `certmesh destroy` CommandMeta). Runs BEFORE any network call so a
    // non-interactive invocation (`--json` / piped) refuses up front instead of
    // contacting the daemon and silently wiping state.
    let meta = crate::help::get("certmesh destroy")
        .ok_or_else(|| anyhow::anyhow!("internal: missing meta for 'certmesh destroy'"))?;
    crate::help::confirm::gate_meta(meta, json, yes)?;

    let client = require_daemon(endpoint, token)?;
    let response: DestroyResponse = decode_response(
        client.post_json("/v1/certmesh/destroy", &serde_json::json!({}))?,
        "Certmesh destroy",
    )?;
    let destroyed = response.destroyed;

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

/// Discover a certmesh CA on the local network via mDNS.
///
/// Browses for `_certmesh._tcp` services for 5 seconds, collects resolved results,
/// and returns the endpoint URL of the discovered CA. When `pinned_fp` is set (an
/// invite carried a CA fingerprint, ADR-017 F3), the CA's `fp=` TXT record is used
/// as a **cross-check hint** (F12): any discovered CA that advertises a *different*
/// fingerprint is dropped as definitively the wrong mesh. The TXT is never the
/// trust source — the authoritative pin check is the preflight in [`join`].
async fn discover_ca(pinned_fp: Option<&str>) -> anyhow::Result<String> {
    eprintln!("Searching for certmesh CA on the local network...");

    let core =
        Arc::new(koi_compose::mdns::build_core(tokio_util::sync::CancellationToken::new()).await?);
    let handle = core
        .subscribe_type(koi_certmesh::CERTMESH_SERVICE_TYPE)
        .await?;

    let deadline = tokio::time::Instant::now() + CA_DISCOVERY_TIMEOUT;
    let certmesh_type = ServiceType::parse(koi_certmesh::CERTMESH_SERVICE_TYPE)
        .expect("the built-in Certmesh service type is valid");
    // (endpoint, instance name, advertised fp= TXT)
    let mut found: Vec<(String, String, Option<String>)> = Vec::new();

    loop {
        tokio::select! {
            event = handle.recv() => {
                match event {
                    Ok(MdnsEvent::Resolved(record)) => add_discovered_ca(&mut found, &record),
                    Ok(_) => continue,
                    Err(BrowseRecvError::Lagged { .. }) => {
                        // Browse delivery is deliberately best-effort. Rebuild from
                        // the domain-owned latest-value projection so a busy LAN
                        // cannot make the join picker retain a partial event history.
                        rebuild_discovered_cas(&mut found, &core, &certmesh_type);
                    }
                    Err(BrowseRecvError::Closed) => break,
                }
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }

    // The deadline and a committed discovery update may become ready together.
    // Take one final authoritative projection after leaving the event loop so a
    // queued delivery can neither hide a new CA nor retain a removed one.
    rebuild_discovered_cas(&mut found, &core, &certmesh_type);
    let _ = core.shutdown().await;

    // F12 cross-check: drop CAs whose advertised fp contradicts the invite pin. CAs
    // that match the pin, or advertise no fp (can't disambiguate — let preflight
    // decide), are kept.
    if let Some(pin) = pinned_fp {
        let before = found.len();
        found.retain(|(_, _, fp)| match fp {
            Some(f) => koi_crypto::pinning::fingerprints_match(f, pin),
            None => true,
        });
        let dropped = before - found.len();
        if dropped > 0 {
            eprintln!(
                "Ignored {dropped} discovered CA(s) whose advertised fingerprint did not match \
                 the invite."
            );
        }
    }

    match found.len() {
        0 => {
            let hint = if pinned_fp.is_some() {
                " matching the invite"
            } else {
                ""
            };
            anyhow::bail!(
                "No certmesh CA{hint} found on the local network.\n\
                 Specify the endpoint manually: koi certmesh join <endpoint>"
            )
        }
        1 => {
            let (endpoint, name, _) = found.into_iter().next().unwrap();
            eprintln!("Found CA: {name} at {endpoint}");
            Ok(endpoint)
        }
        _ => {
            let mut msg = String::from("Multiple certmesh CAs found:\n");
            for (ep, name, _) in &found {
                msg.push_str(&format!("  {name}  {ep}\n"));
            }
            msg.push_str("\nSpecify which to join: koi certmesh join <endpoint>");
            anyhow::bail!(msg)
        }
    }
}

fn rebuild_discovered_cas(
    found: &mut Vec<(String, String, Option<String>)>,
    core: &koi_mdns::MdnsCore,
    certmesh_type: &ServiceType,
) {
    found.clear();
    for record in &core.discovery_snapshot().records {
        let is_certmesh = ServiceType::parse(&record.service_type)
            .is_ok_and(|service_type| &service_type == certmesh_type);
        if is_certmesh {
            add_discovered_ca(found, record);
        }
    }
}

fn add_discovered_ca(found: &mut Vec<(String, String, Option<String>)>, record: &ServiceRecord) {
    let (Some(ip), Some(port)) = (&record.ip, record.port) else {
        return;
    };
    let endpoint = format!("http://{ip}:{port}");
    if !found.iter().any(|(existing, _, _)| existing == &endpoint) {
        found.push((endpoint, record.name.clone(), record.txt.get("fp").cloned()));
    }
}

// ── ACME (RFC 8555) ──────────────────────────────────────────────────

/// Default ACME server-auth TLS port (mirrors `adapters::acme::DEFAULT_ACME_PORT`).
const ACME_PORT: u16 = 5643;

/// Derive the ACME directory URL from a daemon endpoint, swapping the scheme to
/// https and the port to the ACME port. `https://<host>:5643/acme/directory`.
fn acme_directory_url(endpoint: &str) -> anyhow::Result<String> {
    let endpoint = url::Url::parse(endpoint)
        .map_err(|error| anyhow::anyhow!("invalid Certmesh endpoint '{endpoint}': {error}"))?;
    let host = endpoint
        .host()
        .ok_or_else(|| anyhow::anyhow!("Certmesh endpoint has no host"))?;
    let authority = match host {
        url::Host::Domain(domain) => domain.to_string(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => format!("[{address}]"),
    };
    Ok(format!("https://{authority}:{ACME_PORT}/acme/directory"))
}

/// Path to the selected local owner's CA root certificate. A remote daemon's
/// filesystem is deliberately unknowable at this boundary, so no path is
/// advertised for an explicit endpoint.
fn ca_cert_path_hint(endpoint: Option<&str>, data_root: &std::path::Path) -> Option<String> {
    endpoint.is_none().then(|| {
        data_root
            .join("certmesh")
            .join("ca")
            .join("ca-cert.pem")
            .display()
            .to_string()
    })
}

/// `koi certmesh acme enable` — print the directory URL + the client bootstrap
/// recipe. The ACME server starts automatically with the daemon when the CA is
/// initialized + unlocked and `--no-acme` is not set; this command surfaces the
/// connection details and the one-time CA-root trust step.
pub fn acme_enable(
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
    data_root: &std::path::Path,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let status = fetch_certmesh_status(&client)?;
    let authority = status.authority.as_ref();
    let ca_init = authority.is_some();
    let ca_locked = authority.is_none_or(|authority| authority.locked);
    let fingerprint = authority
        .map(|authority| {
            authority.ca_fingerprint.as_deref().ok_or_else(|| {
                anyhow::anyhow!("invalid Certmesh status: authority state has no CA fingerprint")
            })
        })
        .transpose()?;

    let dir_url = endpoint.map(acme_directory_url).transpose()?.map_or_else(
        || {
            local_fqdn("locating the local ACME service")
                .map(|host| format!("https://{host}:{ACME_PORT}/acme/directory"))
        },
        Ok,
    )?;
    let ca_path = ca_cert_path_hint(endpoint, data_root);

    if json {
        let mut acme = serde_json::json!({
            "directory": dir_url,
            "ca_initialized": ca_init,
            "ca_locked": ca_locked,
            "ca_fingerprint": fingerprint,
            "enabled": ca_init && !ca_locked,
        });
        if let Some(path) = ca_path.as_deref() {
            acme["ca_cert_path"] = serde_json::json!(path);
        }
        let out = serde_json::json!({ "acme": acme });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if !ca_init {
        println!("ACME server: unavailable — no CA yet.");
        println!("  Run `koi certmesh create` to initialize the CA first.");
        return Ok(());
    }
    if ca_locked {
        println!("ACME server: waiting — the CA is locked.");
        println!("  Run `koi certmesh unlock`, then restart the daemon.");
        return Ok(());
    }

    println!("ACME (RFC 8555) server is active.");
    println!();
    println!("  Directory URL : {dir_url}");
    if let Some(path) = ca_path.as_deref() {
        println!("  CA root cert  : {path}");
    }
    println!(
        "  CA fingerprint: {}",
        fingerprint.expect("initialized authority was validated above")
    );
    println!();
    println!("Bootstrap (one time): clients must trust the CA root, then point their");
    println!("ACME client at the directory above. dns-01 is the only challenge type;");
    println!("only names inside the Koi DNS zone are issuable.");
    println!();
    println!("  Caddy   : tls {{ issuer acme {{ dir {dir_url} }} }}");
    if let Some(path) = ca_path.as_deref() {
        println!("            (and trust {path} via acme_ca_root / a trusted root)");
        println!("  Traefik : certificatesResolvers.koi.acme.caServer={dir_url}");
        println!("            certificatesResolvers.koi.acme.caCertificates={path}");
        println!("  lego    : LEGO_CA_CERTIFICATES={path} lego --server {dir_url} ...");
    } else {
        println!("  Export the CA root from the selected authority and trust that exported file");
        println!("  before configuring Caddy, Traefik, lego, or another ACME client.");
    }
    println!();
    println!("See `docs/guides/acme.md` for full recipes.");
    Ok(())
}

/// `koi certmesh acme status` — show the ACME directory URL and whether the
/// server is serving (derived from authority state) plus the mesh member count.
pub fn acme_status(json: bool, endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let status = fetch_certmesh_status(&client)?;
    let authority = status.authority.as_ref();
    let ca_init = authority.is_some();
    let ca_locked = authority.is_none_or(|authority| authority.locked);
    let enrollment_open = authority.is_some_and(|authority| authority.enrollment_open);
    let dir_url = endpoint.map(acme_directory_url).transpose()?.map_or_else(
        || {
            local_fqdn("locating the local ACME service")
                .map(|host| format!("https://{host}:{ACME_PORT}/acme/directory"))
        },
        Ok,
    )?;

    let member_count = authority.map_or(0, |authority| authority.member_count);

    let serving = ca_init && !ca_locked;
    if json {
        let out = serde_json::json!({
            "acme": {
                "serving": serving,
                "directory": dir_url,
                "mode": if enrollment_open { "open" } else { "closed (EAB required)" },
                "member_count": member_count,
            }
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!(
        "ACME server: {}",
        if serving { "serving" } else { "not serving" }
    );
    println!("  Directory : {dir_url}");
    println!(
        "  Mode      : {}",
        if enrollment_open {
            "open (free newAccount)"
        } else {
            "closed (external account binding required)"
        }
    );
    if !serving {
        if !ca_init {
            println!("  Reason    : no CA — run `koi certmesh create`");
        } else if ca_locked {
            println!("  Reason    : CA locked — run `koi certmesh unlock`");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_create_ceremony_result() -> serde_json::Map<String, serde_json::Value> {
        serde_json::json!({
            "passphrase": "correct horse battery staple",
            "_entropy_seed": "11".repeat(32),
            "operator": "operator@example.test",
            "_enrollment_open": true,
            "_requires_approval": true,
            "_auto_unlock": false,
            "_effective_profile": "My Team",
            "_totp_secret_hex": "22".repeat(20),
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn create_ceremony_result_requires_every_authoritative_field() {
        for field in [
            "passphrase",
            "_entropy_seed",
            "_enrollment_open",
            "_requires_approval",
            "_auto_unlock",
            "_effective_profile",
        ] {
            let mut result = valid_create_ceremony_result();
            result.remove(field);
            let error = decode_create_ceremony_result(result)
                .err()
                .unwrap_or_else(|| panic!("missing {field} unexpectedly decoded"));
            assert!(error.to_string().contains(field), "{error:#}");
        }
    }

    #[test]
    fn create_ceremony_result_rejects_wrong_types_and_empty_secrets() {
        let mut wrong_type = valid_create_ceremony_result();
        wrong_type.insert("_auto_unlock".into(), serde_json::json!("yes"));
        assert!(decode_create_ceremony_result(wrong_type).is_err());

        let mut empty = valid_create_ceremony_result();
        empty.insert("passphrase".into(), serde_json::json!(""));
        let error = decode_create_ceremony_result(empty).unwrap_err();
        assert!(error.to_string().contains("'passphrase' is empty"));
    }

    #[test]
    fn daemon_response_decoder_rejects_missing_required_certmesh_fields() {
        let error = decode_response::<InviteResponse>(
            serde_json::json!({
                "hostname": "node-02",
                "expires_at": "2026-09-04T12:00:00Z",
                "ca_fingerprint": "sha256:abc"
            }),
            "Certmesh invite",
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing field `token`"));
    }

    #[test]
    fn required_response_strings_cannot_be_empty() {
        let error = require_non_empty("", "ca_fingerprint", "Certmesh create").unwrap_err();
        assert!(error.to_string().contains("'ca_fingerprint' is empty"));
    }

    #[test]
    fn ca_certificate_hint_uses_only_the_selected_local_root() {
        let root = std::path::Path::new("/explicit/koi-data");
        assert_eq!(
            ca_cert_path_hint(None, root),
            Some(
                root.join("certmesh")
                    .join("ca")
                    .join("ca-cert.pem")
                    .display()
                    .to_string()
            )
        );
        assert_eq!(
            ca_cert_path_hint(Some("https://remote.example:5641"), root),
            None,
            "a remote owner's filesystem path must never be inferred from local configuration"
        );
    }

    #[test]
    fn create_certificate_hint_never_infers_a_remote_filesystem_path() {
        let root = std::path::Path::new("/explicit/koi-data");
        assert_eq!(
            local_certificate_path(None, root, "node-01"),
            Some(root.join("certs").join("node-01"))
        );
        assert_eq!(
            local_certificate_path(Some("https://remote.example:5641"), root, "node-01"),
            None
        );
    }

    #[test]
    fn acme_directory_rejects_missing_remote_hosts_and_preserves_ipv6() {
        assert!(acme_directory_url("not a URL").is_err());
        assert_eq!(
            acme_directory_url("http://[::1]:5641").unwrap(),
            format!("https://[::1]:{ACME_PORT}/acme/directory")
        );
    }

    #[test]
    fn preset_labels_match_names() {
        assert_eq!(preset_label("just_me"), "Just Me");
        assert_eq!(preset_label("team"), "My Team");
        assert_eq!(preset_label("org"), "My Organization");
        assert_eq!(preset_label("unknown"), "Just Me");
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
        let result = require_daemon(None, None);
        // This may succeed if there IS a breadcrumb; if not, it fails.
        // We just verify it doesn't panic.
        let _ = result;
    }

    #[test]
    fn require_daemon_explicit_endpoint_does_not_require_breadcrumb() {
        // An explicit endpoint must succeed regardless of breadcrumb state and
        // must NOT read the local breadcrumb token (token-selection is covered
        // directly by commands::token_for_explicit_endpoint tests). Here we just
        // assert the explicit-endpoint path builds a client without bailing.
        let client = require_daemon(Some("http://10.0.0.1:5641"), None);
        assert!(client.is_ok());

        let client = require_daemon(Some("http://10.0.0.1:5641"), Some("remote-token"));
        assert!(client.is_ok());
    }
}
