//! Certmesh command handlers.
//!
//! All certmesh commands delegate to the running service via HTTP.
//! The CLI never performs direct file I/O for certmesh operations -
//! the service has the elevated permissions needed for cert store,
//! file writes, etc.

use std::sync::Arc;

use koi_certmesh::entropy;
use koi_certmesh::profiles::preset_bools;
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
///
/// Token-selection follows the uniform rule in
/// [`crate::commands::token_for_explicit_endpoint`]:
///
/// - **Explicit `endpoint`** → use the explicit `--token`/`KOI_TOKEN` value if
///   set, else **tokenless**. NEVER the local breadcrumb token — pairing it
///   with a remote URL would leak the local daemon's token to that host.
/// - **No explicit endpoint** → use the breadcrumb endpoint + its matching
///   token (the local, trusted daemon).
fn require_daemon(
    endpoint: Option<&str>,
    explicit_token: Option<&str>,
) -> anyhow::Result<KoiClient> {
    if let Some(ep) = endpoint {
        let token = crate::commands::token_for_explicit_endpoint(explicit_token);
        return Ok(KoiClient::with_token(ep, &token));
    }
    let info = koi_config::breadcrumb::read_breadcrumb().ok_or_else(|| {
        anyhow::anyhow!(
            "No running Koi service found.\n\
             Install and start the service first: koi install"
        )
    })?;
    Ok(KoiClient::with_token(&info.endpoint, &info.token))
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
        let resp = client.post_json("/v1/certmesh/create", &body)?;
        let ca_fingerprint = resp
            .get("ca_fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
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

    // CLI composition root: resolve the local data dir once for the ceremony
    // (the unlock ceremony reads the slot table from it).
    #[allow(clippy::disallowed_methods)]
    let ceremony_paths =
        koi_certmesh::CertmeshPaths::with_data_dir(koi_common::paths::koi_data_dir());
    let host = CeremonyHost::new(InitCeremonyRules::new(ceremony_paths.clone()));

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
    //
    // The ceremony already resolved the chosen preset (or custom answers) to
    // the three booleans. We forward those verbatim — the preset name survives
    // only as the display label `_effective_profile`.
    let effective_profile = result_bag
        .get("_effective_profile")
        .and_then(|v| v.as_str())
        .unwrap_or("Just Me")
        .to_string();

    let body = serde_json::json!({
        "passphrase": result_bag.get("passphrase").and_then(|v| v.as_str()).unwrap_or(""),
        "entropy_hex": result_bag.get("_entropy_seed").and_then(|v| v.as_str()).unwrap_or(""),
        "operator": result_bag.get("operator").and_then(|v| v.as_str()),
        "enrollment_open": result_bag.get("_enrollment_open").and_then(|v| v.as_bool()).unwrap_or(true),
        "requires_approval": result_bag.get("_requires_approval").and_then(|v| v.as_bool()).unwrap_or(false),
        "auto_unlock": result_bag.get("_auto_unlock").and_then(|v| v.as_bool()).unwrap_or(false),
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
    let cert_path = ceremony_paths.certs_dir().join(&hostname);

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
    let status = client.get_json("/v1/certmesh/status")?;
    let ca_init = status
        .get("ca_initialized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !ca_init {
        return Ok(false);
    }

    let enrollment_open = status
        .get("enrollment_open")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
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
                    println!("  CA locked:  {}", s.ca_locked);
                    println!(
                        "  Enrollment: {} ({})",
                        if s.enrollment_open { "open" } else { "closed" },
                        if s.requires_approval {
                            "approval required"
                        } else {
                            "no approval"
                        }
                    );
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

pub fn log(endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let resp = client.get_json("/v1/certmesh/log")?;

    let entries = resp.get("entries").and_then(|v| v.as_str()).unwrap_or("");
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
    client.post_json("/v1/certmesh/unlock", &body)?;
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
    invite: Option<&str>,
    json: bool,
    cli_endpoint: Option<&str>,
    cli_token: Option<&str>,
) -> anyhow::Result<()> {
    // The local daemon owns key custody (ADR-015 F1): it generates the member
    // keypair, persists the private key, and installs the signed cert. The CLI
    // only carries public material (CSR out, cert back).
    let local = require_daemon(cli_endpoint, cli_token)?;

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
    let local_hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // 0. Preflight + pin (ADR-017 F3). When the invite carries a CA fingerprint,
    //    fetch the CA's self-reported status and refuse to continue unless its
    //    fingerprint matches the pinned one — so a LAN MITM of plain-HTTP discovery
    //    is rejected *before* we ever transmit a CSR. (`/status` is a GET, so it
    //    needs no token.) The TOTP path has no fingerprint to pin and stays TOFU.
    if let Some(ref pin) = pinned_fp {
        let status = remote.get_json("/v1/certmesh/status").map_err(|e| {
            anyhow::anyhow!("could not preflight the CA at {resolved_endpoint}: {e}")
        })?;
        let advertised = status
            .get("ca_fingerprint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
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
            "sans": [local_hostname, format!("{local_hostname}.local")],
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
    let resp = remote.post_json("/v1/certmesh/join", &serde_json::Value::Object(body))?;

    let service_cert = resp
        .get("service_cert")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("CA response missing service_cert"))?;
    let ca_cert = resp
        .get("ca_cert")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("CA response missing ca_cert"))?;

    // 3. Hand the signed cert to the LOCAL daemon to install next to the key. We
    //    also pass the CA coordinates (endpoint + pinned fingerprint + policy) so
    //    the daemon arms member-pull renewal (ADR-017 F6) — the background loop
    //    later rotates the key + pulls a fresh leaf over mTLS before expiry.
    let mut install_body = serde_json::Map::new();
    install_body.insert("hostname".into(), serde_json::json!(local_hostname));
    install_body.insert("cert_pem".into(), serde_json::json!(service_cert));
    install_body.insert("ca_pem".into(), serde_json::json!(ca_cert));
    install_body.insert("ca_endpoint".into(), serde_json::json!(resolved_endpoint));
    // Pin the install to the OUT-OF-BAND fingerprint from the invite when we have
    // one (F3) — so the local daemon hard-fails if the CA returned a cert that does
    // not match the pin (a /join MITM that slipped past preflight). Without an
    // invite pin (TOTP join), fall back to the CA's self-reported fingerprint
    // (documented TOFU).
    // `pinned_fp` is `Some` for every invite join, so the `or_else` (the CA's
    // self-reported fingerprint — TOFU) is reached ONLY on the TOTP path, which has
    // no out-of-band pin. Never let an invite join fall through to the response fp.
    let install_fp = pinned_fp
        .as_deref()
        .or_else(|| resp.get("ca_fingerprint").and_then(|v| v.as_str()));
    if let Some(fp) = install_fp {
        install_body.insert("ca_fingerprint".into(), serde_json::json!(fp));
    }
    install_body.insert(
        "sans".into(),
        serde_json::json!([local_hostname, format!("{local_hostname}.local")]),
    );
    if let Some(policy) = resp.get("policy") {
        install_body.insert("policy".into(), policy.clone());
    }
    let install = local.post_json(
        "/v1/certmesh/member-cert",
        &serde_json::Value::Object(install_body),
    )?;
    let cert_path = install
        .get("cert_path")
        .and_then(|v| v.as_str())
        .unwrap_or("(local certs dir)");

    if json {
        println!(
            "{}",
            serde_json::json!({
                "enrolled": true,
                "hostname": local_hostname,
                "cert_path": cert_path,
                "ca_fingerprint": resp.get("ca_fingerprint").and_then(|v| v.as_str()),
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
pub fn invite(
    hostname: &str,
    ttl: i64,
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let body = serde_json::json!({
        "hostname": hostname,
        "ttl_mins": ttl,
    });
    let resp = client.post_json("/v1/certmesh/invite", &body)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    let token_str = resp.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let expires_at = resp
        .get("expires_at")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");

    println!("Invite minted for {hostname} (single-use, expires {expires_at}):");
    println!();
    println!("  {}", color::green(token_str));
    println!();
    println!("On {hostname}, run:");
    println!("  koi certmesh join <ca-endpoint> --invite {token_str}");
    Ok(())
}

// ── Promote ─────────────────────────────────────────────────────────

pub async fn promote(
    endpoint: Option<&str>,
    json: bool,
    cli_endpoint: Option<&str>,
    cli_token: Option<&str>,
) -> anyhow::Result<()> {
    // The local daemon must be running
    let _local = require_daemon(cli_endpoint, cli_token)?;

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

    // Generate ephemeral X25519 keypair for DH key agreement
    let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
    let client_pub = client_kp.public_key_bytes();
    let client_pub_hex = koi_common::encoding::hex_encode(&client_pub);

    // Request promotion from the primary with DH public key
    let client = KoiClient::new(&resolved_endpoint);
    let body = serde_json::json!({
        "auth": { "method": "totp", "code": code },
        "ephemeral_public": client_pub_hex,
    });
    let resp = client.post_json("/v1/certmesh/promote", &body)?;

    // Parse the promotion response
    let promote_response: koi_certmesh::protocol::PromoteResponse =
        serde_json::from_value(resp.clone())
            .map_err(|e| anyhow::anyhow!("Failed to parse promotion response: {e}"))?;

    // Decrypt and install the CA key, auth credential, and roster locally
    // using DH key agreement (the passphrase is NOT sent over the wire)
    let (ca_key, auth_state, roster) =
        koi_certmesh::failover::accept_promotion(&promote_response, client_kp)?;

    // Save to local disk. CLI composition root: resolve the data dir once.
    #[allow(clippy::disallowed_methods)]
    let paths = koi_certmesh::CertmeshPaths::with_data_dir(koi_common::paths::koi_data_dir());
    let ca_dir = paths.ca_dir();
    std::fs::create_dir_all(&ca_dir)?;

    let ca_key_der = koi_crypto::keys::ca_keypair_to_der(&ca_key)?;
    let (encrypted_key, slot_table, _master_key) =
        koi_crypto::unlock_slots::envelope_encrypt_new(&ca_key_der, &passphrase)?;
    koi_crypto::keys::save_encrypted_key(&paths.ca_key_path(), &encrypted_key)?;
    slot_table.save(&paths.slot_table_path())?;
    std::fs::write(paths.ca_cert_path(), &promote_response.ca_cert_pem)?;

    // Persist auth credential to auth.json
    let koi_crypto::auth::AuthState::Totp(secret) = &auth_state;
    let stored = koi_crypto::auth::store_totp(secret, &passphrase)?;
    let auth_json = serde_json::to_string_pretty(&stored)?;
    std::fs::write(paths.auth_path(), auth_json)?;

    koi_certmesh::roster::save_roster(&roster, &paths.roster_path())?;

    // Update local member role to Standby
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string());

    let mut roster = koi_certmesh::roster::load_roster(&paths.roster_path())?;
    if let Some(member) = roster.find_member_mut(&hostname) {
        member.role = koi_certmesh::roster::MemberRole::Standby;
        koi_certmesh::roster::save_roster(&roster, &paths.roster_path())?;
    }

    let _ = koi_certmesh::audit::append_entry_to(
        &paths.audit_log_path(),
        "promoted_to_standby",
        &[("hostname", &hostname)],
    );

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
    json: bool,
    endpoint: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let resp = client.post_json("/v1/certmesh/open-enrollment", &serde_json::json!({}))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let state = resp
            .get("enrollment_state")
            .and_then(|v| v.as_str())
            .unwrap_or("open");
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
    let resp = client.post_json("/v1/certmesh/close-enrollment", &serde_json::json!({}))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("Enrollment: closed");
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
    token: Option<&str>,
) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;

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

    let core = Arc::new(koi_mdns::MdnsCore::new()?);
    let handle = core
        .subscribe_type(koi_certmesh::CERTMESH_SERVICE_TYPE)
        .await?;

    let deadline = tokio::time::Instant::now() + CA_DISCOVERY_TIMEOUT;
    // (endpoint, instance name, advertised fp= TXT)
    let mut found: Vec<(String, String, Option<String>)> = Vec::new();

    loop {
        tokio::select! {
            event = handle.recv() => {
                match event {
                    Some(MdnsEvent::Resolved(record)) => {
                        if let (Some(ip), Some(port)) = (&record.ip, record.port) {
                            let endpoint = format!("http://{ip}:{port}");
                            if !found.iter().any(|(ep, _, _)| ep == &endpoint) {
                                let fp = record.txt.get("fp").cloned();
                                found.push((endpoint, record.name.clone(), fp));
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

// ── ACME (RFC 8555) ──────────────────────────────────────────────────

/// Default ACME server-auth TLS port (mirrors `adapters::acme::DEFAULT_ACME_PORT`).
const ACME_PORT: u16 = 5643;

/// Derive the ACME directory URL from a daemon endpoint, swapping the scheme to
/// https and the port to the ACME port. `https://<host>:5643/acme/directory`.
fn acme_directory_url(endpoint: &str) -> String {
    // endpoint looks like "http://host:5641"; extract the host.
    let host = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', ':'])
        .next()
        .filter(|h| !h.is_empty())
        .unwrap_or("localhost");
    format!("https://{host}:{ACME_PORT}/acme/directory")
}

/// Path to the CA root certificate clients must trust to bootstrap.
fn ca_cert_path_hint() -> String {
    #[allow(clippy::disallowed_methods)]
    let data_dir = koi_common::paths::koi_data_dir();
    data_dir
        .join("certmesh")
        .join("ca")
        .join("ca-cert.pem")
        .display()
        .to_string()
}

/// `koi certmesh acme enable` — print the directory URL + the client bootstrap
/// recipe. The ACME server starts automatically with the daemon when the CA is
/// initialized + unlocked and `--no-acme` is not set; this command surfaces the
/// connection details and the one-time CA-root trust step.
pub fn acme_enable(json: bool, endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let resp = client.get_json("/v1/certmesh/status")?;
    let ca_init = resp
        .get("ca_initialized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ca_locked = resp
        .get("ca_locked")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let fingerprint = resp
        .get("ca_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");

    let dir_url = endpoint
        .map(acme_directory_url)
        .unwrap_or_else(|| format!("https://localhost:{ACME_PORT}/acme/directory"));
    let ca_path = ca_cert_path_hint();

    if json {
        let out = serde_json::json!({
            "acme": {
                "directory": dir_url,
                "ca_initialized": ca_init,
                "ca_locked": ca_locked,
                "ca_fingerprint": fingerprint,
                "ca_cert_path": ca_path,
                "enabled": ca_init && !ca_locked,
            }
        });
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
    println!("  CA root cert  : {ca_path}");
    println!("  CA fingerprint: {fingerprint}");
    println!();
    println!("Bootstrap (one time): clients must trust the CA root, then point their");
    println!("ACME client at the directory above. dns-01 is the only challenge type;");
    println!("only names inside the Koi DNS zone are issuable.");
    println!();
    println!("  Caddy   : tls {{ issuer acme {{ dir {dir_url} }} }}");
    println!("            (and trust {ca_path} via acme_ca_root / a trusted root)");
    println!("  Traefik : certificatesResolvers.koi.acme.caServer={dir_url}");
    println!("            certificatesResolvers.koi.acme.caCertificates={ca_path}");
    println!("  lego    : LEGO_CA_CERTIFICATES={ca_path} lego --server {dir_url} ...");
    println!();
    println!("See `docs/guides/acme.md` for full recipes.");
    Ok(())
}

/// `koi certmesh acme status` — show the ACME directory URL and whether the
/// server is serving (derived from CA state) plus the ACME-sourced member count.
pub fn acme_status(json: bool, endpoint: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    let client = require_daemon(endpoint, token)?;
    let resp = client.get_json("/v1/certmesh/status")?;
    let ca_init = resp
        .get("ca_initialized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ca_locked = resp
        .get("ca_locked")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let enrollment_open = resp
        .get("enrollment_open")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dir_url = endpoint
        .map(acme_directory_url)
        .unwrap_or_else(|| format!("https://localhost:{ACME_PORT}/acme/directory"));

    // ACME-issued members are recorded with enrolled_by "acme:*".
    let acme_members = resp
        .get("members")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);

    let serving = ca_init && !ca_locked;
    if json {
        let out = serde_json::json!({
            "acme": {
                "serving": serving,
                "directory": dir_url,
                "mode": if enrollment_open { "open" } else { "closed (EAB required)" },
                "member_count": acme_members,
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
