//! Certmesh command handlers.
//!
//! Local commands (create, status, log, unlock, set-hook) are sync file I/O.
//! Network commands (join) are async — they may discover the CA via mDNS.

use std::sync::Arc;

use koi_certmesh::{audit, ca, certfiles, entropy, profiles::TrustProfile, roster};
use koi_mdns::events::MdnsEvent;

use crate::client::KoiClient;
use crate::format;

/// mDNS discovery timeout for finding a CA on the local network.
const CA_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ── Create ──────────────────────────────────────────────────────────

pub fn create(
    profile: Option<&str>,
    operator: Option<&str>,
    entropy_mode: &str,
    passphrase: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    ensure_not_initialized()?;
    let trust_profile = resolve_profile(profile);
    validate_operator(&trust_profile, operator)?;
    let entropy_seed = collect_entropy_seed(entropy_mode, passphrase)?;
    let ca_passphrase = resolve_passphrase(passphrase)?;
    let ca_state = ca::create_ca(&ca_passphrase, &entropy_seed)?;
    let totp_secret = setup_totp(&ca_passphrase)?;
    let (hostname, cert_dir) = enroll_primary(&ca_state, &trust_profile, operator)?;
    log_initialization(&trust_profile, operator, &hostname);
    install_trust_store(&ca_state);
    display_create_results(&hostname, &cert_dir, &trust_profile, &ca_state, &totp_secret, json);
    Ok(())
}

fn ensure_not_initialized() -> anyhow::Result<()> {
    if ca::is_ca_initialized() {
        anyhow::bail!(
            "CA already initialized. Remove {:?} to start over.",
            ca::ca_dir()
        );
    }
    Ok(())
}

fn resolve_profile(profile: Option<&str>) -> TrustProfile {
    profile
        .and_then(TrustProfile::from_str_loose)
        .unwrap_or(TrustProfile::JustMe)
}

fn validate_operator(trust_profile: &TrustProfile, operator: Option<&str>) -> anyhow::Result<()> {
    if trust_profile.requires_operator() && operator.is_none() {
        anyhow::bail!(
            "The '{}' profile requires --operator <name>.",
            trust_profile
        );
    }
    Ok(())
}

fn collect_entropy_seed(
    entropy_mode: &str,
    passphrase: Option<&str>,
) -> anyhow::Result<[u8; 32]> {
    Ok(match entropy_mode {
        "keyboard" => entropy::collect_entropy(entropy::EntropyMode::KeyboardMashing)?,
        "manual" => {
            let phrase = passphrase
                .ok_or_else(|| anyhow::anyhow!("--passphrase required with --entropy=manual"))?;
            entropy::collect_entropy(entropy::EntropyMode::Manual(phrase.to_string()))?
        }
        _ => entropy::collect_entropy(entropy::EntropyMode::AutoPassphrase)?,
    })
}

fn resolve_passphrase(passphrase: Option<&str>) -> anyhow::Result<String> {
    let result = passphrase
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            eprintln!("Enter a passphrase to protect the CA key:");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap_or_default();
            line.trim().to_string()
        });
    if result.is_empty() {
        anyhow::bail!("Passphrase cannot be empty.");
    }
    Ok(result)
}

fn setup_totp(ca_passphrase: &str) -> anyhow::Result<koi_crypto::totp::TotpSecret> {
    let totp_secret = koi_crypto::totp::generate_secret();
    let encrypted_totp = koi_crypto::totp::encrypt_secret(&totp_secret, ca_passphrase)?;
    koi_crypto::keys::save_encrypted_key(&ca::totp_secret_path(), &encrypted_totp)?;
    Ok(totp_secret)
}

fn enroll_primary(
    ca_state: &ca::CaState,
    trust_profile: &TrustProfile,
    operator: Option<&str>,
) -> anyhow::Result<(String, std::path::PathBuf)> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string());
    let sans = vec![hostname.clone(), format!("{hostname}.local")];
    let issued = ca::issue_certificate(ca_state, &hostname, &sans)?;
    let cert_dir = certfiles::write_cert_files(&hostname, &issued)?;

    let ca_fp = ca::ca_fingerprint(ca_state);
    let mut r = roster::Roster::new(trust_profile.clone(), operator.map(String::from));
    r.members.push(roster::RosterMember {
        hostname: hostname.clone(),
        role: roster::MemberRole::Primary,
        enrolled_at: chrono::Utc::now(),
        enrolled_by: operator.map(String::from),
        cert_fingerprint: issued.fingerprint.clone(),
        cert_expires: issued.expires,
        cert_sans: sans,
        cert_path: cert_dir.display().to_string(),
        status: roster::MemberStatus::Active,
        reload_hook: None,
        last_seen: Some(chrono::Utc::now()),
        pinned_ca_fingerprint: Some(ca_fp),
    });
    roster::save_roster(&r, &ca::roster_path())?;

    Ok((hostname, cert_dir))
}

fn log_initialization(
    trust_profile: &TrustProfile,
    operator: Option<&str>,
    hostname: &str,
) {
    let _ = audit::append_entry(
        "pond_initialized",
        &[
            ("profile", &trust_profile.to_string()),
            ("operator", operator.unwrap_or("self")),
            ("hostname", hostname),
        ],
    );
}

fn install_trust_store(ca_state: &ca::CaState) {
    if let Err(e) = koi_truststore::install_ca_cert(&ca_state.cert_pem, "koi-certmesh-ca") {
        eprintln!("Warning: Could not install CA in system trust store: {e}");
        eprintln!("You may need to install it manually.");
    }
}

fn display_create_results(
    hostname: &str,
    cert_dir: &std::path::Path,
    trust_profile: &TrustProfile,
    ca_state: &ca::CaState,
    totp_secret: &koi_crypto::totp::TotpSecret,
    json: bool,
) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "created": true,
                "profile": trust_profile.to_string(),
                "ca_fingerprint": ca::ca_fingerprint(ca_state),
                "hostname": hostname,
                "cert_path": cert_dir.display().to_string(),
            })
        );
    } else {
        format::certmesh_create_success(
            hostname,
            cert_dir,
            trust_profile,
            &ca::ca_fingerprint(ca_state),
        );
    }

    let qr = koi_crypto::totp::qr_code_unicode(
        totp_secret,
        "Koi Certmesh",
        &format!("admin@{hostname}"),
    );
    println!("\nScan this QR code with your authenticator app:\n");
    println!("{qr}");
}

// ── Status ──────────────────────────────────────────────────────────

pub fn status(json: bool) -> anyhow::Result<()> {
    if !ca::is_ca_initialized() {
        if json {
            println!(
                "{}",
                serde_json::json!({ "ca_initialized": false })
            );
        } else {
            println!("Certificate mesh: not initialized");
            println!("  Run `koi certmesh create` to set up a CA.");
        }
        return Ok(());
    }

    let roster_path = ca::roster_path();
    if roster_path.exists() {
        let r = roster::load_roster(&roster_path)?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ca_initialized": true,
                    "profile": r.metadata.trust_profile,
                    "enrollment_state": r.metadata.enrollment_state,
                    "member_count": r.active_count(),
                    "members": r.members.iter().map(|m| serde_json::json!({
                        "hostname": m.hostname,
                        "role": format!("{:?}", m.role).to_lowercase(),
                        "status": format!("{:?}", m.status).to_lowercase(),
                        "cert_fingerprint": m.cert_fingerprint,
                        "cert_expires": m.cert_expires.to_rfc3339(),
                    })).collect::<Vec<_>>(),
                }))?
            );
        } else {
            format::certmesh_status(&r);
        }
    } else {
        println!("CA initialized but roster not found.");
    }

    Ok(())
}

// ── Log ─────────────────────────────────────────────────────────────

pub fn log() -> anyhow::Result<()> {
    let log = audit::read_log()?;
    if log.is_empty() {
        println!("No audit log entries.");
    } else {
        print!("{log}");
    }
    Ok(())
}

// ── Unlock ──────────────────────────────────────────────────────────

pub fn unlock() -> anyhow::Result<()> {
    if !ca::is_ca_initialized() {
        anyhow::bail!("CA not initialized. Run `koi certmesh create` first.");
    }

    eprintln!("Enter the CA passphrase:");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim();

    let _ca = ca::load_ca(passphrase)?;
    println!("CA unlocked successfully.");
    Ok(())
}

// ── Set Hook ────────────────────────────────────────────────────────

pub fn set_hook(
    reload: &str,
    json: bool,
    endpoint: Option<&str>,
) -> anyhow::Result<()> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".to_string());

    // Try daemon first, fall back to direct roster edit
    if let Some(ep) = endpoint
        .map(String::from)
        .or_else(koi_config::breadcrumb::read_breadcrumb)
    {
        let c = KoiClient::new(&ep);
        if c.health().is_ok() {
            let body = serde_json::json!({
                "hostname": hostname,
                "reload": reload,
            });
            let resp = c.put_json("/v1/certmesh/hook", &body)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                println!("Reload hook set for {hostname}: {reload}");
            }
            return Ok(());
        }
    }

    // Offline: edit roster directly
    if !ca::is_ca_initialized() {
        anyhow::bail!("CA not initialized. Run `koi certmesh create` first.");
    }
    let roster_path = ca::roster_path();
    let mut r = roster::load_roster(&roster_path)?;
    match r.find_member_mut(&hostname) {
        Some(member) => {
            member.reload_hook = Some(reload.to_string());
            roster::save_roster(&r, &roster_path)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "hostname": hostname,
                        "reload": reload,
                    })
                );
            } else {
                println!("Reload hook set for {hostname}: {reload}");
            }
            Ok(())
        }
        None => {
            anyhow::bail!("This host ({hostname}) is not enrolled in the mesh.");
        }
    }
}

// ── Join ────────────────────────────────────────────────────────────

pub async fn join(endpoint: Option<&str>, json: bool) -> anyhow::Result<()> {
    let resolved_endpoint = match endpoint {
        Some(ep) => ep.to_string(),
        None => discover_ca().await?,
    };

    eprintln!("Enter the TOTP code from your authenticator app:");
    let mut code = String::new();
    std::io::stdin().read_line(&mut code)?;
    let code = code.trim().to_string();

    let client = KoiClient::new(&resolved_endpoint);
    let body = serde_json::json!({ "totp_code": code });
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
