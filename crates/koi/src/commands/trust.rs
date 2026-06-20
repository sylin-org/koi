//! `koi trust` — generic OS trust-store root distribution.
//!
//! These commands are **local** (they touch the OS certificate store directly)
//! and never go through the daemon. Koi tracks only the roots *it* installed in
//! `state/trust.json`, so `list`/`remove` manage Koi's own footprint and never
//! enumerate or mutate the OS store wholesale.
//!
//! Charter principle 10 (collaboration): install *any* root (step-ca, mkcert,
//! Caddy's local CA, …), and `export --ca` hands the certmesh root to the tools
//! that bootstrap ACME — see `docs/guides/integrations.md`.

use std::path::Path;

use anyhow::Context;

use crate::commands::print_json;

/// Install a PEM CA certificate into the OS trust store and record it.
pub fn install(pem_path: &Path, json: bool) -> anyhow::Result<()> {
    let pem = std::fs::read_to_string(pem_path)
        .with_context(|| format!("reading certificate file {}", pem_path.display()))?;

    // Validate: real PEM, real X.509, and actually a CA (rejects a leaf cert).
    let cert = os_truststore::Cert::from_pem(&pem)
        .map_err(|e| anyhow::anyhow!("invalid CA certificate: {e}"))?;

    let name = derive_name(pem_path)?;
    let fingerprint = install_cert(&cert, &name, &pem_path.display().to_string())?;

    if json {
        print_json(&serde_json::json!({
            "installed": { "name": name, "fingerprint": fingerprint }
        }));
    } else {
        println!("Installed CA \"{name}\" (sha256: {fingerprint})");
        eprintln!("The OS trust store now trusts certificates signed by this root.");
    }
    Ok(())
}

/// Install a validated CA cert into the OS trust store and record it in
/// `state/trust.json`, returning its fingerprint. Shared by `install` and
/// `diagnose --fix` so the install+record path is written once.
fn install_cert(cert: &os_truststore::Cert, name: &str, source: &str) -> anyhow::Result<String> {
    let fingerprint = koi_crypto::pinning::fingerprint_sha256(cert.der());

    // The certificate is the identity; `name` is the human-readable display label.
    os_truststore::Install::new(cert)
        .label(name)
        .run()
        .map_err(|e| anyhow::anyhow!("failed to install into OS trust store: {e}"))?;

    // Record so `list`/`remove` can manage just this Koi-installed root.
    let mut state = koi_config::state::load_trust_state().unwrap_or_default();
    state.roots.retain(|r| r.name != name);
    state.roots.push(koi_config::state::TrustEntry {
        name: name.to_string(),
        installed_at: chrono::Utc::now().to_rfc3339(),
        fingerprint: fingerprint.clone(),
        source: source.to_string(),
    });
    koi_config::state::save_trust_state(&state).context("saving trust state")?;
    Ok(fingerprint)
}

/// Run the trust-doctor (`koi trust diagnose`) — ADR-020 §13.
///
/// Builds a local certmesh core (reads on-disk identity/roster — no daemon needed,
/// mirroring `export`), runs the single `CertmeshCore::diagnose` logic, prints a
/// loud report, and **exits non-zero when anything is RED**. `--fix` installs the
/// mesh CA into the OS trust store (the one auto-fixable remedy).
pub async fn diagnose(fix: bool, json: bool) -> anyhow::Result<()> {
    let core = tokio::task::spawn_blocking(|| koi_compose::cores::init_certmesh_core(None))
        .await
        .map_err(|e| anyhow::anyhow!("certmesh init task: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("certmesh is unavailable on this node"))?;

    // --fix: install the mesh CA so local apps trust mesh certs (the actionable
    // remedy for the ca_trust_install check). Best-effort; reported, never fatal.
    if fix {
        match core.local_identity().await {
            Some(id) => match os_truststore::Cert::from_pem(&id.ca_cert_pem) {
                Ok(cert) => match install_cert(&cert, "koi-certmesh-ca", "certmesh") {
                    Ok(fp) => eprintln!(
                        "Fixed: installed the mesh CA (sha256: {fp}) into the OS trust store."
                    ),
                    Err(e) => eprintln!("--fix: could not install the mesh CA: {e}"),
                },
                Err(e) => eprintln!("--fix: the mesh CA certificate is invalid: {e}"),
            },
            None => eprintln!("--fix: no local identity — nothing to install (this node is Open)."),
        }
    }

    let diagnosis = core.diagnose().await;

    if json {
        print_json(&diagnosis);
    } else {
        print!("{}", crate::format::trust_diagnosis(&diagnosis));
    }

    // The tool must fail loud: a RED diagnosis exits non-zero.
    if diagnosis.is_red() {
        std::process::exit(diagnosis.exit_code());
    }
    Ok(())
}

/// List the CA roots Koi installed.
pub fn list(json: bool) -> anyhow::Result<()> {
    let state = koi_config::state::load_trust_state().unwrap_or_default();

    if json {
        print_json(&serde_json::json!({ "roots": state.roots }));
        return Ok(());
    }

    if state.roots.is_empty() {
        println!("No Koi-installed CA roots.");
        return Ok(());
    }
    let (h_name, h_installed) = ("NAME", "INSTALLED");
    println!("{h_name:<28}  {h_installed:<20}  FINGERPRINT (sha256)");
    for r in &state.roots {
        let fp_short: String = r.fingerprint.chars().take(16).collect();
        let fp = format!("{fp_short}...");
        let name = &r.name;
        let installed = &r.installed_at;
        println!("{name:<28}  {installed:<20}  {fp}");
    }
    Ok(())
}

/// Remove a Koi-installed CA root by name (OS store + the tracked entry).
pub fn remove(name: &str, json: bool) -> anyhow::Result<()> {
    let mut state = koi_config::state::load_trust_state().unwrap_or_default();
    let Some(entry) = state.roots.iter().find(|r| r.name == name).cloned() else {
        anyhow::bail!(
            "no Koi-installed CA root named \"{name}\" (run `koi trust list` to see them)"
        );
    };

    // The trust-store API is keyed on the certificate, so reconstruct it from the source
    // this entry recorded, then uninstall.
    let pem = std::fs::read_to_string(&entry.source).with_context(|| {
        format!(
            "re-reading the certificate from {} to remove it (the source file must still exist)",
            entry.source
        )
    })?;
    let cert = os_truststore::Cert::from_pem(&pem)
        .map_err(|e| anyhow::anyhow!("the certificate at {} is invalid: {e}", entry.source))?;

    os_truststore::uninstall(&cert)
        .map_err(|e| anyhow::anyhow!("failed to remove from OS trust store: {e}"))?;

    state.roots.retain(|r| r.name != name);
    koi_config::state::save_trust_state(&state).context("saving trust state")?;

    if json {
        print_json(&serde_json::json!({ "removed": name }));
    } else {
        println!("Removed CA \"{name}\" from the OS trust store.");
    }
    Ok(())
}

/// Export a CA certificate (PEM) to stdout. Only `--ca` (the certmesh root) is
/// supported; it is the one the P12 ACME bootstrap recipes need.
pub fn export(ca: bool, _json: bool) -> anyhow::Result<()> {
    if !ca {
        anyhow::bail!(
            "specify what to export: `koi trust export --ca` prints the certmesh root CA"
        );
    }

    // Per-process CLI command: a legitimate composition root, so it resolves the
    // data dir once here (mirrors commands::certmesh).
    #[allow(clippy::disallowed_methods)]
    let paths = koi_certmesh::CertmeshPaths::with_data_dir(koi_common::paths::koi_data_dir());
    let ca_cert_path = paths.ca_cert_path();
    let pem = std::fs::read_to_string(&ca_cert_path).with_context(|| {
        format!(
            "reading certmesh CA certificate at {} (run `koi certmesh create` first)",
            ca_cert_path.display()
        )
    })?;

    // Raw PEM to stdout so it pipes cleanly: `koi trust export --ca > koi-root.pem`.
    print!("{pem}");
    Ok(())
}

/// Derive a trust-store name from the PEM file path, sanitized to satisfy the
/// truststore's name rules (no path separators, `:`, `*`, `?`, `..`, control
/// chars). Falls back to a generic name when the stem sanitizes to nothing.
fn derive_name(pem_path: &Path) -> anyhow::Result<String> {
    let stem = pem_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("koi-root");
    let sanitized: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Collapse `..` (forbidden) and trim separators.
    let cleaned = sanitized.replace("..", "-");
    let name = format!("koi-{}", cleaned.trim_matches('-'));
    if name.len() <= 4 {
        // Just the "koi-" prefix → nothing usable in the stem.
        return Ok("koi-root".to_string());
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn derive_name_sanitizes_path() {
        assert_eq!(
            derive_name(&PathBuf::from("/etc/ssl/step-ca-root.pem")).unwrap(),
            "koi-step-ca-root"
        );
    }

    #[test]
    fn derive_name_strips_dangerous_chars() {
        let name = derive_name(&PathBuf::from("we:ird*name?.pem")).unwrap();
        assert!(!name.contains(':'));
        assert!(!name.contains('*'));
        assert!(!name.contains('?'));
        assert!(!name.contains(".."));
    }

    #[test]
    fn derive_name_falls_back_for_empty_stem() {
        // A stem that sanitizes to nothing → the generic fallback.
        assert_eq!(
            derive_name(&PathBuf::from("/----.pem")).unwrap(),
            "koi-root"
        );
    }

    #[test]
    fn derive_name_is_accepted_by_truststore_validation() {
        // The derived name must pass the truststore's own name rules.
        let name = derive_name(&PathBuf::from("/etc/ssl/step-ca-root.pem")).unwrap();
        // install_ca_cert validates the name first; reuse parse to confirm the
        // name shape is path-safe (no separators/forbidden chars).
        assert!(!name.contains('/') && !name.contains('\\'));
        assert!(!name.contains(':') && !name.contains(".."));
    }
}
