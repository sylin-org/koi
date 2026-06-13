//! `koi token` — daemon access token (DAT) distribution utility.
//!
//! The daemon writes its current token to the breadcrumb file on startup; these
//! commands read it back so an operator can view it or mount it into a container
//! as a secret. Charter principle 5 — the secure path is the easy path: `show`
//! refuses to print the secret to a non-tty unless `--force`, and `write`
//! creates the file owner-only (0600 on Unix; ACL-restricted on Windows).

use std::io::IsTerminal;
use std::path::Path;

use crate::cli::{TokenCommand, TokenSubcommand};

pub fn run(cmd: &TokenCommand, json: bool) -> anyhow::Result<()> {
    match &cmd.command {
        None => {
            eprintln!("Usage: koi token <show|write>");
            eprintln!("  koi token show           print the daemon token (tty only)");
            eprintln!("  koi token show --force   print even when stdout is not a tty");
            eprintln!("  koi token write <path>   write the token to a 0600 file for containers");
            Ok(())
        }
        Some(TokenSubcommand::Show { force }) => show(*force, json),
        Some(TokenSubcommand::Write { path }) => write(path),
    }
}

/// Reads the current daemon token from the breadcrumb, or returns a friendly
/// error if the daemon is not running.
fn load_token() -> anyhow::Result<String> {
    koi_config::breadcrumb::read_breadcrumb()
        .map(|b| b.token)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no daemon token found — is the Koi daemon running? The token is \
                 written to the breadcrumb file when the daemon starts."
            )
        })
}

fn show(force: bool, json: bool) -> anyhow::Result<()> {
    let token = load_token()?;

    // Never echo a secret into a pipe by accident.
    if !force && !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "refusing to print the daemon token to a non-tty (it could be captured in \
             logs or scrollback). Re-run with --force, or use `koi token write <path>` \
             to write a 0600 file for mounting."
        );
    }

    if json {
        crate::commands::print_json(&serde_json::json!({ "token": token }));
    } else {
        println!("{token}");
    }
    Ok(())
}

fn write(path: &Path) -> anyhow::Result<()> {
    let token = load_token()?;
    write_secret_file(path, &token)?;
    // Confirmation goes to stderr so stdout stays clean for scripting.
    eprintln!("Wrote daemon token to {} (owner-only)", path.display());
    Ok(())
}

#[cfg(unix)]
fn write_secret_file(path: &Path, token: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(token.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, token: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, format!("{token}\n"))?;
    #[cfg(windows)]
    restrict_acl(path);
    Ok(())
}

/// Best-effort ACL restriction on Windows using icacls (mirrors the breadcrumb).
#[cfg(windows)]
fn restrict_acl(path: &Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut args = vec![
        path.display().to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        "SYSTEM:F".to_string(),
        "/grant:r".to_string(),
        "BUILTIN\\Administrators:F".to_string(),
    ];
    if let Ok(user) = std::env::var("USERNAME") {
        if !user.eq_ignore_ascii_case("SYSTEM") {
            args.push("/grant:r".to_string());
            args.push(format!("{user}:F"));
        }
    }
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let _ = std::process::Command::new("icacls")
        .args(&args_ref)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}
