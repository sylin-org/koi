#[cfg(windows)]
pub mod windows;

mod install_lock;

#[cfg(unix)]
pub mod unix;

// Shared installer pipeline (ADR-036); the per-init recipes inside are
// Linux-gated, the shared pieces serve every platform.
pub mod recipes;

#[cfg(any(target_os = "macos", all(test, unix)))]
#[cfg_attr(all(test, not(target_os = "macos")), allow(dead_code))]
pub mod macos;

/// Load the install-time local operator policy, safely falling back to the
/// current process identity for foreground/user daemons and pre-policy installs.
pub fn daemon_local_operator(
    data_dir: &std::path::Path,
) -> anyhow::Result<koi_config::local_access::LocalOperator> {
    match koi_config::local_access::load(data_dir) {
        Ok(policy) => Ok(policy.operator),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %koi_config::local_access::policy_path(data_dir).display(),
                "No install-time local operator policy; using the daemon identity"
            );
            current_local_operator()
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn current_local_operator() -> anyhow::Result<koi_config::local_access::LocalOperator> {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    Ok(koi_config::local_access::LocalOperator::UnixUid { uid })
}

/// Capture the workstation operator while installer elevation provenance is
/// still available. The daemon later authenticates peers against this UID.
#[cfg(unix)]
pub fn record_unix_operator(
    user_install: bool,
    requested: Option<&str>,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let uid = if let Some(requested) = requested {
        resolve_unix_user(requested)?
    } else if user_install {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    } else {
        elevated_operator_uid()?
            // Direct root/package installs have no operator provenance; root is
            // safe and `--operator` makes the desired desktop principal explicit.
            .unwrap_or_else(|| unsafe { libc::getuid() })
    };
    let policy = koi_config::local_access::LocalAccessPolicy::new(
        koi_config::local_access::LocalOperator::UnixUid { uid },
    );
    let outcome = koi_config::local_access::save_commit(data_dir, &policy)?;
    koi_common::persist::require_durable(outcome, "persisting the local operator policy")?;
    println!("  Local operator UID: {uid}");
    Ok(())
}

#[cfg(unix)]
fn elevated_operator_uid() -> anyhow::Result<Option<u32>> {
    for name in ["SUDO_UID", "PKEXEC_UID"] {
        let Some(value) = std::env::var_os(name) else {
            continue;
        };
        let value = value
            .into_string()
            .map_err(|_| anyhow::anyhow!("{name} is not valid UTF-8"))?;
        let uid = value
            .parse::<u32>()
            .map_err(|error| anyhow::anyhow!("{name} is not a valid UID: {error}"))?;
        return Ok(Some(uid));
    }
    Ok(None)
}

#[cfg(unix)]
fn resolve_unix_user(value: &str) -> anyhow::Result<u32> {
    if let Ok(uid) = value.parse::<u32>() {
        return Ok(uid);
    }
    let name = std::ffi::CString::new(value)?;
    // SAFETY: getpwnam reads the live NUL-terminated name; the returned static
    // passwd entry is copied immediately by value (installer is single-threaded).
    let passwd = unsafe { libc::getpwnam(name.as_ptr()) };
    if passwd.is_null() {
        anyhow::bail!("local operator user '{value}' does not exist")
    }
    Ok(unsafe { (*passwd).pw_uid })
}

#[cfg(windows)]
fn current_local_operator() -> anyhow::Result<koi_config::local_access::LocalOperator> {
    Ok(koi_config::local_access::LocalOperator::WindowsSid {
        sid: windows::current_user_sid()?,
    })
}

/// Platform-specific service registration.
/// On Windows, integrates with the Service Control Manager (SCM).
/// On Linux, sends systemd sd_notify(READY=1).
pub fn register_service() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        // Windows service registration is handled separately via the install subcommand.
        // When running as a service, the SCM handler is set up in windows::run_service().
        Ok(())
    }
    #[cfg(unix)]
    {
        unix::notify_ready()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(())
    }
}

/// Check that the current process is running as root/administrator.
/// Bails with a clear message if not elevated.
#[cfg(unix)]
pub fn check_root(verb: &str) -> anyhow::Result<()> {
    // SAFETY: getuid() is always safe to call and has no preconditions.
    if unsafe { libc::getuid() } == 0 {
        Ok(())
    } else {
        anyhow::bail!("\"koi {verb}\" requires root privileges. Re-run with sudo.")
    }
}
