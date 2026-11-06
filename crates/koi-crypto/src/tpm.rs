//! Platform credential binding (machine-specific key protection).
//!
//! Protects encrypted CA key material so it can only be decrypted on
//! the machine where the CA was created.  Uses the OS-native credential
//! store via `keyring-core` and its per-platform store crates:
//!
//! - **Windows** - Credential Manager (DPAPI-backed, TPM-backed on
//!   modern hardware with vTPM or firmware TPM)
//! - **macOS** - Keychain (Secure Enclave on Apple Silicon)
//! - **Linux** - kernel keyutils
//!
//! Other operating systems have no store, so [`is_available`] is `false` there.
//!
//! This replaces the original `tss-esapi` TPM stub with a pragmatic
//! cross-platform approach that achieves the same security goal: the
//! encrypted CA key blob is bound to this machine.

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("platform credential store not available: {0}")]
    NotAvailable(String),
    #[error("platform credential binding failed: {0}")]
    Failure(String),
    #[error("no sealed material found for label '{0}'")]
    NotFound(String),
}

/// Outcome of deleting an exact platform credential label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialDelete {
    /// A credential existed and was removed.
    Removed,
    /// No credential existed for the label.
    Absent,
}

#[cfg(feature = "keyring")]
const SERVICE_NAME: &str = "koi-certmesh";

/// The platform credential store, built once per process.
///
/// Each store is configured to name credentials exactly as keyring 3 did, so
/// material sealed by earlier releases is still found.  Entries are built from
/// this private store rather than keyring-core's process-wide default, which
/// the embedding application may own.
#[cfg(feature = "keyring")]
fn platform_store() -> Result<&'static keyring_core::CredentialStore, TpmError> {
    use std::sync::{Arc, LazyLock};

    static STORE: LazyLock<Result<Arc<keyring_core::CredentialStore>, String>> =
        LazyLock::new(|| build_platform_store().map_err(|e| e.to_string()));

    match &*STORE {
        Ok(store) => Ok(store.as_ref()),
        Err(e) => Err(TpmError::NotAvailable(e.clone())),
    }
}

/// Windows Credential Manager: generic credential `{user}.{service}`.
#[cfg(all(feature = "keyring", target_os = "windows"))]
fn build_platform_store() -> keyring_core::Result<std::sync::Arc<keyring_core::CredentialStore>> {
    Ok(windows_native_keyring_store::Store::new()?)
}

/// macOS login (User) keychain: generic password keyed by service and account.
#[cfg(all(feature = "keyring", target_os = "macos"))]
fn build_platform_store() -> keyring_core::Result<std::sync::Arc<keyring_core::CredentialStore>> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

/// Linux kernel keyutils: session keyring, linked into the persistent keyring.
/// keyring 3 described keys as `keyring-rs:{user}@{service}`; the store's own
/// default prefix is `keyring:`, so keep the old one.
#[cfg(all(feature = "keyring", target_os = "linux"))]
fn build_platform_store() -> keyring_core::Result<std::sync::Arc<keyring_core::CredentialStore>> {
    let config = std::collections::HashMap::from([("prefix", "keyring-rs:"), ("divider", "@")]);
    Ok(linux_keyutils_keyring_store::Store::new_with_configuration(
        &config,
    )?)
}

#[cfg(all(
    feature = "keyring",
    not(any(target_os = "windows", target_os = "macos", target_os = "linux"))
))]
fn build_platform_store() -> keyring_core::Result<std::sync::Arc<keyring_core::CredentialStore>> {
    Err(keyring_core::Error::NotSupportedByStore(
        "no platform credential store on this operating system".to_string(),
    ))
}

#[cfg(feature = "keyring")]
fn entry(label: &str) -> Result<keyring_core::Entry, TpmError> {
    platform_store()?
        .build(SERVICE_NAME, label, None)
        .map_err(|e| TpmError::NotAvailable(e.to_string()))
}

/// Whether an entry error means "no such credential".
///
/// keyring 3's keyutils store reported a keyutils access denial as `NoEntry`;
/// linux-keyutils-keyring-store reports it as `NoStorageAccess`.  On Linux
/// (where `NoStorageAccess` can only come from that denial once the entry
/// exists) keep the old meaning.
#[cfg(feature = "keyring")]
fn is_no_entry(error: &keyring_core::Error) -> bool {
    match error {
        keyring_core::Error::NoEntry => true,
        #[cfg(target_os = "linux")]
        keyring_core::Error::NoStorageAccess(_) => true,
        _ => false,
    }
}

/// Check whether the platform credential store is functional.
///
/// Performs a probe write / read / delete cycle with a disposable entry
/// so we know up-front if the store is reachable.  Returns `false` on
/// headless Linux without Secret Service or keyutils.
///
/// Returns `false` immediately if `KOI_NO_CREDENTIAL_STORE=1` is set
/// (used in tests and CI to avoid Keychain authorization prompts on macOS).
#[cfg(feature = "keyring")]
pub fn is_available() -> bool {
    if std::env::var("KOI_NO_CREDENTIAL_STORE").is_ok() {
        return false;
    }

    let probe_user = "koi-probe-test";
    let entry = match entry(probe_user) {
        Ok(e) => e,
        Err(_) => return false,
    };
    if entry.set_password("probe").is_err() {
        return false;
    }
    let _ = entry.delete_credential();
    true
}

/// Seal key material into the platform credential store.
///
/// The material is stored as a binary secret keyed by
/// `(SERVICE_NAME, label)`.
#[cfg(feature = "keyring")]
pub fn seal_key_material(label: &str, data: &[u8]) -> Result<(), TpmError> {
    entry(label)?
        .set_secret(data)
        .map_err(|e| TpmError::Failure(format!("seal failed for '{label}': {e}")))?;
    tracing::debug!(label, "Key material sealed in platform credential store");
    Ok(())
}

/// Unseal (retrieve) key material from the platform credential store.
#[cfg(feature = "keyring")]
pub fn unseal_key_material(label: &str) -> Result<Vec<u8>, TpmError> {
    entry(label)?
        .get_secret()
        .map_err(|e| TpmError::NotFound(format!("unseal failed for '{label}': {e}")))
}

/// Delete sealed key material from the platform credential store.
///
/// Called during `certmesh destroy` to clean up.
#[cfg(feature = "keyring")]
pub fn delete_key_material(label: &str) -> Result<CredentialDelete, TpmError> {
    let entry = entry(label)?;
    match entry.get_secret() {
        Err(e) if is_no_entry(&e) => return Ok(CredentialDelete::Absent),
        Err(e) => {
            return Err(TpmError::Failure(format!(
                "cannot inspect credential before deleting '{label}': {e}"
            )))
        }
        Ok(_) => {}
    }
    match entry.delete_credential() {
        Ok(()) => {
            tracing::debug!(label, "Sealed key material deleted from credential store");
            Ok(CredentialDelete::Removed)
        }
        Err(e) if is_no_entry(&e) => Ok(CredentialDelete::Absent),
        Err(e) => Err(TpmError::Failure(format!(
            "delete failed for '{label}': {e}"
        ))),
    }
}

// ── Stubs when the `keyring` feature is disabled ────────────────────
//
// The public API is unchanged so callers (certmesh CA sealing, the vault) need no
// `#[cfg]`. With keyring off, `is_available()` is `false`, so callers take their
// existing fallback path (the vault's passphrase backend); seal/unseal report the
// missing feature rather than touching any credential store.

/// Always `false` — this build was compiled without the `keyring` feature.
#[cfg(not(feature = "keyring"))]
pub fn is_available() -> bool {
    false
}

#[cfg(not(feature = "keyring"))]
pub fn seal_key_material(label: &str, _data: &[u8]) -> Result<(), TpmError> {
    Err(TpmError::NotAvailable(format!(
        "koi-crypto built without the `keyring` feature; cannot seal '{label}'"
    )))
}

#[cfg(not(feature = "keyring"))]
pub fn unseal_key_material(label: &str) -> Result<Vec<u8>, TpmError> {
    Err(TpmError::NotFound(label.to_string()))
}

#[cfg(not(feature = "keyring"))]
pub fn delete_key_material(_label: &str) -> Result<CredentialDelete, TpmError> {
    // Nothing was sealed without the credential store — destroy is a no-op.
    Ok(CredentialDelete::Absent)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CredentialGuard(String);

    impl Drop for CredentialGuard {
        fn drop(&mut self) {
            let _ = delete_key_material(&self.0);
        }
    }

    #[test]
    fn is_available_returns_bool() {
        // Just verify it doesn't panic - actual availability depends
        // on the CI/dev environment. The env-var guard is tested here.
        std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
        assert!(!is_available());
        std::env::remove_var("KOI_NO_CREDENTIAL_STORE");
    }

    #[test]
    fn seal_unseal_round_trip() {
        if !is_available() {
            eprintln!("platform credential store not available, skipping");
            return;
        }
        let label = format!("koi-test-round-trip-{}", std::process::id());
        let _guard = CredentialGuard(label.clone());
        let data = b"test-secret-material-1234";

        seal_key_material(&label, data).expect("seal should succeed");
        let recovered = unseal_key_material(&label).expect("unseal should succeed");
        assert_eq!(&recovered, data);

        assert_eq!(
            delete_key_material(&label).expect("delete should succeed"),
            CredentialDelete::Removed
        );
        assert_eq!(
            delete_key_material(&label).expect("repeat delete should succeed"),
            CredentialDelete::Absent
        );
        assert!(unseal_key_material(&label).is_err());
    }

    #[test]
    fn unseal_nonexistent_returns_error() {
        if !is_available() {
            return;
        }
        assert!(unseal_key_material("koi-test-nonexistent-key-99999").is_err());
    }
}
