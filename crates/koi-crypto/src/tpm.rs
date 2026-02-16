//! Platform credential binding (machine-specific key protection).
//!
//! Protects encrypted CA key material so it can only be decrypted on
//! the machine where the CA was created.  Uses the OS-native credential
//! store via the `keyring` crate:
//!
//! - **Windows** - Credential Manager (DPAPI-backed, TPM-backed on
//!   modern hardware with vTPM or firmware TPM)
//! - **macOS** - Keychain (Secure Enclave on Apple Silicon)
//! - **Linux** - kernel keyutils or Secret Service (D-Bus)
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

const SERVICE_NAME: &str = "koi-certmesh";

/// Check whether the platform credential store is functional.
///
/// Performs a probe write / read / delete cycle with a disposable entry
/// so we know up-front if the store is reachable.  Returns `false` on
/// headless Linux without Secret Service or keyutils.
pub fn is_available() -> bool {
    let probe_user = "koi-probe-test";
    let entry = match keyring::Entry::new(SERVICE_NAME, probe_user) {
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
pub fn seal_key_material(label: &str, data: &[u8]) -> Result<(), TpmError> {
    let entry = keyring::Entry::new(SERVICE_NAME, label)
        .map_err(|e| TpmError::NotAvailable(e.to_string()))?;
    entry
        .set_secret(data)
        .map_err(|e| TpmError::Failure(format!("seal failed for '{label}': {e}")))?;
    tracing::debug!(label, "Key material sealed in platform credential store");
    Ok(())
}

/// Unseal (retrieve) key material from the platform credential store.
pub fn unseal_key_material(label: &str) -> Result<Vec<u8>, TpmError> {
    let entry = keyring::Entry::new(SERVICE_NAME, label)
        .map_err(|e| TpmError::NotAvailable(e.to_string()))?;
    entry
        .get_secret()
        .map_err(|e| TpmError::NotFound(format!("unseal failed for '{label}': {e}")))
}

/// Delete sealed key material from the platform credential store.
///
/// Called during `certmesh destroy` to clean up.
pub fn delete_key_material(label: &str) -> Result<(), TpmError> {
    let entry = keyring::Entry::new(SERVICE_NAME, label)
        .map_err(|e| TpmError::NotAvailable(e.to_string()))?;
    entry
        .delete_credential()
        .map_err(|e| TpmError::Failure(format!("delete failed for '{label}': {e}")))?;
    tracing::debug!(label, "Sealed key material deleted from credential store");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_available_returns_bool() {
        // Just verify it doesn't panic - actual availability depends
        // on the CI/dev environment.
        let _ = is_available();
    }

    #[test]
    fn seal_unseal_round_trip() {
        if !is_available() {
            eprintln!("platform credential store not available, skipping");
            return;
        }
        let label = "koi-test-round-trip";
        let data = b"test-secret-material-1234";

        seal_key_material(label, data).expect("seal should succeed");
        let recovered = unseal_key_material(label).expect("unseal should succeed");
        assert_eq!(&recovered, data);

        delete_key_material(label).expect("delete should succeed");
        assert!(unseal_key_material(label).is_err());
    }

    #[test]
    fn unseal_nonexistent_returns_error() {
        if !is_available() {
            return;
        }
        assert!(unseal_key_material("koi-test-nonexistent-key-99999").is_err());
    }
}
