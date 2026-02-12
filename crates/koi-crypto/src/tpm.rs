//! TPM 2.0 integration (best-effort).
//!
//! This module is feature-gated and should fail gracefully when TPM
//! hardware or system libraries are unavailable.

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("TPM support not enabled")]
    NotEnabled,
    #[error("TPM not available")]
    NotAvailable,
    #[error("TPM operation failed: {0}")]
    Failure(String),
}

#[cfg(feature = "tpm")]
pub fn is_available() -> bool {
    false
}

#[cfg(not(feature = "tpm"))]
pub fn is_available() -> bool {
    false
}

#[cfg(feature = "tpm")]
pub fn seal_key_material(_label: &str, _data: &[u8]) -> Result<(), TpmError> {
    Err(TpmError::NotAvailable)
}

#[cfg(not(feature = "tpm"))]
pub fn seal_key_material(_label: &str, _data: &[u8]) -> Result<(), TpmError> {
    Err(TpmError::NotEnabled)
}
