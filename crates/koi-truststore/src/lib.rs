//! Platform trust store integration for Koi.
//!
//! Installs the certmesh root CA certificate into the operating system's
//! trust store so that browsers and HTTP clients trust certificates signed
//! by the mesh CA without manual configuration.
//!
//! Platform support:
//! - **Linux**: Copies to `/usr/local/share/ca-certificates/` and runs `update-ca-certificates`
//! - **Windows**: Uses `certutil -addstore Root`
//! - **macOS**: Uses `security add-trusted-cert` with the System keychain

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod darwin;

#[cfg(windows)]
mod windows;

#[derive(Debug, thiserror::Error)]
pub enum TrustStoreError {
    #[error("trust store command failed: {0}")]
    CommandFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid certificate name: {0}")]
    InvalidName(String),
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("platform not supported")]
    Unsupported,
}

/// A parsed and validated CA certificate, ready to install.
///
/// Produced by [`parse_ca_cert`]: the PEM has been re-encoded canonically (so
/// what we install is exactly what we parsed) and the DER bytes are available for
/// fingerprinting by the caller (e.g. `koi_crypto::pinning::fingerprint_sha256`).
#[derive(Debug, Clone)]
pub struct ParsedCaCert {
    /// Canonical single-cert PEM (re-encoded from the parsed DER).
    pub pem: String,
    /// DER bytes of the certificate (input to a SHA-256 fingerprint).
    pub der: Vec<u8>,
}

/// Parse a PEM string and verify it is a CA certificate.
///
/// Rejects, with a clear message:
/// - input that is not a parseable `CERTIFICATE` PEM block ("garbage");
/// - a certificate that is **not** a CA (no `CA:TRUE` basic constraint) — this is
///   the gate that stops a user from installing a server/leaf cert as a root.
///
/// On success returns the canonical PEM + DER so the caller controls what gets
/// installed and how it is fingerprinted.
pub fn parse_ca_cert(cert_pem: &str) -> Result<ParsedCaCert, TrustStoreError> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    // 1. Parse the PEM envelope. Must be a CERTIFICATE block. Fully-qualify the
    // `pem` crate so it is not shadowed by any `pem` symbol in scope.
    let parsed = ::pem::parse(cert_pem).map_err(|e| {
        TrustStoreError::InvalidCertificate(format!("not a valid PEM document: {e}"))
    })?;
    if parsed.tag() != "CERTIFICATE" {
        return Err(TrustStoreError::InvalidCertificate(format!(
            "expected a CERTIFICATE PEM block, found {:?}",
            parsed.tag()
        )));
    }
    let der = parsed.contents().to_vec();

    // 2. Parse the X.509 structure.
    let (_, cert) = X509Certificate::from_der(&der).map_err(|e| {
        TrustStoreError::InvalidCertificate(format!("not a valid X.509 certificate: {e}"))
    })?;

    // 3. Reject a non-CA cert. BasicConstraints CA flag must be present and true.
    let is_ca = match cert.basic_constraints() {
        Ok(Some(bc)) => bc.value.ca,
        _ => false,
    };
    if !is_ca {
        return Err(TrustStoreError::InvalidCertificate(
            "not a CA certificate (no CA basic constraint)".to_string(),
        ));
    }

    // Re-encode the PEM canonically so install writes exactly the parsed bytes.
    let canonical = ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.clone()));
    Ok(ParsedCaCert {
        pem: canonical,
        der,
    })
}

/// Validate that a certificate name is safe for use in file paths.
///
/// Rejects path separators, null bytes, control characters, `..`, and
/// names that are empty or excessively long.
fn validate_name(name: &str) -> Result<(), TrustStoreError> {
    if name.is_empty() {
        return Err(TrustStoreError::InvalidName("name is empty".to_string()));
    }
    if name.len() > 255 {
        return Err(TrustStoreError::InvalidName("name too long".to_string()));
    }
    if name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.contains("..")
        || name.contains(':')
        || name.contains('*')
        || name.contains('?')
    {
        return Err(TrustStoreError::InvalidName(format!(
            "name contains forbidden characters: {name}"
        )));
    }
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(TrustStoreError::InvalidName(format!(
            "name contains control characters: {name}"
        )));
    }
    Ok(())
}

/// Install a PEM-encoded CA certificate into the OS trust store.
///
/// `name` is used to construct the filename (e.g., `"koi-certmesh"` →
/// `koi-certmesh.crt` on Linux). The certificate is written to a
/// platform-appropriate location and the trust store is updated.
///
/// This operation typically requires elevated privileges.
/// Errors are returned but are non-fatal - callers should warn and continue.
pub fn install_ca_cert(cert_pem: &str, name: &str) -> Result<(), TrustStoreError> {
    validate_name(name)?;

    #[cfg(target_os = "linux")]
    {
        linux::install(cert_pem, name)
    }

    #[cfg(windows)]
    {
        windows::install(cert_pem, name)
    }

    #[cfg(target_os = "macos")]
    {
        darwin::install(cert_pem, name)
    }

    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = (cert_pem, name);
        Err(TrustStoreError::Unsupported)
    }
}

/// Remove a CA certificate from the OS trust store by `name`.
///
/// The inverse of [`install_ca_cert`]: removes the cert this `name` installed.
/// Per platform:
/// - **Linux**: deletes `/usr/local/share/ca-certificates/<name>.crt` and runs
///   `update-ca-certificates --fresh`;
/// - **Windows**: `certutil -delstore Root <name>`;
/// - **macOS**: `security delete-certificate -c <name>` on the System keychain.
///
/// Typically requires elevated privileges. Koi only ever removes roots it tracks
/// in its own state — it never enumerates or modifies the OS store wholesale.
pub fn remove_ca_cert(name: &str) -> Result<(), TrustStoreError> {
    validate_name(name)?;

    #[cfg(target_os = "linux")]
    {
        linux::remove(name)
    }

    #[cfg(windows)]
    {
        windows::remove(name)
    }

    #[cfg(target_os = "macos")]
    {
        darwin::remove(name)
    }

    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = name;
        Err(TrustStoreError::Unsupported)
    }
}

/// Best-effort check if a CA certificate with the given name is installed.
///
/// Returns `false` if the check fails or the platform is unsupported.
pub fn is_ca_installed(name: &str) -> bool {
    if validate_name(name).is_err() {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        linux::is_installed(name)
    }

    #[cfg(windows)]
    {
        windows::is_installed(name)
    }

    #[cfg(target_os = "macos")]
    {
        darwin::is_installed(name)
    }

    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = name;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Error type tests ───────────────────────────────────────────────

    #[test]
    fn error_command_failed_display() {
        let err = TrustStoreError::CommandFailed("certutil exit code 1: access denied".to_string());
        let msg = err.to_string();
        assert!(msg.contains("certutil"), "message: {msg}");
        assert!(msg.contains("access denied"), "message: {msg}");
    }

    #[test]
    fn error_io_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = TrustStoreError::from(io_err);
        let msg = err.to_string();
        assert!(msg.contains("permission denied"), "message: {msg}");
    }

    #[test]
    fn error_unsupported_display() {
        let err = TrustStoreError::Unsupported;
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn error_is_debug() {
        let err = TrustStoreError::CommandFailed("test".to_string());
        let debug = format!("{err:?}");
        assert!(debug.contains("CommandFailed"));
    }

    // ── is_ca_installed ────────────────────────────────────────────────

    #[test]
    fn is_ca_installed_returns_bool() {
        // Should not panic regardless of whether the cert exists
        let result = is_ca_installed("nonexistent-cert-for-koi-test");
        assert!(!result, "a nonexistent cert should not be installed");
    }

    // ── install_ca_cert ────────────────────────────────────────────────

    #[test]
    fn install_ca_cert_with_invalid_pem_does_not_panic() {
        // The function may fail (command errors, permission denied) but should
        // never panic. We only verify it returns a Result, not that it succeeds.
        let result = install_ca_cert("not-a-real-pem", "koi-test-invalid");
        // On CI/test environments this will likely fail with permission errors
        // or command errors, which is expected and fine.
        assert!(result.is_ok() || result.is_err());
    }

    // ── parse_ca_cert: CA validation ───────────────────────────────────

    /// Self-signed CA certificate PEM (BasicConstraints CA:TRUE).
    fn make_ca_pem() -> String {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    /// Self-signed leaf/server certificate PEM (no CA basic constraint).
    fn make_leaf_pem() -> String {
        use rcgen::{CertificateParams, KeyPair};
        let params = CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn parse_ca_cert_accepts_a_ca() {
        let pem = make_ca_pem();
        let parsed = parse_ca_cert(&pem).expect("a real CA cert should parse");
        assert!(!parsed.der.is_empty());
        assert!(parsed.pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn parse_ca_cert_rejects_a_non_ca_leaf() {
        let pem = make_leaf_pem();
        let err = parse_ca_cert(&pem).expect_err("a leaf cert must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("not a CA certificate"),
            "expected CA-constraint rejection, got: {msg}"
        );
    }

    #[test]
    fn parse_ca_cert_rejects_garbage() {
        let err = parse_ca_cert("this is not a pem at all").expect_err("garbage must be rejected");
        assert!(matches!(err, TrustStoreError::InvalidCertificate(_)));
    }

    #[test]
    fn parse_ca_cert_rejects_non_certificate_pem_block() {
        // A valid PEM document, but the wrong block type.
        let pem = "-----BEGIN PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n-----END PRIVATE KEY-----\n";
        let err = parse_ca_cert(pem).expect_err("a non-CERTIFICATE block must be rejected");
        assert!(matches!(err, TrustStoreError::InvalidCertificate(_)));
    }

    #[test]
    fn error_invalid_certificate_display() {
        let err = TrustStoreError::InvalidCertificate("not a CA certificate".to_string());
        assert!(err.to_string().contains("not a CA certificate"));
    }

    /// Full install → is_installed → remove round-trip against the real OS trust
    /// store. Ignored by default: it mutates the system store and requires
    /// elevated privileges (Administrator / sudo / root). Run explicitly with
    /// `cargo test -p koi-truststore -- --ignored` on a machine where that is safe.
    #[test]
    #[ignore = "mutates the OS trust store; needs admin"]
    fn install_list_remove_round_trip() {
        let name = "koi-truststore-roundtrip-test";
        let parsed = parse_ca_cert(&make_ca_pem()).expect("generated CA must validate");

        install_ca_cert(&parsed.pem, name).expect("install should succeed with admin rights");
        // Linux can verify by filename; other platforms are best-effort.
        #[cfg(target_os = "linux")]
        assert!(
            is_ca_installed(name),
            "cert should be present after install"
        );

        remove_ca_cert(name).expect("remove should succeed");
        #[cfg(target_os = "linux")]
        assert!(!is_ca_installed(name), "cert should be gone after remove");
    }
}
