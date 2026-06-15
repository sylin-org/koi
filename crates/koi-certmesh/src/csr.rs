//! CSR (PKCS#10 Certificate Signing Request) issuance.
//!
//! The ACME finalize step hands the CA a client-supplied CSR plus the set of
//! identifiers (SANs) the client *proved control of* via challenges. The CA
//! signs a leaf for that CSR — but the issued certificate's SANs are taken from
//! the **authorized** set the caller passes, never blindly from the CSR. This is
//! the security enforcement point: an ACME client could otherwise embed extra,
//! unproven names in its CSR and have them signed.

use chrono::{Duration, Utc};
use rcgen::{CertificateSigningRequestParams, SanType};

use crate::ca::CaState;
use crate::error::CertmeshError;

/// Default leaf validity for a CSR-signed certificate (days).
///
/// Matches the 30-day member-cert convention used by `ca::issue_certificate`.
const DEFAULT_CSR_VALIDITY_DAYS: u32 = 30;

/// Sign a client-supplied PKCS#10 CSR with the CA, issuing a leaf certificate.
///
/// * `csr_pem` — the client CSR in PEM. Parsed via
///   [`CertificateSigningRequestParams::from_pem`], which **parses and verifies
///   the CSR's self-signature**; an invalid signature is rejected.
/// * `sans` — the **authorized** identifiers (the names proven via ACME
///   challenges). The issued certificate carries exactly these SANs. The CSR's
///   own embedded SANs are *not* trusted; they are discarded and replaced.
/// * `validity_days` — leaf validity. Pass `0` to use the 30-day default.
///
/// Returns the issued leaf certificate in PEM.
///
/// # Security
///
/// This function is the SAN-authorization enforcement point. The caller (the
/// ACME finalize handler) is responsible for passing only authorized names, but
/// even if a CSR requests additional SANs, this function issues a certificate
/// bearing **only** the `sans` argument — snuck-in names never get signed.
pub fn sign_csr(
    ca: &CaState,
    csr_pem: &str,
    sans: &[String],
    validity_days: u32,
) -> Result<String, CertmeshError> {
    // Parse + verify the CSR self-signature. A corrupted signature, malformed
    // PEM, or unsupported extension fails here.
    let mut csr_params = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| CertmeshError::InvalidPayload(format!("invalid CSR: {e}")))?;

    // SECURITY: drop whatever SANs the CSR embedded and substitute the
    // caller-authorized set. The CSR's requested SANs are only read above for
    // signature verification — they never reach the issued certificate.
    csr_params.params.subject_alt_names = build_san_list(sans);

    // Leaf validity window.
    let days = if validity_days == 0 {
        DEFAULT_CSR_VALIDITY_DAYS
    } else {
        validity_days
    };
    let not_before = Utc::now();
    let not_after = not_before + Duration::days(i64::from(days));
    csr_params.params.not_before =
        time::OffsetDateTime::from_unix_timestamp(not_before.timestamp())
            .unwrap_or(time::OffsetDateTime::now_utc());
    csr_params.params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after.timestamp())
        .unwrap_or(time::OffsetDateTime::now_utc());

    // Issue the leaf signed by the CA. The 0.13 CSR form of `signed_by` takes
    // (issuer_cert, issuer_key) — the CSR carries its own public key.
    let leaf = csr_params
        .signed_by(&ca.ca_cert, &ca.rcgen_key)
        .map_err(|e| CertmeshError::Certificate(e.to_string()))?;

    Ok(leaf.pem())
}

/// Translate authorized name strings into rcgen SAN entries.
///
/// IP-literal strings become `SanType::IpAddress`; everything else becomes a
/// `SanType::DnsName` (wildcards like `*.example.lan` are valid DNS SANs).
fn build_san_list(sans: &[String]) -> Vec<SanType> {
    sans.iter()
        .filter_map(|s| {
            if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                Some(SanType::IpAddress(ip))
            } else {
                SanType::DnsName(s.clone().try_into().ok()?).into()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::create_ca;
    use rcgen::{CertificateParams, KeyPair};
    use x509_parser::prelude::FromDer;

    fn test_entropy() -> Vec<u8> {
        let _ = koi_common::test::ensure_data_dir("koi-certmesh-csr-tests");
        vec![7u8; 32]
    }

    fn test_ca() -> CaState {
        let paths = crate::CertmeshPaths::with_data_dir(koi_common::test::ensure_data_dir(
            "koi-certmesh-csr-tests",
        ));
        let (ca, _master) = create_ca("csr-test-pass", &test_entropy(), &paths).unwrap();
        ca
    }

    /// Build a CSR with the given requested SANs. Returns (csr_pem, key).
    fn make_csr(requested_sans: &[&str]) -> (String, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let dns: Vec<String> = requested_sans.iter().map(|s| s.to_string()).collect();
        let mut params = CertificateParams::new(dns).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, requested_sans[0]);
        let csr = params.serialize_request(&key).unwrap();
        (csr.pem().unwrap(), key)
    }

    /// Extract the DNS SANs from a leaf cert PEM using x509-parser.
    fn leaf_dns_sans(cert_pem: &str) -> Vec<String> {
        let der = pem::parse(cert_pem).unwrap();
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(der.contents()).unwrap();
        let mut names = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for gn in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = gn {
                    names.push(dns.to_string());
                }
            }
        }
        names.sort();
        names
    }

    #[test]
    fn sign_csr_issues_cert_chaining_to_ca() {
        let ca = test_ca();
        let (csr_pem, _key) = make_csr(&["host-a.lan"]);

        let leaf_pem = sign_csr(&ca, &csr_pem, &["host-a.lan".to_string()], 30).unwrap();
        assert!(leaf_pem.contains("BEGIN CERTIFICATE"));

        // Verify the leaf's issuer matches the CA's subject (chains to the CA).
        let leaf_der = pem::parse(&leaf_pem).unwrap();
        let (_, leaf) =
            x509_parser::certificate::X509Certificate::from_der(leaf_der.contents()).unwrap();

        let ca_der = pem::parse(&ca.cert_pem).unwrap();
        let (_, ca_cert) =
            x509_parser::certificate::X509Certificate::from_der(ca_der.contents()).unwrap();

        assert_eq!(
            leaf.issuer().to_string(),
            ca_cert.subject().to_string(),
            "leaf issuer must equal CA subject"
        );

        // The leaf signature must verify against the CA's public key.
        assert!(
            leaf.verify_signature(Some(ca_cert.public_key())).is_ok(),
            "leaf must be signed by the CA"
        );
    }

    #[test]
    fn sign_csr_uses_authorized_sans_not_csr_sans() {
        let ca = test_ca();
        // CSR requests an EXTRA, unauthorized name ("evil.lan") plus the real one.
        let (csr_pem, _key) = make_csr(&["host-b.lan", "evil.lan"]);

        // Caller authorizes ONLY host-b.lan.
        let authorized = vec!["host-b.lan".to_string()];
        let leaf_pem = sign_csr(&ca, &csr_pem, &authorized, 30).unwrap();

        let issued_sans = leaf_dns_sans(&leaf_pem);
        assert_eq!(
            issued_sans,
            vec!["host-b.lan".to_string()],
            "issued cert must carry ONLY the authorized SANs, not the CSR's snuck-in names"
        );
        assert!(
            !issued_sans.contains(&"evil.lan".to_string()),
            "the unauthorized SAN from the CSR must NOT appear in the issued cert"
        );
    }

    #[test]
    fn sign_csr_rejects_corrupted_signature() {
        let ca = test_ca();
        let (csr_pem, _key) = make_csr(&["host-c.lan"]);

        // Corrupt the CSR signature by flipping bytes in the base64 body.
        let der = pem::parse(&csr_pem).unwrap();
        let mut bytes = der.contents().to_vec();
        // Flip bits in the trailing region (the signature lives at the end of a
        // CertificationRequest DER structure).
        let len = bytes.len();
        for b in bytes.iter_mut().skip(len.saturating_sub(8)) {
            *b ^= 0xFF;
        }
        let corrupted_pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", bytes));

        let result = sign_csr(&ca, &corrupted_pem, &["host-c.lan".to_string()], 30);
        assert!(
            result.is_err(),
            "a CSR with a corrupted signature must be rejected"
        );
        assert!(
            matches!(result, Err(CertmeshError::InvalidPayload(_))),
            "corrupted CSR should map to InvalidPayload, got {result:?}"
        );
    }

    #[test]
    fn sign_csr_validity_zero_uses_default() {
        let ca = test_ca();
        let (csr_pem, _key) = make_csr(&["host-d.lan"]);
        // validity_days = 0 → 30-day default; just assert it issues successfully.
        let leaf_pem = sign_csr(&ca, &csr_pem, &["host-d.lan".to_string()], 0).unwrap();
        assert!(leaf_pem.contains("BEGIN CERTIFICATE"));
    }
}
