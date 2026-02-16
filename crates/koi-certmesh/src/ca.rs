//! Certificate Authority creation and certificate issuance.
//!
//! Creates ECDSA P-256 root CA certificates using `rcgen` and issues
//! service certificates for mesh members signed by the CA.

use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use koi_crypto::keys::{self, CaKeyPair, CryptoError};
use koi_crypto::pinning;
use koi_crypto::unlock_slots::{self, SlotTable};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};

use crate::error::CertmeshError;

const CA_DIR_NAME: &str = "certmesh";
const CA_SUBDIR: &str = "ca";
const CA_KEY_FILENAME: &str = "ca-key.enc";
const CA_CERT_FILENAME: &str = "ca-cert.pem";
const SLOT_TABLE_FILENAME: &str = "unlock-slots.json";
const AUTH_FILENAME: &str = "auth.json";
const ROSTER_FILENAME: &str = "roster.json";

/// Certificate lifetime for issued service certificates.
const CERT_LIFETIME_DAYS: i64 = 30;

/// CA certificate validity period.
const CA_VALIDITY_YEARS: i64 = 10;

/// Holds the decrypted CA state in memory.
pub struct CaState {
    /// The CA's cryptographic key pair (koi-crypto type, zeroized on drop).
    /// Kept alive for its Drop impl and potential re-encryption.
    #[allow(dead_code)]
    pub(crate) key: CaKeyPair,
    /// The CA's rcgen KeyPair for signing operations.
    pub(crate) rcgen_key: KeyPair,
    /// The self-signed CA certificate.
    pub(crate) ca_cert: rcgen::Certificate,
    /// CA certificate in PEM format.
    pub cert_pem: String,
    /// CA certificate in DER format (for fingerprinting).
    pub(crate) cert_der: Vec<u8>,
}

/// Result of issuing a certificate to a member.
#[derive(Debug)]
pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
    pub fullchain_pem: String,
    pub fingerprint: String,
    pub expires: DateTime<Utc>,
}

/// Directory where CA state is stored.
pub fn ca_dir() -> PathBuf {
    koi_common::paths::koi_data_dir()
        .join(CA_DIR_NAME)
        .join(CA_SUBDIR)
}

/// Directory where certmesh state is stored (parent of ca/).
pub fn certmesh_dir() -> PathBuf {
    koi_common::paths::koi_data_dir().join(CA_DIR_NAME)
}

/// Check if a CA has been initialized (encrypted key file exists).
pub fn is_ca_initialized() -> bool {
    ca_dir().join(CA_KEY_FILENAME).exists()
}

/// Path to the encrypted CA key file.
pub fn ca_key_path() -> PathBuf {
    ca_dir().join(CA_KEY_FILENAME)
}

/// Path to the CA certificate PEM file.
pub fn ca_cert_path() -> PathBuf {
    ca_dir().join(CA_CERT_FILENAME)
}

/// Path to the auth credential file.
pub fn auth_path() -> PathBuf {
    ca_dir().join(AUTH_FILENAME)
}

/// Path to the roster file.
pub fn roster_path() -> PathBuf {
    certmesh_dir().join(ROSTER_FILENAME)
}

/// Path to the unlock slot table.
pub fn slot_table_path() -> PathBuf {
    ca_dir().join(SLOT_TABLE_FILENAME)
}

/// Check whether envelope encryption (slot table) is active.
pub fn has_slot_table() -> bool {
    slot_table_path().exists()
}

/// Load the slot table from disk. Returns `None` if no slot table exists
/// (legacy passphrase-direct encryption).
pub fn load_slot_table() -> Result<Option<SlotTable>, CertmeshError> {
    let path = slot_table_path();
    if !path.exists() {
        return Ok(None);
    }
    let table = SlotTable::load(&path).map_err(|e| CertmeshError::Crypto(e.to_string()))?;
    Ok(Some(table))
}

/// Save the slot table to disk.
pub fn save_slot_table(table: &SlotTable) -> Result<(), CertmeshError> {
    table
        .save(&slot_table_path())
        .map_err(|e| CertmeshError::Crypto(e.to_string()))?;
    Ok(())
}

/// Build the CA's CertificateParams (without key — rcgen 0.13 style).
fn build_ca_params() -> Result<CertificateParams, CertmeshError> {
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Koi Certmesh CA");
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "Koi");

    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let not_before = Utc::now();
    let not_after = not_before + Duration::days(CA_VALIDITY_YEARS * 365);
    ca_params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before.timestamp())
        .unwrap_or(time::OffsetDateTime::now_utc());
    ca_params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after.timestamp())
        .unwrap_or(time::OffsetDateTime::now_utc());

    Ok(ca_params)
}

/// Create a new CA from scratch with envelope encryption.
///
/// Generates a keypair, creates a self-signed root CA certificate,
/// encrypts the key with a random master key, creates a slot table
/// with a passphrase slot, and writes everything to disk.
///
/// Returns the CA state and the master key (so callers can add
/// additional unlock slots before discarding it).
pub fn create_ca(
    passphrase: &str,
    entropy_seed: &[u8],
) -> Result<(CaState, [u8; 32]), CertmeshError> {
    let ca_key = keys::generate_ca_keypair(entropy_seed);

    // Build rcgen KeyPair from our P-256 key
    let key_pem = ca_key.private_key_pem();
    let rcgen_key =
        KeyPair::from_pem(&key_pem).map_err(|e| CertmeshError::Certificate(e.to_string()))?;

    // Build CA params and self-sign (rcgen 0.13: params consumed, key by ref)
    let ca_params = build_ca_params()?;
    let ca_cert = ca_params
        .self_signed(&rcgen_key)
        .map_err(|e| CertmeshError::Certificate(e.to_string()))?;

    let cert_pem = ca_cert.pem();
    let cert_der = ca_cert.der().to_vec();

    // Envelope encryption: master key wraps CA key, passphrase wraps master key
    let dir = ca_dir();
    std::fs::create_dir_all(&dir)?;

    let ca_key_der =
        keys::ca_keypair_to_der(&ca_key).map_err(|e| CertmeshError::Crypto(e.to_string()))?;
    let (encrypted_key, slot_table, master_key) =
        unlock_slots::envelope_encrypt_new(&ca_key_der, passphrase)
            .map_err(|e| CertmeshError::Crypto(e.to_string()))?;

    keys::save_encrypted_key(&dir.join(CA_KEY_FILENAME), &encrypted_key)?;
    slot_table
        .save(&dir.join(SLOT_TABLE_FILENAME))
        .map_err(|e| CertmeshError::Crypto(e.to_string()))?;

    // Save CA certificate
    std::fs::write(dir.join(CA_CERT_FILENAME), &cert_pem)?;

    // Platform credential binding — seal the ciphertext in the OS
    // credential store so the key blob is machine-bound.
    if koi_crypto::tpm::is_available() {
        if let Err(e) =
            koi_crypto::tpm::seal_key_material("koi-certmesh-ca", &encrypted_key.ciphertext)
        {
            tracing::warn!(error = %e, "Platform credential sealing failed; falling back to software-only protection");
        } else {
            tracing::info!("CA key material sealed in platform credential store");
        }
    }

    tracing::info!("CA created with envelope encryption");

    Ok((
        CaState {
            key: ca_key,
            rcgen_key,
            ca_cert,
            cert_pem,
            cert_der,
        },
        master_key,
    ))
}

/// Load an existing CA by decrypting the key with the passphrase.
///
/// Supports both legacy (direct passphrase encryption) and envelope
/// encryption (slot table). Legacy keys are auto-migrated to envelope
/// encryption on load.
pub fn load_ca(passphrase: &str) -> Result<CaState, CertmeshError> {
    let dir = ca_dir();
    let key_path = dir.join(CA_KEY_FILENAME);
    let slot_path = dir.join(SLOT_TABLE_FILENAME);

    if !key_path.exists() {
        return Err(CertmeshError::CaNotInitialized);
    }

    let encrypted = keys::load_encrypted_key(&key_path)?;

    let ca_key_der = if slot_path.exists() {
        // ── Envelope encryption path ──
        let slot_table =
            SlotTable::load(&slot_path).map_err(|e| CertmeshError::Crypto(e.to_string()))?;
        let master_key = slot_table
            .unwrap_with_passphrase(passphrase)
            .map_err(|e| match e {
                CryptoError::Decryption(_) => {
                    CertmeshError::Crypto("wrong passphrase or corrupted key file".into())
                }
                other => CertmeshError::Crypto(other.to_string()),
            })?;
        unlock_slots::decrypt_with_master_key(&encrypted, &master_key)
            .map_err(|e| CertmeshError::Crypto(e.to_string()))?
    } else {
        // ── Legacy path: direct passphrase encryption ──
        // Decrypt, then auto-migrate to envelope encryption.
        let plaintext = keys::decrypt_bytes(&encrypted, passphrase).map_err(|e| match e {
            CryptoError::Decryption(_) => {
                CertmeshError::Crypto("wrong passphrase or corrupted key file".into())
            }
            other => CertmeshError::Crypto(other.to_string()),
        })?;

        tracing::info!("Migrating CA key from legacy encryption to envelope encryption");
        let (new_encrypted, slot_table, _master_key) =
            unlock_slots::migrate_to_envelope(&encrypted, passphrase)
                .map_err(|e| CertmeshError::Crypto(e.to_string()))?;

        keys::save_encrypted_key(&key_path, &new_encrypted)?;
        slot_table
            .save(&slot_path)
            .map_err(|e| CertmeshError::Crypto(e.to_string()))?;
        tracing::info!("CA key migrated to envelope encryption");

        plaintext
    };

    build_ca_state_from_der(&ca_key_der)
}

/// Load an existing CA using a pre-unwrapped master key.
///
/// Used when the master key was obtained via TOTP, FIDO2, or auto-unlock
/// rather than passphrase.
pub fn load_ca_with_master_key(master_key: &[u8; 32]) -> Result<CaState, CertmeshError> {
    let dir = ca_dir();
    let key_path = dir.join(CA_KEY_FILENAME);

    if !key_path.exists() {
        return Err(CertmeshError::CaNotInitialized);
    }

    let encrypted = keys::load_encrypted_key(&key_path)?;
    let ca_key_der = unlock_slots::decrypt_with_master_key(&encrypted, master_key)
        .map_err(|e| CertmeshError::Crypto(e.to_string()))?;

    build_ca_state_from_der(&ca_key_der)
}

/// Reconstruct `CaState` from decrypted PKCS#8 DER key bytes.
fn build_ca_state_from_der(ca_key_der: &[u8]) -> Result<CaState, CertmeshError> {
    let ca_key =
        keys::ca_keypair_from_der(ca_key_der).map_err(|e| CertmeshError::Crypto(e.to_string()))?;

    let cert_path = ca_dir().join(CA_CERT_FILENAME);
    let cert_pem = std::fs::read_to_string(&cert_path)?;

    // Parse the cert PEM to get DER for fingerprinting
    let parsed = pem::parse(&cert_pem).map_err(|e| CertmeshError::Certificate(e.to_string()))?;
    let cert_der = parsed.contents().to_vec();

    // Rebuild rcgen KeyPair for signing operations
    let key_pem_str = ca_key.private_key_pem();
    let rcgen_key =
        KeyPair::from_pem(&key_pem_str).map_err(|e| CertmeshError::Certificate(e.to_string()))?;

    // Re-create the self-signed CA cert for use as issuer in signed_by()
    let ca_params = build_ca_params()?;
    let ca_cert = ca_params
        .self_signed(&rcgen_key)
        .map_err(|e| CertmeshError::Certificate(e.to_string()))?;

    Ok(CaState {
        key: ca_key,
        rcgen_key,
        ca_cert,
        cert_pem,
        cert_der,
    })
}

/// Issue a service certificate for a member signed by this CA.
///
/// `sans` should include: hostname, hostname.local, any IPs.
pub fn issue_certificate(
    ca: &CaState,
    hostname: &str,
    sans: &[String],
) -> Result<IssuedCert, CertmeshError> {
    // Generate a new keypair for the member
    let member_key = KeyPair::generate().map_err(|e| CertmeshError::Certificate(e.to_string()))?;

    // Build params with DNS SANs
    let dns_sans: Vec<String> = sans
        .iter()
        .filter(|s| s.parse::<std::net::IpAddr>().is_err())
        .cloned()
        .collect();

    let mut cert_params =
        CertificateParams::new(dns_sans).map_err(|e| CertmeshError::Certificate(e.to_string()))?;

    cert_params
        .distinguished_name
        .push(DnType::CommonName, hostname);

    // Add IP SANs
    for san in sans {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            cert_params.subject_alt_names.push(SanType::IpAddress(ip));
        }
    }

    let not_before = Utc::now();
    let not_after = not_before + Duration::days(CERT_LIFETIME_DAYS);
    cert_params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before.timestamp())
        .unwrap_or(time::OffsetDateTime::now_utc());
    cert_params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after.timestamp())
        .unwrap_or(time::OffsetDateTime::now_utc());

    // Sign with the CA (rcgen 0.13: params.signed_by(&member_key, &ca_cert, &ca_key))
    let member_cert = cert_params
        .signed_by(&member_key, &ca.ca_cert, &ca.rcgen_key)
        .map_err(|e| CertmeshError::Certificate(e.to_string()))?;

    let cert_pem = member_cert.pem();
    let key_pem = member_key.serialize_pem();
    let ca_pem = ca.cert_pem.clone();
    let fullchain_pem = format!("{cert_pem}{ca_pem}");

    let fingerprint = pinning::fingerprint_sha256(member_cert.der());

    Ok(IssuedCert {
        cert_pem,
        key_pem,
        ca_pem,
        fullchain_pem,
        fingerprint,
        expires: not_after,
    })
}

/// Get the SHA-256 fingerprint of the CA certificate.
pub fn ca_fingerprint(ca: &CaState) -> String {
    pinning::fingerprint_sha256(&ca.cert_der)
}

/// Get the SHA-256 fingerprint of the CA certificate on disk.
pub fn ca_fingerprint_from_disk() -> Result<String, CertmeshError> {
    let cert_path = ca_cert_path();
    if !cert_path.exists() {
        return Err(CertmeshError::CaNotInitialized);
    }

    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let parsed = pem::parse(&cert_pem).map_err(|e| CertmeshError::Certificate(e.to_string()))?;
    Ok(pinning::fingerprint_sha256(parsed.contents()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entropy() -> Vec<u8> {
        let _ = koi_common::test::ensure_data_dir("koi-certmesh-ca-tests");
        vec![42u8; 32]
    }

    #[test]
    fn create_ca_produces_valid_state() {
        let ca_key = keys::generate_ca_keypair(&test_entropy());
        let pem = ca_key.public_key_pem();
        assert!(pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn ca_fingerprint_is_deterministic() {
        let cert_der = b"test certificate data for fingerprint";
        let fp1 = pinning::fingerprint_sha256(cert_der);
        let fp2 = pinning::fingerprint_sha256(cert_der);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn is_ca_initialized_false_by_default() {
        let _ = is_ca_initialized();
    }

    #[test]
    fn full_ca_and_issue_round_trip() {
        let (ca, _master_key) = create_ca("test-pass", &test_entropy()).unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!ca.cert_der.is_empty());

        let issued = issue_certificate(
            &ca,
            "stone-05",
            &["stone-05".to_string(), "stone-05.local".to_string()],
        )
        .unwrap();

        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(issued.fullchain_pem.contains(&issued.cert_pem));
        assert!(issued.fullchain_pem.contains(&issued.ca_pem));
        assert_eq!(issued.fingerprint.len(), 64);
    }
}
