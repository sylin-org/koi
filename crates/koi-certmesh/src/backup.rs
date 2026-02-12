//! Certmesh backup/restore encoding.
//!
//! Encodes a versioned, encrypted backup bundle containing CA key material,
//! TOTP secret, roster JSON, and audit log contents.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use koi_crypto::keys::{decrypt_bytes, encrypt_bytes, EncryptedKey};

use crate::error::CertmeshError;

pub const BACKUP_VERSION: u16 = 1;
const BACKUP_MAGIC: &[u8; 8] = b"KOIBACK1";

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    pub version: u16,
    pub created_at: String,
    pub ca_key_pem: String,
    pub ca_cert_pem: String,
    pub totp_secret: Vec<u8>,
    pub roster_json: String,
    pub audit_log: String,
}

impl BackupPayload {
    pub fn new(
        ca_key_pem: String,
        ca_cert_pem: String,
        totp_secret: Vec<u8>,
        roster_json: String,
        audit_log: String,
    ) -> Self {
        Self {
            version: BACKUP_VERSION,
            created_at: Utc::now().to_rfc3339(),
            ca_key_pem,
            ca_cert_pem,
            totp_secret,
            roster_json,
            audit_log,
        }
    }
}

pub fn encode_backup(payload: &BackupPayload, passphrase: &str) -> Result<Vec<u8>, CertmeshError> {
    let json =
        serde_json::to_vec(payload).map_err(|e| CertmeshError::BackupInvalid(e.to_string()))?;
    let encrypted = encrypt_bytes(&json, passphrase)?;
    Ok(encode_envelope(&encrypted))
}

pub fn decode_backup(bytes: &[u8], passphrase: &str) -> Result<BackupPayload, CertmeshError> {
    let encrypted = decode_envelope(bytes)?;
    let plaintext = decrypt_bytes(&encrypted, passphrase)
        .map_err(|e| CertmeshError::BackupInvalid(e.to_string()))?;
    serde_json::from_slice(&plaintext).map_err(|e| CertmeshError::BackupInvalid(e.to_string()))
}

fn encode_envelope(encrypted: &EncryptedKey) -> Vec<u8> {
    let salt_len = encrypted.salt.len() as u16;
    let nonce_len = encrypted.nonce.len() as u16;
    let ct_len = encrypted.ciphertext.len() as u32;

    let mut out = Vec::with_capacity(
        BACKUP_MAGIC.len()
            + 2
            + 2
            + 2
            + 4
            + encrypted.salt.len()
            + encrypted.nonce.len()
            + encrypted.ciphertext.len(),
    );
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    out.extend_from_slice(&salt_len.to_le_bytes());
    out.extend_from_slice(&nonce_len.to_le_bytes());
    out.extend_from_slice(&ct_len.to_le_bytes());
    out.extend_from_slice(&encrypted.salt);
    out.extend_from_slice(&encrypted.nonce);
    out.extend_from_slice(&encrypted.ciphertext);
    out
}

fn decode_envelope(bytes: &[u8]) -> Result<EncryptedKey, CertmeshError> {
    let header_len = BACKUP_MAGIC.len() + 2 + 2 + 2 + 4;
    if bytes.len() < header_len {
        return Err(CertmeshError::BackupInvalid("backup too short".to_string()));
    }

    if &bytes[..BACKUP_MAGIC.len()] != BACKUP_MAGIC {
        return Err(CertmeshError::BackupInvalid(
            "invalid backup magic".to_string(),
        ));
    }

    let mut cursor = BACKUP_MAGIC.len();
    let version = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
    cursor += 2;
    if version != BACKUP_VERSION {
        return Err(CertmeshError::BackupInvalid(format!(
            "unsupported backup version: {version}"
        )));
    }

    let salt_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
    cursor += 2;
    let nonce_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
    cursor += 2;
    let ct_len = u32::from_le_bytes([
        bytes[cursor],
        bytes[cursor + 1],
        bytes[cursor + 2],
        bytes[cursor + 3],
    ]) as usize;
    cursor += 4;

    let expected = header_len + salt_len + nonce_len + ct_len;
    if bytes.len() != expected {
        return Err(CertmeshError::BackupInvalid(
            "backup length mismatch".to_string(),
        ));
    }

    let salt = bytes[cursor..cursor + salt_len].to_vec();
    cursor += salt_len;
    let nonce = bytes[cursor..cursor + nonce_len].to_vec();
    cursor += nonce_len;
    let ciphertext = bytes[cursor..cursor + ct_len].to_vec();

    Ok(EncryptedKey {
        ciphertext,
        salt,
        nonce,
    })
}
