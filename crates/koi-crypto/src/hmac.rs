//! HMAC-SHA256 for outbound integrity (webhook sink signatures).
//!
//! Kept in `koi-crypto` so every keyed-hash primitive lives in one subdomain.
//! This is message authentication only — no key derivation, no new HKDF labels
//! (STACK-0001 K3 untouched).

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over `data` with `key`. Returns the raw 32 digest bytes.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Lowercase hexadecimal encoding of a 32-byte digest (wire form of a signature).
pub fn hex_32(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
    #[test]
    fn rfc4231_case2_vector() {
        let digest = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex_32(&digest),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn empty_key_is_valid() {
        // HMAC accepts zero-length keys; must not panic.
        let _ = hmac_sha256(b"", b"data");
    }
}
