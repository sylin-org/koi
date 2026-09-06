//! Browser proof primitives. A public session ID is never a bearer credential.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand::RngCore;

pub fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn valid_public_key(encoded: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| VerifyingKey::from_sec1_bytes(&bytes).ok())
        .is_some()
}

pub fn verify(
    public_key: &str,
    signature: &str,
    session: &str,
    challenge: &str,
    method: &str,
    path: &str,
) -> bool {
    let Ok(key) = URL_SAFE_NO_PAD.decode(public_key) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_sec1_bytes(&key) else {
        return false;
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature) else {
        return false;
    };
    key.verify(
        message(session, challenge, method, path).as_bytes(),
        &signature,
    )
    .is_ok()
}

pub fn message(session: &str, challenge: &str, method: &str, path: &str) -> String {
    format!("koi-browser-session-v1\n{session}\n{challenge}\n{method}\n{path}")
}
