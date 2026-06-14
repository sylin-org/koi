//! Koi Crypto - cryptographic utilities for the certmesh capability.
//!
//! Provides ECDSA P-256 key management with encryption at rest,
//! TOTP generation/verification with rate limiting, certificate
//! fingerprinting, and ECDSA signing/verification.
//!
//! ## Optional backends
//!
//! - `keyring` (default): OS credential-store key sealing ([`tpm`]). Off → the vault
//!   falls back to its passphrase backend and TOTP unlock slots are unavailable.
//! - `qr` (default): QR rendering in [`totp`] (qrcode + image PNG codec). Off → the
//!   renderers return the `otpauth://` URI text verbatim.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod auth;
pub mod key_agreement;
pub mod keys;
pub mod pinning;
pub mod secret;
pub mod signing;
pub mod totp;
pub mod tpm;
pub mod unlock_slots;
pub mod vault;
