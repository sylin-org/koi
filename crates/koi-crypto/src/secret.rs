//! Zeroize-on-drop newtypes for secret material.
//!
//! These types ensure that secret bytes and strings are always wiped
//! from memory when they go out of scope. They also redact themselves
//! in `Debug` output to prevent accidental leakage in logs.

use std::fmt;
use std::ops::Deref;

use zeroize::Zeroize;

/// Heap-allocated secret bytes that are zeroized on drop.
///
/// `Deref<Target = [u8]>` allows transparent use wherever `&[u8]` is
/// expected, while `Debug` prints `[REDACTED]` to prevent log leakage.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap raw bytes in a secret container.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED ({} bytes)]", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Heap-allocated secret string that is zeroized on drop.
///
/// `Deref<Target = str>` allows transparent use wherever `&str` is
/// expected, while `Debug` prints `[REDACTED]` to prevent log leakage.
pub struct SecretString(String);

impl SecretString {
    /// Wrap a string in a secret container.
    pub fn new(s: String) -> Self {
        Self(s)
    }
}

impl Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED ({} bytes)]", self.0.len())
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_deref() {
        let secret = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(&*secret, &[1, 2, 3]);
    }

    #[test]
    fn secret_bytes_debug_redacts() {
        let secret = SecretBytes::new(vec![0xDE, 0xAD]);
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("DE"));
    }

    #[test]
    fn secret_string_deref() {
        let secret = SecretString::new("hunter2".into());
        assert_eq!(&*secret, "hunter2");
    }

    #[test]
    fn secret_string_debug_redacts() {
        let secret = SecretString::new("hunter2".into());
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("hunter2"));
    }

    #[test]
    fn secret_string_as_ref() {
        let secret = SecretString::new("test".into());
        let s: &str = secret.as_ref();
        assert_eq!(s, "test");
    }
}
