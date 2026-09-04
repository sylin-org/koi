//! Immutable host identity observed once by an application composition root.
//!
//! Host identity is launch input, not a domain and not mutable status. Keeping
//! one strict value prevents presentation and presence adapters from observing
//! the OS independently and disagreeing or substituting `unknown`/`localhost`.

use std::sync::Arc;

/// The machine name accepted for one running Koi composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    hostname: Arc<str>,
    local_fqdn: Arc<str>,
}

impl HostIdentity {
    /// Observe and validate the operating system hostname.
    pub fn observe() -> Result<Self, HostIdentityError> {
        let hostname = hostname::get()
            .map_err(|error| HostIdentityError::Observation(error.to_string()))?
            .into_string()
            .map_err(|_| HostIdentityError::NonUtf8)?;
        Self::from_hostname(hostname)
    }

    /// Validate an explicitly supplied hostname.
    ///
    /// This is useful for hosts that already captured identity and for tests;
    /// it never supplies a default.
    pub fn from_hostname(hostname: impl Into<String>) -> Result<Self, HostIdentityError> {
        let hostname = hostname.into();
        let hostname = hostname.trim().trim_end_matches('.');
        if hostname.is_empty() {
            return Err(HostIdentityError::Empty);
        }
        if hostname.chars().any(char::is_control) {
            return Err(HostIdentityError::ControlCharacter);
        }

        let local_fqdn = if hostname
            .to_ascii_lowercase()
            .strip_suffix(".local")
            .is_some()
        {
            hostname.to_string()
        } else {
            format!("{hostname}.local")
        };
        Ok(Self {
            hostname: Arc::from(hostname),
            local_fqdn: Arc::from(local_fqdn),
        })
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn local_fqdn(&self) -> &str {
        &self.local_fqdn
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostIdentityError {
    #[error("could not observe the machine hostname: {0}")]
    Observation(String),
    #[error("the machine hostname is not valid UTF-8")]
    NonUtf8,
    #[error("the machine hostname is empty")]
    Empty,
    #[error("the machine hostname contains a control character")]
    ControlCharacter,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_identity_is_normalized_without_a_fallback() {
        let identity = HostIdentity::from_hostname(" koi-node.local. ").unwrap();
        assert_eq!(identity.hostname(), "koi-node.local");
        assert_eq!(identity.local_fqdn(), "koi-node.local");
    }

    #[test]
    fn absent_or_unsafe_identity_is_an_error() {
        assert_eq!(
            HostIdentity::from_hostname("...").unwrap_err(),
            HostIdentityError::Empty
        );
        assert_eq!(
            HostIdentity::from_hostname("koi\nnode").unwrap_err(),
            HostIdentityError::ControlCharacter
        );
    }
}
