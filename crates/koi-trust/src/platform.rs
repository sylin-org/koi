//! Real operating-system adapter for the Trust domain.

use os_truststore::{Cert, Report};

use crate::TrustError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallOutcome {
    Present,
    PresentButTrustUnconfirmed { reason: String },
}

pub(crate) trait TrustStore: Send + Sync {
    fn is_present(&self, certificate: &Cert) -> Result<bool, TrustError>;
    fn install(&self, certificate: &Cert, label: &str) -> Result<InstallOutcome, TrustError>;
    fn uninstall(&self, certificate: &Cert) -> Result<(), TrustError>;
}

pub(crate) struct PlatformTrustStore;

impl TrustStore for PlatformTrustStore {
    fn is_present(&self, certificate: &Cert) -> Result<bool, TrustError> {
        os_truststore::is_installed(certificate)
            .map_err(|error| TrustError::Platform(error.to_string()))
    }

    fn install(&self, certificate: &Cert, label: &str) -> Result<InstallOutcome, TrustError> {
        match os_truststore::Install::new(certificate)
            .label(label)
            .run()
            .map_err(|error| TrustError::Platform(error.to_string()))?
        {
            Report::Installed | Report::AlreadyInstalled => Ok(InstallOutcome::Present),
            Report::InstalledNotTrusted { reason } => {
                Ok(InstallOutcome::PresentButTrustUnconfirmed { reason })
            }
            _ => Ok(InstallOutcome::Present),
        }
    }

    fn uninstall(&self, certificate: &Cert) -> Result<(), TrustError> {
        os_truststore::uninstall(certificate)
            .map_err(|error| TrustError::Platform(error.to_string()))
    }
}
