//! Durable, non-secret identity of one Koi installation.

use std::io;
use std::path::{Path, PathBuf};

use koi_common::persist::{self, AtomicCommit, AtomicWriteOptions};
use koi_common::service::{InstallationId, CATALOG_SCHEMA};
use serde::{Deserialize, Serialize};

const INSTALLATION_FILE: &str = "installation.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationDocument {
    pub schema: u32,
    pub installation_id: InstallationId,
}

#[derive(Debug)]
pub enum InstallationError {
    Io(io::Error),
    UnsupportedSchema { found: u32, supported: u32 },
}

impl std::fmt::Display for InstallationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "installation identity I/O failed: {error}"),
            Self::UnsupportedSchema { found, supported } => write!(
                formatter,
                "unsupported installation identity schema {found}; supported schema is {supported}"
            ),
        }
    }
}

impl std::error::Error for InstallationError {}

impl From<io::Error> for InstallationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("state").join(INSTALLATION_FILE)
}

/// Open the existing installation identity or atomically create one UUIDv7.
///
/// Concurrent creators converge by reading the winner. Corrupt and future
/// schemas fail closed and are never replaced with a new identity.
pub fn load_or_create(data_dir: &Path) -> Result<InstallationDocument, InstallationError> {
    load_or_create_at(&path(data_dir))
}

pub fn load_or_create_at(path: &Path) -> Result<InstallationDocument, InstallationError> {
    match persist::read_json::<InstallationDocument>(path) {
        Ok(document) => validate(document),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_or_read_winner(path),
        Err(error) => Err(error.into()),
    }
}

fn create_or_read_winner(path: &Path) -> Result<InstallationDocument, InstallationError> {
    let document = InstallationDocument {
        schema: CATALOG_SCHEMA,
        installation_id: InstallationId::new_uuid_v7(),
    };
    let bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    match persist::write_bytes_atomic_new_with_options(path, &bytes, AtomicWriteOptions::default())
    {
        Ok(AtomicCommit::Durable) => Ok(document),
        Ok(AtomicCommit::DurabilityUncertain(error)) => {
            tracing::error!(path = %path.display(), %error, "installation identity is visible but crash durability is uncertain");
            Ok(document)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            validate(persist::read_json(path)?)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate(document: InstallationDocument) -> Result<InstallationDocument, InstallationError> {
    if document.schema != CATALOG_SCHEMA {
        return Err(InstallationError::UnsupportedSchema {
            found: document.schema,
            supported: CATALOG_SCHEMA,
        });
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "koi-installation-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    #[test]
    fn identity_survives_reopen() {
        let root = root("reopen");
        let first = load_or_create(&root).unwrap();
        let second = load_or_create(&root).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.schema, CATALOG_SCHEMA);
    }

    #[test]
    fn concurrent_creators_converge() {
        let root = root("race");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let root = root.clone();
                std::thread::spawn(move || load_or_create(&root).unwrap())
            })
            .collect();
        let identities: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().installation_id)
            .collect();
        assert!(identities.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn future_schema_is_not_replaced() {
        let root = root("future");
        let path = path(&root);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = br#"{"schema":99,"installation_id":"0199a"}"#;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            load_or_create(&root),
            Err(InstallationError::UnsupportedSchema { found: 99, .. })
        ));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
