//! Private durable aggregate and cross-process transition lock.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use koi_common::persist::{self, AtomicCommit};
use serde::{Deserialize, Serialize};

use crate::TrustError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TrustEntry {
    pub(crate) name: String,
    pub(crate) installed_at: String,
    pub(crate) fingerprint: String,
    pub(crate) source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) certificate_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum TrustTransition {
    Install {
        entry: TrustEntry,
    },
    Uninstall {
        entry: TrustEntry,
    },
    Ensure {
        desired: TrustEntry,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        displaced: Option<TrustEntry>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct TrustState {
    #[serde(default)]
    pub(crate) roots: Vec<TrustEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pending: Option<TrustTransition>,
}

pub(crate) struct Repository {
    data_dir: PathBuf,
    #[cfg(test)]
    final_commit_uncertain: AtomicBool,
    #[cfg(test)]
    final_commit_failed: AtomicBool,
}

impl Repository {
    pub(crate) fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            #[cfg(test)]
            final_commit_uncertain: AtomicBool::new(false),
            #[cfg(test)]
            final_commit_failed: AtomicBool::new(false),
        }
    }

    pub(crate) fn state_path(&self) -> PathBuf {
        self.data_dir.join("state").join("trust.json")
    }

    pub(crate) fn with_locked_state<R>(
        &self,
        action: impl FnOnce(&mut TrustState) -> Result<R, TrustError>,
    ) -> Result<R, TrustError> {
        let state_path = self.state_path();
        let state_dir = state_path
            .parent()
            .expect("trust state always has a state-directory parent");
        persist::create_dir_all_durable(state_dir)?;
        let lock_path = state_dir.join("trust.lock");
        let lock = open_lock(&lock_path)?;
        lock.lock().map_err(TrustError::Io)?;
        let mut state = self.load()?;
        action(&mut state)
    }

    pub(crate) fn load(&self) -> Result<TrustState, TrustError> {
        persist::read_json_or_default(&self.state_path()).map_err(TrustError::Io)
    }

    pub(crate) fn arm(&self, state: &TrustState) -> Result<(), TrustError> {
        match persist::write_json_pretty_commit(&self.state_path(), state)? {
            AtomicCommit::Durable => Ok(()),
            AtomicCommit::DurabilityUncertain(error) => {
                Err(TrustError::DurabilityUncertain(format!(
                    "transition intent is visible but crash durability is unconfirmed ({error})"
                )))
            }
        }
    }

    pub(crate) fn commit(&self, state: &TrustState) -> Result<AtomicCommit, TrustError> {
        #[cfg(test)]
        if self.final_commit_failed.swap(false, Ordering::AcqRel) {
            return Err(TrustError::Io(std::io::Error::other(
                "injected final trust commit failure before replacement",
            )));
        }
        let outcome =
            persist::write_json_pretty_commit(&self.state_path(), state).map_err(TrustError::Io)?;
        #[cfg(test)]
        if matches!(&outcome, AtomicCommit::Durable)
            && self.final_commit_uncertain.swap(false, Ordering::AcqRel)
        {
            return Ok(AtomicCommit::DurabilityUncertain(std::io::Error::other(
                "injected final trust commit uncertainty",
            )));
        }
        Ok(outcome)
    }

    #[cfg(test)]
    pub(crate) fn inject_next_final_commit_uncertainty(&self) {
        self.final_commit_uncertain.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn inject_next_final_commit_failure(&self) {
        self.final_commit_failed.store(true, Ordering::Release);
    }
}

fn open_lock(path: &Path) -> Result<File, TrustError> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(TrustError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_document_keeps_its_wire_shape() {
        let parsed: TrustState = serde_json::from_str(
            r#"{"roots":[{"name":"legacy","installed_at":"2026-06-15T00:00:00Z","fingerprint":"abcd","source":"./root.pem"}]}"#,
        )
        .unwrap();
        assert!(parsed.pending.is_none());
        assert!(parsed.roots[0].certificate_pem.is_none());
        assert!(parsed.roots[0].warning.is_none());
    }

    #[test]
    fn ensure_is_an_additive_tagged_transition() {
        let transition = TrustTransition::Ensure {
            desired: TrustEntry {
                name: "koi-certmesh-ca".into(),
                installed_at: "now".into(),
                fingerprint: "new".into(),
                source: "certmesh".into(),
                certificate_pem: Some("pem".into()),
                warning: None,
            },
            displaced: None,
        };
        let value = serde_json::to_value(transition).unwrap();
        assert_eq!(value["operation"], "ensure");
        assert!(value.get("displaced").is_none());
    }
}
