//! Persisted authorization policy for Koi's machine-local control plane.

use std::io;
use std::path::{Path, PathBuf};

use koi_common::persist;
use serde::{Deserialize, Serialize};

const POLICY_VERSION: u16 = 1;
const POLICY_FILENAME: &str = "local-access.json";

/// The one interactive operator authorized to receive this machine's daemon
/// endpoint and DAT over the local IPC transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LocalOperator {
    UnixUid { uid: u32 },
    WindowsSid { sid: String },
}

/// Machine-owned local access policy captured at service installation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccessPolicy {
    pub version: u16,
    pub operator: LocalOperator,
}

impl LocalAccessPolicy {
    pub fn new(operator: LocalOperator) -> Self {
        Self {
            version: POLICY_VERSION,
            operator,
        }
    }

    fn validate(self) -> io::Result<Self> {
        if self.version != POLICY_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported local access policy version {}; expected {POLICY_VERSION}",
                    self.version
                ),
            ));
        }
        if matches!(&self.operator, LocalOperator::WindowsSid { sid } if sid.trim().is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local access policy has an empty Windows SID",
            ));
        }
        Ok(self)
    }
}

pub fn policy_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state").join(POLICY_FILENAME)
}

pub fn load(data_dir: &Path) -> io::Result<LocalAccessPolicy> {
    persist::read_json::<LocalAccessPolicy>(&policy_path(data_dir))?.validate()
}

pub fn save(data_dir: &Path, policy: &LocalAccessPolicy) -> io::Result<()> {
    policy.clone().validate()?;
    let path = policy_path(data_dir);
    persist::write_json_pretty(&path, policy)?;
    restrict_policy(&path)
}

#[cfg(unix)]
fn restrict_policy(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_policy(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_round_trips_at_an_injected_machine_root() {
        // The libtest thread name is the module-qualified test path; its `::`
        // separators are invalid in Windows filenames, so derive uniqueness
        // the way persist's tests do instead of naming the directory after it.
        let root = std::env::temp_dir().join(format!(
            "koi-local-access-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let policy = LocalAccessPolicy::new(LocalOperator::UnixUid { uid: 1000 });
        save(&root, &policy).unwrap();
        assert_eq!(load(&root).unwrap(), policy);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn empty_windows_sid_is_rejected() {
        let policy = LocalAccessPolicy::new(LocalOperator::WindowsSid {
            sid: "  ".to_string(),
        });
        assert_eq!(
            policy.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
