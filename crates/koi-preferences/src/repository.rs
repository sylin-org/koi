//! Exclusive repository for `state/preferences.json`.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;

use koi_common::persist::{self, AtomicCommit};
use koi_common::service::{
    CandidatePreference, PreferredServiceContext, ServiceId, ServicePreference,
    ServicePreferenceKey, PREFERENCES_SCHEMA,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredPreferences {
    pub(crate) schema: u32,
    #[serde(default)]
    pub(crate) services: Vec<ServicePreference>,
    #[serde(default)]
    pub(crate) candidates: Vec<CandidatePreference>,
}

impl StoredPreferences {
    pub(crate) fn empty() -> Self {
        Self {
            schema: PREFERENCES_SCHEMA,
            services: Vec::new(),
            candidates: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SchemaProbe {
    schema: u32,
}

#[derive(Debug, Deserialize)]
struct LegacyPreferences {
    schema: u32,
    #[serde(default)]
    favorites: Vec<LegacyFavorite>,
    #[serde(default)]
    aliases: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LegacyFavorite {
    Id(ServiceId),
    Record {
        id: ServiceId,
        #[serde(default)]
        last_known: Option<PreferredServiceContext>,
    },
}

pub(crate) enum Opened {
    Writable(StoredPreferences),
    Unsupported { found: u32 },
    RecoveryRequired(String),
}

#[derive(Debug)]
pub(crate) struct Repository {
    state_path: PathBuf,
}

impl Repository {
    pub(crate) fn new(state_path: PathBuf) -> Self {
        Self { state_path }
    }

    pub(crate) fn backup_path(&self) -> PathBuf {
        self.state_path
            .with_file_name("preferences.schema0.json.bak")
    }

    pub(crate) fn open(&self) -> Opened {
        match std::fs::read(&self.state_path) {
            Ok(bytes) => self.decode_or_migrate(&bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Opened::Writable(StoredPreferences::empty())
            }
            Err(error) => Opened::RecoveryRequired(format!(
                "cannot read {}: {error}",
                self.state_path.display()
            )),
        }
    }

    fn decode_or_migrate(&self, bytes: &[u8]) -> Opened {
        let probe = match serde_json::from_slice::<SchemaProbe>(bytes) {
            Ok(probe) => probe,
            Err(error) => {
                return Opened::RecoveryRequired(format!(
                    "preferences document is not valid versioned JSON: {error}"
                ))
            }
        };
        match probe.schema {
            PREFERENCES_SCHEMA => match serde_json::from_slice::<StoredPreferences>(bytes) {
                Ok(mut state) => match validate(&mut state) {
                    Ok(()) => Opened::Writable(state),
                    Err(error) => Opened::RecoveryRequired(error),
                },
                Err(error) => Opened::RecoveryRequired(format!(
                    "preferences schema {PREFERENCES_SCHEMA} is invalid: {error}"
                )),
            },
            0 => self.migrate_schema_zero(bytes),
            found => Opened::Unsupported { found },
        }
    }

    fn migrate_schema_zero(&self, original: &[u8]) -> Opened {
        let legacy = match serde_json::from_slice::<LegacyPreferences>(original) {
            Ok(legacy) if legacy.schema == 0 => legacy,
            Ok(_) => unreachable!("schema probe selected zero"),
            Err(error) => {
                return Opened::RecoveryRequired(format!(
                    "legacy preferences could not be interpreted: {error}"
                ))
            }
        };
        let mut by_id: BTreeMap<ServiceId, ServicePreference> = BTreeMap::new();
        for favorite in legacy.favorites {
            let (id, last_known) = match favorite {
                LegacyFavorite::Id(id) => (id, None),
                LegacyFavorite::Record { id, last_known } => (id, last_known),
            };
            by_id.insert(
                id.clone(),
                ServicePreference {
                    service_key: ServicePreferenceKey::KoiService { id },
                    favorite: true,
                    friendly_alias: None,
                    last_known,
                },
            );
        }
        for (id, alias) in legacy.aliases {
            let Ok(id) = ServiceId::new(id) else {
                return Opened::RecoveryRequired(
                    "legacy preferences contain an invalid alias service id".into(),
                );
            };
            by_id
                .entry(id.clone())
                .or_insert(ServicePreference {
                    service_key: ServicePreferenceKey::KoiService { id },
                    favorite: false,
                    friendly_alias: None,
                    last_known: None,
                })
                .friendly_alias = Some(alias);
        }
        let mut migrated = StoredPreferences {
            schema: PREFERENCES_SCHEMA,
            services: by_id.into_values().collect(),
            candidates: Vec::new(),
        };
        if let Err(error) = validate(&mut migrated) {
            return Opened::RecoveryRequired(error);
        }
        if let Err(error) = self.ensure_backup(original) {
            return Opened::RecoveryRequired(format!(
                "could not back up legacy preferences before migration: {error}"
            ));
        }
        match self.commit(&migrated) {
            Ok(AtomicCommit::Durable) => Opened::Writable(migrated),
            Ok(AtomicCommit::DurabilityUncertain(error)) => {
                let rollback = self.restore_backup();
                Opened::RecoveryRequired(match rollback {
                    Ok(()) => format!(
                        "migration durability was uncertain and the original preferences were restored: {error}"
                    ),
                    Err(rollback) => format!(
                        "migration durability was uncertain ({error}); restore from {} failed ({rollback})",
                        self.backup_path().display()
                    ),
                })
            }
            Err(error) => Opened::RecoveryRequired(format!(
                "legacy preference migration failed; original preferences remain authoritative: {error}"
            )),
        }
    }

    fn ensure_backup(&self, original: &[u8]) -> io::Result<()> {
        let backup = self.backup_path();
        match std::fs::read(&backup) {
            Ok(existing) if existing == original => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} contains a different migration source", backup.display()),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match persist::write_bytes_atomic_new_with_options(
                    &backup,
                    original,
                    persist::AtomicWriteOptions::default(),
                )? {
                    AtomicCommit::Durable => Ok(()),
                    AtomicCommit::DurabilityUncertain(error) => Err(io::Error::other(format!(
                        "backup is visible but crash durability is uncertain: {error}"
                    ))),
                }
            }
            Err(error) => Err(error),
        }
    }

    fn restore_backup(&self) -> io::Result<()> {
        let bytes = std::fs::read(self.backup_path())?;
        persist::require_durable(
            persist::write_bytes_atomic(&self.state_path, &bytes)?,
            "restoring legacy preferences",
        )
    }

    pub(crate) fn lock(&self) -> io::Result<File> {
        let parent = self
            .state_path
            .parent()
            .expect("preferences state has a parent directory");
        persist::create_dir_all_durable(parent)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(parent.join("preferences.lock"))?;
        lock.lock()?;
        Ok(lock)
    }

    pub(crate) fn commit(&self, state: &StoredPreferences) -> io::Result<AtomicCommit> {
        persist::write_json_pretty_commit(&self.state_path, state)
    }
}

fn validate(state: &mut StoredPreferences) -> Result<(), String> {
    if state.schema != PREFERENCES_SCHEMA {
        return Err(format!(
            "unsupported preferences schema {}; supported schema is {PREFERENCES_SCHEMA}",
            state.schema
        ));
    }
    state.services.sort_by(|left, right| {
        left.service_key
            .service_id()
            .cmp(right.service_key.service_id())
    });
    if state
        .services
        .windows(2)
        .any(|pair| pair[0].service_key.service_id() == pair[1].service_key.service_id())
    {
        return Err("preferences contain duplicate service keys".into());
    }
    state
        .candidates
        .sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    if state
        .candidates
        .windows(2)
        .any(|pair| pair[0].candidate_id == pair[1].candidate_id)
    {
        return Err("preferences contain duplicate candidate ids".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "koi-preferences-{name}-{}-{}",
            std::process::id(),
            koi_common::id::generate_short_id()
        ))
    }

    #[test]
    fn schema_zero_migrates_after_byte_exact_backup() {
        let root = root("migrate");
        let path = root.join("state/preferences.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let legacy = br#"{"schema":0,"favorites":["svc_one"],"aliases":{"svc_one":"Workshop"}}"#;
        std::fs::write(&path, legacy).unwrap();
        let repository = Repository::new(path.clone());
        let Opened::Writable(state) = repository.open() else {
            panic!("migration should succeed")
        };
        assert_eq!(std::fs::read(repository.backup_path()).unwrap(), legacy);
        assert_eq!(state.services.len(), 1);
        assert_eq!(
            state.services[0].friendly_alias.as_deref(),
            Some("Workshop")
        );
        assert_eq!(
            serde_json::from_slice::<StoredPreferences>(&std::fs::read(path).unwrap())
                .unwrap()
                .schema,
            PREFERENCES_SCHEMA
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unknown_future_schema_is_never_replaced() {
        let root = root("future");
        let path = root.join("preferences.json");
        std::fs::create_dir_all(&root).unwrap();
        let future = br#"{"schema":99,"favorites":[]}"#;
        std::fs::write(&path, future).unwrap();
        let repository = Repository::new(path.clone());
        assert!(matches!(
            repository.open(),
            Opened::Unsupported { found: 99 }
        ));
        assert_eq!(std::fs::read(path).unwrap(), future);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_legacy_keeps_original_and_reports_recovery() {
        let root = root("bad-legacy");
        let path = root.join("preferences.json");
        std::fs::create_dir_all(&root).unwrap();
        let legacy = br#"{"schema":0,"favorites":["NOT VALID"]}"#;
        std::fs::write(&path, legacy).unwrap();
        let repository = Repository::new(path.clone());
        assert!(matches!(repository.open(), Opened::RecoveryRequired(_)));
        assert_eq!(std::fs::read(path).unwrap(), legacy);
        assert!(!repository.backup_path().exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
