//! Durable personal service intent.
//!
//! This domain owns favorites, local aliases, and dismissed local suggestions.
//! Discovery and catalog facts remain owned by their source domains and composition.

mod repository;

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use koi_common::error::ErrorCode;
use koi_common::persist::AtomicCommit;
use koi_common::service::{
    CandidatePreference, CandidatePreferenceKey, PreferenceErrorBody, PreferencesMode,
    PreferencesProblem, PreferencesStatus, PreferredServiceContext, ServiceId, ServicePreference,
    SetCandidatePreferenceRequest, SetServicePreferenceRequest, PREFERENCES_SCHEMA,
};
use koi_common::status::StatusFeed;
use tokio::sync::{broadcast, watch};

use repository::{Opened, Repository, StoredPreferences};

const MAX_FRIENDLY_ALIAS_BYTES: usize = 160;
const EVENT_CAPACITY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreferencesEvent {
    ServiceChanged {
        service_id: ServiceId,
        revision: u64,
    },
    CandidateChanged {
        candidate_id: ServiceId,
        revision: u64,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum PreferencesError {
    #[error("preferences require schema {supported}, not schema {found}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("preference revision is stale: expected {expected}, current {current}")]
    StaleRevision { expected: u64, current: u64 },
    #[error("preferences are read-only: {0}")]
    ReadOnly(String),
    #[error("invalid preference: {0}")]
    Invalid(String),
    #[error("preference persistence failed: {0}")]
    Io(#[from] io::Error),
    #[error("preference commit is visible but crash durability is uncertain: {0}")]
    DurabilityUncertain(String),
}

impl PreferencesError {
    pub fn error_body(&self) -> PreferenceErrorBody {
        let (error, current_revision, found_schema) = match self {
            Self::UnsupportedSchema { found, .. } => {
                (ErrorCode::UnsupportedSchema, None, Some(*found))
            }
            Self::StaleRevision { current, .. } => (ErrorCode::StaleRevision, Some(*current), None),
            Self::ReadOnly(_) | Self::Io(_) | Self::DurabilityUncertain(_) => {
                (ErrorCode::RecoveryRequired, None, None)
            }
            Self::Invalid(_) => (ErrorCode::InvalidPayload, None, None),
        };
        PreferenceErrorBody {
            error,
            message: self.to_string(),
            current_revision,
            found_schema,
            minimum_schema: matches!(self, Self::UnsupportedSchema { .. })
                .then_some(PREFERENCES_SCHEMA),
            maximum_schema: matches!(self, Self::UnsupportedSchema { .. })
                .then_some(PREFERENCES_SCHEMA),
        }
    }

    pub fn http_status(&self) -> u16 {
        self.error_body().error.http_status()
    }
}

#[derive(Debug)]
pub struct PreferencesCore {
    repository: Repository,
    command: Mutex<()>,
    feed: StatusFeed<PreferencesStatus>,
    events: broadcast::Sender<PreferencesEvent>,
}

impl PreferencesCore {
    pub fn open(state_path: PathBuf) -> Self {
        let repository = Repository::new(state_path);
        let epoch = uuid_epoch();
        let status = match repository.open() {
            Opened::Writable(state) => status_from_state(epoch, state, None),
            Opened::Unsupported { found } => read_only_status(
                epoch,
                PreferencesProblem {
                    error: ErrorCode::UnsupportedSchema,
                    message: format!(
                        "stored preferences use schema {found}; this daemon supports schema {PREFERENCES_SCHEMA}"
                    ),
                    retryable: false,
                    found_schema: Some(found),
                    minimum_schema: Some(PREFERENCES_SCHEMA),
                    maximum_schema: Some(PREFERENCES_SCHEMA),
                },
            ),
            Opened::RecoveryRequired(message) => read_only_status(
                epoch,
                PreferencesProblem {
                    error: ErrorCode::RecoveryRequired,
                    message,
                    retryable: true,
                    found_schema: None,
                    minimum_schema: None,
                    maximum_schema: None,
                },
            ),
        };
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            repository,
            command: Mutex::new(()),
            feed: StatusFeed::new(status),
            events,
        }
    }

    pub fn status(&self) -> Arc<PreferencesStatus> {
        self.feed.current()
    }

    pub fn watch_status(&self) -> watch::Receiver<Arc<PreferencesStatus>> {
        self.feed.subscribe()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PreferencesEvent> {
        self.events.subscribe()
    }

    pub fn set_service(
        &self,
        request: SetServicePreferenceRequest,
        context: Option<PreferredServiceContext>,
    ) -> Result<Arc<PreferencesStatus>, PreferencesError> {
        let _command = self.command.lock().expect("preferences command lock");
        let current = self.require_writable(&request.schema, request.expected_revision)?;
        let alias = normalize_alias(request.friendly_alias)?;
        let service_id = request.service_key.service_id().clone();
        let mut services = current.services.clone();
        let existing = services
            .iter()
            .position(|record| record.service_key.service_id() == &service_id);
        let retained_context =
            context.or_else(|| existing.and_then(|index| services[index].last_known.clone()));
        let next = ServicePreference {
            service_key: request.service_key,
            favorite: request.favorite,
            friendly_alias: alias,
            last_known: retained_context,
        };
        if !next.favorite && next.friendly_alias.is_none() {
            if let Some(index) = existing {
                services.remove(index);
            }
        } else if let Some(index) = existing {
            services[index] = next;
        } else {
            services.push(next);
        }
        services.sort_by(|left, right| {
            left.service_key
                .service_id()
                .cmp(right.service_key.service_id())
        });
        if services == current.services {
            return Ok(current);
        }
        self.commit_and_publish(
            services,
            current.candidates.clone(),
            PreferencesEvent::ServiceChanged {
                service_id,
                revision: current.revision.saturating_add(1),
            },
        )
    }

    pub fn set_candidate(
        &self,
        candidate_id: ServiceId,
        request: SetCandidatePreferenceRequest,
    ) -> Result<Arc<PreferencesStatus>, PreferencesError> {
        let _command = self.command.lock().expect("preferences command lock");
        let current = self.require_writable(&request.schema, request.expected_revision)?;
        validate_candidate_key(&request.candidate_key)?;
        let mut candidates = current.candidates.clone();
        let existing = candidates
            .iter()
            .position(|record| record.candidate_id == candidate_id);
        let next = CandidatePreference {
            candidate_id: candidate_id.clone(),
            candidate_key: request.candidate_key,
            dismissed: request.dismissed,
        };
        if !next.dismissed {
            if let Some(index) = existing {
                candidates.remove(index);
            }
        } else if let Some(index) = existing {
            candidates[index] = next;
        } else {
            candidates.push(next);
        }
        candidates.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
        if candidates == current.candidates {
            return Ok(current);
        }
        self.commit_and_publish(
            current.services.clone(),
            candidates,
            PreferencesEvent::CandidateChanged {
                candidate_id,
                revision: current.revision.saturating_add(1),
            },
        )
    }

    fn require_writable(
        &self,
        schema: &u32,
        expected_revision: u64,
    ) -> Result<Arc<PreferencesStatus>, PreferencesError> {
        if *schema != PREFERENCES_SCHEMA {
            return Err(PreferencesError::UnsupportedSchema {
                found: *schema,
                supported: PREFERENCES_SCHEMA,
            });
        }
        let current = self.status();
        if current.mode != PreferencesMode::Writable {
            if let Some(problem) = current
                .problem
                .as_ref()
                .filter(|problem| problem.error == ErrorCode::UnsupportedSchema)
            {
                return Err(PreferencesError::UnsupportedSchema {
                    found: problem.found_schema.unwrap_or(PREFERENCES_SCHEMA),
                    supported: PREFERENCES_SCHEMA,
                });
            }
            return Err(PreferencesError::ReadOnly(
                current
                    .problem
                    .as_ref()
                    .map(|problem| problem.message.clone())
                    .unwrap_or_else(|| "repository unavailable".into()),
            ));
        }
        if expected_revision != current.revision {
            return Err(PreferencesError::StaleRevision {
                expected: expected_revision,
                current: current.revision,
            });
        }
        Ok(current)
    }

    fn commit_and_publish(
        &self,
        services: Vec<ServicePreference>,
        candidates: Vec<CandidatePreference>,
        event: PreferencesEvent,
    ) -> Result<Arc<PreferencesStatus>, PreferencesError> {
        let _file_lock = self.repository.lock()?;
        let state = StoredPreferences {
            schema: PREFERENCES_SCHEMA,
            services: services.clone(),
            candidates: candidates.clone(),
        };
        match self.repository.commit(&state)? {
            AtomicCommit::Durable => {}
            AtomicCommit::DurabilityUncertain(error) => {
                return Err(PreferencesError::DurabilityUncertain(error.to_string()))
            }
        }
        let current = self.status();
        let next = PreferencesStatus {
            schema: PREFERENCES_SCHEMA,
            epoch: current.epoch.clone(),
            revision: current.revision.saturating_add(1),
            mode: PreferencesMode::Writable,
            services,
            candidates,
            problem: None,
        };
        let published = self.feed.publish(next);
        let _ = self.events.send(event);
        Ok(published)
    }
}

fn status_from_state(
    epoch: String,
    state: StoredPreferences,
    problem: Option<PreferencesProblem>,
) -> PreferencesStatus {
    PreferencesStatus {
        schema: PREFERENCES_SCHEMA,
        epoch,
        revision: 0,
        mode: PreferencesMode::Writable,
        services: state.services,
        candidates: state.candidates,
        problem,
    }
}

fn read_only_status(epoch: String, problem: PreferencesProblem) -> PreferencesStatus {
    PreferencesStatus {
        schema: PREFERENCES_SCHEMA,
        epoch,
        revision: 0,
        mode: PreferencesMode::ReadOnly,
        services: Vec::new(),
        candidates: Vec::new(),
        problem: Some(problem),
    }
}

fn normalize_alias(alias: Option<String>) -> Result<Option<String>, PreferencesError> {
    let alias = alias.map(|value| value.trim().to_string());
    let alias = alias.filter(|value| !value.is_empty());
    if alias
        .as_ref()
        .is_some_and(|value| value.len() > MAX_FRIENDLY_ALIAS_BYTES)
    {
        return Err(PreferencesError::Invalid(format!(
            "friendly alias exceeds {MAX_FRIENDLY_ALIAS_BYTES} UTF-8 bytes"
        )));
    }
    Ok(alias)
}

fn validate_candidate_key(key: &CandidatePreferenceKey) -> Result<(), PreferencesError> {
    if key.recognizer.trim().is_empty() || key.source.trim().is_empty() {
        return Err(PreferencesError::Invalid(
            "candidate recognizer and source are required".into(),
        ));
    }
    Ok(())
}

fn uuid_epoch() -> String {
    uuid::Uuid::now_v7().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use koi_common::service::ServicePreferenceKey;

    fn core(name: &str) -> (PathBuf, PreferencesCore) {
        let root = std::env::temp_dir().join(format!(
            "koi-preferences-core-{name}-{}-{}",
            std::process::id(),
            koi_common::id::generate_short_id()
        ));
        let path = root.join("state/preferences.json");
        (root, PreferencesCore::open(path))
    }

    fn context() -> PreferredServiceContext {
        PreferredServiceContext {
            device_id: koi_common::service::DeviceId::new("dev_one").unwrap(),
            display_name: "Dashboard".into(),
            device_name: Some("workshop".into()),
            kind: koi_common::service::ServiceKind::Web,
            last_condition: koi_common::service::ServiceCondition::Found,
            last_seen: Utc::now(),
        }
    }

    fn request(revision: u64, favorite: bool) -> SetServicePreferenceRequest {
        SetServicePreferenceRequest {
            schema: PREFERENCES_SCHEMA,
            expected_revision: revision,
            service_key: ServicePreferenceKey::KoiService {
                id: ServiceId::new("svc_one").unwrap(),
            },
            favorite,
            friendly_alias: Some(" Workshop ".into()),
        }
    }

    #[test]
    fn commit_publishes_status_then_event_and_survives_restart() {
        let (root, core) = core("restart");
        let status = core.watch_status();
        let mut events = core.subscribe();
        let expected_context = context();
        let updated = core
            .set_service(request(0, true), Some(expected_context.clone()))
            .unwrap();
        assert_eq!(updated.revision, 1);
        assert_eq!(
            updated.services[0].friendly_alias.as_deref(),
            Some("Workshop")
        );
        assert!(status.has_changed().unwrap());
        let event = events.try_recv().unwrap();
        assert!(matches!(
            event,
            PreferencesEvent::ServiceChanged { revision: 1, .. }
        ));
        assert_eq!(core.status().revision, 1, "event observes published state");

        let reopened = PreferencesCore::open(root.join("state/preferences.json"));
        assert_eq!(
            reopened.status().revision,
            0,
            "process epoch resets revision"
        );
        assert!(reopened.status().services[0].favorite);
        assert_eq!(
            reopened.status().services[0].last_known,
            Some(expected_context)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn no_op_and_stale_revision_emit_nothing() {
        let (root, core) = core("conflict");
        let same_context = context();
        core.set_service(request(0, true), Some(same_context.clone()))
            .unwrap();
        let mut events = core.subscribe();
        let unchanged = core
            .set_service(request(1, true), Some(same_context.clone()))
            .unwrap();
        assert_eq!(unchanged.revision, 1);
        assert!(events.try_recv().is_err());
        assert!(matches!(
            core.set_service(request(0, false), Some(same_context)),
            Err(PreferencesError::StaleRevision { current: 1, .. })
        ));
        assert!(events.try_recv().is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_commit_keeps_status_and_emits_no_event() {
        let root = std::env::temp_dir().join(format!(
            "koi-preferences-core-fail-{}",
            koi_common::id::generate_short_id()
        ));
        let path = root.join("state/preferences.json");
        std::fs::create_dir_all(&path).unwrap();
        let core = PreferencesCore::open(path);
        let mut events = core.subscribe();
        assert!(core.set_service(request(0, true), Some(context())).is_err());
        assert_eq!(core.status().revision, 0);
        assert!(core.status().services.is_empty());
        assert!(events.try_recv().is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
