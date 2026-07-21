use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::lab::Lab;
use crate::model::{
    output_path, CheckResult, LabProfile, PreflightReport, ProfileRecoveryReport, RunId,
};
use crate::profile::stable_baseline_matches;

const ACTIVE_JOURNAL: &str = ".lab-runs/active-profile.jsonl";
const ACTIVE_HEARTBEAT: &str = ".lab-runs/active-profile.heartbeat";
const ARCHIVED_JOURNAL: &str = "profile-journal.jsonl";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct JournalRecord {
    schema: u32,
    sequence: u64,
    at: DateTime<Utc>,
    #[serde(flatten)]
    event: JournalEvent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum JournalEvent {
    Started {
        execution_id: RunId,
        profile: LabProfile,
        git_commit: String,
    },
    CasePrepared {
        case_name: String,
        run_id: RunId,
    },
    CaseCleaned {
        run_id: RunId,
    },
    Completed {
        recovered: bool,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct JournalSnapshot {
    pub(crate) execution_id: RunId,
    pub(crate) profile: LabProfile,
    pub(crate) git_commit: String,
    pub(crate) pending_runs: Vec<RunId>,
    pub(crate) completed: bool,
    next_sequence: u64,
}

pub(crate) struct ProfileRecoveryExecution {
    pub(crate) report: ProfileRecoveryReport,
    pub(crate) evidence_path: Option<PathBuf>,
    pub(crate) succeeded: bool,
}

pub(crate) struct ProfileJournal {
    repo_root: PathBuf,
    file: File,
    snapshot: JournalSnapshot,
    heartbeat: Option<Heartbeat>,
}

struct Heartbeat {
    stop: Sender<()>,
    handle: JoinHandle<()>,
}

impl ProfileJournal {
    pub(crate) fn start(
        repo_root: &Path,
        execution_id: RunId,
        profile: LabProfile,
        git_commit: String,
    ) -> Result<Self> {
        let journal_path = repo_root.join(ACTIVE_JOURNAL);
        let parent = journal_path
            .parent()
            .context("active profile journal has no parent")?;
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "could not create profile journal directory {}",
                parent.display()
            )
        })?;
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&journal_path)
            .with_context(|| {
                format!(
                    "could not create active profile journal {}; run recover-profile first",
                    journal_path.display()
                )
            })?;
        let snapshot = JournalSnapshot {
            execution_id: execution_id.clone(),
            profile,
            git_commit: git_commit.clone(),
            pending_runs: Vec::new(),
            completed: false,
            next_sequence: 1,
        };
        let mut journal = Self {
            repo_root: repo_root.to_path_buf(),
            file,
            snapshot,
            heartbeat: None,
        };
        journal.append(JournalEvent::Started {
            execution_id,
            profile,
            git_commit,
        })?;
        journal.start_heartbeat()?;
        Ok(journal)
    }

    fn open_stale(repo_root: &Path, stale_after: Duration) -> Result<Option<Self>> {
        let Some(snapshot) = load_snapshot(repo_root)? else {
            return Ok(None);
        };
        ensure_stale(repo_root, stale_after)?;
        let path = repo_root.join(ACTIVE_JOURNAL);
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .with_context(|| format!("could not open stale journal {}", path.display()))?;
        let mut journal = Self {
            repo_root: repo_root.to_path_buf(),
            file,
            snapshot,
            heartbeat: None,
        };
        journal.start_heartbeat()?;
        Ok(Some(journal))
    }

    pub(crate) fn has_pending_run(&self) -> bool {
        !self.snapshot.pending_runs.is_empty()
    }

    pub(crate) fn prepare_case(&mut self, case_name: &str, run_id: &RunId) -> Result<()> {
        if self.snapshot.completed {
            bail!("cannot prepare a case in a completed profile journal");
        }
        if !self.snapshot.pending_runs.is_empty() {
            bail!("cannot prepare a profile case while another case remains uncleaned");
        }
        self.append(JournalEvent::CasePrepared {
            case_name: case_name.to_owned(),
            run_id: run_id.clone(),
        })?;
        self.snapshot.pending_runs.push(run_id.clone());
        Ok(())
    }

    pub(crate) fn case_cleaned(&mut self, run_id: &RunId) -> Result<()> {
        let Some(index) = self
            .snapshot
            .pending_runs
            .iter()
            .position(|pending| pending == run_id)
        else {
            bail!("cannot clean untracked profile run {}", run_id.as_str());
        };
        self.append(JournalEvent::CaseCleaned {
            run_id: run_id.clone(),
        })?;
        self.snapshot.pending_runs.remove(index);
        Ok(())
    }

    pub(crate) fn finish(mut self, recovered: bool) -> Result<PathBuf> {
        if !self.snapshot.pending_runs.is_empty() {
            bail!("cannot complete a profile journal while a case remains uncleaned");
        }
        if !self.snapshot.completed {
            self.append(JournalEvent::Completed { recovered })?;
            self.snapshot.completed = true;
        }
        self.stop_heartbeat();
        let heartbeat_path = self.repo_root.join(ACTIVE_HEARTBEAT);
        if heartbeat_path.exists() {
            fs::remove_file(&heartbeat_path).with_context(|| {
                format!(
                    "could not remove profile heartbeat {}",
                    heartbeat_path.display()
                )
            })?;
        }
        let source = self.repo_root.join(ACTIVE_JOURNAL);
        let destination = self
            .repo_root
            .join(output_path(self.snapshot.execution_id.as_str()))
            .join(ARCHIVED_JOURNAL);
        let parent = destination
            .parent()
            .context("archived profile journal has no parent")?;
        fs::create_dir_all(parent)?;
        if destination.exists() {
            bail!(
                "refusing to replace archived profile journal {}",
                destination.display()
            );
        }
        fs::rename(&source, &destination).with_context(|| {
            format!(
                "could not archive profile journal {} to {}",
                source.display(),
                destination.display()
            )
        })?;
        Ok(destination)
    }

    fn append(&mut self, event: JournalEvent) -> Result<()> {
        let record = JournalRecord {
            schema: 1,
            sequence: self.snapshot.next_sequence,
            at: Utc::now(),
            event,
        };
        serde_json::to_writer(&mut self.file, &record)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;
        self.snapshot.next_sequence += 1;
        Ok(())
    }

    fn start_heartbeat(&mut self) -> Result<()> {
        let path = self.repo_root.join(ACTIVE_HEARTBEAT);
        write_heartbeat(&path)?;
        let (stop, receiver) = mpsc::channel();
        let handle = thread::spawn(move || loop {
            match receiver.recv_timeout(HEARTBEAT_INTERVAL) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let _ = write_heartbeat(&path);
                }
            }
        });
        self.heartbeat = Some(Heartbeat { stop, handle });
        Ok(())
    }

    fn stop_heartbeat(&mut self) {
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.stop.send(());
            let _ = heartbeat.handle.join();
        }
    }
}

impl Drop for ProfileJournal {
    fn drop(&mut self) {
        self.stop_heartbeat();
    }
}

impl Lab {
    pub(crate) fn recover_profile(&self) -> Result<ProfileRecoveryExecution> {
        self.recover_profile_after(DEFAULT_STALE_AFTER)
    }

    fn recover_profile_after(&self, stale_after: Duration) -> Result<ProfileRecoveryExecution> {
        let Some(mut journal) = ProfileJournal::open_stale(self.repo_root(), stale_after)? else {
            return Ok(ProfileRecoveryExecution {
                report: ProfileRecoveryReport {
                    schema: 1,
                    execution_id: RunId::generate(),
                    created_at: Utc::now(),
                    git_commit: self.git_commit()?,
                    profile: None,
                    recovered_runs: Vec::new(),
                    checks: vec![CheckResult {
                        name: "no_active_profile".into(),
                        passed: true,
                        detail: "no interrupted profile journal exists".into(),
                    }],
                    secrets_redacted: true,
                },
                evidence_path: None,
                succeeded: true,
            });
        };

        let snapshot = journal.snapshot.clone();
        let mut checks = vec![CheckResult {
            name: "stale_controller".into(),
            passed: true,
            detail: format!(
                "profile heartbeat exceeded the {} second recovery threshold",
                stale_after.as_secs()
            ),
        }];
        let mut recovered_runs = Vec::new();
        let mut succeeded = true;

        for run_id in &snapshot.pending_runs {
            match self.cleanup(run_id) {
                Ok(_) => {
                    journal.case_cleaned(run_id)?;
                    recovered_runs.push(run_id.clone());
                    checks.push(CheckResult {
                        name: format!("cleanup_{}", run_id.as_str()),
                        passed: true,
                        detail: "exact journal-owned local and remote state was removed".into(),
                    });
                }
                Err(error) => {
                    checks.push(CheckResult {
                        name: format!("cleanup_{}", run_id.as_str()),
                        passed: false,
                        detail: format!("exact cleanup failed: {error:#}"),
                    });
                    succeeded = false;
                    break;
                }
            }
        }

        if succeeded {
            let initial_path = self
                .repo_root()
                .join(output_path(snapshot.execution_id.as_str()))
                .join("preflight-before.json");
            let initial: PreflightReport =
                serde_json::from_slice(&fs::read(&initial_path).with_context(|| {
                    format!(
                        "could not read recovery baseline {}",
                        initial_path.display()
                    )
                })?)
                .with_context(|| {
                    format!("recovery baseline {} was invalid", initial_path.display())
                })?;
            let preflight = self.preflight()?;
            self.write_json(
                &output_path(snapshot.execution_id.as_str()).join("preflight-recovery-after.json"),
                &preflight,
            )?;
            let baseline_restored = stable_baseline_matches(&initial, &preflight);
            checks.push(CheckResult {
                name: "post_recovery_baseline".into(),
                passed: baseline_restored,
                detail: if baseline_restored {
                    "stable local, node, service, artifact, and listener baselines were restored"
                        .into()
                } else {
                    "post-recovery state differs from the profile's captured baseline".into()
                },
            });
            succeeded = baseline_restored;
        }

        let report = ProfileRecoveryReport {
            schema: 1,
            execution_id: snapshot.execution_id.clone(),
            created_at: Utc::now(),
            git_commit: snapshot.git_commit,
            profile: Some(snapshot.profile),
            recovered_runs,
            checks,
            secrets_redacted: true,
        };
        let evidence_path = self.write_evidence(
            &output_path(snapshot.execution_id.as_str()).join("profile-recovery.json"),
            &report,
        )?;
        if succeeded {
            journal.finish(true)?;
        }
        Ok(ProfileRecoveryExecution {
            report,
            evidence_path: Some(evidence_path),
            succeeded,
        })
    }
}

fn write_heartbeat(path: &Path) -> Result<()> {
    fs::write(path, Utc::now().to_rfc3339())
        .with_context(|| format!("could not update profile heartbeat {}", path.display()))
}

fn ensure_stale(repo_root: &Path, stale_after: Duration) -> Result<()> {
    let journal_path = repo_root.join(ACTIVE_JOURNAL);
    let heartbeat_path = repo_root.join(ACTIVE_HEARTBEAT);
    let journal_modified = fs::metadata(&journal_path)
        .and_then(|metadata| metadata.modified())
        .with_context(|| format!("could not inspect {}", journal_path.display()))?;
    let heartbeat_modified = fs::metadata(&heartbeat_path)
        .and_then(|metadata| metadata.modified())
        .ok();
    let modified = heartbeat_modified
        .map(|heartbeat| heartbeat.max(journal_modified))
        .unwrap_or(journal_modified);
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    if age < stale_after {
        bail!(
            "recovery refused: active profile heartbeat is only {} seconds old (minimum {})",
            age.as_secs(),
            stale_after.as_secs()
        );
    }
    Ok(())
}

fn load_snapshot(repo_root: &Path) -> Result<Option<JournalSnapshot>> {
    let path = repo_root.join(ACTIVE_JOURNAL);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("could not read {}", path.display()))
        }
    };
    let ends_with_newline = bytes.ends_with(b"\n");
    let chunks = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    let mut records = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        if chunk.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<JournalRecord>(chunk) {
            Ok(record) => records.push(record),
            Err(_) if index + 1 == chunks.len() && !ends_with_newline => break,
            Err(error) => bail!("invalid profile journal record {}: {error}", index + 1),
        }
    }
    snapshot_from_records(&records).map(Some)
}

fn snapshot_from_records(records: &[JournalRecord]) -> Result<JournalSnapshot> {
    let Some(first) = records.first() else {
        bail!("active profile journal has no complete records");
    };
    let JournalEvent::Started {
        execution_id,
        profile,
        git_commit,
    } = &first.event
    else {
        bail!("active profile journal does not begin with started");
    };
    let mut pending = BTreeSet::new();
    let mut completed = false;
    for (index, record) in records.iter().enumerate() {
        let expected = index as u64 + 1;
        if record.schema != 1 || record.sequence != expected {
            bail!("invalid profile journal sequence at record {expected}");
        }
        if index == 0 {
            continue;
        }
        if completed {
            bail!("profile journal contains records after completion");
        }
        match &record.event {
            JournalEvent::Started { .. } => bail!("profile journal contains a second start"),
            JournalEvent::CasePrepared { run_id, .. } => {
                if !pending.is_empty() || !pending.insert(run_id.clone()) {
                    bail!("profile journal prepared overlapping or duplicate cases");
                }
            }
            JournalEvent::CaseCleaned { run_id } => {
                if !pending.remove(run_id) {
                    bail!("profile journal cleaned an untracked run");
                }
            }
            JournalEvent::Completed { .. } => {
                if !pending.is_empty() {
                    bail!("profile journal completed with a pending run");
                }
                completed = true;
            }
        }
    }
    Ok(JournalSnapshot {
        execution_id: execution_id.clone(),
        profile: *profile,
        git_commit: git_commit.clone(),
        pending_runs: pending.into_iter().collect(),
        completed,
        next_sequence: records.len() as u64 + 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "koi-profile-journal-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn started() -> JournalRecord {
        JournalRecord {
            schema: 1,
            sequence: 1,
            at: Utc::now(),
            event: JournalEvent::Started {
                execution_id: RunId::parse("v1-20260720T000000Z-00000000").unwrap(),
                profile: LabProfile::Full,
                git_commit: "deadbeef".into(),
            },
        }
    }

    #[test]
    fn journal_round_trip_tracks_one_pending_case() {
        let mut records = vec![started()];
        let run_id = RunId::parse("v1-20260720T000001Z-00000001").unwrap();
        records.push(JournalRecord {
            schema: 1,
            sequence: 2,
            at: Utc::now(),
            event: JournalEvent::CasePrepared {
                case_name: "case".into(),
                run_id: run_id.clone(),
            },
        });
        let encoded = serde_json::to_string(&records[1]).unwrap();
        records[1] = serde_json::from_str(&encoded).unwrap();
        let snapshot = snapshot_from_records(&records).unwrap();
        assert_eq!(snapshot.pending_runs, vec![run_id]);
        assert!(!snapshot.completed);
    }

    #[test]
    fn journal_rejects_invalid_run_ids_during_deserialization() {
        let encoded = serde_json::to_string(&started()).unwrap();
        let hostile = encoded.replace(
            "v1-20260720T000000Z-00000000",
            "../../foreign-run-directory",
        );
        assert!(serde_json::from_str::<JournalRecord>(&hostile).is_err());
    }

    #[test]
    fn journal_rejects_overlapping_cases() {
        let run_a = RunId::parse("v1-20260720T000001Z-00000001").unwrap();
        let run_b = RunId::parse("v1-20260720T000002Z-00000002").unwrap();
        let records = vec![
            started(),
            JournalRecord {
                schema: 1,
                sequence: 2,
                at: Utc::now(),
                event: JournalEvent::CasePrepared {
                    case_name: "a".into(),
                    run_id: run_a,
                },
            },
            JournalRecord {
                schema: 1,
                sequence: 3,
                at: Utc::now(),
                event: JournalEvent::CasePrepared {
                    case_name: "b".into(),
                    run_id: run_b,
                },
            },
        ];
        assert!(snapshot_from_records(&records).is_err());
    }

    #[test]
    fn loader_ignores_only_a_truncated_final_record() {
        let root = temp_root("truncated");
        let path = root.join(ACTIVE_JOURNAL);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut bytes = serde_json::to_vec(&started()).unwrap();
        bytes.extend_from_slice(b"\n{\"schema\":1");
        fs::write(&path, &bytes).unwrap();
        assert_eq!(load_snapshot(&root).unwrap().unwrap().next_sequence, 2);

        bytes.push(b'\n');
        fs::write(&path, &bytes).unwrap();
        assert!(load_snapshot(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fresh_journal_or_heartbeat_refuses_recovery() {
        let root = temp_root("heartbeat");
        let journal = root.join(ACTIVE_JOURNAL);
        let heartbeat = root.join(ACTIVE_HEARTBEAT);
        fs::create_dir_all(heartbeat.parent().unwrap()).unwrap();
        fs::write(&journal, serde_json::to_vec(&started()).unwrap()).unwrap();
        write_heartbeat(&heartbeat).unwrap();
        assert!(ensure_stale(&root, Duration::from_secs(60)).is_err());
        fs::remove_file(&heartbeat).unwrap();
        assert!(ensure_stale(&root, Duration::from_secs(60)).is_err());
        assert!(ensure_stale(&root, Duration::ZERO).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_journal_archives_atomically_with_no_live_marker() {
        let root = temp_root("archive");
        let execution = RunId::parse("v1-20260720T000003Z-00000003").unwrap();
        let run_id = RunId::parse("v1-20260720T000004Z-00000004").unwrap();
        let mut journal = ProfileJournal::start(
            &root,
            execution.clone(),
            LabProfile::Full,
            "deadbeef".into(),
        )
        .unwrap();
        journal.prepare_case("case", &run_id).unwrap();
        journal.case_cleaned(&run_id).unwrap();
        let archive = journal.finish(false).unwrap();

        assert_eq!(
            archive,
            root.join(output_path(execution.as_str()))
                .join(ARCHIVED_JOURNAL)
        );
        assert!(archive.is_file());
        assert!(!root.join(ACTIVE_JOURNAL).exists());
        assert!(!root.join(ACTIVE_HEARTBEAT).exists());
        assert!(
            snapshot_from_records(&read_records(&archive))
                .unwrap()
                .completed
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn read_records(path: &Path) -> Vec<JournalRecord> {
        fs::read(path)
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| serde_json::from_slice(chunk).unwrap())
            .collect()
    }
}
