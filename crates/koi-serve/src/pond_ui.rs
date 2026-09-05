//! Durable, content-addressed storage for Pond's browser presentation.
//!
//! A UI publish has one small mutable commit point: `current.json`. Bundle
//! generations are immutable and named by the SHA-256 digest of their canonical
//! five-file payload. A commit therefore writes and syncs the generation first,
//! then atomically advances the durable pointer. Readers see the old generation
//! or the new generation after a crash, never a partially replaced file set.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use koi_common::persist::{create_dir_all_durable, write_bytes_atomic, AtomicCommit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

/// Reserved public namespace for immutable Pond UI generations.
pub const VERSIONED_UI_PREFIX: &str = "/_koi/ui";

/// The complete and only accepted Pond browser payload.
pub const UI_FILES: [&str; 5] = [
    "index.html",
    "app.js",
    "styles.css",
    "sentences.js",
    "koi.png",
];

const REPOSITORY_DIR: &str = ".koi-pond-ui";
const GENERATIONS_DIR: &str = "generations";
const CURRENT_FILE: &str = "current.json";
const MIGRATION_MARKER_FILE: &str = "migrated.json";
const LEGACY_BUNDLE_FILE: &str = ".koi-pond-bundle.json";
const REPOSITORY_VERSION: u8 = 1;
const SHA256_PREFIX: &str = "sha256:";
const SHA256_HEX_LEN: usize = 64;

/// One member of the canonical five-file Pond browser payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondUiFile {
    pub path: String,
    /// UTF-8 source for text assets; standard base64 for `koi.png`.
    pub content: String,
}

/// Wire and persistence DTO for one complete Pond browser generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondUiPublish {
    pub files: Vec<PondUiFile>,
}

/// A validated immutable generation ready to be persisted.
///
/// Construction is deliberately restricted to [`PondUiRepository::prepare`],
/// keeping validation and the digest input identical at every call site.
pub struct PreparedUiBundle {
    canonical: PondUiPublish,
    bundle: Arc<UiBundle>,
}

/// A visible, reconciled UI commit and its exact crash-durability outcome.
///
/// Even when `durability` is uncertain, the current pointer was replaced and
/// reread successfully, so the caller must activate `bundle` to remain coherent
/// with the repository's visible state.
#[derive(Debug)]
#[must_use = "a committed Pond UI bundle must be activated by its caller"]
pub struct UiCommit {
    pub bundle: Arc<UiBundle>,
    pub durability: AtomicCommit,
}

/// One immutable serving generation.
pub struct UiBundle {
    revision: String,
    safe_revision: String,
    files: HashMap<String, Arc<[u8]>>,
}

impl std::fmt::Debug for UiBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UiBundle")
            .field("revision", &self.revision)
            .field("files", &self.files.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl UiBundle {
    /// Content digest exposed through Pond status and command responses.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Filesystem- and URL-safe form of [`Self::revision`].
    pub fn safe_revision(&self) -> &str {
        &self.safe_revision
    }

    /// Clone one immutable asset without copying its bytes.
    pub fn file(&self, name: &str) -> Option<Arc<[u8]>> {
        self.files.get(name).cloned()
    }
}

/// All retained valid immutable generations.
///
/// The selected revision deliberately does not live here: [`PondStatus`](koi_common::pond::PondStatus)
/// is Pond's one authoritative current-state object once the repository is open.
#[derive(Debug, Default)]
pub struct UiStore {
    generations: HashMap<String, Arc<UiBundle>>,
}

impl UiStore {
    /// Look up an immutable generation by `sha256:<hex>` or its safe hex form.
    pub fn generation(&self, revision: &str) -> Option<Arc<UiBundle>> {
        let revision = normalize_revision(revision)?;
        self.generations.get(&revision).cloned()
    }

    /// Number of retained valid immutable generations.
    pub fn generation_count(&self) -> usize {
        self.generations.len()
    }

    /// Retain a generation before its revision is selected in authoritative status.
    pub fn retain(&mut self, bundle: Arc<UiBundle>) {
        self.generations.insert(bundle.revision.clone(), bundle);
    }
}

/// Pond-owned durable repository for immutable UI generations.
pub struct PondUiRepository {
    ui_dir: PathBuf,
    repository_dir: PathBuf,
    commit: Mutex<()>,
    /// The current pointer is visible, but its directory-metadata flush was
    /// not confirmed. An identical clear must retry that flush instead of
    /// being mistaken for an ordinary already-clear no-op.
    pointer_durability_unconfirmed: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_before_pointer: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    force_generation_uncertain: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    force_pointer_uncertain: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for PondUiRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PondUiRepository")
            .field("repository_dir", &self.repository_dir)
            .finish_non_exhaustive()
    }
}

impl PondUiRepository {
    /// Open a repository, importing the preceding single-bundle or loose-file layout once.
    ///
    /// The migration marker is the authority boundary. Once it exists, the
    /// pointer and its selected generation must validate; startup never falls
    /// back to legacy files or silently repairs the authoritative head.
    pub fn open(ui_dir: PathBuf) -> io::Result<(Self, UiStore, Option<Arc<UiBundle>>)> {
        create_dir_all_durable(&ui_dir)?;
        let repository_dir = ui_dir.join(REPOSITORY_DIR);
        let repository = Self {
            ui_dir,
            repository_dir,
            commit: Mutex::new(()),
            pointer_durability_unconfirmed: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_before_pointer: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            force_generation_uncertain: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            force_pointer_uncertain: std::sync::atomic::AtomicBool::new(false),
        };

        repository.scavenge_stages_best_effort();

        if path_entry_exists(&repository.marker_path())? {
            let (store, current) = repository.load_marked()?;
            repository.retire_legacy_files_best_effort();
            return Ok((repository, store, current));
        }

        let legacy = read_legacy_bundle(&repository.ui_dir)?;
        repository.initialize(legacy)?;
        let (store, current) = repository.load_marked()?;
        repository.retire_legacy_files_best_effort();
        Ok((repository, store, current))
    }

    /// Validate and canonicalize a command payload without changing persistence.
    pub fn prepare(publish: &PondUiPublish) -> Result<PreparedUiBundle, String> {
        prepare_bundle(publish)
    }

    /// Commit `generation -> current pointer` and return serving material plus
    /// the exact crash-durability outcome.
    ///
    /// The caller advances its in-memory store/status/event only after this method
    /// succeeds. An unacknowledged failure before the pointer leaves the preceding
    /// current selection intact; the new immutable generation is safe to retain.
    pub fn commit(&self, prepared: PreparedUiBundle) -> io::Result<UiCommit> {
        let _commit = self
            .commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = self.validate_head()?;
        self.persist_generation(&prepared)?;

        #[cfg(test)]
        if self
            .fail_before_pointer
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(io::Error::other(
                "injected Pond UI failure before current pointer",
            ));
        }

        // `write_pointer` returns an ordinary error only before replacement. Once its
        // replacement is visible, there must be no later fallible step that could report the
        // command as rejected while leaving disk ahead of the live model. The repository is
        // single-writer by construction and the immutable generation was validated above.
        let durability = self.write_pointer(Some(prepared.bundle.revision.clone()))?;
        Ok(UiCommit {
            bundle: prepared.bundle,
            durability,
        })
    }

    /// Atomically clear the current selection while retaining every immutable generation.
    ///
    /// Returning `None` is a validated no-op: the durable pointer already selects no bundle,
    /// so callers must not publish a new status revision or semantic event.
    pub fn clear(&self) -> io::Result<Option<AtomicCommit>> {
        let _commit = self
            .commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.validate_head()?.is_none()
            && !self
                .pointer_durability_unconfirmed
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(None);
        }
        self.write_pointer(None).map(Some)
    }

    fn initialize(&self, legacy: Option<PreparedUiBundle>) -> io::Result<()> {
        // Missing `migrated.json` is not permission to erase the repository: it may have been
        // lost after accepted publishes. Resume only an exact interrupted-initialization shape
        // and preserve/fail on every unknown or previously selected entry.
        let pointer_exists = self.validate_unmarked(legacy.as_ref())?;
        create_dir_all_durable(&self.repository_dir)?;
        create_dir_all_durable(&self.generations_dir())?;
        if !pointer_exists {
            write_pointer_required_durable(&self.pointer_path(), None)?;
        }

        if let Some(prepared) = legacy {
            self.persist_generation(&prepared)?;
            write_pointer_required_durable(
                &self.pointer_path(),
                Some(prepared.bundle.revision.clone()),
            )?;
        }

        write_json_required_durable(
            &self.marker_path(),
            &RepositoryMarker {
                version: REPOSITORY_VERSION,
            },
        )
    }

    fn validate_unmarked(&self, legacy: Option<&PreparedUiBundle>) -> io::Result<bool> {
        if !path_entry_exists(&self.repository_dir)? {
            return Ok(false);
        }
        require_directory(&self.repository_dir, "unmarked repository")?;

        let expected_revision = legacy.map(|prepared| prepared.bundle.revision.as_str());
        let expected_safe = legacy.map(|prepared| prepared.bundle.safe_revision.as_str());
        let mut pointer_exists = false;
        let mut generations_exists = false;
        for entry in std::fs::read_dir(&self.repository_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(invalid_data(
                    "unmarked Pond UI repository contains a non-UTF-8 entry",
                ));
            };
            match name {
                CURRENT_FILE => {
                    if pointer_exists {
                        return Err(invalid_data(
                            "unmarked Pond UI repository contains duplicate current state",
                        ));
                    }
                    let pointer: CurrentPointer =
                        read_json_file(&entry.path(), "unmarked current pointer")?;
                    let allowed_revision = match pointer.revision.as_deref() {
                        None => true,
                        Some(revision) => Some(revision) == expected_revision,
                    };
                    if pointer.version != REPOSITORY_VERSION || !allowed_revision {
                        return Err(invalid_data(
                            "unmarked Pond UI repository has previously selected or unsupported state",
                        ));
                    }
                    pointer_exists = true;
                }
                GENERATIONS_DIR => {
                    if generations_exists {
                        return Err(invalid_data(
                            "unmarked Pond UI repository contains duplicate generation state",
                        ));
                    }
                    require_directory(&entry.path(), "unmarked generations directory")?;
                    for generation in std::fs::read_dir(entry.path())? {
                        let generation = generation?;
                        let name = generation.file_name();
                        let Some(name) = name.to_str() else {
                            return Err(invalid_data(
                                "unmarked Pond UI generations contain a non-UTF-8 entry",
                            ));
                        };
                        let allowed =
                            expected_safe.is_some_and(|safe| name == format!("{safe}.json"));
                        if !allowed {
                            return Err(invalid_data(format!(
                                "unmarked Pond UI repository contains unowned generation entry {name:?}"
                            )));
                        }
                        load_generation_file(&generation.path(), expected_safe.unwrap())?;
                    }
                    generations_exists = true;
                }
                _ => {
                    return Err(invalid_data(format!(
                        "unmarked Pond UI repository contains unknown entry {name:?}"
                    )));
                }
            }
        }
        Ok(pointer_exists)
    }

    fn load_marked(&self) -> io::Result<(UiStore, Option<Arc<UiBundle>>)> {
        require_directory(&self.repository_dir, "repository")?;
        require_directory(&self.generations_dir(), "generations directory")?;
        let marker: RepositoryMarker = read_json_file(&self.marker_path(), "migration marker")?;
        if marker.version != REPOSITORY_VERSION {
            return Err(invalid_data(format!(
                "unsupported Pond UI repository version {}",
                marker.version
            )));
        }

        let pointer: CurrentPointer = read_json_file(&self.pointer_path(), "current pointer")?;
        if pointer.version != REPOSITORY_VERSION {
            return Err(invalid_data(format!(
                "unsupported Pond UI pointer version {}",
                pointer.version
            )));
        }
        if let Some(revision) = pointer.revision.as_deref() {
            validate_full_revision(revision).ok_or_else(|| {
                invalid_data(format!("invalid Pond UI current revision {revision:?}"))
            })?;
        }

        let mut generations = HashMap::new();
        let entries = std::fs::read_dir(self.generations_dir()).map_err(|error| {
            io::Error::new(error.kind(), format!("read Pond UI generations: {error}"))
        })?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if is_generation_stage_name(&name) {
                // Scavenging is best-effort and happens before loading. A stage
                // is never a generation and therefore can never be served.
                continue;
            }
            let Some(safe_revision) = name
                .strip_suffix(".json")
                .filter(|revision| validate_safe_revision(revision))
            else {
                // The private repository is content-addressed; unknown files are
                // never considered generations and therefore can never be served.
                continue;
            };
            // Every correctly named generation may once have been returned to a browser.
            // Silently dropping a damaged non-current one would break that accepted URL, so
            // corruption in any owned generation fails the repository closed.
            let bundle = load_generation_file(&entry.path(), safe_revision)?;
            generations.insert(bundle.revision.clone(), bundle);
        }
        let current = match pointer.revision {
            Some(revision) => Some(generations.get(&revision).cloned().ok_or_else(|| {
                invalid_data(format!("Pond UI current generation {revision} is missing"))
            })?),
            None => None,
        };
        Ok((UiStore { generations }, current))
    }

    fn validate_head(&self) -> io::Result<Option<String>> {
        let marker: RepositoryMarker = read_json_file(&self.marker_path(), "migration marker")?;
        if marker.version != REPOSITORY_VERSION {
            return Err(invalid_data("unsupported Pond UI repository version"));
        }
        let pointer: CurrentPointer = read_json_file(&self.pointer_path(), "current pointer")?;
        if pointer.version != REPOSITORY_VERSION {
            return Err(invalid_data("unsupported Pond UI pointer version"));
        }
        if let Some(revision) = pointer.revision.as_deref() {
            let safe = validate_full_revision(revision)
                .ok_or_else(|| invalid_data("invalid Pond UI current revision"))?;
            let path = self.generations_dir().join(format!("{safe}.json"));
            load_generation_file(&path, safe)?;
        }
        Ok(pointer.revision)
    }

    fn persist_generation(&self, prepared: &PreparedUiBundle) -> io::Result<()> {
        let path = self
            .generations_dir()
            .join(format!("{}.json", prepared.bundle.safe_revision));
        if path_entry_exists(&path)? {
            load_generation_file(&path, &prepared.bundle.safe_revision)?;
            // A preceding attempt may have made the immutable file visible but
            // reported uncertain directory durability. Reflush it before ever
            // allowing the current pointer to advance on retry.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)?
                .sync_all()?;
            return sync_directory(&self.generations_dir());
        }
        let outcome = write_bytes_atomic(&path, &canonical_json(&prepared.canonical)?)?;
        #[cfg(test)]
        let outcome = if self
            .force_generation_uncertain
            .swap(false, std::sync::atomic::Ordering::SeqCst)
            && matches!(outcome, AtomicCommit::Durable)
        {
            AtomicCommit::DurabilityUncertain(io::Error::other(
                "injected Pond UI generation durability uncertainty",
            ))
        } else {
            outcome
        };
        require_durable(outcome, "Pond UI generation")
    }

    fn write_pointer(&self, revision: Option<String>) -> io::Result<AtomicCommit> {
        let outcome = write_json_commit(
            &self.pointer_path(),
            &CurrentPointer {
                version: REPOSITORY_VERSION,
                revision,
            },
        )?;
        #[cfg(test)]
        let outcome = if self
            .force_pointer_uncertain
            .swap(false, std::sync::atomic::Ordering::SeqCst)
            && matches!(outcome, AtomicCommit::Durable)
        {
            AtomicCommit::DurabilityUncertain(io::Error::other(
                "injected Pond UI pointer durability uncertainty",
            ))
        } else {
            outcome
        };
        self.pointer_durability_unconfirmed.store(
            matches!(&outcome, AtomicCommit::DurabilityUncertain(_)),
            std::sync::atomic::Ordering::Release,
        );
        Ok(outcome)
    }

    fn marker_path(&self) -> PathBuf {
        self.repository_dir.join(MIGRATION_MARKER_FILE)
    }

    fn pointer_path(&self) -> PathBuf {
        self.repository_dir.join(CURRENT_FILE)
    }

    fn generations_dir(&self) -> PathBuf {
        self.repository_dir.join(GENERATIONS_DIR)
    }

    fn retire_legacy_files_best_effort(&self) {
        let mut removed = false;
        for name in std::iter::once(LEGACY_BUNDLE_FILE).chain(UI_FILES) {
            let path = self.ui_dir.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata)
                    if metadata.file_type().is_file() || metadata.file_type().is_symlink() =>
                {
                    match std::fs::remove_file(&path) {
                        Ok(()) => removed = true,
                        Err(error) => tracing::warn!(
                            path = %path.display(),
                            %error,
                            "Could not retire a legacy Pond UI file after migration"
                        ),
                    }
                }
                Ok(_) => {
                    tracing::warn!(
                        path = %path.display(),
                        "Ignoring non-file legacy Pond UI entry after migration"
                    );
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => tracing::warn!(
                    path = %path.display(),
                    %error,
                    "Could not inspect a legacy Pond UI file after migration"
                ),
            }
        }
        if removed {
            if let Err(error) = sync_directory(&self.ui_dir) {
                tracing::warn!(
                    path = %self.ui_dir.display(),
                    %error,
                    "Could not confirm legacy Pond UI retirement durability"
                );
            }
        }
    }

    fn scavenge_stages_best_effort(&self) {
        scavenge_directory_stages(&self.repository_dir, is_root_stage_name);
        scavenge_directory_stages(&self.generations_dir(), is_generation_stage_name);
    }

    #[cfg(test)]
    fn fail_next_commit_before_pointer(&self) {
        self.fail_before_pointer
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn make_next_generation_durability_uncertain(&self) {
        self.force_generation_uncertain
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(super) fn make_next_pointer_durability_uncertain(&self) {
        self.force_pointer_uncertain
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryMarker {
    version: u8,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentPointer {
    version: u8,
    revision: Option<String>,
}

fn prepare_bundle(publish: &PondUiPublish) -> Result<PreparedUiBundle, String> {
    let names = publish
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<HashSet<_>>();
    if publish.files.len() != UI_FILES.len()
        || names.len() != UI_FILES.len()
        || !UI_FILES.iter().all(|required| names.contains(required))
    {
        return Err(
            "a Pond publish must contain each of the five fixed UI files exactly once".to_string(),
        );
    }

    let mut canonical_files = Vec::with_capacity(UI_FILES.len());
    let mut files = HashMap::with_capacity(UI_FILES.len());
    for name in UI_FILES {
        let file = publish
            .files
            .iter()
            .find(|file| file.path == name)
            .expect("validated fixed bundle member");
        let bytes = if name == "koi.png" {
            base64::engine::general_purpose::STANDARD
                .decode(file.content.as_bytes())
                .map_err(|error| format!("koi.png: {error}"))?
        } else {
            file.content.as_bytes().to_vec()
        };
        let content = if name == "koi.png" {
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        } else {
            file.content.clone()
        };
        canonical_files.push(PondUiFile {
            path: name.to_string(),
            content,
        });
        files.insert(name.to_string(), Arc::<[u8]>::from(bytes));
    }

    let safe_revision = bundle_digest(&files);
    let revision = format!("{SHA256_PREFIX}{safe_revision}");
    Ok(PreparedUiBundle {
        canonical: PondUiPublish {
            files: canonical_files,
        },
        bundle: Arc::new(UiBundle {
            revision,
            safe_revision,
            files,
        }),
    })
}

fn bundle_digest(files: &HashMap<String, Arc<[u8]>>) -> String {
    let mut digest = Sha256::new();
    for name in UI_FILES {
        let bytes = files.get(name).expect("complete canonical UI bundle");
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes.as_ref());
    }
    format!("{:x}", digest.finalize())
}

fn read_legacy_bundle(ui_dir: &Path) -> io::Result<Option<PreparedUiBundle>> {
    let bundle_path = ui_dir.join(LEGACY_BUNDLE_FILE);
    match std::fs::symlink_metadata(&bundle_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let bytes = std::fs::read(&bundle_path)?;
            let publish: PondUiPublish = serde_json::from_slice(&bytes).map_err(|error| {
                invalid_data(format!(
                    "invalid legacy Pond UI bundle {}: {error}",
                    bundle_path.display()
                ))
            })?;
            return prepare_bundle(&publish).map(Some).map_err(|error| {
                invalid_data(format!(
                    "invalid legacy Pond UI bundle {}: {error}",
                    bundle_path.display()
                ))
            });
        }
        Ok(_) => {
            return Err(invalid_data(format!(
                "legacy Pond UI bundle is not a regular file: {}",
                bundle_path.display()
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    read_loose_legacy_bundle(ui_dir)
}

fn read_loose_legacy_bundle(ui_dir: &Path) -> io::Result<Option<PreparedUiBundle>> {
    let mut existing = Vec::with_capacity(UI_FILES.len());
    for name in UI_FILES {
        let path = ui_dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => existing.push((name, path)),
            Ok(_) => {
                return Err(invalid_data(format!(
                    "legacy Pond UI entry is not a regular file: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if existing.is_empty() {
        return Ok(None);
    }
    if existing.len() != UI_FILES.len() {
        return Err(invalid_data(
            "legacy Pond UI bundle is incomplete; refusing a mixed migration",
        ));
    }

    let mut files = Vec::with_capacity(UI_FILES.len());
    for (name, path) in existing {
        let bytes = std::fs::read(path)?;
        let content = if name == "koi.png" {
            base64::engine::general_purpose::STANDARD.encode(bytes)
        } else {
            String::from_utf8(bytes).map_err(|error| {
                invalid_data(format!("legacy Pond UI {name} is not UTF-8: {error}"))
            })?
        };
        files.push(PondUiFile {
            path: name.to_string(),
            content,
        });
    }
    prepare_bundle(&PondUiPublish { files })
        .map(Some)
        .map_err(invalid_data)
}

fn load_generation_file(path: &Path, expected_safe_revision: &str) -> io::Result<Arc<UiBundle>> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    if !metadata.file_type().is_file() {
        return Err(invalid_data(format!(
            "Pond UI generation is not a regular file: {}",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)?;
    let publish: PondUiPublish = serde_json::from_slice(&bytes).map_err(|error| {
        invalid_data(format!(
            "invalid Pond UI generation {}: {error}",
            path.display()
        ))
    })?;
    let prepared = prepare_bundle(&publish).map_err(invalid_data)?;
    if prepared.bundle.safe_revision != expected_safe_revision {
        return Err(invalid_data(format!(
            "Pond UI generation {} does not match its content digest",
            path.display()
        )));
    }
    if bytes != canonical_json(&prepared.canonical)? {
        return Err(invalid_data(format!(
            "Pond UI generation {} is not canonical",
            path.display()
        )));
    }
    Ok(prepared.bundle)
}

/// Return a safe lowercase hexadecimal URL segment for a wire revision or hex segment.
pub fn safe_revision_segment(revision: &str) -> Option<&str> {
    if validate_safe_revision(revision) {
        Some(revision)
    } else {
        validate_full_revision(revision)
    }
}

/// Whether a path segment is the one canonical public form for a generation.
pub(super) fn is_public_revision_segment(revision: &str) -> bool {
    validate_safe_revision(revision)
}

fn validate_full_revision(revision: &str) -> Option<&str> {
    revision
        .strip_prefix(SHA256_PREFIX)
        .filter(|safe| validate_safe_revision(safe))
}

fn validate_safe_revision(revision: &str) -> bool {
    revision.len() == SHA256_HEX_LEN
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn normalize_revision(revision: &str) -> Option<String> {
    safe_revision_segment(revision).map(|safe| format!("{SHA256_PREFIX}{safe}"))
}

fn canonical_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path, what: &str) -> io::Result<T> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(error.kind(), format!("missing Pond UI {what}: {error}"))
    })?;
    if !metadata.file_type().is_file() {
        return Err(invalid_data(format!(
            "Pond UI {what} is not a regular file: {}",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid Pond UI {what}: {error}")))
}

fn write_json_commit<T: Serialize>(path: &Path, value: &T) -> io::Result<AtomicCommit> {
    write_bytes_atomic(path, &canonical_json(value)?)
}

fn write_json_required_durable<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    require_durable(write_json_commit(path, value)?, "Pond UI initialization")
}

fn write_pointer_required_durable(path: &Path, revision: Option<String>) -> io::Result<()> {
    write_json_required_durable(
        path,
        &CurrentPointer {
            version: REPOSITORY_VERSION,
            revision,
        },
    )
}

fn require_durable(outcome: AtomicCommit, what: &str) -> io::Result<()> {
    match outcome {
        AtomicCommit::Durable => Ok(()),
        AtomicCommit::DurabilityUncertain(error) => Err(io::Error::new(
            error.kind(),
            format!("{what} is visible, but its crash durability could not be confirmed: {error}"),
        )),
    }
}

fn require_directory(path: &Path, what: &str) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("missing Pond UI {what} {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "Pond UI {what} is not a directory: {}",
            path.display()
        )))
    }
}

fn path_entry_exists(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn is_root_stage_name(name: &str) -> bool {
    is_bare_stage_name(name)
        || [CURRENT_FILE, MIGRATION_MARKER_FILE]
            .iter()
            .any(|target| is_stage_for_target(name, target))
}

fn is_generation_stage_name(name: &str) -> bool {
    if is_bare_stage_name(name) {
        return true;
    }
    let Some((revision, suffix)) = name.split_once(".json.") else {
        return false;
    };
    validate_safe_revision(revision) && is_safe_stage_suffix(suffix)
}

fn is_stage_for_target(name: &str, target: &str) -> bool {
    name.strip_prefix(target)
        .and_then(|suffix| suffix.strip_prefix('.'))
        .is_some_and(is_safe_stage_suffix)
}

fn is_bare_stage_name(name: &str) -> bool {
    name.strip_prefix('.').is_some_and(is_safe_stage_suffix)
}

fn is_safe_stage_suffix(suffix: &str) -> bool {
    let Some(body) = suffix
        .strip_prefix("stage-")
        .or_else(|| suffix.strip_prefix("koi-stage-"))
        .and_then(|suffix| suffix.strip_suffix(".tmp"))
    else {
        return false;
    };
    !body.is_empty()
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn scavenge_directory_stages(directory: &Path, is_stage: fn(&str) -> bool) {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(
                path = %directory.display(),
                %error,
                "Could not inspect Pond UI repository for stale stages"
            );
            return;
        }
    }
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(
                path = %directory.display(),
                %error,
                "Could not scan Pond UI repository for stale stages"
            );
            return;
        }
    };
    let mut removed = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "Could not inspect a Pond UI repository entry");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_stage(name) {
            continue;
        }
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
                match std::fs::remove_file(&path) {
                    Ok(()) => removed = true,
                    Err(error) => tracing::warn!(
                        path = %path.display(),
                        %error,
                        "Could not remove a stale Pond UI stage"
                    ),
                }
            }
            Ok(_) => tracing::warn!(
                path = %path.display(),
                "Ignoring a non-file path shaped like a Pond UI stage"
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %path.display(),
                %error,
                "Could not inspect a stale Pond UI stage"
            ),
        }
    }
    if removed {
        if let Err(error) = sync_directory(directory) {
            tracing::warn!(
                path = %directory.display(),
                %error,
                "Could not confirm stale Pond UI stage cleanup durability"
            );
        }
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    // `koi_common::persist::replace_file` uses write-through replacement on
    // Windows. Windows directory handles require separate backup-semantics flags.
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "koi-pond-ui-{name}-{}",
                koi_common::id::generate_short_id()
            ));
            std::fs::create_dir_all(&root).expect("create fixture");
            Self { root }
        }

        fn reopen(&self) -> io::Result<(PondUiRepository, UiStore, Option<Arc<UiBundle>>)> {
            PondUiRepository::open(self.root.clone())
        }

        fn write_legacy(&self, marker: &str) {
            for name in UI_FILES {
                let bytes = if name == "koi.png" {
                    b"png".to_vec()
                } else {
                    format!("{name}-{marker}").into_bytes()
                };
                std::fs::write(self.root.join(name), bytes).expect("write legacy asset");
            }
        }

        fn write_legacy_bundle(&self, marker: &str) {
            std::fs::write(
                self.root.join(LEGACY_BUNDLE_FILE),
                serde_json::to_vec(&publish(marker)).expect("serialize legacy bundle"),
            )
            .expect("write legacy bundle");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn publish(marker: &str) -> PondUiPublish {
        PondUiPublish {
            files: UI_FILES
                .iter()
                .rev()
                .map(|name| PondUiFile {
                    path: (*name).to_string(),
                    content: if *name == "koi.png" {
                        base64::engine::general_purpose::STANDARD.encode(b"png")
                    } else {
                        format!("{name}-{marker}")
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn canonical_payload_has_stable_digest_and_preserves_original_bytes() {
        let prepared = PondUiRepository::prepare(&publish("one")).expect("prepare");
        assert!(validate_safe_revision(prepared.bundle.safe_revision()));
        assert_eq!(
            prepared.bundle.revision(),
            format!("sha256:{}", prepared.bundle.safe_revision())
        );
        assert_eq!(
            prepared
                .canonical
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            UI_FILES
        );
        for file in &prepared.canonical.files {
            let expected = if file.path == "koi.png" {
                b"png".as_slice()
            } else {
                file.content.as_bytes()
            };
            assert_eq!(prepared.bundle.file(&file.path).unwrap().as_ref(), expected);
        }
        assert_eq!(
            safe_revision_segment(prepared.bundle.revision()),
            Some(prepared.bundle.safe_revision())
        );
    }

    #[test]
    fn commit_failure_before_pointer_preserves_old_current_and_retains_generation() {
        let fixture = Fixture::new("old-or-new");
        let (repository, _, initial) = fixture.reopen().expect("open repository");
        assert!(initial.is_none());
        let first = repository
            .commit(PondUiRepository::prepare(&publish("first")).unwrap())
            .expect("first commit")
            .bundle;
        let second = PondUiRepository::prepare(&publish("second")).unwrap();
        let second_revision = second.bundle.revision().to_string();
        repository.fail_next_commit_before_pointer();
        assert!(repository.commit(second).is_err());

        drop(repository);
        let (repository, reopened, current) = fixture.reopen().expect("reopen after failure");
        assert_eq!(
            current.unwrap().revision(),
            first.revision(),
            "unacknowledged commit must retain the old pointer"
        );
        assert!(reopened.generation(&second_revision).is_some());
        assert_eq!(reopened.generation_count(), 2);

        let accepted = repository
            .commit(PondUiRepository::prepare(&publish("second")).unwrap())
            .expect("retry commit")
            .bundle;
        drop(repository);
        let (_, final_store, current) = fixture.reopen().expect("reopen committed repository");
        assert_eq!(current.unwrap().revision(), accepted.revision());
        assert_eq!(final_store.generation_count(), 2);
    }

    #[test]
    fn retained_generations_remain_addressable_after_restart() {
        let fixture = Fixture::new("retained");
        let (repository, _, _) = fixture.reopen().unwrap();
        let first = repository
            .commit(PondUiRepository::prepare(&publish("first")).unwrap())
            .unwrap()
            .bundle;
        let second = repository
            .commit(PondUiRepository::prepare(&publish("second")).unwrap())
            .unwrap()
            .bundle;
        drop(repository);

        let (_, store, current) = fixture.reopen().unwrap();
        assert_eq!(store.generation_count(), 2);
        assert_eq!(
            store
                .generation(first.safe_revision())
                .unwrap()
                .file("app.js")
                .unwrap()
                .as_ref(),
            b"app.js-first"
        );
        assert_eq!(
            store
                .generation(second.revision())
                .unwrap()
                .file("app.js")
                .unwrap()
                .as_ref(),
            b"app.js-second"
        );
        assert_eq!(current.unwrap().revision(), second.revision());
    }

    #[test]
    fn clear_selection_retains_generations_and_duplicate_clear_is_a_noop() {
        let fixture = Fixture::new("clear-selection");
        let (repository, _, _) = fixture.reopen().unwrap();
        let selected = repository
            .commit(PondUiRepository::prepare(&publish("selected")).unwrap())
            .unwrap()
            .bundle;

        assert!(repository.clear().unwrap().is_some());
        let pointer_after_clear = std::fs::read(repository.pointer_path()).unwrap();
        assert!(repository.clear().unwrap().is_none());
        assert_eq!(
            std::fs::read(repository.pointer_path()).unwrap(),
            pointer_after_clear,
            "an already-clear selection must not rewrite durable state"
        );
        drop(repository);

        let (_, store, current) = fixture.reopen().unwrap();
        assert!(current.is_none());
        assert_eq!(store.generation_count(), 1);
        assert_eq!(
            store
                .generation(selected.revision())
                .unwrap()
                .file("app.js")
                .unwrap()
                .as_ref(),
            b"app.js-selected"
        );
    }

    #[test]
    fn first_open_imports_legacy_once_and_retires_direct_files() {
        let fixture = Fixture::new("migration");
        fixture.write_legacy("legacy");

        let (_, _, current) = fixture.reopen().expect("migrate legacy bundle");
        let current = current.expect("imported current bundle");
        assert_eq!(current.file("app.js").unwrap().as_ref(), b"app.js-legacy");
        assert!(fixture
            .root
            .join(REPOSITORY_DIR)
            .join(CURRENT_FILE)
            .is_file());
        assert!(fixture
            .root
            .join(REPOSITORY_DIR)
            .join(MIGRATION_MARKER_FILE)
            .is_file());
        for name in UI_FILES {
            assert!(!fixture.root.join(name).exists(), "legacy {name} retired");
        }
    }

    #[test]
    fn single_bundle_legacy_source_takes_precedence_and_retires_every_source() {
        let fixture = Fixture::new("single-bundle-precedence");
        fixture.write_legacy("older-loose");
        fixture.write_legacy_bundle("newer-bundle");

        let (_, _, current) = fixture.reopen().expect("migrate authoritative bundle");
        assert_eq!(
            current.unwrap().file("app.js").unwrap().as_ref(),
            b"app.js-newer-bundle"
        );
        assert!(!fixture.root.join(LEGACY_BUNDLE_FILE).exists());
        for name in UI_FILES {
            assert!(!fixture.root.join(name).exists(), "legacy {name} retired");
        }
    }

    #[test]
    fn damaged_single_bundle_never_falls_back_to_complete_loose_files() {
        let fixture = Fixture::new("single-bundle-corrupt");
        fixture.write_legacy("valid-loose");
        std::fs::write(fixture.root.join(LEGACY_BUNDLE_FILE), b"{broken").unwrap();

        assert_eq!(
            fixture.reopen().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!fixture
            .root
            .join(REPOSITORY_DIR)
            .join(MIGRATION_MARKER_FILE)
            .exists());

        std::fs::remove_file(fixture.root.join(LEGACY_BUNDLE_FILE)).unwrap();
        std::fs::create_dir(fixture.root.join(LEGACY_BUNDLE_FILE)).unwrap();
        assert_eq!(
            fixture.reopen().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn marked_repository_ignores_legacy_retirement_failures() {
        let fixture = Fixture::new("legacy-retirement-best-effort");
        fixture.write_legacy_bundle("current");
        let (_, _, first) = fixture.reopen().expect("initial migration");
        let revision = first.unwrap().revision().to_string();

        std::fs::create_dir(fixture.root.join(LEGACY_BUNDLE_FILE)).unwrap();
        std::fs::create_dir(fixture.root.join("index.html")).unwrap();
        let (_, _, reopened) = fixture
            .reopen()
            .expect("valid marked repository remains authoritative");
        assert_eq!(reopened.unwrap().revision(), revision);
        assert!(fixture.root.join(LEGACY_BUNDLE_FILE).is_dir());
        assert!(fixture.root.join("index.html").is_dir());
    }

    #[test]
    fn migrated_repository_never_falls_back_to_resurrected_legacy_files() {
        let fixture = Fixture::new("rollback-prevention");
        fixture.write_legacy("first");
        let (_, _, current) = fixture.reopen().unwrap();
        assert!(current.is_some());

        fixture.write_legacy("stale");
        std::fs::remove_file(fixture.root.join(REPOSITORY_DIR).join(CURRENT_FILE)).unwrap();
        let error = fixture
            .reopen()
            .expect_err("missing pointer must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(fixture.root.join("index.html").exists());
    }

    #[test]
    fn missing_or_corrupt_current_generation_fails_closed() {
        let fixture = Fixture::new("corrupt-current");
        let (repository, _, _) = fixture.reopen().unwrap();
        let bundle = repository
            .commit(PondUiRepository::prepare(&publish("current")).unwrap())
            .unwrap()
            .bundle;
        let generation = fixture
            .root
            .join(REPOSITORY_DIR)
            .join(GENERATIONS_DIR)
            .join(format!("{}.json", bundle.safe_revision()));
        drop(repository);
        std::fs::remove_file(generation).unwrap();
        assert_eq!(
            fixture.reopen().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let fixture = Fixture::new("corrupt-pointer");
        fixture.reopen().unwrap();
        std::fs::write(
            fixture.root.join(REPOSITORY_DIR).join(CURRENT_FILE),
            b"{broken",
        )
        .unwrap();
        assert_eq!(
            fixture.reopen().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn corrupt_retained_generation_fails_repository_closed() {
        let fixture = Fixture::new("orphan-corruption");
        let (repository, _, _) = fixture.reopen().unwrap();
        let first = repository
            .commit(PondUiRepository::prepare(&publish("first")).unwrap())
            .unwrap()
            .bundle;
        let second = repository
            .commit(PondUiRepository::prepare(&publish("second")).unwrap())
            .unwrap()
            .bundle;
        drop(repository);
        std::fs::write(
            fixture
                .root
                .join(REPOSITORY_DIR)
                .join(GENERATIONS_DIR)
                .join(format!("{}.json", first.safe_revision())),
            b"{broken",
        )
        .unwrap();

        let error = fixture
            .reopen()
            .expect_err("an accepted generation URL must never disappear silently");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_ne!(first.revision(), second.revision());
    }

    #[test]
    fn valid_canonical_generation_under_the_wrong_digest_preserves_accepted_state() {
        let fixture = Fixture::new("wrong-generation-digest");
        let (repository, _, _) = fixture.reopen().unwrap();
        let accepted = repository
            .commit(PondUiRepository::prepare(&publish("accepted")).unwrap())
            .unwrap()
            .bundle;

        let repository_dir = fixture.root.join(REPOSITORY_DIR);
        let pointer = repository_dir.join(CURRENT_FILE);
        let accepted_generation = repository_dir
            .join(GENERATIONS_DIR)
            .join(format!("{}.json", accepted.safe_revision()));
        let pointer_before = std::fs::read(&pointer).unwrap();
        let accepted_before = std::fs::read(&accepted_generation).unwrap();

        let foreign = PondUiRepository::prepare(&publish("foreign")).unwrap();
        let wrong_safe_revision = if foreign
            .bundle
            .safe_revision()
            .bytes()
            .all(|byte| byte == b'0')
        {
            "1".repeat(SHA256_HEX_LEN)
        } else {
            "0".repeat(SHA256_HEX_LEN)
        };
        let mismatched_generation = repository_dir
            .join(GENERATIONS_DIR)
            .join(format!("{wrong_safe_revision}.json"));
        let canonical_foreign = canonical_json(&foreign.canonical).unwrap();
        std::fs::write(&mismatched_generation, &canonical_foreign).unwrap();
        drop(repository);

        let error = fixture
            .reopen()
            .expect_err("a canonical payload under the wrong digest must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error
            .to_string()
            .contains("does not match its content digest"));
        assert_eq!(std::fs::read(&pointer).unwrap(), pointer_before);
        assert_eq!(
            std::fs::read(&accepted_generation).unwrap(),
            accepted_before
        );
        assert_eq!(
            std::fs::read(&mismatched_generation).unwrap(),
            canonical_foreign
        );
    }

    #[test]
    fn missing_marker_after_an_accepted_publish_fails_without_deleting_state() {
        let fixture = Fixture::new("missing-marker-after-publish");
        let (repository, _, _) = fixture.reopen().unwrap();
        let committed = repository
            .commit(PondUiRepository::prepare(&publish("accepted")).unwrap())
            .unwrap()
            .bundle;
        drop(repository);

        let repository_dir = fixture.root.join(REPOSITORY_DIR);
        let pointer = repository_dir.join(CURRENT_FILE);
        let generation = repository_dir
            .join(GENERATIONS_DIR)
            .join(format!("{}.json", committed.safe_revision()));
        let pointer_before = std::fs::read(&pointer).unwrap();
        let generation_before = std::fs::read(&generation).unwrap();
        std::fs::remove_file(repository_dir.join(MIGRATION_MARKER_FILE)).unwrap();

        let error = fixture
            .reopen()
            .expect_err("an unmarked selected generation is ambiguous and must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(pointer).unwrap(), pointer_before);
        assert_eq!(std::fs::read(generation).unwrap(), generation_before);
        assert!(!repository_dir.join(MIGRATION_MARKER_FILE).exists());
    }

    #[test]
    fn unknown_unmarked_repository_entry_is_preserved_and_fails_closed() {
        let fixture = Fixture::new("unknown-unmarked-entry");
        let repository_dir = fixture.root.join(REPOSITORY_DIR);
        std::fs::create_dir(&repository_dir).unwrap();
        let unknown = repository_dir.join("future-format.data");
        std::fs::write(&unknown, b"do not delete").unwrap();

        let error = fixture
            .reopen()
            .expect_err("unknown unmarked state must not be adopted or erased");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(unknown).unwrap(), b"do not delete");
        assert!(!repository_dir.join(MIGRATION_MARKER_FILE).exists());
    }

    #[test]
    fn exact_empty_interrupted_initialization_resumes_without_destructive_cleanup() {
        let fixture = Fixture::new("resume-empty-initialization");
        let repository_dir = fixture.root.join(REPOSITORY_DIR);
        std::fs::create_dir_all(repository_dir.join(GENERATIONS_DIR)).unwrap();
        koi_common::persist::write_json_pretty(
            &repository_dir.join(CURRENT_FILE),
            &CurrentPointer {
                version: REPOSITORY_VERSION,
                revision: None,
            },
        )
        .unwrap();

        let (_, store, current) = fixture.reopen().expect("resume exact empty repository");
        assert!(current.is_none());
        assert_eq!(store.generation_count(), 0);
        assert!(repository_dir.join(MIGRATION_MARKER_FILE).is_file());
    }

    #[test]
    fn partial_legacy_bundle_is_rejected_without_creating_a_marker() {
        let fixture = Fixture::new("partial-legacy");
        std::fs::write(fixture.root.join("index.html"), "partial").unwrap();
        assert_eq!(
            fixture.reopen().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!fixture
            .root
            .join(REPOSITORY_DIR)
            .join(MIGRATION_MARKER_FILE)
            .exists());
    }

    #[test]
    fn uncertain_generation_is_retained_but_never_advances_the_pointer() {
        let fixture = Fixture::new("generation-uncertain");
        let (repository, _, _) = fixture.reopen().unwrap();
        let first = repository
            .commit(PondUiRepository::prepare(&publish("first")).unwrap())
            .unwrap()
            .bundle;
        let second = PondUiRepository::prepare(&publish("second")).unwrap();
        let second_revision = second.bundle.revision().to_string();

        repository.make_next_generation_durability_uncertain();
        let error = repository
            .commit(second)
            .expect_err("uncertain generation cannot advance current");
        assert!(error.to_string().contains("crash durability"));
        drop(repository);

        let (repository, store, current) = fixture.reopen().unwrap();
        assert_eq!(current.unwrap().revision(), first.revision());
        assert!(store.generation(&second_revision).is_some());

        let retried = repository
            .commit(PondUiRepository::prepare(&publish("second")).unwrap())
            .expect("retry reflushed the orphan generation");
        assert!(matches!(retried.durability, AtomicCommit::Durable));
        assert_eq!(retried.bundle.revision(), second_revision);
    }

    #[test]
    fn uncertain_pointer_is_accepted_and_remains_current_after_restart() {
        let fixture = Fixture::new("pointer-uncertain");
        let (repository, _, _) = fixture.reopen().unwrap();
        repository.make_next_pointer_durability_uncertain();

        let committed = repository
            .commit(PondUiRepository::prepare(&publish("visible")).unwrap())
            .expect("visible pointer must be accepted as committed");
        assert!(matches!(
            committed.durability,
            AtomicCommit::DurabilityUncertain(_)
        ));
        let revision = committed.bundle.revision().to_string();
        drop(repository);

        let (_, _, reopened) = fixture.reopen().unwrap();
        assert_eq!(reopened.unwrap().revision(), revision);
    }

    #[test]
    fn uncertain_clear_is_reflushed_before_becoming_an_already_clear_noop() {
        let fixture = Fixture::new("clear-pointer-uncertain");
        let (repository, _, _) = fixture.reopen().unwrap();
        let _ = repository
            .commit(PondUiRepository::prepare(&publish("selected")).unwrap())
            .unwrap();
        repository.make_next_pointer_durability_uncertain();

        assert!(matches!(
            repository.clear().unwrap(),
            Some(AtomicCommit::DurabilityUncertain(_))
        ));
        assert!(matches!(
            repository.clear().unwrap(),
            Some(AtomicCommit::Durable)
        ));
        assert!(repository.clear().unwrap().is_none());
    }

    #[test]
    fn open_scavenges_only_owned_safe_stage_files() {
        let fixture = Fixture::new("stage-scavenge");
        let (repository, _, _) = fixture.reopen().unwrap();
        let current = repository
            .commit(PondUiRepository::prepare(&publish("current")).unwrap())
            .unwrap()
            .bundle;
        drop(repository);

        let repository_dir = fixture.root.join(REPOSITORY_DIR);
        let generations_dir = repository_dir.join(GENERATIONS_DIR);
        let root_stage = repository_dir.join("current.json.stage-12-34.tmp");
        let generation_stage = generations_dir.join(format!(
            "{}.json.koi-stage-12-34-deadbeef.tmp",
            current.safe_revision()
        ));
        let unknown_root = repository_dir.join("notes.stage-12-34.tmp");
        let unknown_generation = generations_dir.join("not-a-digest.json.stage-12-34.tmp");
        for path in [
            &root_stage,
            &generation_stage,
            &unknown_root,
            &unknown_generation,
        ] {
            std::fs::write(path, b"stage").unwrap();
        }

        let (_, _, selected) = fixture.reopen().expect("reopen after scavenging");
        assert_eq!(selected.unwrap().revision(), current.revision());
        assert!(!root_stage.exists());
        assert!(!generation_stage.exists());
        assert!(unknown_root.exists());
        assert!(unknown_generation.exists());
    }
}
