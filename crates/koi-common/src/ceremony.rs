//! Generic server-driven ceremony framework.
//!
//! A **ceremony** is a server-controlled dialogue between a server and a
//! client (CLI, web UI, SDK). The server owns validation, branching, and
//! all domain logic. Clients are dumb render loops — they display
//! whatever the server sends, collect input, and post it back.
//!
//! # Core model: bag of key-value + rules
//!
//! A ceremony is **not** a linear pipeline of stages. It is:
//!
//! - A **bag** of key-value pairs (the session state), and
//! - A **rules function** that inspects the bag and decides what to do next.
//!
//! ```text
//! evaluate(bag, render_hints) → { prompts[] + messages[] | complete | fatal }
//! ```
//!
//! There is no stage index, no forward/backward cursor. The session is
//! just a `Map<String, Value>` and the rules are a pure function over it.
//! Every time the client submits data, it is merged into the bag, and the
//! rules are re-evaluated.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐        ┌──────────────┐        ┌────────────────┐
//! │  Client   │ ←────→ │ CeremonyHost │ ←────→ │ CeremonyRules  │
//! │ (render   │ step() │ (sessions,   │ eval() │ (domain-       │
//! │  loop)    │        │  lifecycle)  │        │  specific)     │
//! └──────────┘        └──────────────┘        └────────────────┘
//! ```
//!
//! The [`CeremonyHost`] manages sessions and delegates evaluation to a
//! [`CeremonyRules`] implementation. Each domain (certmesh, storage,
//! companions, etc.) provides its own `CeremonyRules`.
//!
//! # Usage
//!
//! ```ignore
//! // 1. Implement CeremonyRules for your domain
//! impl CeremonyRules for PondRules {
//!     fn validate_ceremony_type(&self, ceremony: &str) -> Result<(), String> { ... }
//!     fn evaluate(&self, ceremony_type: &str, bag: &mut Map<String, Value>,
//!                 render: &RenderHints) -> EvalResult { ... }
//! }
//!
//! // 2. Create a host and call step()
//! let host = CeremonyHost::new(rules);
//! let response = host.step(CeremonyRequest {
//!     ceremony: Some("init".into()),
//!     data: serde_json::Map::new(),
//!     ..Default::default()
//! });
//! ```

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Configuration ───────────────────────────────────────────────────

/// Default session time-to-live (5 minutes).
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(300);

/// Default sweep interval for expired sessions (60 seconds).
/// Consumers spawn a background task at this interval calling
/// [`CeremonyHost::sweep_expired`].
pub const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

// ── Render hints ────────────────────────────────────────────────────

/// Client-provided hints for how the server should render rich content.
///
/// Sent per-request so different clients (CLI vs browser) get appropriate
/// output without the server needing to know who's calling.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RenderHints {
    /// Preferred QR code format. Absent = server's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qr: Option<QrFormat>,
}

/// QR code rendering format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QrFormat {
    /// Unicode block characters for terminal display.
    Utf8,
    /// Base64-encoded PNG for `<img src="data:image/png;base64,...">`.
    PngBase64,
    /// Raw URI only — no visual rendering.
    UriOnly,
}

impl Default for QrFormat {
    fn default() -> Self {
        Self::Utf8
    }
}

// ── Protocol types (wire format) ────────────────────────────────────

/// Inbound ceremony request from the client.
///
/// This is the universal request shape for every ceremony step.
/// The client sends key-value data which is merged into the session bag.
#[derive(Debug, Default, Deserialize)]
pub struct CeremonyRequest {
    /// Session ID from a previous response. `None` to start a new ceremony.
    #[serde(default)]
    pub session_id: Option<Uuid>,

    /// Ceremony type identifier (e.g. "init", "join").
    /// Required on the first call; ignored on subsequent calls.
    #[serde(default)]
    pub ceremony: Option<String>,

    /// Key-value pairs to merge into the session bag.
    /// On the first call this can carry prefill data from CLI flags.
    /// On subsequent calls this carries the user's answers to prompts.
    #[serde(default)]
    pub data: serde_json::Map<String, serde_json::Value>,

    /// Client render preferences.
    #[serde(default)]
    pub render: Option<RenderHints>,
}

/// Outbound ceremony response to the client.
///
/// Contains prompts (what to ask the user), messages (what to show),
/// completion status, and any errors.
#[derive(Debug, Serialize)]
pub struct CeremonyResponse {
    /// Session ID — include in the next request.
    pub session_id: Uuid,

    /// Data the server wants the client to collect.
    /// Empty only when `complete` is true or a fatal error occurred.
    pub prompts: Vec<Prompt>,

    /// Informational content to display (instructions, QR codes, summaries).
    /// Can appear alongside prompts.
    pub messages: Vec<Message>,

    /// True when the ceremony is finished (success or fatal error).
    pub complete: bool,

    /// Validation or fatal error detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Prompts ─────────────────────────────────────────────────────────

/// A single data request — tells the client exactly one thing to collect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    /// The bag key this prompt populates.
    pub key: String,

    /// Human-readable question or instruction.
    pub prompt: String,

    /// What kind of input widget the client should render.
    pub input_type: InputType,

    /// Options for `SelectOne` or `SelectMany` input types.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<SelectOption>,

    /// Whether the user must provide a value.
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_true() -> bool {
    true
}

/// A selectable option within a `SelectOne` or `SelectMany` prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectOption {
    /// The value stored in the bag when selected.
    pub value: String,
    /// Display label.
    pub label: String,
    /// Optional description shown below the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The kind of input widget a prompt requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// Pick exactly one from `options`.
    SelectOne,
    /// Pick one or more from `options`.
    SelectMany,
    /// Free text input.
    Text,
    /// Masked text input (passphrases).
    Secret,
    /// Two masked inputs that must match (passphrase + confirmation).
    SecretConfirm,
    /// Short numeric/alphanumeric code (TOTP verification).
    Code,
    /// Raw entropy input (keyboard mashing, mouse movement).
    Entropy,
    /// Hardware key interaction (WebAuthn).
    Fido2,
}

// ── Messages ────────────────────────────────────────────────────────

/// An informational display item — not an input.
///
/// Messages carry content to show the user without requiring input.
/// They can appear alongside prompts (e.g., QR code + code input).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// What kind of content this is.
    pub kind: MessageKind,

    /// Short title or heading.
    pub title: String,

    /// The content body (plain text, base64 image, JSON summary, etc.).
    pub content: String,
}

/// Message content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Plain text instruction or guidance.
    Info,
    /// QR code image (format per `RenderHints::qr`).
    QrCode,
    /// Key-value summary of completed ceremony data.
    Summary,
    /// Error detail with context (non-fatal).
    Error,
}

// ── Session ─────────────────────────────────────────────────────────

/// A live ceremony session — just a bag of key-value pairs plus metadata.
///
/// There is no stage index, no stage name, no progress counter.
/// The [`CeremonyRules`] derive everything from the bag contents.
pub struct Session {
    /// Unique session identifier (UUIDv7).
    pub id: Uuid,

    /// Ceremony type identifier string (e.g. "init", "join").
    pub ceremony_type: String,

    /// The accumulated key-value data. Rules read and write this.
    pub bag: serde_json::Map<String, serde_json::Value>,

    /// Client render hints (from the most recent request).
    pub render: RenderHints,

    /// Monotonic timestamp of creation.
    pub created_at: Instant,

    /// Monotonic timestamp of last activity.
    pub last_active: Instant,

    /// Whether this ceremony has completed.
    pub complete: bool,
}

impl Session {
    /// Store a value in the bag.
    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.bag.insert(key.into(), value);
    }

    /// Get a value from the bag.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.bag.get(key)
    }

    /// Get a string value from the bag.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.bag.get(key).and_then(|v| v.as_str())
    }

    /// Check whether a key exists in the bag.
    pub fn has(&self, key: &str) -> bool {
        self.bag.contains_key(key)
    }

    /// Remove a key from the bag (e.g. to force re-collection on conflict).
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.bag.remove(key)
    }
}

// ── Eval result ─────────────────────────────────────────────────────

/// Result of evaluating the ceremony rules against the current bag.
///
/// Returned by [`CeremonyRules::evaluate`] to tell the host what to
/// present to the client next.
pub enum EvalResult {
    /// The ceremony needs more data. Return prompts and optional messages.
    NeedInput {
        /// Data the client should collect.
        prompts: Vec<Prompt>,
        /// Informational content to display alongside prompts.
        messages: Vec<Message>,
    },

    /// Re-prompt with a validation error. The client shows the error
    /// and re-renders the prompts for the user to correct.
    ValidationError {
        /// Prompts to re-display (typically the offending fields).
        prompts: Vec<Prompt>,
        /// Informational messages.
        messages: Vec<Message>,
        /// Human-readable error description.
        error: String,
    },

    /// The bag is complete and consistent. The ceremony is done.
    Complete {
        /// Final messages (summary, results, etc.).
        messages: Vec<Message>,
    },

    /// Something is terminally wrong (I/O failure, impossible state).
    Fatal(String),
}

// ── Ceremony rules trait ────────────────────────────────────────────

/// Domain-specific ceremony rules.
///
/// Each domain (certmesh, storage, companions, etc.) implements this
/// trait to define its ceremony types and evaluation logic.
///
/// The rules function is essentially:
/// ```text
/// evaluate(ceremony_type, bag, render_hints) → EvalResult
/// ```
///
/// Rules inspect the bag and decide what data is still needed, whether
/// existing data conflicts, or whether the ceremony is complete.
///
/// # Thread safety
///
/// The host calls `evaluate` while holding a session lock. Keep
/// implementations fast — do heavy I/O before returning, or collect
/// parameters here and execute in a post-step hook.
pub trait CeremonyRules: Send + Sync {
    /// Validate a ceremony type string.
    ///
    /// Return `Ok(())` if the string is a known ceremony type,
    /// or `Err("message")` if it isn't.
    fn validate_ceremony_type(&self, ceremony: &str) -> Result<(), String>;

    /// Evaluate the bag and determine what happens next.
    ///
    /// The rules may read and write the bag (e.g. to inject derived keys
    /// like `_totp_secret`, or to remove conflicting keys). The bag
    /// already contains any data the client sent in this request —
    /// it was merged before `evaluate` is called.
    fn evaluate(
        &self,
        ceremony_type: &str,
        bag: &mut serde_json::Map<String, serde_json::Value>,
        render: &RenderHints,
    ) -> EvalResult;
}

// ── Ceremony host ───────────────────────────────────────────────────

/// Generic ceremony host — manages sessions and delegates evaluation
/// to a [`CeremonyRules`] implementation.
///
/// Thread-safe. One host per domain, shared across HTTP handlers.
pub struct CeremonyHost<R: CeremonyRules> {
    rules: R,
    sessions: Mutex<HashMap<Uuid, Session>>,
    session_ttl: Duration,
}

impl<R: CeremonyRules> CeremonyHost<R> {
    /// Create a new ceremony host with the given domain rules.
    pub fn new(rules: R) -> Self {
        Self {
            rules,
            sessions: Mutex::new(HashMap::new()),
            session_ttl: DEFAULT_SESSION_TTL,
        }
    }

    /// Create a ceremony host with a custom session TTL.
    pub fn with_ttl(rules: R, ttl: Duration) -> Self {
        Self {
            rules,
            sessions: Mutex::new(HashMap::new()),
            session_ttl: ttl,
        }
    }

    /// Access the domain rules (e.g. for diagnostics or testing).
    pub fn rules(&self) -> &R {
        &self.rules
    }

    /// Process a ceremony step.
    ///
    /// - If `session_id` is `None`, creates a new session, merges
    ///   `data` into the bag, evaluates the rules, and returns prompts.
    /// - If `session_id` is `Some`, merges `data` into the existing
    ///   session bag, re-evaluates the rules, and returns prompts.
    pub fn step(
        &self,
        request: CeremonyRequest,
    ) -> Result<CeremonyResponse, CeremonyError> {
        match request.session_id {
            None => self.start_new(request),
            Some(id) => self.continue_existing(id, request),
        }
    }

    /// Remove expired sessions. Call periodically from a background task.
    /// Returns the number of sessions removed.
    pub fn sweep_expired(&self) -> usize {
        let mut sessions = self.sessions.lock().expect("session lock poisoned");
        let now = Instant::now();
        let before = sessions.len();
        sessions.retain(|_id, session| {
            now.duration_since(session.last_active) < self.session_ttl
        });
        let removed = before - sessions.len();
        if removed > 0 {
            tracing::debug!(
                removed,
                remaining = sessions.len(),
                "Swept expired ceremony sessions"
            );
        }
        removed
    }

    /// Number of active sessions (for diagnostics).
    pub fn active_session_count(&self) -> usize {
        self.sessions.lock().expect("session lock poisoned").len()
    }

    // ── Internal ────────────────────────────────────────────────────

    fn start_new(
        &self,
        request: CeremonyRequest,
    ) -> Result<CeremonyResponse, CeremonyError> {
        let ceremony = request
            .ceremony
            .as_deref()
            .ok_or_else(|| CeremonyError::MissingField("ceremony".into()))?;

        self.rules
            .validate_ceremony_type(ceremony)
            .map_err(CeremonyError::InvalidCeremony)?;

        let render = request.render.unwrap_or_default();
        let now = Instant::now();

        let mut session = Session {
            id: Uuid::now_v7(),
            ceremony_type: ceremony.to_string(),
            bag: request.data,
            render: render.clone(),
            created_at: now,
            last_active: now,
            complete: false,
        };

        let result = self.rules.evaluate(ceremony, &mut session.bag, &render);
        self.finalize(session, result)
    }

    fn continue_existing(
        &self,
        session_id: Uuid,
        request: CeremonyRequest,
    ) -> Result<CeremonyResponse, CeremonyError> {
        let mut sessions = self.sessions.lock().expect("session lock poisoned");

        let session = sessions
            .get_mut(&session_id)
            .ok_or(CeremonyError::SessionNotFound(session_id))?;

        // Check expiry
        let now = Instant::now();
        if now.duration_since(session.last_active) >= self.session_ttl {
            sessions.remove(&session_id);
            return Err(CeremonyError::SessionExpired);
        }

        if session.complete {
            return Err(CeremonyError::AlreadyComplete);
        }

        // Update activity + render hints
        session.last_active = now;
        if let Some(render) = &request.render {
            session.render = render.clone();
        }

        // Merge new data into the bag
        for (key, value) in request.data {
            session.bag.insert(key, value);
        }

        let render = session.render.clone();
        let ceremony_type = session.ceremony_type.clone();
        let result = self.rules.evaluate(&ceremony_type, &mut session.bag, &render);

        // Extract session to finalize outside the lock
        let session = sessions.remove(&session_id).expect("just accessed");
        drop(sessions);

        self.finalize(session, result)
    }

    /// Convert an `EvalResult` into a `CeremonyResponse` and (re-)store
    /// the session if it isn't complete.
    fn finalize(
        &self,
        mut session: Session,
        result: EvalResult,
    ) -> Result<CeremonyResponse, CeremonyError> {
        let session_id = session.id;

        let (prompts, messages, complete, error) = match result {
            EvalResult::NeedInput { prompts, messages } => {
                (prompts, messages, false, None)
            }
            EvalResult::ValidationError {
                prompts,
                messages,
                error,
            } => (prompts, messages, false, Some(error)),
            EvalResult::Complete { messages } => {
                (Vec::new(), messages, true, None)
            }
            EvalResult::Fatal(msg) => {
                let messages = vec![Message {
                    kind: MessageKind::Error,
                    title: "Ceremony failed".into(),
                    content: msg.clone(),
                }];
                (Vec::new(), messages, true, Some(msg))
            }
        };

        session.complete = complete;

        // Only store if not complete
        if !complete {
            let mut sessions = self.sessions.lock().expect("session lock poisoned");
            sessions.insert(session_id, session);
        }

        Ok(CeremonyResponse {
            session_id,
            prompts,
            messages,
            complete,
            error,
        })
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Ceremony framework errors.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("session not found: {0}")]
    SessionNotFound(Uuid),

    #[error("session expired")]
    SessionExpired,

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid ceremony type: {0}")]
    InvalidCeremony(String),

    #[error("ceremony already complete")]
    AlreadyComplete,

    #[error("internal error: {0}")]
    Internal(String),
}

impl CeremonyError {
    /// Map to an HTTP status code.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::SessionNotFound(_) => 404,
            Self::SessionExpired => 410,
            Self::MissingField(_) => 400,
            Self::InvalidCeremony(_) => 400,
            Self::AlreadyComplete => 409,
            Self::Internal(_) => 500,
        }
    }
}

// ── Builder helpers ─────────────────────────────────────────────────

impl Prompt {
    /// Create a `SelectOne` prompt.
    pub fn select_one(
        key: impl Into<String>,
        prompt: impl Into<String>,
        options: Vec<SelectOption>,
    ) -> Self {
        Self {
            key: key.into(),
            prompt: prompt.into(),
            input_type: InputType::SelectOne,
            options,
            required: true,
        }
    }

    /// Create a `Secret` prompt (masked input).
    pub fn secret(key: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            prompt: prompt.into(),
            input_type: InputType::Secret,
            options: Vec::new(),
            required: true,
        }
    }

    /// Create a `SecretConfirm` prompt (passphrase + confirmation).
    pub fn secret_confirm(
        key: impl Into<String>,
        prompt: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            prompt: prompt.into(),
            input_type: InputType::SecretConfirm,
            options: Vec::new(),
            required: true,
        }
    }

    /// Create a `Code` prompt (short verification code).
    pub fn code(key: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            prompt: prompt.into(),
            input_type: InputType::Code,
            options: Vec::new(),
            required: true,
        }
    }

    /// Create a `Text` prompt (free text).
    pub fn text(key: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            prompt: prompt.into(),
            input_type: InputType::Text,
            options: Vec::new(),
            required: true,
        }
    }

    /// Create an `Entropy` prompt.
    pub fn entropy(key: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            prompt: prompt.into(),
            input_type: InputType::Entropy,
            options: Vec::new(),
            required: true,
        }
    }
}

impl SelectOption {
    /// Create a select option.
    pub fn new(
        value: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            description: None,
        }
    }

    /// Create a select option with a description.
    pub fn with_description(
        value: impl Into<String>,
        label: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            description: Some(description.into()),
        }
    }
}

impl Message {
    /// Create an `Info` message.
    pub fn info(title: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            kind: MessageKind::Info,
            title: title.into(),
            content: content.into(),
        }
    }

    /// Create a `QrCode` message.
    pub fn qr_code(
        title: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            kind: MessageKind::QrCode,
            title: title.into(),
            content: content.into(),
        }
    }

    /// Create a `Summary` message.
    pub fn summary(
        title: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            kind: MessageKind::Summary,
            title: title.into(),
            content: content.into(),
        }
    }

    /// Create an `Error` message.
    pub fn error(title: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            kind: MessageKind::Error,
            title: title.into(),
            content: content.into(),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test rules ──────────────────────────────────────────────────
    //
    // A simple "greeting" ceremony:
    //   - Needs "name" key in the bag
    //   - Validates name is non-empty
    //   - Returns Complete with a summary message when name is present

    struct GreetRules;

    impl CeremonyRules for GreetRules {
        fn validate_ceremony_type(&self, ceremony: &str) -> Result<(), String> {
            match ceremony {
                "greet" => Ok(()),
                other => Err(format!("unknown ceremony: {other}")),
            }
        }

        fn evaluate(
            &self,
            _ceremony_type: &str,
            bag: &mut serde_json::Map<String, serde_json::Value>,
            _render: &RenderHints,
        ) -> EvalResult {
            // Check if name is in the bag
            match bag.get("name").and_then(|v| v.as_str()) {
                None => {
                    // No name yet — ask for it
                    EvalResult::NeedInput {
                        prompts: vec![Prompt::text("name", "What is your name?")],
                        messages: vec![Message::info(
                            "Welcome",
                            "Please introduce yourself.",
                        )],
                    }
                }
                Some(name) if name.is_empty() => {
                    // Empty name — validation error
                    bag.remove("name");
                    EvalResult::ValidationError {
                        prompts: vec![Prompt::text("name", "What is your name?")],
                        messages: Vec::new(),
                        error: "Name cannot be empty".into(),
                    }
                }
                Some(name) => {
                    // Name present and valid — done
                    let summary = format!("Hello, {name}!");
                    EvalResult::Complete {
                        messages: vec![Message::summary("Greeting complete", &summary)],
                    }
                }
            }
        }
    }

    fn make_host() -> CeremonyHost<GreetRules> {
        CeremonyHost::new(GreetRules)
    }

    // ── Tests ───────────────────────────────────────────────────────

    #[test]
    fn start_new_ceremony_returns_prompts() {
        let host = make_host();
        let resp = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("greet".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();

        assert!(!resp.complete);
        assert_eq!(resp.prompts.len(), 1);
        assert_eq!(resp.prompts[0].key, "name");
        assert_eq!(resp.prompts[0].input_type, InputType::Text);
        assert_eq!(resp.messages.len(), 1);
        assert_eq!(resp.messages[0].kind, MessageKind::Info);
        assert_eq!(host.active_session_count(), 1);
    }

    #[test]
    fn complete_ceremony_with_data() {
        let host = make_host();

        // Start
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("greet".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();
        assert!(!r1.complete);

        // Submit name
        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("Alice"));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();
        assert!(r2.complete);
        assert!(r2.prompts.is_empty());
        assert_eq!(r2.messages.len(), 1);
        assert_eq!(r2.messages[0].kind, MessageKind::Summary);
        assert!(r2.messages[0].content.contains("Alice"));

        // Session cleaned up
        assert_eq!(host.active_session_count(), 0);
    }

    #[test]
    fn prefill_completes_in_one_step() {
        let host = make_host();

        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("Bob"));

        let resp = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("greet".into()),
                data,
                render: None,
            })
            .unwrap();

        assert!(resp.complete);
        assert!(resp.prompts.is_empty());
        assert!(resp.messages[0].content.contains("Bob"));
        assert_eq!(host.active_session_count(), 0);
    }

    #[test]
    fn validation_error_re_prompts() {
        let host = make_host();

        // Start
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("greet".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();

        // Submit empty name
        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!(""));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();

        assert!(!r2.complete);
        assert_eq!(r2.error.as_deref(), Some("Name cannot be empty"));
        assert_eq!(r2.prompts.len(), 1);
        assert_eq!(r2.prompts[0].key, "name");
        assert_eq!(host.active_session_count(), 1);

        // Retry with valid name
        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("Charlie"));
        let r3 = host
            .step(CeremonyRequest {
                session_id: Some(r2.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();
        assert!(r3.complete);
        assert!(r3.messages[0].content.contains("Charlie"));
    }

    #[test]
    fn invalid_ceremony_type() {
        let host = make_host();
        let err = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("bogus".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap_err();

        assert!(matches!(err, CeremonyError::InvalidCeremony(_)));
        assert_eq!(err.http_status(), 400);
    }

    #[test]
    fn missing_ceremony_field() {
        let host = make_host();
        let err = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: None,
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap_err();

        assert!(matches!(err, CeremonyError::MissingField(_)));
    }

    #[test]
    fn unknown_session_returns_not_found() {
        let host = make_host();
        let err = host
            .step(CeremonyRequest {
                session_id: Some(Uuid::now_v7()),
                ceremony: None,
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap_err();

        assert!(matches!(err, CeremonyError::SessionNotFound(_)));
        assert_eq!(err.http_status(), 404);
    }

    #[test]
    fn sweep_removes_expired() {
        let host = CeremonyHost::with_ttl(GreetRules, Duration::from_millis(1));

        let _ = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("greet".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();

        assert_eq!(host.active_session_count(), 1);

        // Wait for TTL
        std::thread::sleep(Duration::from_millis(10));

        let removed = host.sweep_expired();
        assert_eq!(removed, 1);
        assert_eq!(host.active_session_count(), 0);
    }

    #[test]
    fn render_hints_propagate() {
        let host = make_host();
        let resp = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("greet".into()),
                data: serde_json::Map::new(),
                render: Some(RenderHints {
                    qr: Some(QrFormat::PngBase64),
                }),
            })
            .unwrap();

        let sessions = host.sessions.lock().unwrap();
        let session = sessions.get(&resp.session_id).unwrap();
        assert_eq!(session.render.qr, Some(QrFormat::PngBase64));
    }

    #[test]
    fn qr_format_serde_round_trip() {
        let hints = RenderHints {
            qr: Some(QrFormat::PngBase64),
        };
        let json = serde_json::to_string(&hints).unwrap();
        assert!(json.contains("png_base64"));
        let parsed: RenderHints = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.qr, Some(QrFormat::PngBase64));
    }

    #[test]
    fn prompt_and_message_serde() {
        let prompt = Prompt::select_one(
            "color",
            "Pick a color",
            vec![
                SelectOption::new("red", "Red"),
                SelectOption::with_description("blue", "Blue", "The color of the sky"),
            ],
        );
        let json = serde_json::to_value(&prompt).unwrap();
        assert_eq!(json["key"], "color");
        assert_eq!(json["input_type"], "select_one");
        assert_eq!(json["options"].as_array().unwrap().len(), 2);

        let msg = Message::qr_code("Scan me", "data:image/png;base64,abc123");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["kind"], "qr_code");
    }

    #[test]
    fn complete_response_serde() {
        let resp = CeremonyResponse {
            session_id: Uuid::now_v7(),
            prompts: vec![Prompt::text("foo", "Enter foo")],
            messages: vec![Message::info("Note", "Something")],
            complete: false,
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["complete"], false);
        assert!(parsed["prompts"].is_array());
        assert!(parsed["messages"].is_array());
        // error should be absent (skip_serializing_if)
        assert!(parsed.get("error").is_none());
    }

    // ── Multi-prompt / multi-message test ───────────────────────────

    /// Rules that ask for two things at once and return a message + prompt together.
    struct MultiRules;

    impl CeremonyRules for MultiRules {
        fn validate_ceremony_type(&self, ceremony: &str) -> Result<(), String> {
            match ceremony {
                "multi" => Ok(()),
                other => Err(format!("unknown: {other}")),
            }
        }

        fn evaluate(
            &self,
            _ceremony_type: &str,
            bag: &mut serde_json::Map<String, serde_json::Value>,
            _render: &RenderHints,
        ) -> EvalResult {
            let has_color = bag.get("color").and_then(|v| v.as_str()).is_some();
            let has_size = bag.get("size").and_then(|v| v.as_str()).is_some();
            let has_confirm = bag.get("confirm").and_then(|v| v.as_str()).is_some();

            if !has_color || !has_size {
                // Ask for both at once
                let mut prompts = Vec::new();
                if !has_color {
                    prompts.push(Prompt::select_one(
                        "color",
                        "Pick a color",
                        vec![
                            SelectOption::new("red", "Red"),
                            SelectOption::new("blue", "Blue"),
                        ],
                    ));
                }
                if !has_size {
                    prompts.push(Prompt::select_one(
                        "size",
                        "Pick a size",
                        vec![
                            SelectOption::new("s", "Small"),
                            SelectOption::new("l", "Large"),
                        ],
                    ));
                }
                return EvalResult::NeedInput {
                    prompts,
                    messages: vec![Message::info("Setup", "Choose your preferences.")],
                };
            }

            if !has_confirm {
                // Show summary message + ask for confirmation
                let summary = format!(
                    "Color: {}, Size: {}",
                    bag["color"].as_str().unwrap(),
                    bag["size"].as_str().unwrap()
                );
                return EvalResult::NeedInput {
                    prompts: vec![Prompt::text("confirm", "Type 'yes' to confirm")],
                    messages: vec![Message::summary("Review", &summary)],
                };
            }

            EvalResult::Complete {
                messages: vec![Message::summary("Done", "Order placed.")],
            }
        }
    }

    #[test]
    fn multi_prompt_returns_multiple_fields() {
        let host = CeremonyHost::new(MultiRules);

        // Start with empty bag — should get 2 prompts
        let r1 = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("multi".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();
        assert!(!r1.complete);
        assert_eq!(r1.prompts.len(), 2);
        assert_eq!(r1.prompts[0].key, "color");
        assert_eq!(r1.prompts[1].key, "size");
        assert_eq!(r1.messages.len(), 1);

        // Submit both answers
        let mut data = serde_json::Map::new();
        data.insert("color".into(), serde_json::json!("red"));
        data.insert("size".into(), serde_json::json!("l"));
        let r2 = host
            .step(CeremonyRequest {
                session_id: Some(r1.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();
        assert!(!r2.complete);
        assert_eq!(r2.prompts.len(), 1);
        assert_eq!(r2.prompts[0].key, "confirm");
        // Summary message alongside prompt
        assert_eq!(r2.messages.len(), 1);
        assert_eq!(r2.messages[0].kind, MessageKind::Summary);

        // Confirm
        let mut data = serde_json::Map::new();
        data.insert("confirm".into(), serde_json::json!("yes"));
        let r3 = host
            .step(CeremonyRequest {
                session_id: Some(r2.session_id),
                ceremony: None,
                data,
                render: None,
            })
            .unwrap();
        assert!(r3.complete);
    }

    #[test]
    fn partial_prefill_asks_only_for_missing() {
        let host = CeremonyHost::new(MultiRules);

        // Start with color already known
        let mut data = serde_json::Map::new();
        data.insert("color".into(), serde_json::json!("blue"));

        let resp = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("multi".into()),
                data,
                render: None,
            })
            .unwrap();

        assert!(!resp.complete);
        // Only size should be prompted
        assert_eq!(resp.prompts.len(), 1);
        assert_eq!(resp.prompts[0].key, "size");
    }

    #[test]
    fn fatal_error_completes_with_error() {
        struct FatalRules;

        impl CeremonyRules for FatalRules {
            fn validate_ceremony_type(&self, _: &str) -> Result<(), String> {
                Ok(())
            }
            fn evaluate(
                &self,
                _: &str,
                _: &mut serde_json::Map<String, serde_json::Value>,
                _: &RenderHints,
            ) -> EvalResult {
                EvalResult::Fatal("disk full".into())
            }
        }

        let host = CeremonyHost::new(FatalRules);
        let resp = host
            .step(CeremonyRequest {
                session_id: None,
                ceremony: Some("boom".into()),
                data: serde_json::Map::new(),
                render: None,
            })
            .unwrap();

        assert!(resp.complete);
        assert_eq!(resp.error.as_deref(), Some("disk full"));
        assert_eq!(resp.messages.len(), 1);
        assert_eq!(resp.messages[0].kind, MessageKind::Error);
        assert_eq!(host.active_session_count(), 0);
    }
}
