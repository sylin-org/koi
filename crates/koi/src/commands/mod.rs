//! CLI command handlers, organized by domain.
//!
//! - `mdns` - mDNS commands (discover, announce, unregister, resolve, subscribe).
//! - `certmesh` - Certificate mesh commands (create, join, status, log, unlock, set-hook).
//! - `dns` - DNS commands (serve, lookup, add/remove/list).
//! - `health` - Health commands (status, watch, add/remove, log).
//! - `proxy` - Proxy commands (add/remove/list/status).
//!
//! Shared infrastructure (mode detection, payload builders, formatting) lives here.

pub mod ceremony_cli;
pub mod certmesh;
pub mod dns;
pub mod factory_reset;
pub mod health;
pub mod mcp;
pub mod mdns;
pub mod pond;
pub mod proxy;
pub mod status;
pub mod token;
pub mod trust;
pub mod udp;

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use crate::cli::Cli;
use crate::client::KoiClient;

/// Default timeout for browse/subscribe commands (seconds).
pub(crate) const DEFAULT_TIMEOUT: u64 = 5;

// ── Mode detection ───────────────────────────────────────────────────

/// Execution mode for commands that support both an explicitly requested local
/// composition and the authoritative daemon boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Operate directly in this process. This is never selected implicitly and
    /// is refused while a local daemon is reachable, preserving one native
    /// resource owner per machine.
    Standalone,
    /// Talk to a running daemon via HTTP.
    Client {
        endpoint: String,
        /// Daemon Access Token from breadcrumb (empty if not available).
        token: String,
    },
}

/// The explicit access token, if any: the `--token` flag (which also reads
/// `KOI_TOKEN` via clap's `env`, flag winning). Returned only when non-empty so
/// an empty `KOI_TOKEN=""` does not masquerade as a real token.
pub(crate) fn cli_token(cli: &Cli) -> Option<&str> {
    cli.token.as_deref().filter(|t| !t.is_empty())
}

/// The uniform token-selection rule, factored out so it is unit-testable
/// without a live daemon or breadcrumb.
///
/// - **Explicit endpoint** present → use the `--token`/`KOI_TOKEN` value if set,
///   otherwise **tokenless** (empty). NEVER the breadcrumb token: pairing the
///   local daemon's token with a remote URL would leak it to that host.
/// - **No explicit endpoint** → caller uses authenticated local discovery
///   (private breadcrumb or local control), which returns one matching endpoint/token pair.
pub(crate) fn token_for_explicit_endpoint(explicit_token: Option<&str>) -> String {
    explicit_token.unwrap_or("").to_string()
}

/// Select a command's one execution owner.
///
/// A missing or unreachable daemon is an observable error, never permission to
/// open the same durable state and native resources in a second process. The
/// caller may explicitly request standalone operation, but even that is refused
/// while the authenticated local daemon is alive.
pub(crate) fn detect_mode(cli: &Cli) -> anyhow::Result<Mode> {
    let local = if cli.endpoint.is_some() && !cli.standalone {
        // The operator named this owner explicitly; local ownership is
        // irrelevant and its credentials must never be consulted.
        koi_client::LocalDaemonObservation::Absent
    } else {
        local_daemon_mode()
    };
    select_mode(
        cli.standalone,
        cli.endpoint.as_deref(),
        cli_token(cli),
        local,
    )
}

fn local_daemon_mode() -> koi_client::LocalDaemonObservation<Mode> {
    match koi_client::observe_local_daemon_access() {
        koi_client::LocalDaemonObservation::Present(access) => {
            match KoiClient::new(&access.endpoint).health() {
                Ok(()) => koi_client::LocalDaemonObservation::Present(Mode::Client {
                    endpoint: access.endpoint,
                    token: access.token,
                }),
                Err(error) => koi_client::LocalDaemonObservation::Uncertain(error),
            }
        }
        koi_client::LocalDaemonObservation::Absent => koi_client::LocalDaemonObservation::Absent,
        koi_client::LocalDaemonObservation::Uncertain(error) => {
            koi_client::LocalDaemonObservation::Uncertain(error)
        }
    }
}

fn select_mode(
    standalone: bool,
    explicit_endpoint: Option<&str>,
    explicit_token: Option<&str>,
    local: koi_client::LocalDaemonObservation<Mode>,
) -> anyhow::Result<Mode> {
    if standalone {
        if explicit_endpoint.is_some() {
            anyhow::bail!("--standalone and --endpoint select different owners; use exactly one");
        }
        match local {
            koi_client::LocalDaemonObservation::Present(_) => {
                anyhow::bail!(
                    "Standalone mode refuses to run beside the active local Koi service. Use the service, or stop it before retrying with --standalone."
                );
            }
            koi_client::LocalDaemonObservation::Uncertain(error) => {
                anyhow::bail!(
                    "Standalone mode cannot prove that the local Koi service is absent: {error}. Resolve local service discovery before retrying."
                );
            }
            koi_client::LocalDaemonObservation::Absent => {}
        }
        return Ok(Mode::Standalone);
    }

    if let Some(endpoint) = explicit_endpoint {
        // Explicit endpoint: use the explicit --token/KOI_TOKEN if set, else
        // tokenless. Never the breadcrumb token (would leak to a remote host).
        return Ok(Mode::Client {
            endpoint: endpoint.to_string(),
            token: token_for_explicit_endpoint(explicit_token),
        });
    }

    match local {
        koi_client::LocalDaemonObservation::Present(mode) => Ok(mode),
        koi_client::LocalDaemonObservation::Absent => Err(anyhow::anyhow!(
            "No running Koi service found. Start the installed service or pass --endpoint. Use --standalone only for an intentional local session."
        )),
        koi_client::LocalDaemonObservation::Uncertain(error) => Err(anyhow::anyhow!(
            "The local Koi service owner could not be verified: {error}. Refusing to guess between daemon and standalone ownership."
        )),
    }
}

/// Build a [`KoiClient`] for a command that always needs a running daemon (mDNS admin and
/// every certmesh command), folding the token-leak rule and local health-probe
/// into one place.
///
/// - **Explicit `endpoint`** → use the explicit `--token`/`KOI_TOKEN` value if set, else
///   **tokenless** (never the local breadcrumb token — pairing it with a remote URL would
///   leak the local daemon's token to that host). No health-probe: the operator named the
///   target deliberately.
/// - **No explicit endpoint** → use authenticated local discovery only after a
///   health-probe confirms a daemon is answering; otherwise bail with an actionable
///   message. The probe matches [`detect_mode`] so stale discovery material never routes
///   a command at a dead endpoint.
pub(crate) fn require_client(
    endpoint: Option<&str>,
    explicit_token: Option<&str>,
) -> anyhow::Result<KoiClient> {
    if let Some(ep) = endpoint {
        let token = token_for_explicit_endpoint(explicit_token);
        return Ok(KoiClient::with_token(ep, &token));
    }
    match koi_client::observe_local_daemon_access() {
        koi_client::LocalDaemonObservation::Present(access) => {
            let client = KoiClient::with_token(&access.endpoint, &access.token);
            client.health().map_err(|error| {
                anyhow::anyhow!(
                    "The local Koi owner is published at {}, but its health boundary is unavailable: {error}",
                    access.endpoint
                )
            })?;
            Ok(client)
        }
        koi_client::LocalDaemonObservation::Absent => anyhow::bail!(
            "No running Koi service found.\n\
             Install and start the service first: koi install (or pass --endpoint)."
        ),
        koi_client::LocalDaemonObservation::Uncertain(error) => anyhow::bail!(
            "The local Koi service owner could not be verified: {error}. Resolve local service discovery or pass an explicit --endpoint."
        ),
    }
}

pub(crate) async fn with_mode<T, LFut, CFut, L, C>(
    mode: Mode,
    local: L,
    client_fn: C,
) -> anyhow::Result<T>
where
    L: FnOnce() -> LFut,
    C: FnOnce(KoiClient) -> CFut,
    LFut: Future<Output = anyhow::Result<T>>,
    CFut: Future<Output = anyhow::Result<T>>,
{
    match mode {
        Mode::Standalone => local().await,
        Mode::Client { endpoint, token } => {
            let client = KoiClient::with_token(&endpoint, &token);
            client_fn(client).await
        }
    }
}

pub(crate) fn with_mode_sync<T, L, C>(mode: Mode, local: L, client_fn: C) -> anyhow::Result<T>
where
    L: FnOnce() -> anyhow::Result<T>,
    C: FnOnce(KoiClient) -> anyhow::Result<T>,
{
    match mode {
        Mode::Standalone => local(),
        Mode::Client { endpoint, token } => {
            let client = KoiClient::with_token(&endpoint, &token);
            client_fn(client)
        }
    }
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Parse `KEY=VALUE` entries into a HashMap.
pub(crate) fn parse_txt(entries: &[String]) -> HashMap<String, String> {
    entries
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Resolve the effective timeout duration.
///
/// - `Some(0)` → infinite (run forever)
/// - `Some(n)` → n seconds
/// - `None` → fall back to the provided default (`None` default = infinite)
pub(crate) fn effective_timeout(
    explicit: Option<u64>,
    default_secs: Option<u64>,
) -> Option<Duration> {
    match explicit {
        Some(0) => None,
        Some(secs) => Some(Duration::from_secs(secs)),
        None => default_secs.map(Duration::from_secs),
    }
}

/// Serialize and print a boundary value without turning an encoding failure
/// into a successful command exit.
pub(crate) fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

/// Decode an exact daemon boundary value instead of manufacturing presentation
/// defaults when a peer violates the advertised contract.
pub(crate) fn decode_response<T>(value: serde_json::Value, surface: &str) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(value)
        .map_err(|error| anyhow::anyhow!("invalid {surface} response: {error}"))
}

/// Decode one required response field while retaining a dependency-light HTTP
/// client. Domain-native snapshot types should use [`decode_response`]; this
/// helper is for the small adapter-only acknowledgement envelopes.
pub(crate) fn decode_field<T>(
    value: &serde_json::Value,
    field: &str,
    surface: &str,
) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let field_value = value
        .get(field)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("invalid {surface} response: missing `{field}`"))?;
    serde_json::from_value(field_value)
        .map_err(|error| anyhow::anyhow!("invalid {surface} response field `{field}`: {error}"))
}

pub(crate) fn require_ok_response(value: &serde_json::Value, surface: &str) -> anyhow::Result<()> {
    let status: String = decode_field(value, "status", surface)?;
    if status == "ok" {
        Ok(())
    } else {
        anyhow::bail!("invalid {surface} response: expected status `ok`, received `{status}`")
    }
}

/// Build a `RegisterPayload` from CLI arguments.
pub(crate) fn build_register_payload(
    name: &str,
    service_type: &str,
    port: u16,
    ip: Option<&str>,
    txt: &[String],
) -> koi_mdns::protocol::RegisterPayload {
    koi_mdns::protocol::RegisterPayload {
        name: name.to_string(),
        service_type: service_type.to_string(),
        port,
        ip: ip.map(String::from),
        lease_secs: None,
        txt: parse_txt(txt),
    }
}

/// Print the human-readable registration success message.
pub(crate) fn print_register_success(result: &koi_mdns::protocol::RegistrationResult) {
    println!(
        "Registered \"{}\" ({}) on port {} [id: {}]",
        result.name, result.service_type, result.port, result.id
    );
    eprintln!("Service is being advertised. Press Ctrl+C to unregister and exit.");
}

/// Wait for Ctrl+C or an optional timeout, whichever comes first.
pub(crate) async fn wait_for_signal_or_timeout(timeout: Option<Duration>) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match timeout {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }
}

/// Run a streaming operation with Ctrl+C and optional timeout cancellation.
///
/// Extracts the `tokio::select! { stream, ctrl_c, timeout }` skeleton
/// that is shared across discover, subscribe, and similar streaming commands.
pub(crate) async fn run_streaming<F, Fut>(
    timeout: Option<u64>,
    default_timeout: Option<u64>,
    stream_fn: F,
) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let dur = effective_timeout(timeout, default_timeout);
    tokio::select! {
        result = stream_fn() => { result?; }
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match dur {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_txt tests ──────────────────────────────────────────────

    #[test]
    fn parse_txt_basic_key_value() {
        let entries = vec!["version=1.0".to_string(), "env=prod".to_string()];
        let txt = parse_txt(&entries);
        assert_eq!(txt.get("version").unwrap(), "1.0");
        assert_eq!(txt.get("env").unwrap(), "prod");
        assert_eq!(txt.len(), 2);
    }

    #[test]
    fn parse_txt_empty_input() {
        let entries: Vec<String> = vec![];
        let txt = parse_txt(&entries);
        assert!(txt.is_empty());
    }

    #[test]
    fn parse_txt_skips_entries_without_equals() {
        let entries = vec!["noequals".to_string(), "valid=yes".to_string()];
        let txt = parse_txt(&entries);
        assert_eq!(txt.len(), 1);
        assert_eq!(txt.get("valid").unwrap(), "yes");
    }

    #[test]
    fn parse_txt_value_with_equals() {
        // Only splits on first '='
        let entries = vec!["path=/api/v1=test".to_string()];
        let txt = parse_txt(&entries);
        assert_eq!(txt.get("path").unwrap(), "/api/v1=test");
    }

    #[test]
    fn parse_txt_empty_value() {
        let entries = vec!["key=".to_string()];
        let txt = parse_txt(&entries);
        assert_eq!(txt.get("key").unwrap(), "");
    }

    // ── effective_timeout tests ──────────────────────────────────────

    #[test]
    fn effective_timeout_explicit_zero_means_infinite() {
        assert_eq!(effective_timeout(Some(0), Some(5)), None);
    }

    #[test]
    fn effective_timeout_explicit_value_overrides_default() {
        assert_eq!(
            effective_timeout(Some(15), Some(5)),
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn effective_timeout_none_uses_default() {
        assert_eq!(
            effective_timeout(None, Some(5)),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn effective_timeout_none_with_no_default_means_infinite() {
        assert_eq!(effective_timeout(None, None), None);
    }

    #[test]
    fn effective_timeout_explicit_zero_overrides_any_default() {
        assert_eq!(effective_timeout(Some(0), Some(999)), None);
        assert_eq!(effective_timeout(Some(0), None), None);
    }

    // ── build_register_payload tests ─────────────────────────────────

    #[test]
    fn build_register_payload_basic() {
        let payload = build_register_payload("My App", "_http._tcp", 8080, None, &[]);
        assert_eq!(payload.name, "My App");
        assert_eq!(payload.service_type, "_http._tcp");
        assert_eq!(payload.port, 8080);
        assert!(payload.ip.is_none());
        assert!(payload.lease_secs.is_none());
        assert!(payload.txt.is_empty());
    }

    #[test]
    fn build_register_payload_with_ip_and_txt() {
        let txt = vec!["version=2.1".to_string(), "env=staging".to_string()];
        let payload =
            build_register_payload("My App", "_http._tcp", 9090, Some("192.168.1.42"), &txt);
        assert_eq!(payload.ip.as_deref(), Some("192.168.1.42"));
        assert_eq!(payload.txt.get("version").unwrap(), "2.1");
        assert_eq!(payload.txt.get("env").unwrap(), "staging");
    }

    #[test]
    fn build_register_payload_always_has_no_lease() {
        let payload = build_register_payload("X", "_tcp", 80, None, &[]);
        assert!(payload.lease_secs.is_none());
    }

    #[test]
    fn response_decoding_rejects_missing_or_wrong_typed_fields() {
        let missing =
            decode_field::<bool>(&serde_json::json!({}), "started", "DNS start").unwrap_err();
        assert!(missing.to_string().contains("missing `started`"));

        let wrong =
            decode_field::<u64>(&serde_json::json!({ "sent": "eight" }), "sent", "UDP send")
                .unwrap_err();
        assert!(wrong.to_string().contains("response field `sent`"));
    }

    #[test]
    fn json_presentation_failure_is_a_command_failure() {
        struct RefusesSerialization;

        impl serde::Serialize for RefusesSerialization {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("intentional encoding failure"))
            }
        }

        let error = print_json(&RefusesSerialization).unwrap_err();
        assert!(error.to_string().contains("intentional encoding failure"));
    }

    // ── token-selection tests ────────────────────────────────────────
    //
    // The security-critical rule: an explicit --endpoint must NEVER be paired
    // with the local breadcrumb token. token_for_explicit_endpoint encodes that
    // rule and is unit-testable without a live daemon or breadcrumb.

    #[test]
    fn explicit_endpoint_without_token_is_tokenless() {
        // No --token/KOI_TOKEN → empty string (tokenless), never the breadcrumb.
        assert_eq!(token_for_explicit_endpoint(None), "");
    }

    #[test]
    fn explicit_endpoint_uses_provided_token() {
        assert_eq!(
            token_for_explicit_endpoint(Some("remote-secret")),
            "remote-secret"
        );
    }

    #[test]
    fn automatic_mode_never_falls_back_to_a_second_local_owner() {
        let error = select_mode(
            false,
            None,
            None,
            koi_client::LocalDaemonObservation::Absent,
        )
        .unwrap_err();
        assert!(error.to_string().contains("No running Koi service"));
    }

    #[test]
    fn explicit_standalone_is_refused_beside_a_live_local_daemon() {
        let local = Mode::Client {
            endpoint: "http://127.0.0.1:5641".to_string(),
            token: "local".to_string(),
        };
        let error = select_mode(
            true,
            None,
            None,
            koi_client::LocalDaemonObservation::Present(local),
        )
        .unwrap_err();
        assert!(error.to_string().contains("refuses to run beside"));
    }

    #[test]
    fn explicit_standalone_is_available_when_it_is_the_only_owner() {
        assert_eq!(
            select_mode(true, None, None, koi_client::LocalDaemonObservation::Absent,).unwrap(),
            Mode::Standalone
        );
    }

    #[test]
    fn standalone_refuses_when_local_ownership_is_uncertain() {
        let error = select_mode(
            true,
            None,
            None,
            koi_client::LocalDaemonObservation::Uncertain(koi_client::ClientError::Decode(
                "malformed breadcrumb".to_string(),
            )),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cannot prove"));
        assert!(error.to_string().contains("malformed breadcrumb"));
    }

    #[test]
    fn explicit_endpoint_never_uses_local_daemon_credentials() {
        let local = Mode::Client {
            endpoint: "http://127.0.0.1:5641".to_string(),
            token: "local-secret".to_string(),
        };
        assert_eq!(
            select_mode(
                false,
                Some("https://remote.example:5642"),
                Some("remote-secret"),
                koi_client::LocalDaemonObservation::Present(local),
            )
            .unwrap(),
            Mode::Client {
                endpoint: "https://remote.example:5642".to_string(),
                token: "remote-secret".to_string(),
            }
        );
    }

    #[test]
    fn standalone_and_endpoint_are_mutually_exclusive() {
        let error = select_mode(
            true,
            Some("http://localhost:5641"),
            None,
            koi_client::LocalDaemonObservation::Absent,
        )
        .unwrap_err();
        assert!(error.to_string().contains("use exactly one"));
    }
}
