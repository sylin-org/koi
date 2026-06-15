//! KoiClient construction and the blocking-call bridge.
//!
//! `KoiClient` (koi-client) is blocking `ureq`. Every call from an async MCP tool
//! handler must therefore run on a blocking thread via [`call`]. The client itself
//! is shared behind an `Arc` and is cheap to clone for each `spawn_blocking`.

use std::sync::Arc;

use koi_client::{ClientError, KoiClient};

/// Build a [`KoiClient`] for the running daemon.
///
/// Resolution order:
/// 1. The breadcrumb file the daemon writes on startup (endpoint + token).
/// 2. The `KOI_ENDPOINT` env var, paired with `KOI_TOKEN` if present.
///
/// Returns `None` only when neither a breadcrumb nor `KOI_ENDPOINT` is available.
/// A returned client does **not** imply a reachable daemon — probe with
/// [`KoiClient::health`] (the tools do this and surface an actionable error).
pub fn build_client() -> Option<KoiClient> {
    if let Some(client) = KoiClient::from_breadcrumb() {
        return Some(client);
    }
    let endpoint = std::env::var("KOI_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())?;
    match std::env::var("KOI_TOKEN").ok().filter(|s| !s.is_empty()) {
        Some(token) => Some(KoiClient::with_token(&endpoint, &token)),
        None => Some(KoiClient::new(&endpoint)),
    }
}

/// The actionable message returned to an agent when no daemon can be reached.
/// NEVER include a token here (or anywhere in tool output).
pub const NO_DAEMON_MSG: &str = "no Koi daemon reachable — start one with `koi --daemon` \
     (or set KOI_ENDPOINT/KOI_TOKEN)";

/// Run a blocking `KoiClient` call on a blocking thread.
///
/// `f` receives a `&KoiClient` and returns the client's own `Result`. The closure
/// runs via [`tokio::task::spawn_blocking`] so the async runtime is never blocked
/// on `ureq` I/O. A panic or join failure is mapped to a transport-style error.
pub async fn call<T, F>(client: &Arc<KoiClient>, f: F) -> Result<T, ClientError>
where
    T: Send + 'static,
    F: FnOnce(&KoiClient) -> Result<T, ClientError> + Send + 'static,
{
    let client = Arc::clone(client);
    match tokio::task::spawn_blocking(move || f(&client)).await {
        Ok(result) => result,
        Err(join_err) => Err(ClientError::Transport(format!(
            "blocking task failed: {join_err}"
        ))),
    }
}
