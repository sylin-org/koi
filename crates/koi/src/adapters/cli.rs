use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncBufReadExt;

use koi_mdns::MdnsCore;

use super::dispatch;

/// CLI session grace period: 5 seconds (short-lived sessions).
const SESSION_GRACE: Duration = Duration::from_secs(5);

/// Run the CLI adapter: read NDJSON from stdin, write responses to stdout.
pub async fn start(core: Arc<MdnsCore>) -> anyhow::Result<()> {
    let session_id = dispatch::new_session_id();
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        dispatch::handle_line(&core, &session_id, &line, SESSION_GRACE, &mut stdout).await?;
    }

    core.session_disconnected(&session_id);
    Ok(())
}
