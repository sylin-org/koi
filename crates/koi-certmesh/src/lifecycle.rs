//! Reload-hook execution after a certificate renewal.
//!
//! ADR-017 P3/F6: renewal is **member-initiated pull** — the member generates a
//! fresh keypair + CSR and the CA signs it ([`crate::CertmeshCore::renew_self_if_due`]).
//! The CA no longer regenerates or ships member keys, so the old CA-push renewal
//! functions are gone. What remains here is the post-renewal reload hook the
//! member runs locally after installing its new cert.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::blocking_worker::CertmeshBlockingPermit;
use crate::protocol::HookResult;
use crate::repository::ArtifactTransaction;
use crate::{CertmeshDomain, CertmeshError, CertmeshEvent, CertmeshPaths};

/// How often the renewal loop checks whether the local cert is due for renewal.
pub const RENEWAL_CHECK_INTERVAL_SECS: u64 = 3600; // 1 hour
const RELOAD_HOOK_TIMEOUT: Duration = Duration::from_secs(30);
const RELOAD_HOOK_POLL: Duration = Duration::from_millis(20);
const RELOAD_INTENT_VERSION: u8 = 1;

/// One at-least-once post-certificate activation owned by Certmesh.
///
/// The hook is expected to be idempotent: a crash after the command succeeds
/// but before the intent is cleared replays it on the next startup.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ReloadIntent {
    version: u8,
    pub(crate) command: String,
    pub(crate) certificate_fingerprint: String,
    pub(crate) attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error: Option<String>,
}

impl ReloadIntent {
    pub(crate) fn new(command: String, certificate_fingerprint: String) -> Self {
        Self {
            version: RELOAD_INTENT_VERSION,
            command,
            certificate_fingerprint,
            attempts: 0,
            last_error: None,
        }
    }

    fn same_operation(&self, other: &Self) -> bool {
        self.command == other.command
            && self.certificate_fingerprint == other.certificate_fingerprint
    }
}

/// Dedicated bounded owner for reload-hook effects. It deliberately does not
/// share Certmesh's aggregate worker: a slow local integration cannot delay
/// status reads or unrelated trust commands. Dropping the last owner signals a
/// running child to be killed, then the contained worker joins deterministically.
pub(crate) struct ReloadExecutor {
    cancel: Arc<AtomicBool>,
    worker: crate::blocking_worker::CertmeshBlockingWorker,
}

impl ReloadExecutor {
    pub(crate) fn new() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            worker: crate::blocking_worker::CertmeshBlockingWorker::new(),
        }
    }

    pub(crate) async fn reserve(&self) -> Result<CertmeshBlockingPermit, CertmeshError> {
        self.worker.reserve().await
    }

    pub(crate) fn dispatch(
        &self,
        permit: CertmeshBlockingPermit,
        domain: Arc<CertmeshDomain>,
        intent: ReloadIntent,
    ) -> tokio::sync::oneshot::Receiver<HookResult> {
        let cancel = Arc::clone(&self.cancel);
        self.worker.dispatch_with_permit(permit, move || {
            execute_and_settle(domain, intent, cancel, RELOAD_HOOK_TIMEOUT)
        })
    }

    /// Re-arm an intent found by the persistence-aware bootstrap boundary.
    pub(crate) fn reconcile(&self, domain: Arc<CertmeshDomain>) {
        let intent = match load_intent(&domain.paths) {
            Ok(Some(intent)) => intent,
            Ok(None) => return,
            Err(error) => {
                tracing::error!(%error, "Could not read pending Certmesh reload intent");
                return;
            }
        };
        let cancel = Arc::clone(&self.cancel);
        match self
            .worker
            .try_run(move || execute_and_settle(domain, intent, cancel, RELOAD_HOOK_TIMEOUT))
        {
            Ok(completion) => drop(completion),
            Err(error) => tracing::error!(%error, "Could not arm pending Certmesh reload intent"),
        }
    }
}

impl Drop for ReloadExecutor {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

pub(crate) fn render_intent(intent: &ReloadIntent) -> Result<Vec<u8>, CertmeshError> {
    serde_json::to_vec_pretty(intent)
        .map_err(|error| CertmeshError::Internal(format!("serialize reload intent: {error}")))
}

pub(crate) fn load_intent(paths: &CertmeshPaths) -> Result<Option<ReloadIntent>, CertmeshError> {
    match std::fs::read(paths.reload_intent_path()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| CertmeshError::Internal(format!("read reload intent: {error}"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CertmeshError::Io(error)),
    }
}

pub(crate) fn status(paths: &CertmeshPaths) -> Option<crate::status::CertmeshReloadStatus> {
    match load_intent(paths) {
        Ok(Some(intent)) => Some(crate::status::CertmeshReloadStatus {
            command: intent.command,
            certificate_fingerprint: Some(intent.certificate_fingerprint),
            attempts: intent.attempts,
            last_error: intent.last_error,
        }),
        Ok(None) => None,
        Err(error) if paths.reload_intent_path().exists() => {
            Some(crate::status::CertmeshReloadStatus {
                command: "<unreadable>".into(),
                certificate_fingerprint: None,
                attempts: 0,
                last_error: Some(error.to_string()),
            })
        }
        Err(_) => None,
    }
}

/// Execute a reload hook command after cert renewal.
///
/// Splits the command on whitespace and executes directly without a
/// shell intermediary.  Shell metacharacters are rejected at the HTTP
/// layer (`set_hook_handler`), so this is safe.
///
/// Returns a structured result. Never panics - failure is reported
/// in the `HookResult`.
#[cfg(test)]
pub(crate) fn execute_reload_hook(hook: &str) -> HookResult {
    execute_reload_hook_with_control(hook, RELOAD_HOOK_TIMEOUT, &AtomicBool::new(false))
}

fn execute_reload_hook_with_control(
    hook: &str,
    timeout: Duration,
    cancel: &AtomicBool,
) -> HookResult {
    let parts: Vec<&str> = hook.split_whitespace().collect();
    let Some(program) = parts.first() else {
        return HookResult {
            success: false,
            command: hook.to_string(),
            output: Some("empty hook command".into()),
        };
    };
    let mut child = match Command::new(program)
        .args(&parts[1..])
        // Hook output is intentionally not buffered: an operator-controlled
        // process must not exhaust daemon memory or disk while waiting to exit.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return HookResult {
                success: false,
                command: hook.to_string(),
                output: Some(error.to_string()),
            }
        }
    };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return HookResult {
                    success: status.success(),
                    command: hook.to_string(),
                    output: (!status.success()).then(|| format!("hook exited with {status}")),
                }
            }
            Ok(None) if cancel.load(Ordering::Acquire) => {
                let _ = child.kill();
                let _ = child.wait();
                return HookResult {
                    success: false,
                    command: hook.to_string(),
                    output: Some("hook cancelled during Certmesh shutdown".into()),
                };
            }
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return HookResult {
                    success: false,
                    command: hook.to_string(),
                    output: Some(format!("hook timed out after {} ms", timeout.as_millis())),
                };
            }
            Ok(None) => std::thread::sleep(RELOAD_HOOK_POLL.min(timeout)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return HookResult {
                    success: false,
                    command: hook.to_string(),
                    output: Some(error.to_string()),
                };
            }
        }
    }
}

fn execute_and_settle(
    domain: Arc<CertmeshDomain>,
    intent: ReloadIntent,
    cancel: Arc<AtomicBool>,
    timeout: Duration,
) -> HookResult {
    let mut result = execute_reload_hook_with_control(&intent.command, timeout, &cancel);
    let _transition = Arc::clone(&domain.transition).blocking_lock_owned();
    let current = match load_intent(&domain.paths) {
        Ok(Some(current)) if current.same_operation(&intent) => current,
        Ok(_) => return result,
        Err(error) => {
            result.success = false;
            result.output = Some(format!("hook ran but reload intent is unreadable: {error}"));
            domain.refresh_status_under_transition();
            let _ = domain.event_tx.send(CertmeshEvent::ReloadHookFailed {
                command: intent.command,
                reason: result.output.clone().unwrap_or_default(),
            });
            return result;
        }
    };

    let mut transaction = ArtifactTransaction::new();
    if result.success {
        if let Err(error) = transaction.append(
            domain.paths.audit_log_path(),
            crate::audit::render_entry(
                "certificate_reload_completed",
                &[("command", intent.command.as_str())],
            ),
            true,
        ) {
            result.success = false;
            result.output = Some(format!("reload audit could not be committed: {error}"));
            transaction = ArtifactTransaction::new();
        } else {
            transaction.remove(domain.paths.reload_intent_path());
        }
    }
    if !result.success {
        let mut failed = current;
        failed.attempts = failed.attempts.saturating_add(1);
        failed.last_error = result.output.clone();
        match render_intent(&failed) {
            Ok(bytes) => transaction.write(domain.paths.reload_intent_path(), bytes, true),
            Err(error) => result.output = Some(error.to_string()),
        }
        if let Err(error) = transaction.append(
            domain.paths.audit_log_path(),
            crate::audit::render_entry(
                "certificate_reload_failed",
                &[
                    ("command", intent.command.as_str()),
                    (
                        "reason",
                        result.output.as_deref().unwrap_or("reload hook failed"),
                    ),
                ],
            ),
            true,
        ) {
            result.output = Some(format!(
                "{}; reload failure audit could not be committed: {error}",
                result.output.as_deref().unwrap_or("reload hook failed")
            ));
        }
    }

    match domain.commit_artifacts_under_transition(transaction) {
        Ok(outcome) => {
            if let Err(error) = domain.finish_commit_under_transition(outcome) {
                result.success = false;
                result.output = Some(format!(
                    "hook ran, but intent durability could not be confirmed: {error}"
                ));
            }
        }
        Err(error) => {
            result.success = false;
            result.output = Some(format!("hook settled but intent update failed: {error}"));
        }
    }
    domain.refresh_status_under_transition();
    if result.success {
        let _ = domain.event_tx.send(CertmeshEvent::ReloadHookCompleted {
            command: intent.command,
        });
    } else {
        let _ = domain.event_tx.send(CertmeshEvent::ReloadHookFailed {
            command: intent.command,
            reason: result.output.clone().unwrap_or_default(),
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const TEST_ECHO_CMD: &str = "/bin/echo ok";
    #[cfg(windows)]
    const TEST_ECHO_CMD: &str = "C:\\Windows\\System32\\cmd.exe /c echo ok";

    #[test]
    fn execute_reload_hook_success() {
        let result = execute_reload_hook(TEST_ECHO_CMD);
        assert!(result.success, "hook failed: {:?}", result.output);
        assert!(result.output.is_none());
    }

    #[test]
    fn execute_reload_hook_failure() {
        let cmd = if cfg!(windows) {
            "cmd /C exit 1"
        } else {
            "exit 1"
        };
        let result = execute_reload_hook(cmd);
        assert!(!result.success);
    }

    #[test]
    fn execute_reload_hook_bad_command() {
        let result = execute_reload_hook("this-command-definitely-does-not-exist-xyz-9999");
        // On Unix, sh -c "bad-command" returns exit code 127 (success=false)
        // On Windows, cmd /C "bad-command" returns a non-zero exit code
        assert!(!result.success);
    }

    #[test]
    fn execute_reload_hook_empty_command() {
        // An empty command string should not panic
        let result = execute_reload_hook("");
        assert_eq!(result.command, "");
    }

    #[test]
    fn execute_reload_hook_does_not_buffer_operator_output() {
        #[cfg(unix)]
        let cmd = "/bin/echo stderr_msg";
        #[cfg(windows)]
        let cmd = "C:\\Windows\\System32\\cmd.exe /c echo stderr_msg";
        let result = execute_reload_hook(cmd);
        assert!(result.success, "hook failed: {:?}", result.output);
        assert!(result.output.is_none());
    }

    #[test]
    #[cfg(unix)]
    fn execute_reload_hook_kills_a_timed_out_child() {
        let cancelled = AtomicBool::new(false);
        let result = execute_reload_hook_with_control(
            "/bin/sleep 10",
            Duration::from_millis(30),
            &cancelled,
        );
        assert!(!result.success);
        assert!(result.output.unwrap().contains("timed out"));
    }

    #[test]
    #[cfg(unix)]
    fn execute_reload_hook_kills_a_cancelled_child() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let thread = std::thread::spawn(move || {
            execute_reload_hook_with_control(
                "/bin/sleep 10",
                Duration::from_secs(5),
                &worker_cancelled,
            )
        });
        std::thread::sleep(Duration::from_millis(30));
        cancelled.store(true, Ordering::Release);
        let result = thread.join().unwrap();
        assert!(!result.success);
        assert!(result.output.unwrap().contains("cancelled"));
    }
}
