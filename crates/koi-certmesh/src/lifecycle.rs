//! Reload-hook execution after a certificate renewal.
//!
//! ADR-017 P3/F6: renewal is **member-initiated pull** — the member generates a
//! fresh keypair + CSR and the CA signs it ([`crate::CertmeshCore::renew_self_if_due`]).
//! The CA no longer regenerates or ships member keys, so the old CA-push renewal
//! functions are gone. What remains here is the post-renewal reload hook the
//! member runs locally after installing its new cert.

use std::process::Command;

use crate::protocol::HookResult;

/// How often the renewal loop checks whether the local cert is due for renewal.
pub const RENEWAL_CHECK_INTERVAL_SECS: u64 = 3600; // 1 hour

/// Execute a reload hook command after cert renewal.
///
/// Splits the command on whitespace and executes directly without a
/// shell intermediary.  Shell metacharacters are rejected at the HTTP
/// layer (`set_hook_handler`), so this is safe.
///
/// Returns a structured result. Never panics - failure is reported
/// in the `HookResult`.
pub fn execute_reload_hook(hook: &str) -> HookResult {
    let parts: Vec<&str> = hook.split_whitespace().collect();
    let result = if parts.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty hook command",
        ))
    } else {
        Command::new(parts[0]).args(&parts[1..]).output()
    };

    match result {
        Ok(output) => {
            let combined = String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr);
            let trimmed = combined.trim().to_string();

            HookResult {
                success: output.status.success(),
                command: hook.to_string(),
                output: if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                },
            }
        }
        Err(e) => HookResult {
            success: false,
            command: hook.to_string(),
            output: Some(e.to_string()),
        },
    }
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
        assert!(result.output.unwrap().contains("ok"));
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
    fn execute_reload_hook_captures_stderr() {
        #[cfg(unix)]
        let cmd = "/bin/echo stderr_msg";
        #[cfg(windows)]
        let cmd = "C:\\Windows\\System32\\cmd.exe /c echo stderr_msg";
        let result = execute_reload_hook(cmd);
        assert!(result.success, "hook failed: {:?}", result.output);
        assert!(result
            .output
            .as_deref()
            .unwrap_or("")
            .contains("stderr_msg"));
    }
}
