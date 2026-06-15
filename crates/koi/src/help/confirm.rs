//! The single destructive-confirmation gate.
//!
//! Every destructive CLI command routes through [`gate`] (or [`gate_meta`],
//! which resolves the token + danger line from a command's [`CommandMeta`]).
//! There is exactly one policy, so non-interactive behaviour cannot drift
//! between commands:
//!
//! - `--yes` (the global escape hatch) → pass silently.
//! - non-interactive (`--json` **or** stdin/stdout is not a TTY) without
//!   `--yes` → **refuse** with a fixed message so scripts fail loud instead of
//!   silently wiping data.
//! - interactive TTY → print the command's danger line, prompt the operator to
//!   type the exact token, and require an exact match.
//!
//! This replaces the per-command hand-rolled prompts that previously bypassed
//! confirmation in `--json` mode (a real data-loss bug) and hung on piped
//! stdin (a `read_line` with no TTY check).

use std::io::{IsTerminal, Write};

use super::meta::{CommandMeta, Confirmation};

/// The exact message emitted when a destructive command is invoked
/// non-interactively without `--yes`. Kept as a constant so tests can assert
/// on it without duplicating the string.
pub const REFUSE_NON_INTERACTIVE: &str =
    "destructive command requires --yes in non-interactive mode";

/// Whether the current process can run an interactive confirmation prompt.
///
/// Requires both stdin and stdout to be TTYs: stdout so the operator can see
/// the prompt, stdin so they can type the token. Factored out so the gate's
/// non-interactive decision is testable in isolation via
/// [`gate_with_interactive`].
fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// The one destructive-confirmation gate.
///
/// See the module docs for the policy. `token_word` is the exact string the
/// operator must type (e.g. `"DESTROY"`, `"RESET"`); it is also printed in the
/// prompt so the operator knows what to type. No danger line is printed — use
/// [`gate_meta`] to render a command's warning text first.
pub fn gate(token_word: &str, json: bool, yes: bool) -> anyhow::Result<()> {
    gate_with_interactive(token_word, json, yes, is_interactive())
}

/// Gate variant that resolves the danger line + token from a command's
/// [`CommandMeta`]. This is how dispatch consults the `confirmation` field:
/// the token word and the warning text live in the meta map (single source of
/// truth), not hardcoded at the call site. After printing the danger line it
/// delegates to [`gate`] so there is exactly one policy implementation.
///
/// A command whose `confirmation` is `None` is not destructive and passes
/// silently — callers should only route destructive commands here.
pub fn gate_meta(meta: &CommandMeta, json: bool, yes: bool) -> anyhow::Result<()> {
    match meta.confirmation {
        Some(Confirmation::TypeToken { message, token }) => {
            // The danger line is only useful to a human on an interactive TTY;
            // skip it when we are about to refuse non-interactively or pass on
            // --yes, so scripts get a clean error / no spurious output.
            if !yes && !json && is_interactive() {
                eprintln!();
                eprintln!("{message}");
                eprintln!();
            }
            gate(token, json, yes)
        }
        None => Ok(()),
    }
}

/// Inner gate with the TTY decision injected, so the non-interactive policy is
/// unit-testable without a real terminal.
fn gate_with_interactive(
    token_word: &str,
    json: bool,
    yes: bool,
    interactive: bool,
) -> anyhow::Result<()> {
    // The escape hatch: explicit consent, no prompt.
    if yes {
        return Ok(());
    }

    // Non-interactive (scripted/piped) without --yes: refuse loudly. Never
    // silently proceed — that was the data-loss bug this gate exists to kill.
    if json || !interactive {
        anyhow::bail!(REFUSE_NON_INTERACTIVE);
    }

    // Interactive TTY: demand an exact token match.
    eprint!("Type {token_word} to confirm: ");
    std::io::stderr().flush().ok();

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim() != token_word {
        anyhow::bail!("confirmation declined");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_passes_silently_even_in_json() {
        assert!(gate("DESTROY", true, true).is_ok());
        assert!(gate("RESET", false, true).is_ok());
    }

    #[test]
    fn json_without_yes_refuses() {
        let err = gate("DESTROY", true, false).unwrap_err();
        assert_eq!(err.to_string(), REFUSE_NON_INTERACTIVE);
    }

    #[test]
    fn non_tty_without_yes_refuses() {
        // interactive = false simulates piped stdin/redirected stdout.
        let err = gate_with_interactive("DESTROY", false, false, false).unwrap_err();
        assert_eq!(err.to_string(), REFUSE_NON_INTERACTIVE);
    }

    #[test]
    fn yes_short_circuits_before_tty_check() {
        // Even with no TTY and no json, --yes wins.
        assert!(gate_with_interactive("RESET", false, true, false).is_ok());
    }
}
