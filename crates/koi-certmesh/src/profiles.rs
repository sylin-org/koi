//! Trust-profile presets.
//!
//! The mesh's security posture is two real booleans — `enrollment_open`
//! and `requires_approval` — stored in the roster. The named presets
//! ("Just Me" / "My Team" / "My Organization") survive only as **UX labels**
//! in the ceremony and the CLI: each maps to a `(enrollment_open,
//! requires_approval, auto_unlock)` tuple. There is no `TrustProfile` enum
//! and nothing about presets is persisted — only the booleans are.
//!
//! `auto_unlock` is a creation-time decision (whether to save the passphrase
//! to the koi-crypto vault so the daemon boots unlocked). It is **not** stored
//! in the roster; it is threaded from create-time into the vault writer.

/// Resolved preset booleans: `(enrollment_open, requires_approval, auto_unlock)`.
pub type PresetBools = (bool, bool, bool);

/// Resolve a preset name to its `(enrollment_open, requires_approval, auto_unlock)`
/// tuple. Accepts the canonical snake_case keys plus common CLI aliases.
///
/// | Preset            | enrollment_open | requires_approval | auto_unlock |
/// |-------------------|-----------------|-------------------|-------------|
/// | Just Me           | true            | false             | true        |
/// | My Team           | true            | true              | true        |
/// | My Organization   | false           | true              | false       |
///
/// Returns `None` for an unknown name (caller decides how to reprompt).
pub fn preset_bools(name: &str) -> Option<PresetBools> {
    match name.to_lowercase().as_str() {
        "just_me" | "just-me" | "justme" | "personal" | "1" => Some((true, false, true)),
        "my_team" | "my-team" | "myteam" | "team" | "2" => Some((true, true, true)),
        "my_organization" | "my-organization" | "myorganization" | "organization" | "org" | "3" => {
            Some((false, true, false))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_tuples_match_the_diet_table() {
        // Just Me: open, no approval, auto-unlock
        assert_eq!(preset_bools("just_me"), Some((true, false, true)));
        // My Team: open, approval, auto-unlock
        assert_eq!(preset_bools("my_team"), Some((true, true, true)));
        // My Organization: closed, approval, manual unlock
        assert_eq!(preset_bools("my_organization"), Some((false, true, false)));
    }

    #[test]
    fn preset_aliases_resolve() {
        assert_eq!(preset_bools("just-me"), Some((true, false, true)));
        assert_eq!(preset_bools("team"), Some((true, true, true)));
        assert_eq!(preset_bools("org"), Some((false, true, false)));
        assert_eq!(preset_bools("1"), Some((true, false, true)));
        assert_eq!(preset_bools("3"), Some((false, true, false)));
    }

    #[test]
    fn unknown_preset_is_none() {
        assert_eq!(preset_bools("invalid"), None);
        assert_eq!(preset_bools(""), None);
    }
}
