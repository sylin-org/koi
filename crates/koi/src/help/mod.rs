//! CLI help surface — the catalog + `?` detail renderer and its metadata.
//!
//! **Clap (`crate::cli`) is the single source of truth** for the command tree.
//! This module augments it with presentation/semantic metadata it cannot express
//! (glyphs, categories, long descriptions, curated examples, HTTP-API equivalents,
//! confirmation gates), keyed by the clap moniker path in [`meta::META`].
//!
//! Drift between clap and the metadata is a **test failure**, enforced by the two
//! conformance tests below (P09). The renderer was folded in from the former
//! standalone `command-surface` crate, specialized to Koi's concrete enums.

pub mod confirm;
mod glyph;
mod meta;
mod profile;
mod render;
mod writers;

pub use meta::{get, KoiCategory, KoiScope};
pub use render::{print_catalog, print_category_catalog, print_command_detail};

#[cfg(test)]
mod tests {
    use super::meta;
    use crate::cli::Cli;
    use clap::{CommandFactory, Parser};
    use std::collections::BTreeSet;

    /// Walk the clap `Command` tree and collect every LEAF command path as a
    /// space-joined moniker (e.g. `"certmesh rotate-auth"`, `"mdns admin ls"`).
    ///
    /// A leaf is a command with no subcommands. Intermediate group nodes
    /// (`mdns`, `certmesh`, `mdns admin`, `token`, …) are not leaves and are
    /// skipped. The top-level `koi` node itself is not included.
    fn clap_leaf_paths() -> BTreeSet<String> {
        let cmd = Cli::command();
        let mut leaves = BTreeSet::new();
        for sub in cmd.get_subcommands() {
            collect_leaves(sub, &mut Vec::new(), &mut leaves);
        }
        leaves
    }

    fn collect_leaves(cmd: &clap::Command, prefix: &mut Vec<String>, out: &mut BTreeSet<String>) {
        prefix.push(cmd.get_name().to_string());
        let subs: Vec<&clap::Command> = cmd.get_subcommands().collect();
        if subs.is_empty() {
            out.insert(prefix.join(" "));
        } else {
            for sub in subs {
                collect_leaves(sub, prefix, out);
            }
        }
        prefix.pop();
    }

    /// Bidirectional coverage: every clap leaf has a `CommandMeta`, and every
    /// `CommandMeta` key is a real clap leaf. Catches `rotate-totp`-style drift
    /// (a meta entry whose command does not exist) and missing entries (a new
    /// clap command with no help metadata) by construction.
    #[test]
    fn meta_covers_every_clap_leaf() {
        let clap_leaves = clap_leaf_paths();
        let meta_keys: BTreeSet<String> = meta::META.keys().map(|k| k.to_string()).collect();

        let missing_meta: Vec<&String> = clap_leaves.difference(&meta_keys).collect();
        let orphan_meta: Vec<&String> = meta_keys.difference(&clap_leaves).collect();

        assert!(
            missing_meta.is_empty(),
            "clap leaf commands with no CommandMeta entry: {missing_meta:?}"
        );
        assert!(
            orphan_meta.is_empty(),
            "CommandMeta entries that are not real clap leaves: {orphan_meta:?}"
        );
    }

    /// Every example command in every `CommandMeta` must parse against clap.
    /// Catches phantom-flag drift (`--process`, `--exec`, `--totp`,
    /// `--include-logs`) because clap rejects unknown flags.
    #[test]
    fn every_example_parses() {
        let mut failures: Vec<String> = Vec::new();

        for m in meta::META.values() {
            for example in m.examples {
                // Examples that demonstrate a *shell* idiom (command substitution
                // like `$(date +%F)`) are not a single literal argv — they are
                // documenting the shell, not a flag/arg contract. Skip them; the
                // test's job is to catch phantom flags/args, not shell syntax.
                if example.command.contains("$(") {
                    continue;
                }
                let argv = shell_split(example.command);
                // Examples are written as `koi <args...>`; clap expects the
                // binary name as argv[0].
                if argv.first().map(String::as_str) != Some("koi") {
                    failures.push(format!(
                        "[{}] example does not start with `koi`: {:?}",
                        m.name, example.command
                    ));
                    continue;
                }
                if let Err(e) = Cli::try_parse_from(&argv) {
                    failures.push(format!(
                        "[{}] example failed to parse: {:?}\n    {}",
                        m.name,
                        example.command,
                        e.to_string().lines().next().unwrap_or("")
                    ));
                }
            }
        }

        assert!(
            failures.is_empty(),
            "CommandMeta examples that do not parse against clap:\n  - {}",
            failures.join("\n  - ")
        );
    }

    /// Minimal shell-style splitter: splits on whitespace but keeps
    /// double-quoted and single-quoted runs together (quotes stripped). Enough
    /// for the example corpus (`mdns announce "My App" …`, `udp send … 'hello'`).
    fn shell_split(input: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut in_single = false;
        let mut in_double = false;
        let mut has_token = false;

        for c in input.chars() {
            match c {
                '\'' if !in_double => {
                    in_single = !in_single;
                    has_token = true;
                }
                '"' if !in_single => {
                    in_double = !in_double;
                    has_token = true;
                }
                c if c.is_whitespace() && !in_single && !in_double => {
                    if has_token {
                        out.push(std::mem::take(&mut cur));
                        has_token = false;
                    }
                }
                c => {
                    cur.push(c);
                    has_token = true;
                }
            }
        }
        if has_token {
            out.push(cur);
        }
        out
    }
}
