# ADR-007: Command Surface and Glyph System

**Status:** Accepted  
**Date:** 2025-11-01

## Context

Koi needed semantic metadata for its command surface - grouping commands by category, tagging behaviors (streaming, admin, interactive), scoping audiences (operator vs developer) - while routing the same commands across CLI, HTTP, and pipe transports. Clap already owns argument structure, types, defaults, and help text, so any manifest system risked duplicating that work. The CLI also needed capability-aware rendering that degrades gracefully across terminal environments (Nerd Font → emoji → ASCII, TrueColor → 16-color → plain).

## Decision

A standalone `command-surface` crate was created with three orthogonal classification axes - `Category` (grouping), `Tag` (behavior), and `Scope` (audience) - each defined as application enums implementing trait contracts. A `Glyph` trait carries ordered `Presentation` variants (NerdFont, Emoji, Ascii, None) and semantic `Color` intents, resolved at render time against a detected `TerminalProfile`.

The hard rule: **never duplicate Clap**. The manifest owns semantics only; Clap owns structure. Channel bindings (`HttpBinding`, `PipeBinding`) are a separate registry that references commands by name, enabling parity validation between CLI and HTTP surfaces without coupling them.

## Consequences

- Every command definition lives in one place. Clap owns structure, the manifest owns identity and routing metadata.
- Adding a new transport channel requires only a new `ChannelBinding` implementation, not changes to command definitions.
- Terminal capability detection resolves glyph presentation at render time - the same command shows Nerd Font icons on modern terminals and plain ASCII on CI runners.
- The crate adds a build-time dependency but no runtime cost beyond glyph resolution during help/status display.
