# Command Surface Spec — v2

**Status:** Implemented  
**Date:** 2026-02-12  
**Lineage:** Zen Garden `command_manifest.rs` → Koi v1 proposal → this spec  
**Crate name:** `command-surface`

---

## Vision

Define your command surface once. Route it to any channel. Render it for any
terminal.

A standalone Rust crate that gives CLI applications:

1. A **semantic command manifest** — categories, tags, scopes, examples,
   cross-references — all defined by the application using trait contracts.
2. **Multi-channel routing** — the same command identity maps to CLI args, HTTP
   routes, pipe verbs, or anything else. Channel bindings are separate from
   command definitions.
3. **Capability-aware rendering** — a presentation pipeline that degrades
   gracefully from Nerd Font → emoji → ASCII, from TrueColor → 16-color →
   plain text, driven by a `Glyph` trait the application controls.
4. **Machine-queryable catalog** — JSON/OpenAPI output for tooling,
   completions, web UIs.

---

## Hard Rule: Never Duplicate Clap

Clap owns **structure** — argument names, types, defaults, short/long flags,
validation, help text, subcommand tree.

The manifest owns **semantics** — categories, tags, scopes, channels, examples,
cross-references, visual identity.

The bright-line test: **if adding an argument requires updating two places, the
design is wrong.** The manifest may *lean on* Clap introspection
(`Command::get_subcommands()`, `Arg::get_help()`, etc.) but never re-declares
what Clap already knows.

---

## Reuse-First Principle

This crate is **not** a rendering framework, a color library, or an OpenAPI
generator. When a mature crate already exists, we lean on it and provide only
thin adapters or data that those crates can consume.

Examples:

- Terminal styles: use `console` (style + Windows support).
- Terminal capability detection: use `is-terminal`, `supports-color`,
  and `terminal_size`.
- OpenAPI: use `utoipa` + `utoipa-swagger-ui`.
- JSON serialization: use `serde` + `serde_json` only.

---

## Dependency Orchestration (Preferred Stack)

We orchestrate best-in-class crates and keep our scope limited to
manifest semantics and integration glue.

| Scope | Preferred crate(s) | Role | Notes |
|---|---|---|---|
| CLI parsing | `clap` | Command tree + arg parsing | Single source of truth for structure |
| Static manifest | `once_cell` | `Lazy` initialization | Keep manifests zero-cost at startup |
| Serialization | `serde`, `serde_json` | JSON output | No custom formats |
| Terminal detection | `is-terminal`, `supports-color`, `terminal_size` | Capabilities + width | Reuse existing probes |
| Terminal styling | `console` | ANSI output adapters | No custom escape engine |
| OpenAPI model | `utoipa` | Spec assembly | Programmatic spec merging |
| Swagger UI | `utoipa-swagger-ui` | Interactive docs | Best UX; points to `/openapi.json` |
| HTTP framework | `axum` | Serve JSON + UI | Best UX + ecosystem fit |

If a crate already solves a problem well, we adopt it and avoid building a
parallel abstraction.

| Data | Owner | Manifest Role |
|---|---|---|
| Arg names, types, defaults | Clap | Don't touch |
| Short/long help text | Clap | Don't duplicate — manifest has its own one-liner for the categorized listing; `--help` still uses Clap |
| Subcommand tree structure | Clap | Lean on it — debug validation walks `Command::get_subcommands()` |
| Parameter schemas | Clap | Reference via introspection for channel bindings (e.g. OpenAPI), never re-declare |
| Help rendering | Clap | Replace *top-level* no-args output only; subcommand `--help` stays Clap |

---

## Core Types

Everything below is generic. The crate ships trait contracts; applications
provide the concrete enums and their visual identity.

### 1. Glyph — Visual Identity on the Definition

Every classifiable element (tag, category, scope) carries its own rendering
instructions. The application author — not the renderer — decides what
"destructive" looks like.

```rust
/// Ordered rendering preferences. First supported option wins.
#[derive(Debug, Clone, Copy)]
pub enum Presentation {
    /// Nerd Font icon (requires Nerd Font detection).
    NerdFont(&'static str),
    /// Unicode emoji or symbol.
    Emoji(&'static str),
    /// ASCII-safe text.
    Ascii(&'static str),
    /// Show nothing at this level.
    None,
}

/// Semantic color intent. The renderer maps this to terminal capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Color {
    Accent,
    Success,
    Warning,
    Danger,
    Muted,
    Info,
    Custom(u8, u8, u8),
}

/// Visual identity trait. Implemented by application-defined tags,
/// categories, and scopes.
pub trait Glyph {
    /// Ordered presentation chain. First supported by the terminal wins.
    /// e.g. [NerdFont("\u{f578}"), Emoji("🐠"), Ascii("[koi]")]
    fn presentations(&self) -> &'static [Presentation] { &[] }

    /// Semantic color for this element.
    fn color(&self) -> Option<Color> { None }

    /// Short badge text for inline display: "streaming", "!destructive"
    fn badge(&self) -> Option<&'static str> { None }
}
```

### 2. Category, Tag, Scope — Three Orthogonal Axes

Each is an application-defined enum implementing a trait + `Glyph`.

```rust
/// Semantic grouping of commands.
/// Koi: Core, Discovery, Trust, Dns, Health, Proxy
/// Zen Garden: Stone, Garden, System
pub trait Category: Copy + Eq + Hash + Glyph + Serialize {
    fn label(&self) -> &'static str;
    fn order(&self) -> u8;
}

/// Behavioural classification of a command.
/// Koi: Streaming, Destructive, RequiresDaemon, Elevated, ...
/// Zen Garden: RemoteCapable, LocalOnly, ...
pub trait Tag: Copy + Eq + Hash + Glyph + Serialize {
    fn label(&self) -> &'static str;
}

/// Visibility / access boundary.
/// Koi: Public, Admin, Internal
/// Zen Garden: Public, Debug
pub trait Scope: Copy + Eq + Hash + Glyph + Serialize {
    fn label(&self) -> &'static str;
}
```

The three axes answer different questions:

- **Category** — where does this command *live*? (grouping)
- **Tag** — what does this command *do*? (behaviour)
- **Scope** — who *should* use it? (audience)

A command can be `Discovery` (category) + `[Streaming, ReadOnly]` (tags) +
`Public` (scope). Orthogonal, all visually mappable.

### 3. CommandDef — Generic Over Application Types

```rust
pub struct CommandDef<C: Category, T: Tag, S: Scope> {
    /// Lookup key (e.g. "mdns discover").
    pub name: &'static str,
    /// One-line summary for the categorized listing.
    /// NOT a replacement for Clap's `about` — those coexist.
    pub summary: &'static str,
    /// Category for grouping.
    pub category: C,
    /// Behavioural tags (zero or more).
    pub tags: &'static [T],
    /// Visibility scope.
    pub scope: S,
    /// Usage examples (command + description pairs).
    pub examples: &'static [Example],
    /// Related command names ("see also").
    pub see_also: &'static [&'static str],
}

pub struct Example {
    pub command: &'static str,
    pub description: &'static str,
}
```

Note what's **absent**: no `usage` string (Clap owns that), no parameter list
(Clap owns that), no long help text (Clap owns that).

### 4. CommandManifest

```rust
pub struct CommandManifest<C: Category, T: Tag, S: Scope> {
    commands: HashMap<&'static str, CommandDef<C, T, S>>,
}

impl<C: Category, T: Tag, S: Scope> CommandManifest<C, T, S> {
    pub fn new() -> Self { ... }
    pub fn add(&mut self, def: CommandDef<C, T, S>) { ... }
    pub fn get(&self, name: &str) -> Option<&CommandDef<C, T, S>> { ... }
    pub fn by_category(&self, cat: C) -> Vec<&CommandDef<C, T, S>> { ... }
    pub fn by_tag(&self, tag: T) -> Vec<&CommandDef<C, T, S>> { ... }
    pub fn by_scope(&self, scope: S) -> Vec<&CommandDef<C, T, S>> { ... }
    pub fn all_sorted(&self) -> Vec<&CommandDef<C, T, S>> { ... }
    pub fn categories_in_order(&self) -> Vec<C> { ... }
}
```

---

## Channels — Multi-Surface Routing

The manifest holds commands. Channel bindings are a **separate registry that
references commands by name**. This keeps the core crate oblivious to HTTP
methods, pipe protocols, or any channel-specific concept.

```rust
/// A channel binding connects a manifest command to a transport endpoint.
pub trait ChannelBinding {
    /// The manifest command name this binding routes.
    fn command(&self) -> &'static str;
}
```

Applications define their own binding types:

```rust
// ── HTTP channel (Koi, Zen Garden) ──────────────────────────────────

pub struct HttpBinding {
    pub command: &'static str,
    pub method: HttpMethod,
    pub route: &'static str,       // "/api/v1/mdns/observe"
}
impl ChannelBinding for HttpBinding {
    fn command(&self) -> &'static str { self.command }
}

// ── Named-pipe / Unix-socket channel (Koi) ──────────────────────────

pub struct PipeBinding {
    pub command: &'static str,
    pub verb: &'static str,         // "mdns.observe"
}
impl ChannelBinding for PipeBinding {
    fn command(&self) -> &'static str { self.command }
}
```

A `ChannelMap` registers these and supports parity validation:

```rust
pub struct ChannelMap<B: ChannelBinding> {
    bindings: HashMap<&'static str, B>,
}

impl<B: ChannelBinding> ChannelMap<B> {
    pub fn add(&mut self, binding: B) { ... }
    pub fn get(&self, command: &str) -> Option<&B> { ... }

    /// Debug-assert that every manifest command has a binding and
    /// vice-versa. Catches parity drift at test time.
    pub fn validate_parity<C, T, S>(
        &self,
        manifest: &CommandManifest<C, T, S>,
    ) where C: Category, T: Tag, S: Scope { ... }
}
```

**What this enables:**

- Auto-generate OpenAPI/Swagger from HttpBinding + Clap introspection
- Parity enforcement: every CLI command has an HTTP route and vice-versa
- Web UIs that mirror the CLI 1:1 (rich swagger-like experience)
- Pipe/IPC adapters that look up the manifest rather than maintaining
  their own routing table
- Parameter schemas come from Clap introspection, not manifest
  re-declaration

---

## Rendering Pipeline

### Terminal Profile — Capability Detection

```rust
#[derive(Debug, Clone)]
pub struct TerminalProfile {
    pub color: ColorSupport,
    pub icons: IconSupport,
    pub width: Option<u16>,
    pub interactive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSupport { None, Basic16, Ansi256, TrueColor }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconSupport { Ascii, Unicode, NerdFont }
```

Detection consults `COLORTERM`, `TERM`, `NO_COLOR`, `FORCE_COLOR`,
`$WT_SESSION` (Windows Terminal), `is_terminal()`, `terminal_size()`, etc.

### Output Model — Thin Adapters Over Existing Crates

Prefer existing terminal styling crates instead of inventing a new styling
system. The renderer should produce a **minimal, testable** output model that
adapts to:

- `owo-colors` / `termcolor` / `console` for ANSI output
- Plain text for piped output
- Optional HTML/Markdown only if a real need appears

If we need a shared internal representation, keep it small (text + semantic
intent), and let the writer map that intent to the chosen library. No custom
escape-code engine.

### Resolution — Glyph + Profile → Output Intent

```rust
impl TerminalProfile {
    /// Walk the presentation chain; return the first supported option.
    pub fn resolve_glyph(&self, g: &dyn Glyph) -> Option<String> {
        for p in g.presentations() {
            match (p, self.icons) {
                (Presentation::NerdFont(s), IconSupport::NerdFont) => return Some(s.to_string()),
                (Presentation::Emoji(s), IconSupport::Unicode | IconSupport::NerdFont) => return Some(s.to_string()),
                (Presentation::Ascii(s), _) => return Some(s.to_string()),
                (Presentation::None, _) => return Option::None,
                _ => continue,
            }
        }
        Option::None
    }

    /// Map semantic Color to this terminal's color capability.
    pub fn resolve_color(&self, c: Color) -> Option<TermColor> {
        match self.color {
            ColorSupport::None => Option::None,
            ColorSupport::Basic16 => Some(c.to_basic()),
            ColorSupport::Ansi256 => Some(c.to_256()),
            ColorSupport::TrueColor => Some(c.to_rgb()),
        }
    }
}
```

### Writers — Adapters Over Existing Output Crates

We only ship thin writers that delegate to existing crates. Example targets:

- `AnsiWriter` implemented with `termcolor` or `owo-colors`
- `PlainWriter` (no formatting)
- Optional `HtmlWriter` / `MarkdownWriter` only if a concrete need exists

### Full Pipeline

```
Application types (KoiTag, KoiCategory, KoiScope)
        │
        ▼  impl Glyph
    Glyph trait (presentations, color, badge)
        │
        ▼  TerminalProfile resolves capability
    Minimal output model (text + semantic intent)
        │
        ▼  Output writer (adapter)
    ANSI terminal │ Plain text │ Optional HTML/Markdown
```

### Degradation Table

| Element | TrueColor | 16-color | No color | Piped |
|---|---|---|---|---|
| Category header | Bold + brand color | Bold | UPPERCASE | Plain |
| Badge `[streaming]` | Dim cyan | Dim | `[streaming]` | `[streaming]` |
| Badge `[!destructive]` | Bold red | Bold | `[!destructive]` | `[destructive]` |
| Nerd Font icon `\u{f578}` | `\u{f578}` | — | — | — |
| Emoji `🐠` | `🐠` | `🐠` | `[koi]` | `[koi]` |
| Column alignment | Terminal width | Terminal width | 80 | None |

---

## Koi Application Layer

The crate ships traits. Koi provides the concrete types.

### Koi Categories

```rust
#[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum KoiCategory { Core, Discovery, Trust, Dns, Health, Proxy }

impl Category for KoiCategory {
    fn label(&self) -> &'static str {
        match self {
            Self::Core      => "Core",
            Self::Discovery => "Discovery (mDNS)",
            Self::Trust     => "Trust (Certmesh)",
            Self::Dns       => "DNS",
            Self::Health    => "Health",
            Self::Proxy     => "Proxy",
        }
    }
    fn order(&self) -> u8 {
        match self { Self::Core => 0, Self::Discovery => 1, Self::Trust => 2,
                      Self::Dns => 3, Self::Health => 4, Self::Proxy => 5 }
    }
}

impl Glyph for KoiCategory {
    fn presentations(&self) -> &'static [Presentation] {
        match self {
            Self::Core      => &[Presentation::Emoji("⚙"), Presentation::Ascii("[core]")],
            Self::Discovery => &[Presentation::NerdFont("\u{f578}"),
                                 Presentation::Emoji("🐠"),
                                 Presentation::Ascii("[koi]")],
            Self::Trust     => &[Presentation::Emoji("🔐"), Presentation::Ascii("[trust]")],
            Self::Dns       => &[Presentation::Emoji("🌐"), Presentation::Ascii("[dns]")],
            Self::Health    => &[Presentation::Emoji("💓"), Presentation::Ascii("[health]")],
            Self::Proxy     => &[Presentation::Emoji("🔀"), Presentation::Ascii("[proxy]")],
        }
    }
    fn color(&self) -> Option<Color> { Some(Color::Accent) }
}
```

### Koi Tags

```rust
#[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum KoiTag {
    Streaming, OneShot, RequiresDaemon, Standalone, DualMode,
    Destructive, Mutating, ReadOnly, Elevated, Admin,
}

impl Tag for KoiTag {
    fn label(&self) -> &'static str {
        match self {
            Self::Streaming      => "Streaming",
            Self::OneShot        => "One-shot",
            Self::RequiresDaemon => "Requires daemon",
            Self::Standalone     => "Standalone",
            Self::DualMode       => "Dual-mode",
            Self::Destructive    => "Destructive",
            Self::Mutating       => "Mutating",
            Self::ReadOnly       => "Read-only",
            Self::Elevated       => "Elevated",
            Self::Admin          => "Admin",
        }
    }
}

impl Glyph for KoiTag {
    fn presentations(&self) -> &'static [Presentation] {
        match self {
            Self::Streaming   => &[Presentation::Emoji("⇶"), Presentation::Ascii(">>")],
            Self::Destructive => &[Presentation::Emoji("⚠"), Presentation::Ascii("!!")],
            Self::Elevated    => &[Presentation::Emoji("🔒"), Presentation::Ascii("^^")],
            _ => &[],
        }
    }
    fn color(&self) -> Option<Color> {
        match self {
            Self::Destructive => Some(Color::Danger),
            Self::Elevated    => Some(Color::Warning),
            Self::Streaming   => Some(Color::Info),
            Self::Admin       => Some(Color::Warning),
            _ => None,
        }
    }
    fn badge(&self) -> Option<&'static str> {
        match self {
            Self::Streaming      => Some("streaming"),
            Self::Destructive    => Some("!destructive"),
            Self::RequiresDaemon => Some("daemon"),
            Self::Elevated       => Some("elevated"),
            Self::Admin          => Some("admin"),
            _ => None,
        }
    }
}
```

### Koi Scopes

```rust
#[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum KoiScope { Public, Admin, Internal }

impl Scope for KoiScope {
    fn label(&self) -> &'static str {
        match self { Self::Public => "Public", Self::Admin => "Admin",
                     Self::Internal => "Internal" }
    }
}

impl Glyph for KoiScope {
    fn badge(&self) -> Option<&'static str> {
        match self { Self::Admin => Some("admin"), Self::Internal => Some("internal"), _ => None }
    }
    fn color(&self) -> Option<Color> {
        match self { Self::Internal => Some(Color::Muted), _ => None }
    }
}
```

### Koi Manifest Population

```rust
use once_cell::sync::Lazy;

pub static MANIFEST: Lazy<CommandManifest<KoiCategory, KoiTag, KoiScope>> =
    Lazy::new(build_manifest);

fn build_manifest() -> CommandManifest<KoiCategory, KoiTag, KoiScope> {
    let mut m = CommandManifest::new();

    m.add(CommandDef {
        name: "mdns discover",
        summary: "Discover services on the local network",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::DualMode, KoiTag::Streaming, KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example { command: "koi mdns discover", description: "All service types (5s)" },
            Example { command: "koi mdns discover _http._tcp", description: "HTTP services only" },
            Example { command: "koi mdns discover --timeout 0", description: "Run until Ctrl-C" },
        ],
        see_also: &["mdns subscribe", "mdns resolve"],
    });

    m.add(CommandDef {
        name: "certmesh destroy",
        summary: "Destroy the certificate mesh (removes all CA data)",
        category: KoiCategory::Trust,
        tags: &[KoiTag::RequiresDaemon, KoiTag::Destructive, KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example { command: "koi certmesh destroy", description: "Remove all CA data and certs" },
        ],
        see_also: &["certmesh create", "certmesh backup"],
    });

    m.add(CommandDef {
        name: "health watch",
        summary: "Live terminal health dashboard",
        category: KoiCategory::Health,
        tags: &[KoiTag::RequiresDaemon, KoiTag::Streaming, KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example { command: "koi health watch", description: "Refresh every 2s" },
            Example { command: "koi health watch --interval 10", description: "Refresh every 10s" },
        ],
        see_also: &["health status", "health add"],
    });

    // ... remaining ~40 commands

    m
}
```

### Koi Channel Bindings

```rust
pub static HTTP_BINDINGS: Lazy<ChannelMap<HttpBinding>> = Lazy::new(|| {
    let mut c = ChannelMap::new();
    c.add(HttpBinding { command: "mdns discover",    method: Get,  route: "/api/v1/mdns/discover" });
    c.add(HttpBinding { command: "mdns announce",    method: Post, route: "/api/v1/mdns/announce" });
    c.add(HttpBinding { command: "mdns subscribe",   method: Get,  route: "/api/v1/mdns/subscribe" });
    c.add(HttpBinding { command: "certmesh create",  method: Post, route: "/api/v1/certmesh" });
    c.add(HttpBinding { command: "certmesh destroy", method: Delete, route: "/api/v1/certmesh" });
    c.add(HttpBinding { command: "certmesh status",  method: Get,  route: "/api/v1/certmesh/status" });
    c.add(HttpBinding { command: "health status",    method: Get,  route: "/api/v1/health" });
    c.add(HttpBinding { command: "health watch",     method: Get,  route: "/api/v1/health/watch" });
    // ...
    c
});

pub static PIPE_BINDINGS: Lazy<ChannelMap<PipeBinding>> = Lazy::new(|| {
    let mut c = ChannelMap::new();
    c.add(PipeBinding { command: "mdns discover",  verb: "mdns.discover" });
    c.add(PipeBinding { command: "mdns subscribe", verb: "mdns.subscribe" });
    // ...
    c
});
```

### Koi Premium No-Args Display

When `koi` is run with no subcommand, replace the current Clap help dump with
manifest-driven output:

```
🐠 Koi v0.2.x — local-first service infrastructure

  Daemon:    running (uptime 4h 23m)
  Platform:  windows

⚙ CORE
  status             Show status of all capabilities
  install            Install Koi as a system service             ⚠ elevated
  uninstall          Uninstall the Koi system service            ⚠ elevated  !! destructive
  version            Show version information

🐠 DISCOVERY (mDNS)
  mdns discover      Discover services on the local network      ⇶ streaming
  mdns announce      Announce a service via mDNS                 ⇶ streaming
  mdns unregister    Unregister a service by ID
  mdns resolve       Resolve a specific service instance
  mdns subscribe     Subscribe to lifecycle events               ⇶ streaming

🔐 TRUST (Certmesh)
  certmesh create    Initialize a new certificate mesh
  certmesh join      Join an existing mesh                       [daemon]
  certmesh status    Show mesh status
  certmesh destroy   Destroy the certificate mesh                !! destructive
  ...

🌐 DNS
  dns serve          Start the local DNS resolver                ⚠ elevated
  dns lookup         Query the resolver
  ...

💓 HEALTH
  health status      Show current health status                  [daemon]
  health watch       Live health dashboard                       ⇶ streaming  [daemon]
  ...

🔀 PROXY
  proxy add          Add a TLS proxy entry                       [daemon]
  proxy status       Show proxy status                           [daemon]
  ...

  ─────────────────────────────────────────────────────
  Detailed help:    koi commands <name>
  Full directory:   koi commands
  JSON catalog:     koi commands --json
  Start daemon:     koi --daemon
```

When icons aren't supported, the same output degrades:

```
Koi v0.2.x — local-first service infrastructure

  Daemon:    running (uptime 4h 23m)
  Platform:  windows

[core] CORE
  status             Show status of all capabilities
  install            Install Koi as a system service             ^^ [elevated]
  uninstall          Uninstall the Koi system service            ^^ [elevated]  !! [destructive]
  version            Show version information

[koi] DISCOVERY (mDNS)
  mdns discover      Discover services on the local network      >> [streaming]
  ...
```

### Koi `koi commands` Meta-Command

| Invocation | Behaviour |
|---|---|
| `koi commands` | Full categorized directory (no status header) |
| `koi commands mdns discover` | Detail view: examples, see-also, channel bindings |
| `koi commands --category trust` | Only trust/certmesh commands |
| `koi commands --tag streaming` | All streaming commands across categories |
| `koi commands --scope admin` | Admin-only commands |
| `koi commands --json` | Machine-readable full manifest + bindings |

---

## Clap Cross-Validation

A `#[cfg(debug_assertions)]` check at startup (and a `#[test]`) walks
`Cli::command().get_subcommands()` recursively and asserts:

1. Every Clap subcommand path has a manifest entry.
2. Every manifest entry has a Clap subcommand path.
3. Every manifest command has an HTTP binding (if HTTP channel is used).
4. Every HTTP binding references an existing manifest command.

This catches drift between Clap wiring, manifest entries, and channel
bindings — all at `cargo test` time, not in production.

```rust
// Behind feature = "clap"
pub fn validate_against_clap<C, T, S>(
    manifest: &CommandManifest<C, T, S>,
    clap_cmd: &clap::Command,
) where C: Category, T: Tag, S: Scope {
    let clap_names = collect_subcommand_paths(clap_cmd);
    let manifest_names: HashSet<_> = manifest.all_names().collect();
    // ... assert bidirectional coverage
}
```

---

## Tag-Driven Middleware (Future)

With tags on every command, the dispatcher can automatically apply behaviour:

| Tag | Middleware action |
|---|---|
| `Streaming` | Wire Ctrl+C handler + optional `--timeout` enforcement |
| `RequiresDaemon` | Fail fast with clear instructions if no daemon found |
| `Destructive` | Prompt "Are you sure?" unless `--force` is passed |
| `Elevated` | Check admin/root and suggest `sudo` / Run as Administrator |
| `DualMode` | Try daemon → fall back to standalone (existing `detect_mode`) |

Not required for v1 but the tags make it trivially addable.

---

## Crate Structure

```
command-surface/
  Cargo.toml
  src/
    lib.rs               // CommandDef, CommandManifest, Example
    traits.rs            // Category, Tag, Scope trait definitions
    glyph.rs             // Glyph, Presentation, Color
    channel.rs           // ChannelBinding, ChannelMap, parity validation
        render/
            mod.rs             // Minimal output model + adapter traits
            profile.rs         // TerminalProfile, ColorSupport, IconSupport, detection
            default.rs         // DefaultCatalogRenderer
            writers/
                ansi.rs          // Thin adapter over termcolor/owo-colors/console
                plain.rs         // PlainWriter
                html.rs          // HtmlWriter (feature: html, only if needed)
                markdown.rs      // MarkdownWriter (feature: markdown, only if needed)
    json.rs              // Serialize manifest + bindings (feature: serde)
    validate.rs          // Cross-check against clap (feature: clap)
    openapi.rs           // OpenAPI stub from HTTP bindings (feature: openapi)
```

### Feature Flags

| Feature | Deps Added | What It Enables |
|---|---|---|
| *(default)* | none | Core types, traits, `CommandManifest` |
| `serde` | serde | JSON serialization of manifest + bindings |
| `render` | is-terminal, terminal_size, supports-color, termcolor/owo-colors | `TerminalProfile`, minimal output model, `AnsiWriter`, `PlainWriter` |
| `clap` | clap | `validate_against_clap()` |
| `html` | (render) | `HtmlWriter` (only if needed) |
| `markdown` | (render) | `MarkdownWriter` (only if needed) |
| `openapi` | serde_json, openapiv3/utoipa (TBD) | OpenAPI model emitted using existing crates |

With default features only, the crate is **zero-dependency**.

---

## Implementation Plan

| Phase | Deliverable | Target | Status |
|---|---|---|---|
| **1** | Core crate: traits, `CommandDef`, `CommandManifest`, `Glyph`, `Presentation`, `Color` | `command-surface/src/{lib,traits,glyph}.rs` | ✅ Done — also added `Confirmation`, `ApiEndpoint`, `QueryParam` |
| **2** | Koi integration: define `KoiCategory`, `KoiTag`, `KoiScope`, populate manifest | `crates/koi/src/surface.rs` | ✅ Done — 55 commands registered across 6 categories |
| **3** | Rendering adapters: `TerminalProfile`, minimal output model, `AnsiWriter`, `PlainWriter`, catalog renderer | `command-surface/src/render/` | ✅ Done — `profile.rs`, `default.rs`, `writers/{ansi,plain}.rs` |
| **4** | Replace `print_top_level_help()` with manifest-driven display in Koi | `crates/koi/src/main.rs` | ✅ Done — `print_catalog()` with Clap fallback |
| **5** | `koi commands` meta-command + `--json` | `crates/koi/src/commands/catalog.rs` | Superseded — `koi <group>` shows category catalogs, `koi <command>?` shows detail views. No separate `koi commands` subcommand needed. |
| **6** | Channel bindings: `ChannelBinding`, `ChannelMap`, HTTP/pipe bindings | `command-surface/src/channel.rs` | Superseded — HTTP API is embedded in `CommandDef.api: &[ApiEndpoint]` rather than a separate channel registry. Simpler and avoids parity drift by construction. |
| **7** | Clap cross-validation + channel parity validation | `command-surface/src/validate.rs` | Deferred — not yet needed; parity is manually maintained |
| **8** | Port Zen Garden to `command-surface` — validate trait surface | Zen Garden repo | Deferred — future work |
| **9** | Publish `command-surface` 0.1.0 on crates.io | After both consumers stable | Deferred — future work |

Phases 1-4 delivered immediate value. Phases 5-6 were addressed with a simpler
design that inlines API metadata directly into `CommandDef`. Phases 7-9 remain
future work.

---

## Non-Goals

- **Not replacing Clap** — Clap owns parsing, arg definitions, and
  subcommand `--help`. The manifest supplements with semantic metadata.
- **Not a plugin system** — commands are statically registered. No runtime
  discovery.
- **Not re-declaring parameters** — channel bindings reference Clap
  introspection for param schemas. The manifest never re-declares arg names,
  types, or defaults.
- **Not a web framework** — the HTML writer and OpenAPI generator produce
  static artifacts. Serving them is the application's job.

---

## Prior Art & Gap Analysis

**crates.io search (Feb 2026):** No existing crate provides this pattern.

| Crate | Downloads | What it does | Gap |
|---|---|---|---|
| `clap-cargo` | 7M | Reusable cargo plugin flags | Convention crate, no metadata |
| `clap-i18n-richformatter` | 6K | i18n for clap error messages | No categories, tags, channels |
| `zfish` | 297 | Full CLI framework | Replaces clap, not supplementary |

**Clap extensibility roadmap** ([discussion #3476](https://github.com/clap-rs/clap/discussions/3476)):
epage proposes a `CommandData`/`ArgData` AnyMap plugin system for custom
metadata. Brainstorming since Feb 2022, no shipping date. The gap will persist.

**differentiation:** `command-surface` is not a clap plugin. It works alongside
any CLI parser (clap, argh, hand-rolled) and adds the semantic layer that no
parser provides: categories, tags, scopes, channels, and capability-aware
rendering.
