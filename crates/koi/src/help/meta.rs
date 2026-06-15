//! The `CommandMeta` map — the augmentation clap cannot express.
//!
//! Clap (`crate::cli`) is the single source of truth for the *command tree*:
//! which leaf commands exist, their args, and their flags. This module carries the
//! presentation/semantic metadata that clap does not model — glyphs, categories,
//! long descriptions, curated examples, HTTP-API equivalents, and confirmation
//! gates — keyed by the **clap moniker path** (e.g. `"certmesh rotate-auth"`).
//!
//! Drift between the two is a **test failure**: see the conformance tests in
//! `super` (`meta_covers_every_clap_leaf` and `every_example_parses`). Migrated
//! from the former `command-surface` crate's `build_manifest()` (P09).

use std::collections::HashMap;
use std::sync::LazyLock;

use super::glyph::{Color, Glyph, Presentation};

#[derive(Clone, Copy, Debug)]
pub struct Example {
    pub command: &'static str,
    pub description: &'static str,
}

/// An HTTP API endpoint reference for CLI help display.
///
/// Shows the HTTP equivalent of a CLI command (e.g. `GET /v1/mdns/discover`).
/// Full OpenAPI metadata is owned by the domain crates via `#[utoipa::path]`.
#[derive(Clone, Copy, Debug)]
pub struct ApiEndpoint {
    pub method: &'static str,
    pub path: &'static str,
}

/// Pre-invocation confirmation gate metadata.
///
/// Checked by the CLI dispatch layer before the handler runs, via
/// [`super::confirm::gate_meta`]. Has no effect on HTTP endpoints — the API is
/// not interactive. The token + message here are the single source of truth
/// for a command's confirmation prompt (no hardcoded tokens at the call site).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirmation {
    /// Prompt the user to type an exact token (e.g. `"RESET"`).
    TypeToken {
        message: &'static str,
        token: &'static str,
    },
}

/// Presentation + semantic metadata for one clap leaf command.
///
/// Everything here is what clap *cannot* express; the command tree itself
/// (existence, args, flags) is owned by `crate::cli`.
#[derive(Clone, Copy, Debug)]
pub struct CommandMeta {
    /// The clap moniker path, e.g. `"certmesh rotate-auth"` (the map key too).
    pub name: &'static str,
    pub summary: &'static str,
    pub category: KoiCategory,
    pub tags: &'static [KoiTag],
    pub scope: KoiScope,
    pub examples: &'static [Example],
    pub see_also: &'static [&'static str],
    /// Multi-paragraph explanation shown by the `?` detail view.
    pub long_description: &'static str,
    /// HTTP API equivalents. Empty slice means CLI-only.
    pub api: &'static [ApiEndpoint],
    /// Optional pre-invocation confirmation gate (CLI-only). Consulted by
    /// dispatch via [`super::confirm::gate_meta`] before the handler runs.
    pub confirmation: Option<Confirmation>,
}

// ── Classification axes (concrete; no generic traits) ────────────────

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum KoiCategory {
    Core,
    Discovery,
    Trust,
    /// Generic OS trust-store management (`koi trust`), distinct from the certmesh
    /// CA (`KoiCategory::Trust`). Installs/exports arbitrary roots.
    TrustStore,
    Dns,
    Health,
    Proxy,
    Udp,
    Mcp,
}

impl KoiCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Core => "Core",
            Self::Discovery => "Discovery (mDNS)",
            Self::Trust => "Trust (Certmesh)",
            Self::TrustStore => "Trust store",
            Self::Dns => "DNS",
            Self::Health => "Health",
            Self::Proxy => "Proxy",
            Self::Udp => "UDP",
            Self::Mcp => "MCP",
        }
    }

    pub fn order(&self) -> u8 {
        match self {
            Self::Core => 0,
            Self::Discovery => 1,
            Self::Trust => 2,
            Self::TrustStore => 3,
            Self::Dns => 4,
            Self::Health => 5,
            Self::Proxy => 6,
            Self::Udp => 7,
            Self::Mcp => 8,
        }
    }

    pub fn cli_prefix(&self) -> &'static str {
        match self {
            Self::Core => "",
            Self::Discovery => "mdns ",
            Self::Trust => "certmesh ",
            Self::TrustStore => "trust ",
            Self::Dns => "dns ",
            Self::Health => "health ",
            Self::Proxy => "proxy ",
            Self::Udp => "udp ",
            Self::Mcp => "mcp ",
        }
    }

    pub fn cli_name(&self) -> &'static str {
        match self {
            Self::Core => "status",
            Self::Discovery => "mdns",
            Self::Trust => "certmesh",
            Self::TrustStore => "trust",
            Self::Dns => "dns",
            Self::Health => "health",
            Self::Proxy => "proxy",
            Self::Udp => "udp",
            Self::Mcp => "mcp",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Core => "Service lifecycle and system info",
            Self::Discovery => "Discover and announce services on the local network",
            Self::Trust => "Zero-config TLS certificate mesh",
            Self::TrustStore => "Install and export CA roots in the OS trust store",
            Self::Dns => "Local DNS resolver with static records",
            Self::Health => "Service health checks and monitoring",
            Self::Proxy => "TLS-terminating reverse proxy",
            Self::Udp => "UDP datagram bridging for containers",
            Self::Mcp => "Expose the LAN to AI agents over MCP",
        }
    }
}

impl Glyph for KoiCategory {
    fn presentations(&self) -> &'static [Presentation] {
        match self {
            Self::Core => &[Presentation::Emoji("⚙"), Presentation::Ascii("[core]")],
            Self::Discovery => &[Presentation::Emoji("🐠"), Presentation::Ascii("[koi]")],
            Self::Trust => &[Presentation::Emoji("🔐"), Presentation::Ascii("[trust]")],
            Self::TrustStore => &[Presentation::Emoji("🪪"), Presentation::Ascii("[root]")],
            Self::Dns => &[Presentation::Emoji("🌐"), Presentation::Ascii("[dns]")],
            Self::Health => &[Presentation::Emoji("💓"), Presentation::Ascii("[health]")],
            Self::Proxy => &[Presentation::Emoji("🔀"), Presentation::Ascii("[proxy]")],
            Self::Udp => &[Presentation::Emoji("📡"), Presentation::Ascii("[udp]")],
            Self::Mcp => &[Presentation::Emoji("🤖"), Presentation::Ascii("[mcp]")],
        }
    }

    fn color(&self) -> Option<Color> {
        Some(Color::Accent)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum KoiTag {
    Streaming,
    Destructive,
    Mutating,
    ReadOnly,
    Elevated,
    Admin,
    CliOnly,
}

impl KoiTag {
    /// Whether this tag conveys *actionable* information worth showing
    /// prominently. Non-highlight tags are hidden in highlight-only modes.
    pub fn highlight(&self) -> bool {
        matches!(
            self,
            Self::Destructive | Self::Elevated | Self::Streaming | Self::CliOnly
        )
    }
}

impl Glyph for KoiTag {
    fn presentations(&self) -> &'static [Presentation] {
        match self {
            Self::Streaming => &[Presentation::Emoji("⇶"), Presentation::Ascii(">>")],
            Self::Destructive => &[Presentation::Emoji("⚠"), Presentation::Ascii("!!")],
            Self::Elevated => &[Presentation::Emoji("🔒"), Presentation::Ascii("^^")],
            Self::CliOnly => &[Presentation::Emoji("⌨"), Presentation::Ascii("[cli]")],
            _ => &[],
        }
    }

    fn color(&self) -> Option<Color> {
        match self {
            Self::Destructive => Some(Color::Danger),
            Self::Elevated => Some(Color::Warning),
            Self::Streaming => Some(Color::Info),
            Self::Admin => Some(Color::Warning),
            Self::CliOnly => Some(Color::Muted),
            _ => None,
        }
    }

    fn badge(&self) -> Option<&'static str> {
        match self {
            Self::Streaming => Some("streaming"),
            Self::Destructive => Some("!destructive"),
            Self::Mutating => Some("mutating"),
            Self::ReadOnly => Some("read-only"),
            Self::Elevated => Some("elevated"),
            Self::Admin => Some("admin"),
            Self::CliOnly => Some("cli-only"),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum KoiScope {
    Public,
    Admin,
}

impl Glyph for KoiScope {
    fn badge(&self) -> Option<&'static str> {
        match self {
            Self::Admin => Some("admin"),
            _ => None,
        }
    }

    fn color(&self) -> Option<Color> {
        None
    }
}

// ── Lookup ───────────────────────────────────────────────────────────

/// All command metadata, keyed by the clap moniker path.
pub static META: LazyLock<HashMap<&'static str, CommandMeta>> = LazyLock::new(build_meta);

/// Look up a command by its space-joined clap moniker (e.g. `"dns lookup"`).
pub fn get(name: &str) -> Option<&'static CommandMeta> {
    META.get(name)
}

/// All commands in a category, sorted by name (catalog order).
pub fn by_category(cat: KoiCategory) -> Vec<&'static CommandMeta> {
    let mut items: Vec<_> = META.values().filter(|m| m.category == cat).collect();
    items.sort_by_key(|m| m.name);
    items
}

/// Categories that appear in the map, in display order.
pub fn categories_in_order() -> Vec<KoiCategory> {
    let mut categories: Vec<KoiCategory> = Vec::new();
    for m in META.values() {
        if !categories.contains(&m.category) {
            categories.push(m.category);
        }
    }
    categories.sort_by_key(|c| c.order());
    categories
}

/// Curated getting-started examples per category (3-5 each).
/// These tell a workflow story, not an exhaustive command reference.
pub fn curated_examples(category: KoiCategory) -> &'static [Example] {
    match category {
        KoiCategory::Core => &[
            Example {
                command: "koi launch",
                description: "Open the dashboard",
            },
            Example {
                command: "koi status",
                description: "Quick look at all capabilities",
            },
            Example {
                command: "koi install",
                description: "Install as a system service",
            },
        ],
        KoiCategory::Discovery => &[
            Example {
                command: "koi mdns announce \"My API\" _http._tcp 8080",
                description: "Publish a service",
            },
            Example {
                command: "koi mdns discover",
                description: "Find services on the network",
            },
            Example {
                command: "koi mdns subscribe _http._tcp",
                description: "Watch for service changes",
            },
            Example {
                command: "koi mdns admin ls",
                description: "List all daemon registrations",
            },
        ],
        KoiCategory::Trust => &[
            Example {
                command: "koi certmesh create --profile team --operator ops",
                description: "Bootstrap a new mesh",
            },
            Example {
                command: "koi certmesh join http://ca-host:5641",
                description: "Enroll into an existing mesh",
            },
            Example {
                command: "koi certmesh status",
                description: "Check mesh health",
            },
            Example {
                command: "koi certmesh backup mesh.koi",
                description: "Create an encrypted backup",
            },
            Example {
                command: "koi certmesh open-enrollment",
                description: "Let new members join",
            },
        ],
        KoiCategory::Dns => &[
            Example {
                command: "koi dns add app.lan 10.0.0.5",
                description: "Create a static record",
            },
            Example {
                command: "koi dns lookup app.lan",
                description: "Test name resolution",
            },
            Example {
                command: "koi dns serve",
                description: "Start the resolver",
            },
        ],
        KoiCategory::Health => &[
            Example {
                command: "koi health add api --http https://app/health",
                description: "Register an HTTP check",
            },
            Example {
                command: "koi health status",
                description: "Snapshot of all checks",
            },
            Example {
                command: "koi health watch --interval 5",
                description: "Live dashboard",
            },
        ],
        KoiCategory::Proxy => &[
            Example {
                command: "koi proxy add web --listen 8443 --backend 127.0.0.1:8080",
                description: "TLS-terminate in front of a TCP backend",
            },
            Example {
                command: "koi proxy status",
                description: "Show listeners and their real state",
            },
            Example {
                command: "koi proxy list",
                description: "List all proxy entries",
            },
        ],
        KoiCategory::Udp => &[
            Example {
                command: "koi udp bind --port 5353",
                description: "Bind a host UDP port",
            },
            Example {
                command: "koi udp status",
                description: "Show active bindings",
            },
            Example {
                command: "koi udp send <id> --dest 10.0.0.5:5353 'hello'",
                description: "Send a datagram",
            },
        ],
        KoiCategory::Mcp => &[Example {
            command: "koi mcp serve",
            description: "Serve MCP over stdio for an AI agent host",
        }],
        KoiCategory::TrustStore => &[
            Example {
                command: "koi trust install ./step-ca-root.pem",
                description: "Trust a step-ca root system-wide",
            },
            Example {
                command: "koi trust list",
                description: "Show the roots Koi installed",
            },
            Example {
                command: "koi trust export --ca",
                description: "Print the certmesh root (for ACME bootstrap)",
            },
        ],
    }
}

/// Quick-start examples shown on the top-level catalog.
pub fn quick_start_examples() -> &'static [Example] {
    &[
        Example {
            command: "koi mdns discover",
            description: "Find services on the network",
        },
        Example {
            command: "koi certmesh status",
            description: "Check certificate mesh health",
        },
        Example {
            command: "koi health watch",
            description: "Live health dashboard",
        },
    ]
}

fn build_meta() -> HashMap<&'static str, CommandMeta> {
    let entries: &[CommandMeta] = COMMANDS;
    let mut map = HashMap::with_capacity(entries.len());
    for meta in entries {
        let previous = map.insert(meta.name, *meta);
        debug_assert!(previous.is_none(), "duplicate command meta: {}", meta.name);
    }
    map
}

/// The command metadata table. One entry per clap leaf command.
static COMMANDS: &[CommandMeta] = &[
    // ── Core ─────────────────────────────────────────────────────────
    CommandMeta {
        name: "install",
        summary: "Install Koi as a system service",
        long_description: "\
Registers Koi as a system service so it starts automatically on boot.

On Windows this creates a Windows Service via the Service Control Manager.
On Linux this writes a systemd unit file. On macOS a launchd plist is created.

The daemon runs in the background and exposes the HTTP API on the configured
port (default 5641) and the IPC pipe for local CLI communication.

Requires elevated privileges (Administrator / sudo).",
        category: KoiCategory::Core,
        tags: &[KoiTag::Elevated, KoiTag::Mutating, KoiTag::CliOnly],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi install",
            description: "Install the system service",
        }],
        see_also: &["uninstall"],
        api: &[],
        confirmation: None,
    },
    CommandMeta {
        name: "uninstall",
        summary: "Uninstall the Koi system service",
        long_description: "\
Removes the Koi system service registration. The daemon will be stopped
if it is currently running, and the service entry will be deleted.

State and configuration files are NOT removed - only the service
registration itself. You can re-install later with 'koi install'.

Requires elevated privileges (Administrator / sudo).",
        category: KoiCategory::Core,
        tags: &[
            KoiTag::Elevated,
            KoiTag::Destructive,
            KoiTag::Mutating,
            KoiTag::CliOnly,
        ],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi uninstall",
            description: "Remove the system service",
        }],
        see_also: &["install", "factory-reset"],
        api: &[],
        confirmation: None,
    },
    CommandMeta {
        name: "version",
        summary: "Show version information",
        long_description: "\
Prints the Koi version and build platform. Use --json for machine-readable
output.",
        category: KoiCategory::Core,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi version",
                description: "Show version and platform",
            },
            Example {
                command: "koi version --json",
                description: "JSON output",
            },
        ],
        see_also: &["status"],
        api: &[ApiEndpoint {
            method: "GET",
            path: crate::adapters::http::paths::UNIFIED_STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "launch",
        summary: "Open the dashboard in a web browser",
        long_description: "\
Opens the Koi dashboard in the default web browser. The dashboard shows
a live overview of all capabilities, health checks, DNS records, certmesh
status, proxy entries, and an activity feed.

By default opens http://localhost:5641. If you are using a custom port
(--port or KOI_PORT), that port is used instead.

The daemon must be running for the dashboard to load.",
        category: KoiCategory::Core,
        tags: &[KoiTag::ReadOnly, KoiTag::CliOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi launch",
                description: "Open dashboard in the default browser",
            },
            Example {
                command: "koi --port 8080 launch",
                description: "Open dashboard on a custom port",
            },
        ],
        see_also: &["status"],
        api: &[],
        confirmation: None,
    },
    CommandMeta {
        name: "status",
        summary: "Show status of all capabilities",
        long_description: "\
Displays a dashboard of all Koi capabilities: mDNS, certmesh, DNS,
health, and proxy. Shows whether each subsystem is running, along with
key metrics (registration counts, CA state, listener counts, etc.).

When the daemon is running, status is fetched via IPC. In standalone
mode, it reads local state files directly.",
        category: KoiCategory::Core,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi status",
                description: "Show capability status",
            },
            Example {
                command: "koi status --json",
                description: "JSON output for scripting",
            },
        ],
        see_also: &["version"],
        api: &[ApiEndpoint {
            method: "GET",
            path: crate::adapters::http::paths::UNIFIED_STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "token show",
        summary: "Print the daemon access token",
        long_description: "\
Prints the current daemon access token (DAT) — the secret that authorizes
mutating HTTP requests (anything that is not a GET). The token is read from
the breadcrumb file the daemon writes on startup.

For safety it refuses to print to a non-tty (where it could be captured in
logs or scrollback) unless you pass --force. To hand the token to a
container, prefer `koi token write`.",
        category: KoiCategory::Core,
        tags: &[KoiTag::ReadOnly, KoiTag::CliOnly],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi token show",
                description: "Print the token (tty only)",
            },
            Example {
                command: "koi token show --json",
                description: "Emit {\"token\": \"...\"} for scripting",
            },
        ],
        see_also: &["token write"],
        api: &[],
        confirmation: None,
    },
    CommandMeta {
        name: "token write",
        summary: "Write the daemon token to a 0600 file",
        long_description: "\
Writes the current daemon access token to a file with owner-only
permissions (0600 on Unix; ACL-restricted on Windows), ready to mount into
a container as a secret. Pair with `--http-bind` to expose the daemon and
let containers authenticate their requests.",
        category: KoiCategory::Core,
        tags: &[KoiTag::CliOnly],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi token write /run/koi/token",
            description: "Write the token for mounting into a container",
        }],
        see_also: &["token show"],
        api: &[],
        confirmation: None,
    },
    // ── Discovery (mDNS) ─────────────────────────────────────────────
    CommandMeta {
        name: "mdns discover",
        summary: "Discover services on the local network",
        long_description: "\
Performs a multicast DNS browse on the local network and streams discovered
services to the terminal. By default it browses for all service types.
Provide a service type to filter (e.g. _http._tcp).

The command runs as a streaming operation - it will keep discovering
services until you press Ctrl+C or the --timeout expires.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Streaming, KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi mdns discover",
                description: "Discover all service types",
            },
            Example {
                command: "koi mdns discover --timeout 10",
                description: "Stop after 10 seconds",
            },
        ],
        see_also: &["mdns subscribe", "mdns resolve"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_mdns::http::paths::DISCOVER,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns announce",
        summary: "Announce a service on the local network",
        long_description: "\
Publishes a service on the local network via multicast DNS so that other
devices can discover it. The service stays registered in the daemon until
explicitly unregistered or the daemon shuts down.

Arguments: <name> <service-type> <port> [key=value ...]

The name is a human-readable label. The service type follows the mDNS
convention (e.g. _http._tcp, _ssh._tcp). Trailing key=value pairs become
TXT records.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi mdns announce \"My App\" _http._tcp 8080",
                description: "Announce an HTTP service",
            },
            Example {
                command: "koi mdns announce \"NAS\" _smb._tcp 445 version=3",
                description: "With TXT record",
            },
        ],
        see_also: &["mdns unregister", "mdns discover"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_mdns::http::paths::ANNOUNCE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns unregister",
        summary: "Unregister a previously announced service",
        long_description: "\
Removes a service registration that was created with 'koi mdns announce'.
The registration ID was returned when the service was announced and can
also be found via 'koi mdns admin ls'.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi mdns unregister abc123",
            description: "Remove a registration by ID",
        }],
        see_also: &["mdns announce", "mdns admin ls"],
        api: &[ApiEndpoint {
            method: "DELETE",
            path: koi_mdns::http::paths::UNREGISTER,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns resolve",
        summary: "Resolve a specific service instance",
        long_description: "\
Performs a targeted mDNS resolve for a specific service instance name.
Returns the host, port, IP addresses, and TXT records for that instance.

The instance name is the full mDNS name including the service type and
.local. suffix (e.g. \"My App._http._tcp.local.\").",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi mdns resolve \"My App._http._tcp.local.\"",
            description: "Resolve a service instance",
        }],
        see_also: &["mdns discover"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_mdns::http::paths::RESOLVE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns subscribe",
        summary: "Subscribe to lifecycle events for a service type",
        long_description: "\
Streams real-time lifecycle events (found, lost, updated) for services
matching a given type. Useful for building reactive automations.

The subscription runs until Ctrl+C or --timeout. Each event is emitted
as a line of JSON when --json is used, or as a formatted line otherwise.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Streaming, KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi mdns subscribe _http._tcp",
                description: "Stream service events",
            },
            Example {
                command: "koi mdns subscribe _http._tcp --json",
                description: "NDJSON for piping",
            },
        ],
        see_also: &["mdns discover"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_mdns::http::paths::SUBSCRIBE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns admin status",
        summary: "Show daemon status",
        long_description: "\
Shows the internal mDNS daemon state: number of active registrations,
how many are alive vs draining, and whether the mDNS engine is running.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Admin, KoiTag::ReadOnly],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi mdns admin status",
            description: "Check daemon registration status",
        }],
        see_also: &["mdns admin ls"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_mdns::http::paths::ADMIN_STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns admin ls",
        summary: "List all registrations",
        long_description: "\
Lists every active service registration in the daemon, including
registration IDs, service types, ports, and current state (alive/draining).",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Admin, KoiTag::ReadOnly],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi mdns admin ls",
            description: "List all registrations",
        }],
        see_also: &["mdns admin inspect", "mdns admin status"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_mdns::http::paths::ADMIN_LS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns admin inspect",
        summary: "Inspect a registration by ID or prefix",
        long_description: "\
Shows detailed information about a single registration, including its
full mDNS advertisement, TXT records, creation time, and current state.
You can use a full ID or a unique prefix.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Admin, KoiTag::ReadOnly],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi mdns admin inspect abc123",
            description: "Inspect a registration",
        }],
        see_also: &["mdns admin ls"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_mdns::http::paths::ADMIN_INSPECT,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns admin unregister",
        summary: "Force-unregister a registration",
        long_description: "\
Immediately removes a registration from the daemon without a graceful
drain period. The service will stop being advertised on the network
instantly. Use 'mdns admin drain' for a graceful removal.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Admin, KoiTag::Destructive, KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi mdns admin unregister abc123",
            description: "Force-unregister a registration",
        }],
        see_also: &["mdns admin drain", "mdns admin ls"],
        api: &[ApiEndpoint {
            method: "DELETE",
            path: koi_mdns::http::paths::ADMIN_UNREGISTER,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns admin drain",
        summary: "Force-drain a registration",
        long_description: "\
Puts a registration into draining state. The service continues to respond
to existing queries but no new announcements are sent. After the drain
period expires, the registration is fully removed.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Admin, KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi mdns admin drain abc123",
            description: "Drain a registration",
        }],
        see_also: &["mdns admin revive", "mdns admin unregister"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_mdns::http::paths::ADMIN_DRAIN,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "mdns admin revive",
        summary: "Revive a draining registration",
        long_description: "\
Moves a registration out of draining state back to alive. The service
resumes normal mDNS announcements on the network.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Admin, KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi mdns admin revive abc123",
            description: "Revive a registration",
        }],
        see_also: &["mdns admin drain"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_mdns::http::paths::ADMIN_REVIVE,
        }],
        confirmation: None,
    },
    // ── Trust (Certmesh) ─────────────────────────────────────────────
    CommandMeta {
        name: "certmesh create",
        summary: "Create a new certificate mesh",
        long_description: "\
Initializes a new certificate mesh on this node, making it the root CA.
This generates the root keypair, self-signed certificate, and local
configuration.

Profiles control enrollment defaults and approval policy:
    just-me       - open enrollment, no operator requirement
    team          - open enrollment, operator required
    organization  - closed enrollment by default, operator required

Without flags, this command runs an interactive wizard that guides
profile selection and CA passphrase setup.

Optional policy overrides:
    --enrollment open|closed
    --require-approval true|false",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi certmesh create --profile team --operator ops",
                description: "Initialize a CA mesh",
            },
            Example {
                command: "koi certmesh create --profile just-me --enrollment closed --require-approval false",
                description: "Override default enrollment policy",
            },
            Example {
                command: "koi certmesh create",
                description: "Run the guided interactive wizard",
            },
        ],
        see_also: &[
            "certmesh join",
            "certmesh open-enrollment",
            "certmesh status",
        ],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::CREATE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh join",
        summary: "Join an existing certificate mesh",
        long_description: "\
Enrolls this node into an existing certificate mesh by contacting the
CA node's enrollment endpoint. The CA must have an open enrollment
window (see 'certmesh open-enrollment').

During enrollment, this node generates a keypair, sends a CSR to the CA,
and receives a signed certificate. The node then participates in the
mesh's automatic renewal cycle.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi certmesh join http://ca-host:5641",
                description: "Join a remote CA",
            },
            Example {
                command: "koi certmesh join",
                description: "Discover a CA on the LAN via mDNS",
            },
        ],
        see_also: &["certmesh create", "certmesh status"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::JOIN,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh status",
        summary: "Show certificate mesh status",
        long_description: "\
Displays the current state of the certificate mesh: CA role, certificate
expiry dates, number of enrolled members, renewal status, and whether
the enrollment window is open.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi certmesh status",
                description: "Show mesh status",
            },
            Example {
                command: "koi certmesh status --json",
                description: "JSON for scripting",
            },
        ],
        see_also: &["certmesh log"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_certmesh::http::paths::STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh log",
        summary: "Show the audit log",
        long_description: "\
Displays the certmesh audit trail: certificate issuances, renewals,
revocations, enrollment events, and CA operations. Each entry includes
a timestamp and actor.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi certmesh log",
            description: "Show audit log",
        }],
        see_also: &["certmesh status"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_certmesh::http::paths::LOG,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh unlock",
        summary: "Unlock the CA",
        long_description: "\
Unlocks the CA private key so the mesh can issue and renew certificates.
The CA starts in a locked state after daemon restart for security.
Unlocking requires the CA passphrase if one was set during creation.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh unlock",
            description: "Unlock the CA",
        }],
        see_also: &["certmesh status"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::UNLOCK,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh set-hook",
        summary: "Set a post-renewal reload hook",
        long_description: "\
Configures a shell command that runs after each successful certificate
renewal. Typically used to reload services that need to pick up the
new certificate (e.g. nginx, HAProxy, Envoy).

The hook runs as the Koi daemon user. Use --reload to set the reload
command.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh set-hook --reload \"systemctl restart nginx\"",
            description: "Reload nginx after renewal",
        }],
        see_also: &["certmesh status"],
        api: &[ApiEndpoint {
            method: "PUT",
            path: koi_certmesh::http::paths::SET_HOOK,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh promote",
        summary: "Promote a member to standby CA",
        long_description: "\
Promotes a mesh member to standby CA role. The standby receives an
encrypted copy of the CA signing key so it can issue certificates if the
original CA goes away.

Promotion is a deliberate, manual operator action - there is no automatic
failover or election. A dead CA pauses renewals (30-day certs give days of
runway); it does not cause an outage.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh promote http://ca-host:5641",
            description: "Promote to standby CA",
        }],
        see_also: &["certmesh create"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::PROMOTE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh open-enrollment",
        summary: "Open the enrollment window",
        long_description: "\
Opens the window during which new nodes can join the mesh. The window
stays open until explicitly closed with 'certmesh close-enrollment'.

This is a security gate: enrollment should only be open when you are
actively adding nodes to the mesh.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh open-enrollment",
            description: "Open enrollment",
        }],
        see_also: &["certmesh close-enrollment", "certmesh join"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::OPEN_ENROLLMENT,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh close-enrollment",
        summary: "Close the enrollment window",
        long_description: "\
Immediately closes the enrollment window. No new nodes can join the mesh
until enrollment is re-opened. Existing members are unaffected.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh close-enrollment",
            description: "Close enrollment",
        }],
        see_also: &["certmesh open-enrollment"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::CLOSE_ENROLLMENT,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh rotate-auth",
        summary: "Rotate the TOTP enrollment secret",
        long_description: "\
Generates a new TOTP secret for enrollment authentication. The old
secret is immediately invalidated. Share the new secret with operators
who need to enroll new nodes.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh rotate-auth",
            description: "Rotate enrollment credential",
        }],
        see_also: &["certmesh open-enrollment"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::ROTATE_AUTH,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh backup",
        summary: "Create an encrypted backup bundle",
        long_description: "\
Creates an encrypted backup of the certmesh state, including the CA
keypair, issued certificates, enrollment configuration, and audit log.

The backup file (.koi) is encrypted with a passphrase and can be
restored on any node with 'certmesh restore'. Regular backups are
critical for disaster recovery - if the CA key is lost and no backup
exists, the entire mesh must be recreated.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi certmesh backup mesh.koi",
                description: "Write a backup bundle",
            },
            Example {
                command: "koi certmesh backup /mnt/backup/mesh-$(date +%F).koi",
                description: "Date-stamped backup",
            },
        ],
        see_also: &["certmesh restore"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::BACKUP,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh restore",
        summary: "Restore certmesh state from a backup bundle",
        long_description: "\
Restores a certmesh backup created with 'certmesh backup'. This replaces
the current certmesh state on this node with the backup contents.

WARNING: Any current certmesh state on this node will be overwritten.
The restore will prompt for the backup passphrase.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh restore mesh.koi",
            description: "Restore from a backup bundle",
        }],
        see_also: &["certmesh backup"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::RESTORE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh revoke",
        summary: "Revoke a member from the mesh",
        long_description: "\
Revokes a member's certificate, immediately preventing it from
participating in the mesh. The member's certificate is added to the
CRL (Certificate Revocation List).

A --reason is required for audit purposes. Common reasons: lost,
compromised, superseded, departed.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi certmesh revoke host1 --reason lost",
                description: "Revoke a member",
            },
            Example {
                command: "koi certmesh revoke db-02 --reason compromised",
                description: "Revoke a compromised node",
            },
        ],
        see_also: &["certmesh status", "certmesh log"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::REVOKE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh destroy",
        summary: "Destroy the certificate mesh",
        long_description: "\
Permanently removes all certmesh state on this node: CA keypair,
certificates, enrollments, audit log, and configuration. This action
is IRREVERSIBLE.

If this node is the root CA, all mesh members will lose their ability
to renew certificates. Create a backup first with 'certmesh backup'.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Destructive, KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh destroy",
            description: "Remove CA state",
        }],
        see_also: &["certmesh backup"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::DESTROY,
        }],
        confirmation: Some(Confirmation::TypeToken {
            message: "\
This will PERMANENTLY DELETE all certmesh state including CA keys,\n\
certificates, enrollments, and audit logs.\n\
If this node is the root CA, all mesh members will lose their\n\
ability to renew certificates.",
            token: "DESTROY",
        }),
    },
    CommandMeta {
        name: "certmesh acme enable",
        summary: "Show the ACME (RFC 8555) directory URL + client recipe",
        long_description: "\
The ACME server lets any standard ACME client (Caddy, Traefik, lego,
certbot) obtain certificates from the Koi CA with zero Koi knowledge. It
serves dns-01 self-served in-process over a dedicated server-auth TLS
listener (default :5643) and issues ONLY for names inside the Koi DNS zone.

The server starts automatically with the daemon when the CA is initialized
and unlocked (disable with --no-acme / KOI_NO_ACME). This command prints
the directory URL and the one-time CA-root trust step clients need.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::ReadOnly, KoiTag::CliOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi certmesh acme enable",
            description: "Show the ACME directory URL + bootstrap recipe",
        }],
        see_also: &["certmesh acme status", "certmesh status"],
        api: &[],
        confirmation: None,
    },
    CommandMeta {
        name: "certmesh acme status",
        summary: "Show ACME server status",
        long_description: "\
Reports whether the ACME (RFC 8555) server is serving (it serves when the
CA is initialized and unlocked), the directory URL, and the enrollment mode
(open = free newAccount; closed = external account binding required).",
        category: KoiCategory::Trust,
        tags: &[KoiTag::ReadOnly, KoiTag::CliOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi certmesh acme status",
                description: "Show ACME server status",
            },
            Example {
                command: "koi certmesh acme status --json",
                description: "JSON for scripting",
            },
        ],
        see_also: &["certmesh acme enable"],
        api: &[],
        confirmation: None,
    },
    // ── DNS ──────────────────────────────────────────────────────────
    CommandMeta {
        name: "dns serve",
        summary: "Start the DNS resolver",
        long_description: "\
Starts the local DNS resolver on the configured port (default 53).
The resolver handles queries for static records added via 'dns add'
and can forward unknown queries upstream.

Requires elevated privileges because port 53 is a privileged port.",
        category: KoiCategory::Dns,
        tags: &[KoiTag::Elevated, KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi dns serve",
            description: "Start the resolver",
        }],
        see_also: &["dns stop", "dns status", "dns add"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_dns::http::paths::SERVE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "dns stop",
        summary: "Stop the DNS resolver",
        long_description: "\
Stops the local DNS resolver. Static records are preserved and will be
served again when the resolver is restarted.",
        category: KoiCategory::Dns,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi dns stop",
            description: "Stop the resolver",
        }],
        see_also: &["dns serve"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_dns::http::paths::STOP,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "dns status",
        summary: "Show DNS resolver status",
        long_description: "\
Shows whether the DNS resolver is running, which port and zone it is
configured for, and the number of static and mDNS-derived records.",
        category: KoiCategory::Dns,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi dns status",
            description: "Check resolver status",
        }],
        see_also: &["dns serve", "dns list"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_dns::http::paths::STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "dns lookup",
        summary: "Lookup a name through the resolver",
        long_description: "\
Queries the local DNS resolver for a name. Supports A, AAAA, or ANY
record types via --record-type.

This is useful for testing that static records and mDNS-derived entries
resolve correctly before pointing production traffic at the resolver.",
        category: KoiCategory::Dns,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi dns lookup example.lan",
                description: "Query default (A) record",
            },
            Example {
                command: "koi dns lookup example.lan --record-type AAAA",
                description: "Query IPv6",
            },
        ],
        see_also: &["dns add", "dns list"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_dns::http::paths::LOOKUP,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "dns add",
        summary: "Add a static DNS entry",
        long_description: "\
Creates a static DNS record in the local resolver. The entry is persisted
to disk and survives daemon restarts.

Arguments: <name> <ip>

The name should be within the configured DNS zone (default: .lan).",
        category: KoiCategory::Dns,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi dns add example.lan 10.0.0.10",
                description: "Add a static record",
            },
            Example {
                command: "koi dns add db.lan 10.0.0.20",
                description: "Add another",
            },
        ],
        see_also: &["dns remove", "dns list", "dns lookup"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_dns::http::paths::ADD,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "dns remove",
        summary: "Remove a static DNS entry",
        long_description: "\
Removes a static DNS record from the resolver. The change takes effect
immediately and is persisted to disk.",
        category: KoiCategory::Dns,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi dns remove example.lan",
            description: "Remove a static record",
        }],
        see_also: &["dns add", "dns list"],
        api: &[ApiEndpoint {
            method: "DELETE",
            path: koi_dns::http::paths::REMOVE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "dns list",
        summary: "List all resolvable names",
        long_description: "\
Shows all names the DNS resolver can answer for: static records added
via 'dns add' and entries derived from mDNS service discovery.",
        category: KoiCategory::Dns,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi dns list",
            description: "List static records",
        }],
        see_also: &["dns add", "dns lookup"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_dns::http::paths::LIST,
        }],
        confirmation: None,
    },
    // ── Health ────────────────────────────────────────────────────────
    CommandMeta {
        name: "health status",
        summary: "Show current health status",
        long_description: "\
Shows the current state of all registered health checks: service name,
check type (HTTP/TCP), last result, and last transition time.",
        category: KoiCategory::Health,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi health status",
                description: "Show health snapshot",
            },
            Example {
                command: "koi health status --json",
                description: "JSON for monitoring",
            },
        ],
        see_also: &["health watch", "health log"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_health::http::paths::STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "health watch",
        summary: "Live terminal watch view",
        long_description: "\
Displays a live-updating dashboard of all health checks. The screen
refreshes at the configured interval (default: 2 seconds). Press
Ctrl+C to exit.

Use --interval to control refresh rate.",
        category: KoiCategory::Health,
        tags: &[KoiTag::Streaming, KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi health watch",
                description: "Default refresh rate",
            },
            Example {
                command: "koi health watch --interval 5",
                description: "Refresh every 5 seconds",
            },
        ],
        see_also: &["health status"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_health::http::paths::STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "health add",
        summary: "Add a service health check",
        long_description: "\
Registers a new health check with the daemon. Supported check types:

  --http <url>      HTTP GET, expects 2xx response
  --tcp <host:port> TCP connection check

The check runs at the daemon's configured interval and reports state
transitions (healthy → unhealthy and back).",
        category: KoiCategory::Health,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi health add api --http https://example.com/health",
                description: "Add an HTTP check",
            },
            Example {
                command: "koi health add db --tcp 127.0.0.1:5432",
                description: "TCP port check",
            },
        ],
        see_also: &["health remove", "health status"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_health::http::paths::ADD,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "health remove",
        summary: "Remove a service health check",
        long_description: "\
Removes a health check registration. The check stops running immediately
and its history is removed from the transition log.",
        category: KoiCategory::Health,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi health remove api",
            description: "Remove a check",
        }],
        see_also: &["health add", "health status"],
        api: &[ApiEndpoint {
            method: "DELETE",
            path: koi_health::http::paths::REMOVE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "health log",
        summary: "Show health transition log",
        long_description: "\
Shows the history of health state transitions: when services went from
healthy to unhealthy and back. Each entry includes a timestamp, service
name, old state, new state, and reason.",
        category: KoiCategory::Health,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi health log",
            description: "Show transition log",
        }],
        see_also: &["health status", "health watch"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_health::http::paths::STATUS,
        }],
        confirmation: None,
    },
    // ── Proxy ─────────────────────────────────────────────────────────
    CommandMeta {
        name: "proxy add",
        summary: "Add or update a proxy entry",
        long_description: "\
Adds a TLS-terminating TCP passthrough. Koi binds the listen port, terminates
TLS with a certmesh certificate (if one is on disk) or a generated self-signed
cert, then pipes raw bytes to the backend — so WebSockets and any bidirectional
protocol work transparently.

It is passthrough only: no path routing, no header injection, no rewrites. For
those, point this proxy at Caddy/Traefik/nginx and let them do L7 routing.

Arguments: <name> --listen <port> --backend <host:port>

If a proxy with the same name exists, it is updated in place.",
        category: KoiCategory::Proxy,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi proxy add web --listen 8443 --backend 127.0.0.1:8080",
                description: "Add a TLS passthrough",
            },
            Example {
                command: "koi proxy add api --listen 9443 --backend 127.0.0.1:3000",
                description: "Another passthrough",
            },
        ],
        see_also: &["proxy remove", "proxy list", "proxy status"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_proxy::http::paths::ADD,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "proxy remove",
        summary: "Remove a proxy entry",
        long_description: "\
Removes a proxy entry by name. The listener stops immediately and the
port is released.",
        category: KoiCategory::Proxy,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi proxy remove web",
            description: "Remove a proxy",
        }],
        see_also: &["proxy add", "proxy list"],
        api: &[ApiEndpoint {
            method: "DELETE",
            path: koi_proxy::http::paths::REMOVE,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "proxy status",
        summary: "Show proxy status",
        long_description: "\
Shows all proxy listeners: name, listen port, backend, TLS certificate source
(certmesh or self-signed), and real STATE — running, or the bind/accept error
(e.g. 'address in use') when a listener failed to start.",
        category: KoiCategory::Proxy,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi proxy status",
            description: "Show proxy status",
        }],
        see_also: &["proxy list", "proxy add"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_proxy::http::paths::STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "proxy list",
        summary: "List configured proxies",
        long_description: "\
Lists all configured proxy entries with their names, listen ports,
and backends. Use 'proxy status' for runtime details.",
        category: KoiCategory::Proxy,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi proxy list",
            description: "List proxies",
        }],
        see_also: &["proxy status", "proxy add"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_proxy::http::paths::LIST,
        }],
        confirmation: None,
    },
    // ── UDP ───────────────────────────────────────────────────────────
    CommandMeta {
        name: "udp bind",
        summary: "Bind a host UDP port",
        long_description: "\
Creates a new UDP socket on the host and returns a binding ID. The
binding is lease-based: it expires after `--lease` seconds unless
renewed with 'udp heartbeat'.

Containers cannot bind host UDP ports directly, so this command
provides a bridge: bind via Koi, then send/receive datagrams
through the binding ID.",
        category: KoiCategory::Udp,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi udp bind --port 5353",
                description: "Bind port 5353",
            },
            Example {
                command: "koi udp bind --port 0 --lease 600",
                description: "OS-assigned port, 10 min lease",
            },
        ],
        see_also: &["udp unbind", "udp status", "udp heartbeat"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_udp::http::paths::BIND,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "udp unbind",
        summary: "Unbind (close) a UDP binding",
        long_description: "\
Closes a previously bound UDP socket and releases the port. Any
in-progress recv streams are terminated.",
        category: KoiCategory::Udp,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi udp unbind <id>",
            description: "Close a binding",
        }],
        see_also: &["udp bind", "udp status"],
        api: &[ApiEndpoint {
            method: "DELETE",
            path: koi_udp::http::paths::UNBIND,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "udp send",
        summary: "Send a datagram through a binding",
        long_description: "\
Sends a UDP datagram through an existing binding. The payload is
provided as a string on the CLI (base64-encoded in the HTTP API).
The destination is a host:port pair.",
        category: KoiCategory::Udp,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi udp send <id> --dest 10.0.0.5:5353 'hello'",
            description: "Send a datagram",
        }],
        see_also: &["udp bind"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_udp::http::paths::SEND,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "udp status",
        summary: "Show active UDP bindings",
        long_description: "\
Lists all active UDP bindings with their IDs, local addresses, and
remaining lease times.",
        category: KoiCategory::Udp,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi udp status",
            description: "List bindings",
        }],
        see_also: &["udp bind", "udp unbind"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_udp::http::paths::STATUS,
        }],
        confirmation: None,
    },
    CommandMeta {
        name: "udp heartbeat",
        summary: "Renew a binding's lease",
        long_description: "\
Extends the lease of an active UDP binding, preventing it from
expiring. The lease is reset to its original duration.",
        category: KoiCategory::Udp,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi udp heartbeat <id>",
            description: "Renew lease",
        }],
        see_also: &["udp bind", "udp status"],
        api: &[ApiEndpoint {
            method: "PUT",
            path: koi_udp::http::paths::HEARTBEAT,
        }],
        confirmation: None,
    },
    // ── MCP ───────────────────────────────────────────────────────────
    CommandMeta {
        name: "mcp serve",
        summary: "Serve the MCP protocol over stdio",
        long_description: "\
Runs a Model Context Protocol (MCP) server on stdin/stdout so an AI agent
host (Claude Code, Claude Desktop, or any MCP client) can use Koi's local
network as a substrate: discover, name, and announce LAN services.

The server talks to a running Koi daemon (discovered via the breadcrumb,
or KOI_ENDPOINT/KOI_TOKEN). It exposes read tools (lan_discover,
lan_resolve, dns_lookup, lan_inventory, health_snapshot, runtime_instances,
mcp_servers_on_lan) and write tools (lan_announce, lan_unregister, dns_add,
dns_remove). Services announced via lan_announce are auto-heartbeated and
unregistered when the server stops. CA-admin operations are not exposed.

This command is launched by the MCP host, not run interactively. See
docs/guides/mcp.md for client configuration.",
        category: KoiCategory::Mcp,
        tags: &[KoiTag::Streaming, KoiTag::CliOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi mcp serve",
            description: "Serve MCP over stdio for an AI agent host",
        }],
        see_also: &["mdns discover", "mdns announce", "dns add"],
        api: &[],
        confirmation: None,
    },
    // ── Trust store (generic OS root distribution) ─────────────────────
    CommandMeta {
        name: "trust install",
        summary: "Install a CA certificate into the OS trust store",
        long_description: "\
Reads a PEM-encoded CA certificate and installs it into the operating system's
trusted-root store, so browsers and HTTP clients trust everything that root
signs — no per-app configuration.

Koi validates the input first: it must be a real X.509 certificate AND a CA
(it has the CA basic constraint). A server/leaf certificate is rejected with
\"not a CA certificate\". The root is recorded in state/trust.json so `koi trust
list` and `koi trust remove` can manage exactly the roots Koi installed — Koi
never enumerates or mutates the rest of the OS store.

Works with any CA root: step-ca, mkcert, Caddy's local CA, a corporate root, or
Koi's own certmesh root (see `koi trust export --ca`).

Requires elevated privileges (Administrator / sudo).",
        category: KoiCategory::TrustStore,
        tags: &[KoiTag::Elevated, KoiTag::Mutating, KoiTag::CliOnly],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi trust install ./step-ca-root.pem",
            description: "Trust a step-ca root system-wide",
        }],
        see_also: &["trust list", "trust remove", "trust export"],
        api: &[],
        confirmation: None,
    },
    CommandMeta {
        name: "trust list",
        summary: "List the CA roots Koi installed",
        long_description: "\
Lists the CA roots that Koi installed into the OS trust store, with their
fingerprints and install timestamps. This shows only Koi's own footprint
(tracked in state/trust.json) — not the entire OS trust store.",
        category: KoiCategory::TrustStore,
        tags: &[KoiTag::ReadOnly, KoiTag::CliOnly],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi trust list",
                description: "Show the roots Koi installed",
            },
            Example {
                command: "koi trust list --json",
                description: "Machine-readable output",
            },
        ],
        see_also: &["trust install", "trust remove"],
        api: &[],
        confirmation: None,
    },
    CommandMeta {
        name: "trust remove",
        summary: "Remove a Koi-installed CA root",
        long_description: "\
Removes a CA root that Koi installed, by the name shown in `koi trust list`.
The certificate is removed from the OS trust store and its entry is dropped
from state/trust.json. Roots Koi did not install are never touched.

Requires elevated privileges (Administrator / sudo).",
        category: KoiCategory::TrustStore,
        tags: &[KoiTag::Elevated, KoiTag::Mutating, KoiTag::CliOnly],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi trust remove koi-step-ca-root",
            description: "Untrust a previously installed root",
        }],
        see_also: &["trust list", "trust install"],
        api: &[],
        confirmation: None,
    },
    CommandMeta {
        name: "trust export",
        summary: "Export the certmesh root CA to stdout",
        long_description: "\
Prints the certmesh root CA certificate (PEM) to stdout, so you can hand it to
tools that bootstrap their own trust — for example seeding an ACME client or a
container's CA bundle:

  koi trust export --ca > koi-root.pem

The certmesh CA must exist (run `koi certmesh create` first). See the ACME
guide for how this fits the ACME bootstrap recipes.",
        category: KoiCategory::TrustStore,
        tags: &[KoiTag::ReadOnly, KoiTag::CliOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi trust export --ca",
            description: "Print the certmesh root (for ACME bootstrap)",
        }],
        see_also: &["trust install", "certmesh create"],
        api: &[],
        confirmation: None,
    },
    // ── factory-reset (Core; defined last to mirror the original manifest) ─
    CommandMeta {
        name: "factory-reset",
        summary: "Wipe all state and restart the service",
        long_description: "\
Destroys the Koi program data folder and recreates it from scratch,
then restarts the system service. This removes ALL local state:

  • mDNS registrations
  • CA private keys and issued certificates
  • DNS records
  • Health-check configurations
  • Proxy routes
  • Log files
  • config.toml

This is irreversible. If this node is the certmesh CA root, every
certificate it ever issued becomes unverifiable.

Requires elevated privileges (Administrator / sudo).",
        category: KoiCategory::Core,
        tags: &[
            KoiTag::Elevated,
            KoiTag::Destructive,
            KoiTag::Mutating,
            KoiTag::CliOnly,
        ],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi factory-reset",
            description: "Wipe all state and restart",
        }],
        see_also: &["uninstall", "install"],
        api: &[],
        confirmation: Some(Confirmation::TypeToken {
            message: "\
This will PERMANENTLY DELETE all Koi state including CA keys,\n\
certificates, DNS records, and configuration.\n\
If this node is the certmesh CA root, all issued certificates\n\
will become unverifiable.",
            token: "RESET",
        }),
    },
];
