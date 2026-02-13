use command_surface::render::writers::{AnsiWriter, PlainWriter};
use command_surface::render::{
    write_catalog, write_command_detail, write_overview, CatalogOptions, ColorSupport,
    OutputWriter, Segment, TerminalProfile, TextStyle,
};
use command_surface::{
    ApiEndpoint, Category, Color, CommandDef, CommandManifest, Example, Glyph, Presentation,
    QueryParam, Scope, Tag,
};
use once_cell::sync::Lazy;
use std::io::{self};

pub static MANIFEST: Lazy<CommandManifest<KoiCategory, KoiTag, KoiScope>> =
    Lazy::new(build_manifest);

pub fn print_command_detail(def: &CommandDef<KoiCategory, KoiTag, KoiScope>) -> io::Result<()> {
    let profile = TerminalProfile::detect_stdout();
    let mut out = io::stdout();

    if profile.color == ColorSupport::None || !profile.interactive {
        let mut writer = PlainWriter::new(&mut out);
        write_command_detail(def, &profile, &mut writer)
    } else {
        let mut writer = AnsiWriter::new(&mut out);
        write_command_detail(def, &profile, &mut writer)
    }
}

pub fn print_catalog(api_endpoint: &str) -> io::Result<()> {
    let profile = TerminalProfile::detect_stdout();
    let mut out = io::stdout();

    if profile.color == ColorSupport::None || !profile.interactive {
        let mut writer = PlainWriter::new(&mut out);
        write_overview(&MANIFEST, &profile, &mut writer)?;
        write_quick_start(&mut writer, &profile)?;
        writer.write_blank()?;
        write_footer(&mut writer, &profile, "koi <group>", "koi <command>?")?;
        write_api_docs_hint(&mut writer, &profile, api_endpoint)
    } else {
        let mut writer = AnsiWriter::new(&mut out);
        write_overview(&MANIFEST, &profile, &mut writer)?;
        write_quick_start(&mut writer, &profile)?;
        writer.write_blank()?;
        write_footer(&mut writer, &profile, "koi <group>", "koi <command>?")?;
        write_api_docs_hint(&mut writer, &profile, api_endpoint)
    }
}

pub fn print_category_catalog(category: KoiCategory, scope: Option<KoiScope>) -> io::Result<()> {
    let profile = TerminalProfile::detect_stdout();
    let mut out = io::stdout();
    let manifest = filtered_manifest(category, scope);

    let cli_name = category_cli_name(category);
    let title = format!("koi {cli_name} \u{2014} available commands");
    let help = format!("koi {cli_name} <command> --help");

    let options = CatalogOptions {
        include_tags: true,
        include_scope: false,
        highlight_only: true,
        strip_prefix: true,
        indent: 2,
    };

    if profile.color == ColorSupport::None || !profile.interactive {
        let detail = format!("koi {cli_name} <command>?");
        let mut writer = PlainWriter::new(&mut out);
        write_title(&mut writer, &profile, &title)?;
        writer.write_blank()?;
        write_catalog(&manifest, &profile, &mut writer, options)?;
        write_curated_examples(category, &mut writer, &profile)?;
        writer.write_blank()?;
        write_footer(&mut writer, &profile, &help, &detail)
    } else {
        let detail = format!("koi {cli_name} <command>?");
        let mut writer = AnsiWriter::new(&mut out);
        write_title(&mut writer, &profile, &title)?;
        writer.write_blank()?;
        write_catalog(&manifest, &profile, &mut writer, options)?;
        write_curated_examples(category, &mut writer, &profile)?;
        writer.write_blank()?;
        write_footer(&mut writer, &profile, &help, &detail)
    }
}
fn write_title<W: OutputWriter>(
    writer: &mut W,
    profile: &TerminalProfile,
    title: &str,
) -> io::Result<()> {
    let mut style = TextStyle::plain();
    style.bold = true;
    if let Some(color) = profile.resolve_color(Color::Accent) {
        style.fg = Some(color);
    }
    writer.write_line(&[Segment::new(title, style)])
}

fn write_curated_examples<W: OutputWriter>(
    category: KoiCategory,
    writer: &mut W,
    profile: &TerminalProfile,
) -> io::Result<()> {
    let examples = curated_examples(category);
    if examples.is_empty() {
        return Ok(());
    }

    writer.write_blank()?;
    let mut header_style = TextStyle::plain();
    header_style.bold = true;
    if let Some(color) = profile.resolve_color(Color::Info) {
        header_style.fg = Some(color);
    }
    writer.write_line(&[Segment::new("Examples", header_style)])?;

    let mut desc_style = TextStyle::plain();
    desc_style.dim = true;

    for example in examples {
        writer.write_line(&[
            Segment::new(format!("  {}", example.command), TextStyle::plain()),
            Segment::new(format!("  # {}", example.description), desc_style),
        ])?;
    }

    Ok(())
}

fn write_quick_start<W: OutputWriter>(writer: &mut W, profile: &TerminalProfile) -> io::Result<()> {
    let examples: &[Example] = &[
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
    ];

    writer.write_blank()?;
    let mut header_style = TextStyle::plain();
    header_style.bold = true;
    if let Some(color) = profile.resolve_color(Color::Info) {
        header_style.fg = Some(color);
    }
    writer.write_line(&[Segment::new("Quick start", header_style)])?;

    let mut desc_style = TextStyle::plain();
    desc_style.dim = true;

    for example in examples {
        writer.write_line(&[
            Segment::new(format!("  {}", example.command), TextStyle::plain()),
            Segment::new(format!("  # {}", example.description), desc_style),
        ])?;
    }

    Ok(())
}

fn write_footer<W: OutputWriter>(
    writer: &mut W,
    profile: &TerminalProfile,
    help: &str,
    detail_hint: &str,
) -> io::Result<()> {
    let mut style = TextStyle::plain();
    style.dim = true;
    if let Some(color) = profile.resolve_color(Color::Muted) {
        style.fg = Some(color);
    }

    writer.write_line(&[Segment::new(
        format!("Run {help} for flags, or {detail_hint} for a guide"),
        style,
    )])
}

fn write_api_docs_hint<W: OutputWriter>(
    writer: &mut W,
    profile: &TerminalProfile,
    api_endpoint: &str,
) -> io::Result<()> {
    let mut style = TextStyle::plain();
    style.dim = true;
    if let Some(color) = profile.resolve_color(Color::Muted) {
        style.fg = Some(color);
    }

    writer.write_line(&[Segment::new(
        format!("API docs:  {api_endpoint}/docs"),
        style,
    )])
}

fn filtered_manifest(
    category: KoiCategory,
    scope: Option<KoiScope>,
) -> CommandManifest<KoiCategory, KoiTag, KoiScope> {
    let mut manifest = CommandManifest::new();
    for def in MANIFEST.by_category(category) {
        if scope.is_none_or(|s| s == def.scope) {
            manifest.add(*def);
        }
    }
    manifest
}

fn category_cli_name(category: KoiCategory) -> &'static str {
    match category {
        KoiCategory::Core => "core",
        KoiCategory::Discovery => "mdns",
        KoiCategory::Trust => "certmesh",
        KoiCategory::Dns => "dns",
        KoiCategory::Health => "health",
        KoiCategory::Proxy => "proxy",
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub enum KoiCategory {
    Core,
    Discovery,
    Trust,
    Dns,
    Health,
    Proxy,
}

impl Category for KoiCategory {
    fn label(&self) -> &'static str {
        match self {
            Self::Core => "Core",
            Self::Discovery => "Discovery (mDNS)",
            Self::Trust => "Trust (Certmesh)",
            Self::Dns => "DNS",
            Self::Health => "Health",
            Self::Proxy => "Proxy",
        }
    }

    fn order(&self) -> u8 {
        match self {
            Self::Core => 0,
            Self::Discovery => 1,
            Self::Trust => 2,
            Self::Dns => 3,
            Self::Health => 4,
            Self::Proxy => 5,
        }
    }

    fn cli_prefix(&self) -> &'static str {
        match self {
            Self::Core => "",
            Self::Discovery => "mdns ",
            Self::Trust => "certmesh ",
            Self::Dns => "dns ",
            Self::Health => "health ",
            Self::Proxy => "proxy ",
        }
    }

    fn cli_name(&self) -> &'static str {
        match self {
            Self::Core => "status",
            Self::Discovery => "mdns",
            Self::Trust => "certmesh",
            Self::Dns => "dns",
            Self::Health => "health",
            Self::Proxy => "proxy",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::Core => "Service lifecycle and system info",
            Self::Discovery => "Discover and announce services on the local network",
            Self::Trust => "Zero-config TLS certificate mesh",
            Self::Dns => "Local DNS resolver with static records",
            Self::Health => "Service health checks and monitoring",
            Self::Proxy => "TLS-terminating reverse proxy",
        }
    }
}

impl Glyph for KoiCategory {
    fn presentations(&self) -> &'static [Presentation] {
        match self {
            Self::Core => &[Presentation::Emoji("⚙"), Presentation::Ascii("[core]")],
            Self::Discovery => &[Presentation::Emoji("🐠"), Presentation::Ascii("[koi]")],
            Self::Trust => &[Presentation::Emoji("🔐"), Presentation::Ascii("[trust]")],
            Self::Dns => &[Presentation::Emoji("🌐"), Presentation::Ascii("[dns]")],
            Self::Health => &[Presentation::Emoji("💓"), Presentation::Ascii("[health]")],
            Self::Proxy => &[Presentation::Emoji("🔀"), Presentation::Ascii("[proxy]")],
        }
    }

    fn color(&self) -> Option<Color> {
        Some(Color::Accent)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub enum KoiTag {
    Streaming,
    Destructive,
    Mutating,
    ReadOnly,
    Elevated,
    Admin,
}

impl Tag for KoiTag {
    fn label(&self) -> &'static str {
        match self {
            Self::Streaming => "Streaming",
            Self::Destructive => "Destructive",
            Self::Mutating => "Mutating",
            Self::ReadOnly => "Read-only",
            Self::Elevated => "Elevated",
            Self::Admin => "Admin",
        }
    }

    fn highlight(&self) -> bool {
        matches!(self, Self::Destructive | Self::Elevated | Self::Streaming)
    }
}

impl Glyph for KoiTag {
    fn presentations(&self) -> &'static [Presentation] {
        match self {
            Self::Streaming => &[Presentation::Emoji("⇶"), Presentation::Ascii(">>")],
            Self::Destructive => &[Presentation::Emoji("⚠"), Presentation::Ascii("!!")],
            Self::Elevated => &[Presentation::Emoji("🔒"), Presentation::Ascii("^^")],
            _ => &[],
        }
    }

    fn color(&self) -> Option<Color> {
        match self {
            Self::Destructive => Some(Color::Danger),
            Self::Elevated => Some(Color::Warning),
            Self::Streaming => Some(Color::Info),
            Self::Admin => Some(Color::Warning),
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
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
#[allow(dead_code)]
pub enum KoiScope {
    Public,
    Admin,
    Internal,
}

impl Scope for KoiScope {
    fn label(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Admin => "Admin",
            Self::Internal => "Internal",
        }
    }

    fn is_default(&self) -> bool {
        matches!(self, Self::Public)
    }
}

impl Glyph for KoiScope {
    fn badge(&self) -> Option<&'static str> {
        match self {
            Self::Admin => Some("admin"),
            Self::Internal => Some("internal"),
            _ => None,
        }
    }

    fn color(&self) -> Option<Color> {
        match self {
            Self::Internal => Some(Color::Muted),
            _ => None,
        }
    }
}

/// Curated getting-started examples per category (3-5 each).
/// These tell a workflow story, not an exhaustive command reference.
fn curated_examples(category: KoiCategory) -> &'static [Example] {
    match category {
        KoiCategory::Core => &[
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
                command: "koi certmesh open-enrollment --until 2h",
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
                command: "koi proxy add web --listen 8443 --backend http://127.0.0.1:8080",
                description: "TLS-terminate a backend",
            },
            Example {
                command: "koi proxy status",
                description: "Show active listeners",
            },
            Example {
                command: "koi proxy list",
                description: "List all proxy entries",
            },
        ],
    }
}

fn build_manifest() -> CommandManifest<KoiCategory, KoiTag, KoiScope> {
    let mut m = CommandManifest::new();

    // ── Core ─────────────────────────────────────────────────────────
    m.add(CommandDef {
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
        tags: &[KoiTag::Elevated, KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi install",
            description: "Install the system service",
        }],
        see_also: &["uninstall"],
        api: &[],
    })
    .add(CommandDef {
        name: "uninstall",
        summary: "Uninstall the Koi system service",
        long_description: "\
Removes the Koi system service registration. The daemon will be stopped
if it is currently running, and the service entry will be deleted.

State and configuration files are NOT removed — only the service
registration itself. You can re-install later with 'koi install'.

Requires elevated privileges (Administrator / sudo).",
        category: KoiCategory::Core,
        tags: &[KoiTag::Elevated, KoiTag::Destructive, KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi uninstall",
            description: "Remove the system service",
        }],
        see_also: &["install"],
        api: &[],
    })
    .add(CommandDef {
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
            tag: "system",
            summary: "Unified status of all capabilities",
            request_body: None,
            response_body: Some("UnifiedStatusResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "system",
            summary: "Unified status of all capabilities",
            request_body: None,
            response_body: Some("UnifiedStatusResponse"),
            query_params: &[],
            content_type: None,
        }],
    });

    // ── Discovery (mDNS) ─────────────────────────────────────────────
    m.add(CommandDef {
        name: "mdns discover",
        summary: "Discover services on the local network",
        long_description: "\
Performs a multicast DNS browse on the local network and streams discovered
services to the terminal. By default it browses for all service types.
Provide a service type to filter (e.g. _http._tcp).

The command runs as a streaming operation — it will keep discovering
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
            tag: "mdns",
            summary: "Browse for mDNS services (SSE stream)",
            request_body: None,
            response_body: None,
            query_params: &[
                QueryParam {
                    name: "type",
                    param_type: "string",
                    required: false,
                    description: "mDNS service type to browse for (omit to list all types)",
                },
                QueryParam {
                    name: "idle_for",
                    param_type: "integer",
                    required: false,
                    description: "Idle timeout in seconds before closing the stream",
                },
            ],
            content_type: Some("text/event-stream"),
        }],
    })
    .add(CommandDef {
        name: "mdns announce",
        summary: "Announce a service on the local network",
        long_description: "\
Publishes a service on the local network via multicast DNS so that other
devices can discover it. The service stays registered in the daemon until
explicitly unregistered or the daemon shuts down.

Arguments: <name> <service-type> <port> [--txt key=value ...]

The name is a human-readable label. The service type follows the mDNS
convention (e.g. _http._tcp, _ssh._tcp). TXT records can carry metadata.",
        category: KoiCategory::Discovery,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Public,
        examples: &[
            Example {
                command: "koi mdns announce \"My App\" _http._tcp 8080",
                description: "Announce an HTTP service",
            },
            Example {
                command: "koi mdns announce \"NAS\" _smb._tcp 445 --txt version=3",
                description: "With TXT record",
            },
        ],
        see_also: &["mdns unregister", "mdns discover"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_mdns::http::paths::ANNOUNCE,
            tag: "mdns",
            summary: "Register a new mDNS service",
            request_body: Some("RegisterPayload"),
            response_body: Some("RegistrationResult"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "mdns",
            summary: "Unregister an mDNS service",
            request_body: None,
            response_body: None,
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "mdns",
            summary: "Resolve an mDNS service by name",
            request_body: None,
            response_body: None,
            query_params: &[QueryParam {
                name: "name",
                param_type: "string",
                required: true,
                description: "Full mDNS instance name to resolve",
            }],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "mdns",
            summary: "Subscribe to mDNS events (SSE stream)",
            request_body: None,
            response_body: None,
            query_params: &[
                QueryParam {
                    name: "type",
                    param_type: "string",
                    required: true,
                    description: "mDNS service type to watch",
                },
                QueryParam {
                    name: "idle_for",
                    param_type: "integer",
                    required: false,
                    description: "Idle timeout in seconds before closing the stream",
                },
            ],
            content_type: Some("text/event-stream"),
        }],
    })
    .add(CommandDef {
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
            tag: "mdns-admin",
            summary: "Daemon status overview",
            request_body: None,
            response_body: Some("DaemonStatus"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "mdns-admin",
            summary: "List all registrations",
            request_body: None,
            response_body: Some("AdminRegistration"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "mdns-admin",
            summary: "Inspect a single registration",
            request_body: None,
            response_body: Some("AdminRegistration"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "mdns-admin",
            summary: "Force-unregister a service",
            request_body: None,
            response_body: None,
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "mdns-admin",
            summary: "Drain a registration (mark for removal)",
            request_body: None,
            response_body: None,
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "mdns-admin",
            summary: "Revive a draining registration",
            request_body: None,
            response_body: None,
            query_params: &[],
            content_type: None,
        }],
    });

    // ── Trust (Certmesh) ─────────────────────────────────────────────
    m.add(CommandDef {
        name: "certmesh create",
        summary: "Create a new certificate mesh",
        long_description: "\
Initializes a new certificate mesh on this node, making it the root CA.
This generates the root keypair, self-signed certificate, and local
configuration.

Profiles control default certificate lifetimes and renewal policies:
  team     — 90-day certs, auto-renew at 2/3 life
  homelab  — 1-year certs, relaxed validation
  ops      — 30-day certs, strict compliance

After creation, use 'certmesh open-enrollment' to allow other nodes
to join the mesh.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi certmesh create --profile team --operator ops",
                description: "Initialize a CA mesh",
            },
            Example {
                command: "koi certmesh create --profile homelab",
                description: "Homelab-friendly defaults",
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
            tag: "certmesh",
            summary: "Initialize a new CA via the running service",
            request_body: Some("CreateCaRequest"),
            response_body: Some("CreateCaResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
                command: "koi certmesh join http://10.0.0.1:5641 --totp 123456",
                description: "With TOTP auth",
            },
        ],
        see_also: &["certmesh create", "certmesh status"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::JOIN,
            tag: "certmesh",
            summary: "Enroll a new member in the mesh",
            request_body: Some("JoinRequest"),
            response_body: Some("JoinResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
        see_also: &["certmesh compliance", "certmesh log"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_certmesh::http::paths::STATUS,
            tag: "certmesh",
            summary: "Certmesh status overview",
            request_body: None,
            response_body: Some("CertmeshStatus"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
        see_also: &["certmesh status", "certmesh compliance"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_certmesh::http::paths::LOG,
            tag: "certmesh",
            summary: "Return audit log entries",
            request_body: None,
            response_body: Some("AuditLogResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "certmesh compliance",
        summary: "Show compliance summary",
        long_description: "\
Checks the certificate mesh against best-practice compliance rules:
certificate lifetimes, key strengths, renewal coverage, enrollment
window state, and backup freshness. Useful for audits.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::ReadOnly],
        scope: KoiScope::Public,
        examples: &[Example {
            command: "koi certmesh compliance",
            description: "Show compliance summary",
        }],
        see_also: &["certmesh status", "certmesh log"],
        api: &[ApiEndpoint {
            method: "GET",
            path: koi_certmesh::http::paths::COMPLIANCE,
            tag: "certmesh",
            summary: "Return compliance summary and audit log counts",
            request_body: None,
            response_body: Some("ComplianceResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "certmesh",
            summary: "Decrypt the CA key",
            request_body: Some("UnlockRequest"),
            response_body: Some("UnlockResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "certmesh set-hook",
        summary: "Set a post-renewal reload hook",
        long_description: "\
Configures a shell command that runs after each successful certificate
renewal. Typically used to reload services that need to pick up the
new certificate (e.g. nginx, HAProxy, Envoy).

The hook runs as the Koi daemon user. Use --reload for a reload command
or --exec for a custom script.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi certmesh set-hook --reload \"systemctl restart nginx\"",
                description: "Reload nginx after renewal",
            },
            Example {
                command: "koi certmesh set-hook --exec /opt/hooks/on-renew.sh",
                description: "Run a custom script",
            },
        ],
        see_also: &["certmesh status"],
        api: &[ApiEndpoint {
            method: "PUT",
            path: koi_certmesh::http::paths::SET_HOOK,
            tag: "certmesh",
            summary: "Set a post-renewal reload hook for a member",
            request_body: Some("SetHookRequest"),
            response_body: Some("SetHookResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "certmesh promote",
        summary: "Promote a member to standby CA",
        long_description: "\
Promotes a mesh member to standby CA role. The standby receives a copy
of the CA signing key and can take over if the primary CA goes offline.

This is the key operation for high-availability certmesh deployments.",
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
            tag: "certmesh",
            summary: "TOTP-verified CA key transfer to a standby",
            request_body: Some("PromoteRequest"),
            response_body: Some("PromoteResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "certmesh open-enrollment",
        summary: "Open the enrollment window",
        long_description: "\
Opens a time-limited window during which new nodes can join the mesh.
The window closes automatically after the specified duration or when
explicitly closed with 'certmesh close-enrollment'.

This is a security gate: enrollment should only be open when you are
actively adding nodes to the mesh.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi certmesh open-enrollment --until 2h",
                description: "Open enrollment for 2 hours",
            },
            Example {
                command: "koi certmesh open-enrollment --until 15m",
                description: "15-minute window",
            },
        ],
        see_also: &["certmesh close-enrollment", "certmesh join"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::OPEN_ENROLLMENT,
            tag: "certmesh",
            summary: "Open the enrollment window",
            request_body: Some("OpenEnrollmentRequest"),
            response_body: None,
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "certmesh",
            summary: "Close the enrollment window",
            request_body: None,
            response_body: None,
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "certmesh set-policy",
        summary: "Set enrollment scope constraints",
        long_description: "\
Restricts which nodes can enroll based on domain name, IP range, or
other criteria. Policies are checked at enrollment time — existing
members are not retroactively affected.

Use --domain to restrict enrollment to a specific domain suffix.
Use --cidr to restrict by IP range.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi certmesh set-policy --domain lab.local",
                description: "Restrict enrollment to a domain",
            },
            Example {
                command: "koi certmesh set-policy --cidr 10.0.0.0/24",
                description: "Restrict by network",
            },
        ],
        see_also: &["certmesh open-enrollment"],
        api: &[ApiEndpoint {
            method: "PUT",
            path: koi_certmesh::http::paths::SET_POLICY,
            tag: "certmesh",
            summary: "Set enrollment scope constraints",
            request_body: Some("PolicyRequest"),
            response_body: Some("PolicySummary"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "certmesh rotate-totp",
        summary: "Rotate the TOTP enrollment secret",
        long_description: "\
Generates a new TOTP secret for enrollment authentication. The old
secret is immediately invalidated. Share the new secret with operators
who need to enroll new nodes.",
        category: KoiCategory::Trust,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[Example {
            command: "koi certmesh rotate-totp",
            description: "Rotate enrollment secret",
        }],
        see_also: &["certmesh open-enrollment"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::ROTATE_TOTP,
            tag: "certmesh",
            summary: "Rotate the TOTP enrollment secret",
            request_body: Some("RotateTotpRequest"),
            response_body: Some("RotateTotpResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "certmesh backup",
        summary: "Create an encrypted backup bundle",
        long_description: "\
Creates an encrypted backup of the certmesh state, including the CA
keypair, issued certificates, enrollment configuration, and audit log.

The backup file (.koi) is encrypted with a passphrase and can be
restored on any node with 'certmesh restore'. Regular backups are
critical for disaster recovery — if the CA key is lost and no backup
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
        see_also: &["certmesh restore", "certmesh compliance"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_certmesh::http::paths::BACKUP,
            tag: "certmesh",
            summary: "Create an encrypted certmesh backup bundle",
            request_body: Some("BackupRequest"),
            response_body: Some("BackupResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "certmesh",
            summary: "Restore certmesh state from a backup bundle",
            request_body: Some("RestoreRequest"),
            response_body: Some("RestoreResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "certmesh",
            summary: "Revoke a member",
            request_body: Some("RevokeRequest"),
            response_body: Some("RevokeResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "certmesh",
            summary: "Remove all certmesh state",
            request_body: None,
            response_body: Some("DestroyResponse"),
            query_params: &[],
            content_type: None,
        }],
    });

    // ── DNS ──────────────────────────────────────────────────────────
    m.add(CommandDef {
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
            tag: "dns",
            summary: "Start the DNS resolver",
            request_body: None,
            response_body: Some("StartedResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "dns",
            summary: "Stop the DNS resolver",
            request_body: None,
            response_body: Some("StoppedResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "dns",
            summary: "DNS resolver status",
            request_body: None,
            response_body: Some("StatusResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "dns lookup",
        summary: "Lookup a name through the resolver",
        long_description: "\
Queries the local DNS resolver for a name. Supports A, AAAA, CNAME,
TXT, and SRV record types via --record-type.

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
            tag: "dns",
            summary: "Lookup a name through the resolver",
            request_body: None,
            response_body: Some("LookupResponse"),
            query_params: &[
                QueryParam {
                    name: "name",
                    param_type: "string",
                    required: true,
                    description: "Domain name to resolve",
                },
                QueryParam {
                    name: "type",
                    param_type: "string",
                    required: false,
                    description: "Record type (A, AAAA, CNAME, etc.)",
                },
            ],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "dns",
            summary: "Add a static DNS entry",
            request_body: Some("EntryRequest"),
            response_body: Some("EntriesResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "dns",
            summary: "Remove a static DNS entry",
            request_body: None,
            response_body: Some("EntriesResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "dns",
            summary: "List all resolvable names",
            request_body: None,
            response_body: Some("NamesResponse"),
            query_params: &[],
            content_type: None,
        }],
    });

    // ── Health ────────────────────────────────────────────────────────
    m.add(CommandDef {
        name: "health status",
        summary: "Show current health status",
        long_description: "\
Shows the current state of all registered health checks: service name,
check type (HTTP/TCP/process), last result, and last transition time.",
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
            tag: "health",
            summary: "Current health snapshot of all checks",
            request_body: None,
            response_body: Some("HealthSnapshot"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "health",
            summary: "Current health snapshot of all checks",
            request_body: None,
            response_body: Some("HealthSnapshot"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "health add",
        summary: "Add a service health check",
        long_description: "\
Registers a new health check with the daemon. Supported check types:

  --http <url>     HTTP GET, expects 2xx response
  --tcp <host:port> TCP connection check
  --process <name>  Process existence check

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
            tag: "health",
            summary: "Add a service health check",
            request_body: Some("AddCheckRequest"),
            response_body: Some("StatusOk"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "health",
            summary: "Remove a service health check",
            request_body: None,
            response_body: Some("StatusOk"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "health",
            summary: "Current health snapshot of all checks",
            request_body: None,
            response_body: Some("HealthSnapshot"),
            query_params: &[],
            content_type: None,
        }],
    });

    // ── Proxy ─────────────────────────────────────────────────────────
    m.add(CommandDef {
        name: "proxy add",
        summary: "Add or update a proxy entry",
        long_description: "\
Configures a TLS-terminating reverse proxy entry. Koi uses certificates
from the certmesh (if available) to terminate TLS and forward traffic
to a plaintext backend.

Arguments: <name> --listen <port> --backend <url>

If a proxy with the same name exists, it is updated in place.",
        category: KoiCategory::Proxy,
        tags: &[KoiTag::Mutating],
        scope: KoiScope::Admin,
        examples: &[
            Example {
                command: "koi proxy add web --listen 8443 --backend http://127.0.0.1:8080",
                description: "Add a TLS proxy",
            },
            Example {
                command: "koi proxy add api --listen 9443 --backend http://127.0.0.1:3000",
                description: "Another proxy",
            },
        ],
        see_also: &["proxy remove", "proxy list", "proxy status"],
        api: &[ApiEndpoint {
            method: "POST",
            path: koi_proxy::http::paths::ADD,
            tag: "proxy",
            summary: "Add or update a proxy entry",
            request_body: Some("AddProxyRequest"),
            response_body: Some("StatusOk"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
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
            tag: "proxy",
            summary: "Remove a proxy entry",
            request_body: None,
            response_body: Some("StatusOk"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "proxy status",
        summary: "Show proxy status",
        long_description: "\
Shows all active proxy listeners: name, listen port, backend URL,
TLS certificate source, and connection counts.",
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
            tag: "proxy",
            summary: "Show proxy status",
            request_body: None,
            response_body: Some("ProxyStatusResponse"),
            query_params: &[],
            content_type: None,
        }],
    })
    .add(CommandDef {
        name: "proxy list",
        summary: "List configured proxies",
        long_description: "\
Lists all configured proxy entries with their names, listen ports,
and backend URLs. Use 'proxy status' for runtime details.",
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
            tag: "proxy",
            summary: "List configured proxy entries",
            request_body: None,
            response_body: Some("ProxyEntriesResponse"),
            query_params: &[],
            content_type: None,
        }],
    });

    m
}
