//! Catalog + command-detail rendering.
//!
//! Moved from the former `command-surface` crate's `render/default.rs` and the
//! binary's `surface.rs` wrappers (P09), specialized to Koi's concrete
//! [`KoiCategory`]/[`KoiTag`]/[`KoiScope`] — no `<C, T, S>` generics. The output
//! algorithm is byte-for-byte identical to the pre-P09 renderer.

use std::io;

use super::glyph::{Color, Glyph};
use super::meta::{self, ApiEndpoint, CommandMeta, Example, KoiCategory, KoiScope, KoiTag};
use super::profile::{ColorSupport, TerminalProfile};
use super::writers::{AnsiWriter, OutputWriter, PlainWriter, Segment, TextStyle};

// ── Public entry points (formerly surface.rs) ────────────────────────

/// Render the `?` detail view for a single command.
pub fn print_command_detail(meta: &CommandMeta) -> io::Result<()> {
    let profile = TerminalProfile::detect_stdout();
    let mut out = io::stdout();

    if profile.color == ColorSupport::None || !profile.interactive {
        let mut writer = PlainWriter::new(&mut out);
        write_command_detail(meta, &profile, &mut writer)
    } else {
        let mut writer = AnsiWriter::new(&mut out);
        write_command_detail(meta, &profile, &mut writer)
    }
}

/// Render the top-level catalog (overview + quick start + footer + API hint).
pub fn print_catalog(api_endpoint: &str) -> io::Result<()> {
    let profile = TerminalProfile::detect_stdout();
    let mut out = io::stdout();

    if profile.color == ColorSupport::None || !profile.interactive {
        let mut writer = PlainWriter::new(&mut out);
        write_overview(&profile, &mut writer)?;
        write_quick_start(&mut writer, &profile)?;
        writer.write_blank()?;
        write_footer(&mut writer, &profile, "koi <group>", "koi <command>?")?;
        write_api_docs_hint(&mut writer, &profile, api_endpoint)
    } else {
        let mut writer = AnsiWriter::new(&mut out);
        write_overview(&profile, &mut writer)?;
        write_quick_start(&mut writer, &profile)?;
        writer.write_blank()?;
        write_footer(&mut writer, &profile, "koi <group>", "koi <command>?")?;
        write_api_docs_hint(&mut writer, &profile, api_endpoint)
    }
}

/// Render the per-category catalog (`koi mdns`, `koi certmesh`, …).
pub fn print_category_catalog(category: KoiCategory, scope: Option<KoiScope>) -> io::Result<()> {
    let profile = TerminalProfile::detect_stdout();
    let mut out = io::stdout();
    let commands = filtered_commands(category, scope);

    let cli_name = category.cli_name();
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
        write_catalog(&commands, &profile, &mut writer, options)?;
        write_curated_examples(category, &mut writer, &profile)?;
        writer.write_blank()?;
        write_footer(&mut writer, &profile, &help, &detail)
    } else {
        let detail = format!("koi {cli_name} <command>?");
        let mut writer = AnsiWriter::new(&mut out);
        write_title(&mut writer, &profile, &title)?;
        writer.write_blank()?;
        write_catalog(&commands, &profile, &mut writer, options)?;
        write_curated_examples(category, &mut writer, &profile)?;
        writer.write_blank()?;
        write_footer(&mut writer, &profile, &help, &detail)
    }
}

fn filtered_commands(category: KoiCategory, scope: Option<KoiScope>) -> Vec<&'static CommandMeta> {
    meta::by_category(category)
        .into_iter()
        .filter(|m| scope.is_none_or(|s| s == m.scope))
        .collect()
}

// ── Catalog header / footer fragments (formerly surface.rs) ──────────

fn write_title<W: OutputWriter + ?Sized>(
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

fn write_curated_examples<W: OutputWriter + ?Sized>(
    category: KoiCategory,
    writer: &mut W,
    profile: &TerminalProfile,
) -> io::Result<()> {
    let examples = meta::curated_examples(category);
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

fn write_quick_start<W: OutputWriter + ?Sized>(
    writer: &mut W,
    profile: &TerminalProfile,
) -> io::Result<()> {
    let examples: &[Example] = meta::quick_start_examples();

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

fn write_footer<W: OutputWriter + ?Sized>(
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

fn write_api_docs_hint<W: OutputWriter + ?Sized>(
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

// ── Catalog options (formerly render/default.rs) ─────────────────────

#[derive(Clone, Copy, Debug)]
pub struct CatalogOptions {
    pub include_tags: bool,
    pub include_scope: bool,
    /// Only render tags where `KoiTag::highlight()` is true (destructive,
    /// elevated, streaming).  Suppresses noise like mutating / read-only.
    pub highlight_only: bool,
    /// Strip the category's `cli_prefix()` from displayed command names.
    pub strip_prefix: bool,
    pub indent: usize,
}

// ---------------------------------------------------------------------------
// Full catalog (one command per line)
// ---------------------------------------------------------------------------

fn write_catalog<W: OutputWriter + ?Sized>(
    commands: &[&CommandMeta],
    profile: &TerminalProfile,
    writer: &mut W,
    options: CatalogOptions,
) -> io::Result<()> {
    let display_name = |meta: &CommandMeta| -> String {
        if options.strip_prefix {
            let prefix = meta.category.cli_prefix();
            meta.name
                .strip_prefix(prefix)
                .unwrap_or(meta.name)
                .to_string()
        } else {
            meta.name.to_string()
        }
    };

    let name_width = commands
        .iter()
        .map(|meta| display_name(meta).len())
        .max()
        .unwrap_or(0);
    let max_width = profile.width.map(|w| w as usize);

    let categories = categories_in_order(commands);
    for (cat_index, category) in categories.iter().enumerate() {
        if cat_index > 0 {
            writer.write_blank()?;
        }

        let header = format_header(profile, *category);
        writer.write_line(&header)?;

        for meta in by_category(commands, *category) {
            let dname = display_name(meta);
            let line = format_command_line(profile, meta, &dname, name_width, max_width, options);
            writer.write_line(&line)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Overview (one line per category: icon + CLI name + description)
// ---------------------------------------------------------------------------

fn write_overview<W: OutputWriter + ?Sized>(
    profile: &TerminalProfile,
    writer: &mut W,
) -> io::Result<()> {
    let categories = meta::categories_in_order();

    // Column width based on cli_name
    let name_width = categories
        .iter()
        .map(|cat| cat.cli_name().len())
        .max()
        .unwrap_or(0);

    for category in &categories {
        let cli_name = category.cli_name();
        let description = category.description();
        let count = meta::by_category(*category).len();

        // Icon
        let icon = profile.resolve_glyph(category).unwrap_or_default();
        let indent = if icon.is_empty() {
            "  ".to_string()
        } else {
            format!("  {} ", icon)
        };

        let mut name_style = TextStyle::plain();
        name_style.bold = true;
        if let Some(color) = category.color().and_then(|c| profile.resolve_color(c)) {
            name_style.fg = Some(color);
        }

        let desc_style = TextStyle::plain();

        let mut count_style = TextStyle::plain();
        count_style.dim = true;

        writer.write_line(&[
            Segment::new(indent, TextStyle::plain()),
            Segment::new(
                format!("{:<width$}", cli_name, width = name_width),
                name_style,
            ),
            Segment::new(format!("  {}", description), desc_style),
            Segment::new(format!("  ({count})"), count_style),
        ])?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Categories present in `commands`, in display order.
fn categories_in_order(commands: &[&CommandMeta]) -> Vec<KoiCategory> {
    let mut categories: Vec<KoiCategory> = Vec::new();
    for meta in commands {
        if !categories.contains(&meta.category) {
            categories.push(meta.category);
        }
    }
    categories.sort_by_key(|c| c.order());
    categories
}

/// Commands in `commands` matching `cat`, sorted by name.
fn by_category<'a>(commands: &[&'a CommandMeta], cat: KoiCategory) -> Vec<&'a CommandMeta> {
    let mut items: Vec<_> = commands
        .iter()
        .copied()
        .filter(|meta| meta.category == cat)
        .collect();
    items.sort_by_key(|meta| meta.name);
    items
}

fn format_header(profile: &TerminalProfile, category: KoiCategory) -> Vec<Segment> {
    let mut text = String::new();
    if let Some(icon) = profile.resolve_glyph(&category) {
        text.push_str(&icon);
        text.push(' ');
    }
    text.push_str(category.label());

    let mut style = TextStyle::plain();
    style.bold = true;
    if let Some(color) = category.color().and_then(|c| profile.resolve_color(c)) {
        style.fg = Some(color);
    }

    vec![Segment::new(text, style)]
}

fn format_command_line(
    profile: &TerminalProfile,
    meta: &CommandMeta,
    display_name: &str,
    name_width: usize,
    max_width: Option<usize>,
    options: CatalogOptions,
) -> Vec<Segment> {
    let indent = " ".repeat(options.indent);
    let summary = truncate_summary(meta.summary, name_width, max_width, options.indent);
    let base = format!(
        "{indent}{:<width$}  {summary}",
        display_name,
        width = name_width
    );

    let mut segments = vec![Segment::new(base, TextStyle::plain())];

    // Collect tag badge texts so we can deduplicate against scope below
    let mut rendered_badges: Vec<&str> = Vec::new();

    if options.include_tags {
        for tag in meta.tags {
            if options.highlight_only && !tag.highlight() {
                continue;
            }
            if let Some(badge) = tag.badge() {
                rendered_badges.push(badge);
                segments.push(badge_segment(profile, badge, *tag));
            }
        }
    }

    if options.include_scope {
        if let Some(badge) = meta.scope.badge() {
            // Skip scope badge if a tag already rendered the same text
            if !rendered_badges.contains(&badge) {
                segments.push(scope_segment(profile, badge, meta.scope));
            }
        }
    }

    segments
}

fn badge_segment(profile: &TerminalProfile, badge: &str, tag: KoiTag) -> Segment {
    let mut style = TextStyle::plain();
    style.dim = true;

    if let Some(color) = tag.color().and_then(|c| profile.resolve_color(c)) {
        style.fg = Some(color);
        if matches!(tag.color(), Some(Color::Danger | Color::Warning)) {
            style.bold = true;
            style.dim = false;
        }
    }

    Segment::new(format!("  [{badge}]"), style)
}

fn scope_segment(profile: &TerminalProfile, badge: &str, scope: KoiScope) -> Segment {
    let mut style = TextStyle::plain();
    style.dim = true;
    if let Some(color) = scope.color().and_then(|c| profile.resolve_color(c)) {
        style.fg = Some(color);
    }

    Segment::new(format!("  [{badge}]"), style)
}

// ---------------------------------------------------------------------------
// Command detail view (the ? feature)
// ---------------------------------------------------------------------------

fn write_command_detail<W: OutputWriter + ?Sized>(
    meta: &CommandMeta,
    profile: &TerminalProfile,
    writer: &mut W,
) -> io::Result<()> {
    // ── Title ────────────────────────────────────────────────────────
    let icon = profile.resolve_glyph(&meta.category).unwrap_or_default();
    let title = if icon.is_empty() {
        format!("koi {}", meta.name)
    } else {
        format!("{} koi {}", icon, meta.name)
    };

    let mut title_style = TextStyle::plain();
    title_style.bold = true;
    if let Some(color) = meta.category.color().and_then(|c| profile.resolve_color(c)) {
        title_style.fg = Some(color);
    }
    writer.write_line(&[Segment::new(&title, title_style)])?;

    // ── Summary ──────────────────────────────────────────────────────
    writer.write_line(&[Segment::new(meta.summary, TextStyle::plain())])?;

    // ── Divider ──────────────────────────────────────────────────────
    let width = profile.width.map(|w| w as usize).unwrap_or(60).min(72);
    let mut divider_style = TextStyle::plain();
    divider_style.dim = true;
    writer.write_line(&[Segment::new("\u{2500}".repeat(width), divider_style)])?;

    // ── Long description ─────────────────────────────────────────────
    if !meta.long_description.is_empty() {
        writer.write_blank()?;
        for line in meta.long_description.lines() {
            writer.write_line(&[Segment::new(line, TextStyle::plain())])?;
        }
    }

    // ── Tags / metadata ──────────────────────────────────────────────
    let badges: Vec<&str> = meta.tags.iter().filter_map(|t| t.badge()).collect();
    let scope_badge = meta.scope.badge();
    if !badges.is_empty() || scope_badge.is_some() {
        writer.write_blank()?;
        let mut meta_header = TextStyle::plain();
        meta_header.bold = true;
        writer.write_line(&[Segment::new("Attributes", meta_header)])?;

        let mut segs = Vec::new();
        for tag in meta.tags {
            if let Some(badge) = tag.badge() {
                segs.push(badge_segment(profile, badge, *tag));
            }
        }
        if let Some(badge) = scope_badge {
            if !badges.contains(&badge) {
                segs.push(scope_segment(profile, badge, meta.scope));
            }
        }
        // Prepend indent
        segs.insert(0, Segment::new("  ", TextStyle::plain()));
        writer.write_line(&segs)?;
    }

    // ── Examples ──────────────────────────────────────────────────────
    if !meta.examples.is_empty() {
        writer.write_blank()?;
        let mut ex_header = TextStyle::plain();
        ex_header.bold = true;
        writer.write_line(&[Segment::new("Examples", ex_header)])?;

        let mut desc_style = TextStyle::plain();
        desc_style.dim = true;

        for example in meta.examples {
            writer.write_line(&[
                Segment::new(format!("  {}", example.command), TextStyle::plain()),
                Segment::new(format!("  # {}", example.description), desc_style),
            ])?;
        }
    }
    // ── HTTP API ─────────────────────────────────────────────────────
    if !meta.api.is_empty() {
        writer.write_blank()?;
        let mut api_header = TextStyle::plain();
        api_header.bold = true;
        writer.write_line(&[Segment::new("HTTP API", api_header)])?;

        let mut method_style = TextStyle::plain();
        method_style.bold = true;
        if let Some(color) = profile.resolve_color(Color::Info) {
            method_style.fg = Some(color);
        }

        for ep in meta.api {
            let ApiEndpoint { method, path } = ep;
            writer.write_line(&[
                Segment::new("  ", TextStyle::plain()),
                Segment::new(format!("{:<7}", method), method_style),
                Segment::new(format!(" {}", path), TextStyle::plain()),
            ])?;
        }
    }
    // ── See also ──────────────────────────────────────────────────────
    if !meta.see_also.is_empty() {
        writer.write_blank()?;
        let mut label_style = TextStyle::plain();
        label_style.dim = true;

        let related = meta
            .see_also
            .iter()
            .map(|s| format!("koi {s}?"))
            .collect::<Vec<_>>()
            .join(", ");
        writer.write_line(&[
            Segment::new("See also: ", label_style),
            Segment::new(related, TextStyle::plain()),
        ])?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn truncate_summary(
    summary: &str,
    name_width: usize,
    max_width: Option<usize>,
    indent: usize,
) -> String {
    let Some(width) = max_width else {
        return summary.to_string();
    };

    let prefix = indent + name_width + 2;
    if prefix >= width {
        return String::new();
    }

    let available = width.saturating_sub(prefix);
    let text_len = summary.chars().count();
    if text_len <= available {
        return summary.to_string();
    }

    let ellipsis = 3;
    if available <= ellipsis {
        return "...".to_string();
    }

    let keep = available - ellipsis;
    let truncated: String = summary.chars().take(keep).collect();
    format!("{truncated}...")
}
