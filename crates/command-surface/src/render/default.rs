use crate::{Category, CommandDef, CommandManifest, Scope, Tag};
use std::io;

use super::{OutputWriter, Segment, TerminalProfile, TextStyle};

#[derive(Clone, Copy, Debug)]
pub struct CatalogOptions {
    pub include_tags: bool,
    pub include_scope: bool,
    /// Only render tags where `Tag::highlight()` is true (destructive,
    /// elevated, streaming).  Suppresses noise like mutating / read-only.
    pub highlight_only: bool,
    /// Strip the category's `cli_prefix()` from displayed command names.
    /// Turns "certmesh backup" → "backup" when inside the certmesh view.
    pub strip_prefix: bool,
    pub indent: usize,
}

impl Default for CatalogOptions {
    fn default() -> Self {
        Self {
            include_tags: true,
            include_scope: true,
            highlight_only: false,
            strip_prefix: false,
            indent: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Full catalog (one command per line)
// ---------------------------------------------------------------------------

pub fn write_catalog<C, T, S, W>(
    manifest: &CommandManifest<C, T, S>,
    profile: &TerminalProfile,
    writer: &mut W,
    options: CatalogOptions,
) -> io::Result<()>
where
    C: Category,
    T: Tag,
    S: Scope,
    W: OutputWriter + ?Sized,
{
    let display_name = |def: &CommandDef<C, T, S>| -> String {
        if options.strip_prefix {
            let prefix = def.category.cli_prefix();
            def.name
                .strip_prefix(prefix)
                .unwrap_or(def.name)
                .to_string()
        } else {
            def.name.to_string()
        }
    };

    let name_width = manifest
        .all_sorted()
        .iter()
        .map(|def| display_name(def).len())
        .max()
        .unwrap_or(0);
    let max_width = profile.width.map(|w| w as usize);

    for (cat_index, category) in manifest.categories_in_order().iter().enumerate() {
        if cat_index > 0 {
            writer.write_blank()?;
        }

        let header = format_header(profile, *category);
        writer.write_line(&header)?;

        for def in manifest.by_category(*category) {
            let dname = display_name(def);
            let line = format_command_line(profile, def, &dname, name_width, max_width, options);
            writer.write_line(&line)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Compact summary (one category per line, command names joined with ·)
// ---------------------------------------------------------------------------

pub fn write_summary_catalog<C, T, S, W>(
    manifest: &CommandManifest<C, T, S>,
    profile: &TerminalProfile,
    writer: &mut W,
    max_per_category: usize,
) -> io::Result<()>
where
    C: Category,
    T: Tag,
    S: Scope,
    W: OutputWriter + ?Sized,
{
    let categories = manifest.categories_in_order();

    // Compute label column width (icon + label)
    let label_width = categories
        .iter()
        .map(|cat| {
            let icon_len = profile
                .resolve_glyph(cat)
                .map(|s| s.chars().count() + 1) // +1 for space
                .unwrap_or(0);
            icon_len + cat.label().chars().count()
        })
        .max()
        .unwrap_or(0);

    for (cat_index, category) in categories.iter().enumerate() {
        if cat_index > 0 {
            writer.write_blank()?;
        }

        // Sort: default-scope first, then alphabetically
        let mut defs = manifest.by_category(*category);
        defs.sort_by(|a, b| {
            let a_default = a.scope.is_default();
            let b_default = b.scope.is_default();
            b_default.cmp(&a_default).then_with(|| a.name.cmp(b.name))
        });

        let prefix = category.cli_prefix();
        let short_names: Vec<&str> = defs
            .iter()
            .map(|d| d.name.strip_prefix(prefix).unwrap_or(d.name))
            .collect();

        let total = short_names.len();
        let show = if total <= max_per_category + 2 {
            // If overflow is tiny (≤2), just show all
            total
        } else {
            max_per_category
        };

        let visible: Vec<&str> = short_names[..show].to_vec();
        let overflow = total.saturating_sub(show);

        // Build icon + label segment
        let mut label_text = String::new();
        if let Some(icon) = profile.resolve_glyph(category) {
            label_text.push_str(&icon);
            label_text.push(' ');
        }
        label_text.push_str(category.label());

        // Pad label to alignment
        let label_chars = label_text.chars().count();
        let pad = label_width.saturating_sub(label_chars) + 4; // 4 extra spaces gap
        for _ in 0..pad {
            label_text.push(' ');
        }

        let mut label_style = TextStyle::plain();
        label_style.bold = true;
        if let Some(color) = category.color().and_then(|c| profile.resolve_color(c)) {
            label_style.fg = Some(color);
        }

        let cmd_text = visible.join(" · ");
        let overflow_text = if overflow > 0 {
            format!("  +{overflow} more")
        } else {
            String::new()
        };

        let mut overflow_style = TextStyle::plain();
        overflow_style.dim = true;

        writer.write_line(&[
            Segment::new(label_text, label_style),
            Segment::new(cmd_text, TextStyle::plain()),
            Segment::new(overflow_text, overflow_style),
        ])?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Overview (one line per category: icon + CLI name + description)
// ---------------------------------------------------------------------------

pub fn write_overview<C, T, S, W>(
    manifest: &CommandManifest<C, T, S>,
    profile: &TerminalProfile,
    writer: &mut W,
) -> io::Result<()>
where
    C: Category,
    T: Tag,
    S: Scope,
    W: OutputWriter + ?Sized,
{
    let categories = manifest.categories_in_order();

    // Column width based on cli_name
    let name_width = categories
        .iter()
        .map(|cat| cat.cli_name().len())
        .max()
        .unwrap_or(0);

    for category in &categories {
        let cli_name = category.cli_name();
        let description = category.description();
        let count = manifest.by_category(*category).len();

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

fn format_header<C: Category>(profile: &TerminalProfile, category: C) -> Vec<Segment> {
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

fn format_command_line<C, T, S>(
    profile: &TerminalProfile,
    def: &CommandDef<C, T, S>,
    display_name: &str,
    name_width: usize,
    max_width: Option<usize>,
    options: CatalogOptions,
) -> Vec<Segment>
where
    C: Category,
    T: Tag,
    S: Scope,
{
    let indent = " ".repeat(options.indent);
    let summary = truncate_summary(def.summary, name_width, max_width, options.indent);
    let base = format!(
        "{indent}{:<width$}  {summary}",
        display_name,
        width = name_width
    );

    let mut segments = vec![Segment::new(base, TextStyle::plain())];

    // Collect tag badge texts so we can deduplicate against scope below
    let mut rendered_badges: Vec<&str> = Vec::new();

    if options.include_tags {
        for tag in def.tags {
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
        if let Some(badge) = def.scope.badge() {
            // Skip scope badge if a tag already rendered the same text
            if !rendered_badges.contains(&badge) {
                segments.push(scope_segment(profile, badge, def.scope));
            }
        }
    }

    segments
}

fn badge_segment<T: Tag>(profile: &TerminalProfile, badge: &str, tag: T) -> Segment {
    let mut style = TextStyle::plain();
    style.dim = true;

    if let Some(color) = tag.color().and_then(|c| profile.resolve_color(c)) {
        style.fg = Some(color);
        if matches!(
            tag.color(),
            Some(crate::Color::Danger | crate::Color::Warning)
        ) {
            style.bold = true;
            style.dim = false;
        }
    }

    Segment::new(format!("  [{badge}]"), style)
}

fn scope_segment<S: Scope>(profile: &TerminalProfile, badge: &str, scope: S) -> Segment {
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

pub fn write_command_detail<C, T, S, W>(
    def: &CommandDef<C, T, S>,
    profile: &TerminalProfile,
    writer: &mut W,
) -> io::Result<()>
where
    C: Category,
    T: Tag,
    S: Scope,
    W: OutputWriter + ?Sized,
{
    // ── Title ────────────────────────────────────────────────────────
    let icon = profile.resolve_glyph(&def.category).unwrap_or_default();
    let title = if icon.is_empty() {
        format!("koi {}", def.name)
    } else {
        format!("{} koi {}", icon, def.name)
    };

    let mut title_style = TextStyle::plain();
    title_style.bold = true;
    if let Some(color) = def.category.color().and_then(|c| profile.resolve_color(c)) {
        title_style.fg = Some(color);
    }
    writer.write_line(&[Segment::new(&title, title_style)])?;

    // ── Summary ──────────────────────────────────────────────────────
    writer.write_line(&[Segment::new(def.summary, TextStyle::plain())])?;

    // ── Divider ──────────────────────────────────────────────────────
    let width = profile.width.map(|w| w as usize).unwrap_or(60).min(72);
    let mut divider_style = TextStyle::plain();
    divider_style.dim = true;
    writer.write_line(&[Segment::new("\u{2500}".repeat(width), divider_style)])?;

    // ── Long description ─────────────────────────────────────────────
    if !def.long_description.is_empty() {
        writer.write_blank()?;
        for line in def.long_description.lines() {
            writer.write_line(&[Segment::new(line, TextStyle::plain())])?;
        }
    }

    // ── Tags / metadata ──────────────────────────────────────────────
    let badges: Vec<&str> = def.tags.iter().filter_map(|t| t.badge()).collect();
    let scope_badge = def.scope.badge();
    if !badges.is_empty() || scope_badge.is_some() {
        writer.write_blank()?;
        let mut meta_header = TextStyle::plain();
        meta_header.bold = true;
        writer.write_line(&[Segment::new("Attributes", meta_header)])?;

        let mut segs = Vec::new();
        for tag in def.tags {
            if let Some(badge) = tag.badge() {
                segs.push(badge_segment(profile, badge, *tag));
            }
        }
        if let Some(badge) = scope_badge {
            if !badges.contains(&badge) {
                segs.push(scope_segment(profile, badge, def.scope));
            }
        }
        // Prepend indent
        segs.insert(0, Segment::new("  ", TextStyle::plain()));
        writer.write_line(&segs)?;
    }

    // ── Examples ──────────────────────────────────────────────────────
    if !def.examples.is_empty() {
        writer.write_blank()?;
        let mut ex_header = TextStyle::plain();
        ex_header.bold = true;
        writer.write_line(&[Segment::new("Examples", ex_header)])?;

        let mut desc_style = TextStyle::plain();
        desc_style.dim = true;

        for example in def.examples {
            writer.write_line(&[
                Segment::new(format!("  {}", example.command), TextStyle::plain()),
                Segment::new(format!("  # {}", example.description), desc_style),
            ])?;
        }
    }
    // ── HTTP API ─────────────────────────────────────────────────────
    if !def.api.is_empty() {
        writer.write_blank()?;
        let mut api_header = TextStyle::plain();
        api_header.bold = true;
        writer.write_line(&[Segment::new("HTTP API", api_header)])?;

        let mut method_style = TextStyle::plain();
        method_style.bold = true;
        if let Some(color) = profile.resolve_color(crate::Color::Info) {
            method_style.fg = Some(color);
        }

        for ep in def.api {
            writer.write_line(&[
                Segment::new("  ", TextStyle::plain()),
                Segment::new(format!("{:<7}", ep.method), method_style),
                Segment::new(format!(" {}", ep.path), TextStyle::plain()),
            ])?;
        }
    }
    // ── See also ──────────────────────────────────────────────────────
    if !def.see_also.is_empty() {
        writer.write_blank()?;
        let mut label_style = TextStyle::plain();
        label_style.dim = true;

        let related = def
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
