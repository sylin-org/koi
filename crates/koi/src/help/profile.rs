//! Terminal capability detection + glyph/color resolution.
//!
//! Moved verbatim from the former `command-surface` crate (P09). Degrades
//! gracefully: non-interactive stdout, `NO_COLOR`, and `TERM=dumb` all fall back
//! to no-color / ASCII glyphs so the catalog stays readable when piped.

use super::glyph::{Color, Glyph, Presentation};
use is_terminal::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSupport {
    None,
    Basic16,
    Ansi256,
    TrueColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconSupport {
    Ascii,
    Unicode,
}

#[derive(Debug, Clone)]
pub struct TerminalProfile {
    pub color: ColorSupport,
    pub icons: IconSupport,
    pub width: Option<u16>,
    pub interactive: bool,
}

impl TerminalProfile {
    pub fn detect_stdout() -> Self {
        let stdout = std::io::stdout();
        let interactive = stdout.is_terminal();
        let color = detect_color_support(interactive);
        let icons = detect_icon_support(interactive);
        let width = terminal_size::terminal_size().map(|(w, _)| w.0);

        Self {
            color,
            icons,
            width,
            interactive,
        }
    }

    pub fn resolve_glyph(&self, g: &dyn Glyph) -> Option<String> {
        for p in g.presentations() {
            match (p, self.icons) {
                (Presentation::Emoji(s), IconSupport::Unicode) => return Some((*s).to_string()),
                (Presentation::Ascii(s), _) => return Some((*s).to_string()),
                _ => continue,
            }
        }
        None
    }

    pub fn resolve_color(&self, c: Color) -> Option<console::Color> {
        // Koi's palette has no RGB `Custom` colors, so every supported level maps
        // through the basic-16 table (the 256/truecolor distinction only mattered
        // for `Custom`). `None` support disables color entirely.
        match self.color {
            ColorSupport::None => None,
            ColorSupport::Basic16 | ColorSupport::Ansi256 | ColorSupport::TrueColor => {
                Some(color_to_basic(c))
            }
        }
    }
}

fn detect_color_support(interactive: bool) -> ColorSupport {
    if !interactive {
        return ColorSupport::None;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return ColorSupport::None;
    }

    let support = supports_color::on(supports_color::Stream::Stdout);
    match support {
        Some(info) if info.has_16m => ColorSupport::TrueColor,
        Some(info) if info.has_256 => ColorSupport::Ansi256,
        Some(_) => ColorSupport::Basic16,
        None => ColorSupport::None,
    }
}

fn detect_icon_support(interactive: bool) -> IconSupport {
    if !interactive {
        return IconSupport::Ascii;
    }

    let term = std::env::var("TERM").unwrap_or_default();
    if term.eq_ignore_ascii_case("dumb") {
        return IconSupport::Ascii;
    }

    IconSupport::Unicode
}

fn color_to_basic(color: Color) -> console::Color {
    match color {
        Color::Accent => console::Color::Blue,
        Color::Warning => console::Color::Yellow,
        Color::Danger => console::Color::Red,
        Color::Muted => console::Color::White,
        Color::Info => console::Color::Cyan,
    }
}
