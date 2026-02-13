use crate::{Color, Glyph, Presentation};
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
    NerdFont,
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
                (Presentation::NerdFont(s), IconSupport::NerdFont) => {
                    return Some((*s).to_string())
                }
                (Presentation::Emoji(s), IconSupport::Unicode | IconSupport::NerdFont) => {
                    return Some((*s).to_string())
                }
                (Presentation::Ascii(s), _) => return Some((*s).to_string()),
                (Presentation::None, _) => return None,
                _ => continue,
            }
        }
        None
    }

    pub fn resolve_color(&self, c: Color) -> Option<console::Color> {
        match self.color {
            ColorSupport::None => None,
            ColorSupport::Basic16 => Some(color_to_basic(c)),
            ColorSupport::Ansi256 => Some(color_to_256(c)),
            ColorSupport::TrueColor => Some(color_to_rgb(c)),
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

    let nerd = std::env::var("KOI_NERDFONT")
        .or_else(|_| std::env::var("NERD_FONT"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if nerd {
        IconSupport::NerdFont
    } else {
        IconSupport::Unicode
    }
}

fn color_to_basic(color: Color) -> console::Color {
    match color {
        Color::Accent => console::Color::Blue,
        Color::Success => console::Color::Green,
        Color::Warning => console::Color::Yellow,
        Color::Danger => console::Color::Red,
        Color::Muted => console::Color::White,
        Color::Info => console::Color::Cyan,
        Color::Custom(_, _, _) => console::Color::White,
    }
}

fn color_to_256(color: Color) -> console::Color {
    match color {
        Color::Custom(r, g, b) => console::Color::Color256(rgb_to_ansi256(r, g, b)),
        _ => color_to_basic(color),
    }
}

fn color_to_rgb(color: Color) -> console::Color {
    match color {
        Color::Custom(r, g, b) => console::Color::Color256(rgb_to_ansi256(r, g, b)),
        _ => color_to_basic(color),
    }
}

fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    if r == g && g == b {
        if r < 8 {
            return 16;
        }
        if r > 248 {
            return 231;
        }
        return 232 + ((r as u16 - 8) / 10) as u8;
    }

    let r = ((r as f32 / 255.0) * 5.0).round() as u8;
    let g = ((g as f32 / 255.0) * 5.0).round() as u8;
    let b = ((b as f32 / 255.0) * 5.0).round() as u8;
    16 + (36 * r) + (6 * g) + b
}
