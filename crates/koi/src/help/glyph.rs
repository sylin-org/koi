//! Glyph + color model for the help renderer.
//!
//! Folded in from the former `command-surface` crate (P09) and trimmed to the
//! subset Koi's glyphs actually use: `Presentation` carries an ordered list of
//! icon renderings (Emoji → Ascii) resolved against the detected
//! [`TerminalProfile`](super::profile::TerminalProfile); `Color` is a semantic
//! intent mapped to a concrete `console::Color` at render time. (The generic
//! crate also had NerdFont/None presentations and RGB `Custom` colors — no Koi
//! glyph used them, so they were dropped.)

#[derive(Debug, Clone, Copy)]
pub enum Presentation {
    Emoji(&'static str),
    Ascii(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Color {
    Accent,
    Warning,
    Danger,
    Muted,
    Info,
}

/// Carries the ordered icon presentations and semantic color for a renderable
/// metadata axis (category / tag / scope).
pub trait Glyph {
    fn presentations(&self) -> &'static [Presentation] {
        &[]
    }

    fn color(&self) -> Option<Color> {
        None
    }

    fn badge(&self) -> Option<&'static str> {
        None
    }
}
