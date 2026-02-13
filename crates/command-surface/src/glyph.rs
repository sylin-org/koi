#[derive(Debug, Clone, Copy)]
pub enum Presentation {
    NerdFont(&'static str),
    Emoji(&'static str),
    Ascii(&'static str),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Color {
    Accent,
    Success,
    Warning,
    Danger,
    Muted,
    Info,
    Custom(u8, u8, u8),
}

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
