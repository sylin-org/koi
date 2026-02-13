mod default;
mod profile;
pub mod writers;

pub use default::{
    write_catalog, write_command_detail, write_overview, write_summary_catalog, CatalogOptions,
};
pub use profile::{ColorSupport, IconSupport, TerminalProfile};

use std::io;

#[derive(Clone, Copy, Debug, Default)]
pub struct TextStyle {
    pub fg: Option<console::Color>,
    pub bold: bool,
    pub dim: bool,
}

impl TextStyle {
    pub fn plain() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub text: String,
    pub style: TextStyle,
}

impl Segment {
    pub fn new(text: impl Into<String>, style: TextStyle) -> Self {
        Self {
            text: text.into(),
            style,
        }
    }
}

pub trait OutputWriter {
    fn write_line(&mut self, segments: &[Segment]) -> io::Result<()>;

    fn write_blank(&mut self) -> io::Result<()> {
        self.write_line(&[])
    }
}
