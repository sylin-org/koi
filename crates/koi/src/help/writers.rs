//! Styled-segment output model + the two concrete writers (ANSI / plain).
//!
//! Moved verbatim from the former `command-surface` crate (P09). A line is a list
//! of [`Segment`]s, each with a [`TextStyle`]. [`AnsiWriter`] applies the style via
//! `console`; [`PlainWriter`] drops styling for non-interactive / `NO_COLOR` output.

use std::io::{self, Write};

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

pub struct AnsiWriter<'a> {
    out: &'a mut dyn Write,
}

impl<'a> AnsiWriter<'a> {
    pub fn new(out: &'a mut dyn Write) -> Self {
        Self { out }
    }
}

impl OutputWriter for AnsiWriter<'_> {
    fn write_line(&mut self, segments: &[Segment]) -> io::Result<()> {
        use console::Style;
        for segment in segments {
            let mut style = Style::new();
            if let Some(color) = segment.style.fg {
                style = style.fg(color);
            }
            if segment.style.bold {
                style = style.bold();
            }
            if segment.style.dim {
                style = style.dim();
            }

            write!(self.out, "{}", style.apply_to(&segment.text))?;
        }
        writeln!(self.out)?;
        Ok(())
    }
}

pub struct PlainWriter<'a> {
    out: &'a mut dyn Write,
}

impl<'a> PlainWriter<'a> {
    pub fn new(out: &'a mut dyn Write) -> Self {
        Self { out }
    }
}

impl OutputWriter for PlainWriter<'_> {
    fn write_line(&mut self, segments: &[Segment]) -> io::Result<()> {
        for segment in segments {
            write!(self.out, "{}", segment.text)?;
        }
        writeln!(self.out)?;
        Ok(())
    }
}
