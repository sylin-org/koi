use crate::render::{OutputWriter, Segment};
use console::Style;
use std::io::{self, Write};

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
