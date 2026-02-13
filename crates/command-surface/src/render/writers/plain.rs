use crate::render::{OutputWriter, Segment};
use std::io::{self, Write};

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
