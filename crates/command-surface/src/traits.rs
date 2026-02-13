use crate::Glyph;
use std::hash::Hash;

pub trait Category: Copy + Eq + Hash + Glyph + 'static {
    fn label(&self) -> &'static str;
    fn order(&self) -> u8;

    /// CLI prefix for commands in this category (e.g. "certmesh ", "mdns ").
    /// Used by compact/stripped rendering to derive short command names.
    fn cli_prefix(&self) -> &'static str {
        ""
    }

    /// Short CLI name shown in overview mode (e.g. "certmesh", "mdns").
    fn cli_name(&self) -> &'static str {
        self.label()
    }

    /// One-line description of what this category does.
    fn description(&self) -> &'static str {
        ""
    }
}

pub trait Tag: Copy + Eq + Hash + Glyph + 'static {
    fn label(&self) -> &'static str;

    /// Whether this tag conveys *actionable* information worth showing
    /// prominently (destructive, elevated, streaming).  Non-highlight tags
    /// (mutating, read-only, admin) are hidden in compact/highlight modes.
    fn highlight(&self) -> bool {
        true
    }
}

pub trait Scope: Copy + Eq + Hash + Glyph + 'static {
    fn label(&self) -> &'static str;

    /// Whether this is the default/public scope.  Commands with the default
    /// scope are shown first in compact summaries.
    fn is_default(&self) -> bool {
        true
    }
}
