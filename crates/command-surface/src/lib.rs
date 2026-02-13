mod glyph;
mod traits;

pub use glyph::{Color, Glyph, Presentation};
pub use traits::{Category, Scope, Tag};

#[cfg(feature = "render")]
pub mod render;

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

#[derive(Clone, Copy, Debug)]
pub struct Example {
    pub command: &'static str,
    pub description: &'static str,
}

/// Pre-invocation confirmation gate.
///
/// Declared in the command manifest and checked by the CLI dispatch layer
/// *before* the handler runs.  Has no effect on HTTP endpoints — the API
/// is not interactive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirmation {
    /// Prompt the user to type an exact token (e.g. `"RESET"`).
    ///
    /// The `message` is printed to stderr first, then the user is asked
    /// to type `token`.  Any other input aborts.
    TypeToken {
        message: &'static str,
        token: &'static str,
    },
    /// Simple yes/no prompt.  The `message` is shown, and the user must
    /// type `y` or `yes` (case-insensitive) to proceed.
    YesNo { message: &'static str },
}

impl Confirmation {
    /// Run the confirmation prompt on the given reader/writer pair.
    ///
    /// Returns `Ok(true)` if the user confirmed, `Ok(false)` if they
    /// declined, and `Err` on I/O failure.
    pub fn prompt<R: BufRead, W: Write>(&self, reader: &mut R, writer: &mut W) -> io::Result<bool> {
        match self {
            Confirmation::TypeToken { message, token } => {
                writeln!(writer, "{message}")?;
                write!(writer, "Type {token} to continue: ")?;
                writer.flush()?;
                let mut line = String::new();
                reader.read_line(&mut line)?;
                Ok(line.trim() == *token)
            }
            Confirmation::YesNo { message } => {
                write!(writer, "{message} [y/N] ")?;
                writer.flush()?;
                let mut line = String::new();
                reader.read_line(&mut line)?;
                let answer = line.trim().to_ascii_lowercase();
                Ok(answer == "y" || answer == "yes")
            }
        }
    }

    /// Convenience: prompt on real stdin/stderr.
    pub fn prompt_stdio(&self) -> io::Result<bool> {
        let mut stdin = io::stdin().lock();
        let mut stderr = io::stderr();
        self.prompt(&mut stdin, &mut stderr)
    }
}

/// A query parameter for an HTTP API endpoint.
#[derive(Clone, Copy, Debug)]
pub struct QueryParam {
    pub name: &'static str,
    /// OpenAPI type: `"string"`, `"integer"`, or `"boolean"`.
    pub param_type: &'static str,
    pub required: bool,
    pub description: &'static str,
}

/// An HTTP API endpoint — single source of truth for path, method,
/// request/response schemas, query parameters, and content type.
///
/// The manifest-driven OpenAPI generator reads these at startup to
/// produce the entire `/openapi.json` spec dynamically, so there is
/// never a second declaration of the same route.
#[derive(Clone, Copy, Debug)]
pub struct ApiEndpoint {
    pub method: &'static str,
    pub path: &'static str,
    /// OpenAPI tag for grouping (e.g. `"mdns"`, `"certmesh"`).
    pub tag: &'static str,
    /// One-line HTTP-specific summary for the OpenAPI operation.
    pub summary: &'static str,
    /// Schema name of the JSON request body, if any (e.g. `"JoinRequest"`).
    pub request_body: Option<&'static str>,
    /// Schema name of the JSON response body, if any (e.g. `"JoinResponse"`).
    pub response_body: Option<&'static str>,
    /// Query parameters for the endpoint (&[] if none).
    pub query_params: &'static [QueryParam],
    /// Override the default `application/json` content type
    /// (e.g. `Some("text/event-stream")` for SSE endpoints).
    pub content_type: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct CommandDef<C: Category, T: Tag, S: Scope> {
    pub name: &'static str,
    pub summary: &'static str,
    pub category: C,
    pub tags: &'static [T],
    pub scope: S,
    pub examples: &'static [Example],
    pub see_also: &'static [&'static str],
    /// Multi-paragraph explanation shown by the `?` detail view.
    /// Lines are separated by `\n`. Empty string means no detail available.
    pub long_description: &'static str,
    /// HTTP API equivalents. Empty slice means CLI-only.
    pub api: &'static [ApiEndpoint],
    /// Optional pre-invocation confirmation gate (CLI-only).
    ///
    /// When set, the CLI dispatch layer should call
    /// [`Confirmation::prompt_stdio`] before running the command handler.
    /// The HTTP API ignores this field entirely.
    pub confirmation: Option<Confirmation>,
}

impl<C: Category, T: Tag, S: Scope> CommandDef<C, T, S> {
    /// Returns `true` if this command requires interactive confirmation
    /// before execution.
    pub fn requires_confirmation(&self) -> bool {
        self.confirmation.is_some()
    }

    /// Run the confirmation gate if one is defined.
    ///
    /// Returns `Ok(true)` if no confirmation is needed or the user confirmed,
    /// `Ok(false)` if the user declined.
    pub fn gate(&self) -> io::Result<bool> {
        match &self.confirmation {
            None => Ok(true),
            Some(c) => c.prompt_stdio(),
        }
    }
}

#[derive(Default)]
pub struct CommandManifest<C: Category, T: Tag, S: Scope> {
    commands: HashMap<&'static str, CommandDef<C, T, S>>,
}

impl<C: Category, T: Tag, S: Scope> CommandManifest<C, T, S> {
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
        }
    }

    pub fn add(&mut self, def: CommandDef<C, T, S>) -> &mut Self {
        let previous = self.commands.insert(def.name, def);
        debug_assert!(previous.is_none(), "duplicate command name: {}", def.name);
        self
    }

    pub fn get(&self, name: &str) -> Option<&CommandDef<C, T, S>> {
        self.commands.get(name)
    }

    pub fn all_sorted(&self) -> Vec<&CommandDef<C, T, S>> {
        let mut items: Vec<_> = self.commands.values().collect();
        items.sort_by_key(|def| (def.category.order(), def.name));
        items
    }

    pub fn by_category(&self, cat: C) -> Vec<&CommandDef<C, T, S>> {
        let mut items: Vec<_> = self
            .commands
            .values()
            .filter(|def| def.category == cat)
            .collect();
        items.sort_by_key(|def| def.name);
        items
    }

    pub fn by_tag(&self, tag: T) -> Vec<&CommandDef<C, T, S>> {
        let mut items: Vec<_> = self
            .commands
            .values()
            .filter(|def| def.tags.contains(&tag))
            .collect();
        items.sort_by_key(|def| def.name);
        items
    }

    pub fn by_scope(&self, scope: S) -> Vec<&CommandDef<C, T, S>> {
        let mut items: Vec<_> = self
            .commands
            .values()
            .filter(|def| def.scope == scope)
            .collect();
        items.sort_by_key(|def| def.name);
        items
    }

    pub fn categories_in_order(&self) -> Vec<C> {
        let mut categories = Vec::new();
        for def in self.commands.values() {
            if !categories.contains(&def.category) {
                categories.push(def.category);
            }
        }
        categories.sort_by_key(|cat| cat.order());
        categories
    }
}
