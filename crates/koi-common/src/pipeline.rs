use serde::Serialize;

/// Pipeline status for streaming responses.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PipelineStatus {
    Ongoing,
    Finished,
}

/// A response with optional pipeline metadata.
/// `#[serde(flatten)]` on body produces flat JSON output.
/// `skip_serializing_if` on status/warning means clean responses have no extra keys.
///
/// Generic over `B` so each domain provides its own response body type.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineResponse<B: Serialize> {
    #[serde(flatten)]
    pub body: B,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<PipelineStatus>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl<B: Serialize> PipelineResponse<B> {
    /// Wrap a response with no pipeline metadata (the happy path).
    pub fn clean(body: B) -> Self {
        Self {
            body,
            status: None,
            warning: None,
        }
    }

    /// Wrap a response with an ongoing status.
    #[allow(dead_code)]
    pub fn ongoing(body: B) -> Self {
        Self {
            body,
            status: Some(PipelineStatus::Ongoing),
            warning: None,
        }
    }

    /// Wrap a response with a finished status.
    #[allow(dead_code)]
    pub fn finished(body: B) -> Self {
        Self {
            body,
            status: Some(PipelineStatus::Finished),
            warning: None,
        }
    }

    /// Attach a warning to this response.
    #[allow(dead_code)]
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warning = Some(warning.into());
        self
    }
}
