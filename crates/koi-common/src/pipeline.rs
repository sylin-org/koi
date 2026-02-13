use serde::Serialize;
use utoipa::ToSchema;

/// Pipeline status for streaming responses.
#[derive(Debug, Clone, Serialize, PartialEq, ToSchema)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal body type for testing PipelineResponse serialization.
    #[derive(Debug, Clone, Serialize)]
    struct TestBody {
        value: String,
    }

    #[test]
    fn clean_response_omits_status_and_warning() {
        let resp = PipelineResponse::clean(TestBody {
            value: "hello".into(),
        });
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.get("value").unwrap(), "hello");
        assert!(!obj.contains_key("status"), "clean should omit status");
        assert!(!obj.contains_key("warning"), "clean should omit warning");
    }

    #[test]
    fn ongoing_response_includes_status_ongoing() {
        let resp = PipelineResponse::ongoing(TestBody {
            value: "data".into(),
        });
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("status").unwrap(), "ongoing");
        assert!(!json.as_object().unwrap().contains_key("warning"));
    }

    #[test]
    fn finished_response_includes_status_finished() {
        let resp = PipelineResponse::finished(TestBody {
            value: "data".into(),
        });
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("status").unwrap(), "finished");
    }

    #[test]
    fn with_warning_attaches_warning_field() {
        let resp = PipelineResponse::clean(TestBody {
            value: "data".into(),
        })
        .with_warning("something unusual");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("warning").unwrap(), "something unusual");
    }

    #[test]
    fn flatten_produces_flat_json_not_nested_body() {
        let resp = PipelineResponse::clean(TestBody {
            value: "flat".into(),
        });
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("value").is_some());
        assert!(json.get("body").is_none());
    }

    #[test]
    fn ongoing_with_warning_includes_both() {
        let resp =
            PipelineResponse::ongoing(TestBody { value: "x".into() }).with_warning("heads up");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("status").unwrap(), "ongoing");
        assert_eq!(json.get("warning").unwrap(), "heads up");
        assert_eq!(json.get("value").unwrap(), "x");
    }

    #[test]
    fn pipeline_status_serializes_to_lowercase() {
        assert_eq!(
            serde_json::to_value(PipelineStatus::Ongoing).unwrap(),
            serde_json::json!("ongoing")
        );
        assert_eq!(
            serde_json::to_value(PipelineStatus::Finished).unwrap(),
            serde_json::json!("finished")
        );
    }
}
