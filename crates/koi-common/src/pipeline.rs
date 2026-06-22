use serde::Serialize;

/// A response envelope. `#[serde(flatten)]` emits the body's fields at the top
/// level (no `{"body": …}` nesting), so a response serializes as just its body.
///
/// Generic over `B` so each domain provides its own response body type.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineResponse<B: Serialize> {
    #[serde(flatten)]
    pub body: B,
}

impl<B: Serialize> PipelineResponse<B> {
    /// Wrap a response body for the wire.
    pub fn clean(body: B) -> Self {
        Self { body }
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
    fn flatten_produces_flat_json_not_nested_body() {
        let resp = PipelineResponse::clean(TestBody {
            value: "flat".into(),
        });
        let json = serde_json::to_value(&resp).unwrap();
        // The body's fields appear at the top level; there is no `body` wrapper key.
        assert_eq!(json.get("value").unwrap(), "flat");
        assert!(json.get("body").is_none());
    }
}
