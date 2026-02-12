use serde::{Deserialize, Serialize};

use crate::error::ErrorCode;

/// Standard error body for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
    pub message: String,
}

pub fn error_body(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        error: code,
        message: message.into(),
    }
}
