use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::api::{error_body, ErrorBody};
use crate::error::ErrorCode;

pub fn error_response(code: ErrorCode, message: impl Into<String>) -> axum::response::Response {
    let status = StatusCode::from_u16(code.http_status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    error_response_with_status(status, code, message)
}

pub fn error_response_with_status(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
) -> axum::response::Response {
    let body: ErrorBody = error_body(code, message);
    (status, Json(body)).into_response()
}
