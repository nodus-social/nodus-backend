//! One error type for the whole surface.
//!
//! Mastodon clients read `{"error": "…"}` and switch on the status code, so a handler
//! never returns a bare status: the body always names what went wrong, and the status
//! always matches the kind.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// A client-visible failure.
#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    #[must_use]
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }

    /// `401` — no token, or a token that no longer resolves.
    #[must_use]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    /// `403` — authenticated, but the token lacks the scope.
    #[must_use]
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// `404` — includes "exists but is invisible to you", deliberately.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// `422` — the request parsed but is invalid; `error` names the field.
    #[must_use]
    pub fn unprocessable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, message)
    }

    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

/// A database failure is a `500` with a generic body: the detail goes to the log, not
/// to the client, because it names tables and columns.
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "database error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong on our side")
    }
}

/// Result alias used by handlers.
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn an_error_body_names_the_failure() {
        let response = ApiError::not_found("Record not found").into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), 1024).await.expect("body");
        assert_eq!(String::from_utf8_lossy(&body), r#"{"error":"Record not found"}"#);
    }
}
