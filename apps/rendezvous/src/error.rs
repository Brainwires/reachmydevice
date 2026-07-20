//! Error type mapped to HTTP responses.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Application error; converts to a JSON HTTP error response.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("registration is closed")]
    RegistrationClosed,
    #[error("too many attempts; retry in {0}s")]
    TooManyRequests(u64),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::RegistrationClosed => {
                (StatusCode::FORBIDDEN, "registration is closed".into())
            }
            AppError::TooManyRequests(secs) => (
                StatusCode::TOO_MANY_REQUESTS,
                format!("too many attempts; retry in {secs}s"),
            ),
            // Never leak internal details to clients; log them instead.
            AppError::Db(e) => {
                tracing::error!(error = %e, "database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
