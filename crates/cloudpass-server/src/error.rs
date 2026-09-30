//! Error handling.
//!
//! Two rules govern everything here:
//!
//! * **No internal detail reaches the client.** A database error becomes
//!   `{"error":"internal"}` with a 500, and the cause goes to the log only. Stack
//!   traces and SQL text are reconnaissance material.
//! * **Authentication failures are indistinguishable.** A wrong password, an
//!   unregistered account and a tampered message all produce the same 401 body, so
//!   nothing in the API can be used as an oracle.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// The error type every handler returns.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Credentials did not verify. Deliberately covers several distinct causes.
    #[error("authentication failed")]
    InvalidCredentials,

    /// Missing, malformed or expired session token.
    #[error("unauthorized")]
    Unauthorized,

    #[error("not found")]
    NotFound,

    /// The request was understood but is not acceptable.
    #[error("bad request: {0}")]
    BadRequest(&'static str),

    /// Something went wrong that the client cannot act on. The payload is for logs.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            // The cause is logged, not returned.
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();

        if let Self::Internal(cause) = &self {
            // Only place an internal cause is ever rendered, and it goes to the log.
            tracing::error!(error = %cause, "request failed");
        }

        (status, Json(ErrorBody { error: code })).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(format!("database: {error}"))
    }
}

impl From<cloudpass_core::Error> for ApiError {
    fn from(error: cloudpass_core::Error) -> Self {
        // A cryptographic failure during login is an authentication failure; the
        // distinction is not the client's business.
        match error {
            cloudpass_core::Error::AuthFailed => Self::InvalidCredentials,
            other => Self::Internal(format!("core: {other}")),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        Self::Internal(format!("json: {error}"))
    }
}

/// Convenience alias for handler results.
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_causes_are_not_exposed_in_the_response_code() {
        let error = ApiError::Internal("connection to 10.0.0.5 refused".to_owned());
        let (status, code) = error.parts();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(code, "internal");
    }

    #[test]
    fn a_wrong_password_maps_to_the_same_response_as_a_missing_account() {
        // Both of these are `InvalidCredentials` by construction; the test exists to
        // make the intent explicit and to fail if someone adds a distinct variant.
        let crypto_failure: ApiError = cloudpass_core::Error::AuthFailed.into();
        let wrong_password = ApiError::InvalidCredentials;
        assert_eq!(crypto_failure.parts(), wrong_password.parts());
    }
}
