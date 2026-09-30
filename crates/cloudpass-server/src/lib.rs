//! CloudPass sync server.
//!
//! The whole point of this crate is what it *cannot* do. It stores opaque envelopes,
//! ordering metadata and OPAQUE registration records. It has no code path that could
//! decrypt an item, because it never receives a key: the client's wrapped user key
//! lives in a column as bytes, and the master password never leaves the device.
//!
//! Layering:
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`codec`] | base64 wire encoding, identifier normalisation, time |
//! | [`db`] | schema and the few storage primitives |
//! | [`state`] | shared application state and the fake-salt derivation |
//! | [`auth`] | session tokens, device registration, the auth extractor |
//! | [`routes`] | the HTTP surface |
//! | [`static_files`] | the web portal, served from disk |
//! | [`downloads`] | the desktop build this server offers, described and hashed |
//!
//! [`error`] is worth reading before adding an endpoint: it is what keeps internal
//! failures and credential failures from turning into an oracle.

#![forbid(unsafe_code)]

pub mod auth;
pub mod codec;
pub mod db;
pub mod downloads;
pub mod error;
pub mod routes;
pub mod state;
pub mod static_files;

use std::sync::Arc;

pub use error::{ApiError, ApiResult};
pub use state::AppState;

/// Builds the complete application.
///
/// Kept separate from `main` so tests can drive the real router in-process, with the
/// real middleware, without binding a port.
pub fn app(state: Arc<AppState>) -> axum::Router {
    routes::router(state)
}
