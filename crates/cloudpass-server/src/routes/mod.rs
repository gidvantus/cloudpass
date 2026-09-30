//! API routes.

pub mod accounts;
pub mod meta;
pub mod sync;

use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

use crate::state::AppState;

/// Builds the whole API.
///
/// Public routes do what their name says: `prelogin`, registration and login are the
/// only things reachable without a session token. Everything that touches stored
/// data sits behind [`crate::auth::AuthSession`].
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/meta", get(meta::meta))
        .route("/api/v1/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/api/v1/accounts/register/start",
            post(accounts::register_start),
        )
        .route(
            "/api/v1/accounts/register/finish",
            post(accounts::register_finish),
        )
        .route("/api/v1/accounts/login/start", post(accounts::login_start))
        .route(
            "/api/v1/accounts/login/finish",
            post(accounts::login_finish),
        )
        .route(
            "/api/v1/accounts/key-envelope",
            get(accounts::get_key_envelope),
        )
        // Replacing a credential. Public on purpose: the OPAQUE exchange inside these
        // two requests *is* the authentication, and a bearer token is deliberately not
        // accepted — see the module documentation in `accounts.rs`.
        .route(
            "/api/v1/accounts/credentials/start",
            post(accounts::credentials_start),
        )
        .route(
            "/api/v1/accounts/credentials/finish",
            post(accounts::credentials_finish),
        )
        // Signing in with a recovery key, and replacing both credentials at once. Also
        // public, because the user this exists for has no password to authenticate with.
        .route(
            "/api/v1/accounts/recovery/start",
            post(accounts::recovery_start),
        )
        .route(
            "/api/v1/accounts/recovery/finish",
            post(accounts::recovery_finish),
        )
        .route("/api/v1/devices", get(accounts::list_devices))
        .route(
            "/api/v1/vaults",
            post(sync::create_vault).get(sync::list_vaults),
        )
        .route("/api/v1/sync/push", post(sync::push))
        .route("/api/v1/sync/pull", get(sync::pull))
        // Everything that is not an API route is the web portal. A fallback rather than a
        // wildcard route, so a new API path can never be shadowed by a file of the same
        // name — the API is matched first, always.
        .fallback(crate::static_files::serve)
        .with_state(state)
}
