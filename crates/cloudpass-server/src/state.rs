//! Shared application state.

use std::path::PathBuf;
use std::sync::Arc;

use cloudpass_core::opaque::server::ServerSetupState;
use sqlx::SqlitePool;

use crate::db;
use crate::error::ApiResult;

/// Everything a handler needs, shared behind an [`Arc`].
///
/// There is deliberately no field here holding a key, a password or anything derived
/// from one. `server_setup` is OPAQUE protocol state: it lets the server participate
/// in authentication, and it cannot decrypt a vault. Whoever holds it learns nothing
/// about stored items.
pub struct AppState {
    pub pool: SqlitePool,
    /// OPAQUE server state. Secret in the sense that losing it locks everyone out and
    /// leaking it weakens offline resistance — but it never touches item data.
    pub setup: ServerSetupState,
    /// Key for deriving deterministic fake KDF salts, so that `prelogin` answers the
    /// same shape for an unknown identifier as for a known one.
    pub prelogin_secret: [u8; 32],
    /// Whether new accounts may be created. Turned off once a household server is set
    /// up, which is the cheapest possible defence against drive-by registrations.
    pub registration_open: bool,
    /// Where the web portal's files are, already resolved. `None` means there is no
    /// portal to serve, which is a supported state rather than an error.
    ///
    /// Not a secret: it is a path to public files, and the only reason it lives in the
    /// state is so that it is resolved once instead of on every request.
    pub web_root: Option<PathBuf>,
    /// The desktop build this server offers for download, if it has one.
    ///
    /// Discovered and hashed once at startup: the artifact is tens of megabytes, and a
    /// download endpoint that re-read it on every request just to describe it would be a
    /// needless way to spend a disk.
    pub desktop_build: Option<crate::downloads::DesktopBuild>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("registration_open", &self.registration_open)
            .finish_non_exhaustive()
    }
}

/// Builds the state: connects, applies the schema, and loads or creates the
/// server-side secrets.
pub async fn init(database_url: &str) -> ApiResult<Arc<AppState>> {
    let pool = db::connect(database_url).await?;

    let setup_bytes = db::load_or_create_state(&pool, "opaque_server_setup", || {
        ServerSetupState::generate().serialize()
    })
    .await?;
    let setup = ServerSetupState::deserialize(&setup_bytes)?;

    let secret_bytes = db::load_or_create_state(&pool, "prelogin_secret", || {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        secret.to_vec()
    })
    .await?;

    let mut prelogin_secret = [0u8; 32];
    if secret_bytes.len() != 32 {
        return Err(crate::error::ApiError::Internal(
            "stored prelogin secret has the wrong length".to_owned(),
        ));
    }
    prelogin_secret.copy_from_slice(&secret_bytes);

    let web_root = crate::static_files::resolve_root(&crate::static_files::default_root());

    // Looked for next to the portal, because that is where the build scripts put it and where
    // the static handler already serves from. No portal and no override means no download to
    // offer — a statement about this server, not a failure of it.
    let desktop_build = crate::downloads::resolve_directory(web_root.as_deref())
        .and_then(|directory| crate::downloads::find_build(&directory));

    if let Some(build) = &desktop_build {
        tracing::info!(
            file = %build.file_name,
            bytes = build.size,
            sha256 = %build.sha256,
            "offering a desktop build for download"
        );
    }

    Ok(Arc::new(AppState {
        pool,
        setup,
        prelogin_secret,
        registration_open: std::env::var("CLOUDPASS_REGISTRATION_OPEN")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true),
        web_root,
        desktop_build,
    }))
}

/// Derives the salt returned for an identifier that has no account.
///
/// A server that answered "no such account" would be an account-enumeration oracle,
/// and the KDF salt has to be returned before authentication anyway. Deriving it
/// deterministically from a server secret means an attacker cannot tell a real salt
/// from a fake one, and cannot probe the same identifier twice to see it change.
#[must_use]
pub fn fake_kdf_salt(secret: &[u8; 32], identifier: &str) -> [u8; 16] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(secret), identifier.as_bytes());
    let mut salt = [0u8; 16];
    // Expanding into a 16-byte buffer cannot fail for HKDF-SHA256.
    hk.expand(b"cloudpass/v1/fake-kdf-salt", &mut salt)
        .expect("16 bytes is a valid HKDF output length");
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_salts_are_stable_and_identifier_bound() {
        let secret = [7u8; 32];
        assert_eq!(
            fake_kdf_salt(&secret, "alice@example.com"),
            fake_kdf_salt(&secret, "alice@example.com")
        );
        assert_ne!(
            fake_kdf_salt(&secret, "alice@example.com"),
            fake_kdf_salt(&secret, "bob@example.com")
        );
    }

    #[test]
    fn fake_salts_depend_on_the_server_secret() {
        assert_ne!(
            fake_kdf_salt(&[1u8; 32], "alice@example.com"),
            fake_kdf_salt(&[2u8; 32], "alice@example.com")
        );
    }
}
