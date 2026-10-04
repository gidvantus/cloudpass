//! Session tokens and the authentication extractor.
//!
//! # Why bearer tokens rather than the OPAQUE session key
//!
//! OPAQUE already proves the client knows the password and hands both sides a shared
//! session key. Using it to sign every request would work, but it also means the
//! server must keep per-session cryptographic state and the client must never reuse a
//! nonce across a replay-prone channel. A random token over TLS, stored **hashed**,
//! is simpler, and the hash-at-rest detail removes the one real weakness of bearer
//! tokens: a database leak cannot be turned into a live session, because the stored
//! value is not the token.
//!
//! Lookup is by hash, which is a primary-key read — so there is no comparison of
//! secrets at all, and therefore no timing side channel to get wrong.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::codec::now_unix;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// How long a session stays valid. Long enough that a desktop client is not
/// constantly asking for the master password, short enough to bound a stolen token.
pub const SESSION_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

/// SHA-256 of a token. This, not the token, is what the database stores.
#[must_use]
pub fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

/// Issues a fresh session token for a device.
///
/// The token is returned exactly once; only its hash is persisted.
pub async fn issue_token(
    pool: &SqlitePool,
    user_id: Uuid,
    device_id: Uuid,
) -> ApiResult<(String, i64)> {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);

    let expires_at = now_unix() + SESSION_TTL_SECONDS;
    sqlx::query(
        "INSERT INTO sessions(token_hash, user_id, device_id, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(hash_token(&token).to_vec())
    .bind(user_id.to_string())
    .bind(device_id.to_string())
    .bind(now_unix())
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok((token, expires_at))
}

/// Registers a device, or refreshes a known one.
///
/// Returns the device id to use. A revoked device stays revoked: presenting its id
/// again does not resurrect it, and the caller gets `Unauthorized`.
///
/// A device that already exists must present **the same** signing key it registered
/// before. Accepting a new key for an existing device id would let anyone who guessed
/// or observed a device id take over its identity — and with it, the ability to
/// substitute the signed head of an account's vault.
pub async fn upsert_device(
    pool: &SqlitePool,
    user_id: Uuid,
    requested: Option<Uuid>,
    name: &str,
    signing_public_key: &[u8; 32],
) -> ApiResult<Uuid> {
    let now = now_unix();

    if let Some(device_id) = requested {
        let existing = sqlx::query(
            "SELECT user_id, revoked_at, signing_public_key FROM devices WHERE device_id = ?",
        )
        .bind(device_id.to_string())
        .fetch_optional(pool)
        .await?;

        match existing {
            Some(row) => {
                let owner: String = row.get("user_id");
                let revoked: Option<i64> = row.get("revoked_at");
                if owner != user_id.to_string() || revoked.is_some() {
                    return Err(ApiError::Unauthorized);
                }

                let stored: Option<Vec<u8>> = row.get("signing_public_key");
                match stored {
                    Some(stored) if stored.as_slice() != signing_public_key => {
                        return Err(ApiError::Unauthorized);
                    }
                    Some(_) => {}
                    // A device from before signing keys existed: bind its key now,
                    // on its first login since the upgrade.
                    None => {
                        sqlx::query(
                            "UPDATE devices SET signing_public_key = ? WHERE device_id = ?",
                        )
                        .bind(signing_public_key.as_slice())
                        .bind(device_id.to_string())
                        .execute(pool)
                        .await?;
                    }
                }

                sqlx::query("UPDATE devices SET name = ?, last_seen_at = ? WHERE device_id = ?")
                    .bind(name)
                    .bind(now)
                    .bind(device_id.to_string())
                    .execute(pool)
                    .await?;
                return Ok(device_id);
            }
            None => {
                sqlx::query(
                    "INSERT INTO devices(device_id, user_id, name, signing_public_key, \
                     created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(device_id.to_string())
                .bind(user_id.to_string())
                .bind(name)
                .bind(signing_public_key.as_slice())
                .bind(now)
                .bind(now)
                .execute(pool)
                .await?;
                return Ok(device_id);
            }
        }
    }

    let device_id = cloudpass_core::ids::random_uuid();
    sqlx::query(
        "INSERT INTO devices(device_id, user_id, name, signing_public_key, created_at, \
         last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(device_id.to_string())
    .bind(user_id.to_string())
    .bind(name)
    .bind(signing_public_key.as_slice())
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(device_id)
}

/// Reads a device's registered signing key.
///
/// `None` means the device exists but has no key bound yet, which the caller must
/// treat as "cannot sign", not as "trusted".
pub async fn device_signing_key(pool: &SqlitePool, device_id: Uuid) -> ApiResult<Option<[u8; 32]>> {
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT signing_public_key FROM devices WHERE device_id = ?")
            .bind(device_id.to_string())
            .fetch_optional(pool)
            .await?
            .flatten();

    let Some(bytes) = stored else {
        return Ok(None);
    };
    let key = cloudpass_core::device::DevicePublicKey::from_slice(&bytes)
        .map_err(|e| ApiError::Internal(format!("stored device key is invalid: {e}")))?;
    Ok(Some(*key.as_bytes()))
}

/// The authenticated caller, extracted from the `Authorization` header.
#[derive(Debug, Clone, Copy)]
pub struct AuthSession {
    pub user_id: Uuid,
    pub device_id: Uuid,
}

impl FromRequestParts<Arc<AppState>> for AuthSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;

        let token = header
            .strip_prefix("Bearer ")
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or(ApiError::Unauthorized)?;

        let row =
            sqlx::query("SELECT user_id, device_id, expires_at FROM sessions WHERE token_hash = ?")
                .bind(hash_token(token).to_vec())
                .fetch_optional(&state.pool)
                .await?
                .ok_or(ApiError::Unauthorized)?;

        let expires_at: i64 = row.get("expires_at");
        if expires_at <= now_unix() {
            return Err(ApiError::Unauthorized);
        }

        let user_id = parse_uuid(row.get::<String, _>("user_id"))?;
        let device_id = parse_uuid(row.get::<String, _>("device_id"))?;

        // Revoking a device must cut off its existing sessions immediately, not only
        // future logins.
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM devices WHERE device_id = ?")
                .bind(device_id.to_string())
                .fetch_optional(&state.pool)
                .await?
                .flatten();
        if revoked.is_some() {
            return Err(ApiError::Unauthorized);
        }

        Ok(Self { user_id, device_id })
    }
}

fn parse_uuid(value: String) -> ApiResult<Uuid> {
    Uuid::parse_str(&value).map_err(|e| ApiError::Internal(format!("stored uuid is invalid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_hashed_and_distinct() {
        let a = hash_token("token-a");
        let b = hash_token("token-b");
        assert_ne!(a, b);
        // The stored value must not be the token itself.
        assert_ne!(hex_encode(&a), "token-a");
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
