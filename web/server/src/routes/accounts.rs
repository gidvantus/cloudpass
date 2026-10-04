//! Account routes: KDF parameter discovery, OPAQUE registration and login, and the
//! stored key envelopes.
//!
//! # Shape of the exchange
//!
//! ```text
//!   prelogin              -> kdf_salt + params   (identical shape whether or not the account exists)
//!   register/start        -> OPAQUE response(s)  (stateless: nothing is written)
//!   register/finish       -> user_id             (the account is created here, and only here)
//!   login/start           -> OPAQUE response + attempt id
//!   login/finish          -> bearer token
//!   key-envelope  GET     -> the wrapped user key (opaque to the server)
//!   credentials/start     -> OPAQUE response + attempt id + registration response
//!   credentials/finish    -> replaces the master record and the envelopes
//!   recovery/start        -> OPAQUE response + attempt id + two registration responses
//!   recovery/finish       -> bearer token, and every earlier session is cut off
//! ```
//!
//! Registration is deliberately split so that nothing is persisted until the client
//! has proved it can complete the protocol. An abandoned registration leaves no row,
//! which removes both the squatting window and the cleanup job.
//!
//! # Two credentials per account
//!
//! The master password is one credential and the Emergency Kit's recovery key is
//! another, each with its own OPAQUE record. They have to be separate: a user who has
//! forgotten the password cannot present it, so a recovery route that ran through the
//! master record could never be used by the one person it exists for.
//!
//! # Who may replace a credential, and what they must prove
//!
//! Every endpoint that writes a credential — `register/finish`, `credentials/finish`,
//! `recovery/finish` — completes an OPAQUE exchange against **the credential being
//! replaced** in the same request pair. A bearer token is deliberately *not* enough.
//!
//! The reason is not only that a stolen token should not be able to change a password.
//! Replacing the master record and the wrapped user key must be atomic with the proof,
//! or the two can be made to disagree: a caller holding a session could install a
//! password it knows and an envelope full of random bytes, and the account would then
//! be undecryptable by its owner *and* by the attacker. With the proof in the same
//! transaction, the only actor who can rewrite the wrapped key is one that already
//! holds whatever protects that key.
//!
//! OPAQUE's registration half is stateless on the server, which is what makes this
//! cheap: `*/start` answers the login request and every registration request the flow
//! will need, and `*/finish` carries them all back together with the proof.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use uuid::Uuid;

use cloudpass_core::opaque::server as opaque_server;
use cloudpass_core::params::{KdfParams, KDF_SALT_LEN};

use crate::auth::{self, AuthSession};
use crate::codec::{normalize_identifier, now_unix, B64};
use crate::error::{ApiError, ApiResult};
use crate::state::{fake_kdf_salt, AppState};

/// How long a half-finished login may sit in the database.
const LOGIN_ATTEMPT_TTL_SECONDS: i64 = 5 * 60;

/// Largest envelope the server will store for one item or key slot.
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// The credential a normal login uses.
const MASTER_PURPOSE: &str = "master";

/// The credential printed in the Emergency Kit.
const RECOVERY_PURPOSE: &str = "recovery";

/// The OPAQUE credential identifier for a purpose other than the master password.
///
/// OPAQUE derives its per-credential OPRF key from this value, so it must be identical
/// at registration and at every later use, and distinct from the master credential's
/// identifier, which is the account identifier itself. Deriving it from the identifier
/// rather than the user id is what makes that possible: registration begins before the
/// server has seen a user id, and the identifier is stable from the first request.
///
/// Account identifiers never contain a control character — [`normalize_identifier`]
/// rejects them — so a NUL separator cannot be forged by someone who registers an
/// account under a name of their choosing.
fn recovery_credential_identifier(identifier: &str) -> String {
    format!("{identifier}\u{0}{RECOVERY_PURPOSE}")
}

// ---------------------------------------------------------------------------
// DTOs
//
// Every request type carries `deny_unknown_fields`. That is not tidiness: it is the
// mechanism that makes "the server cannot accept key material" enforceable. A client
// that tried to send `user_key` or `master_password` would get a 422 instead of
// having the field silently dropped, and the test suite asserts exactly that.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreloginRequest {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct PreloginResponse {
    pub kdf_salt: B64,
    pub kdf_m_kib: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStartRequest {
    pub identifier: String,
    /// Registration request for the master credential.
    pub request: B64,
    /// Registration request for the Emergency Kit's credential, when the client has a
    /// kit to install. Optional so that a client without one can still register.
    #[serde(default)]
    pub recovery_request: Option<B64>,
}

#[derive(Debug, Serialize)]
pub struct RegisterStartResponse {
    pub response: B64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_response: Option<B64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishRequest {
    /// Chosen by the client, not by the server.
    ///
    /// The wrapped user key is bound to this value through its associated data, so
    /// the client must know it *before* it can build the envelope it is about to
    /// send. Assigning the id server-side would make that impossible and force the
    /// binding to be dropped.
    pub user_id: Uuid,
    pub identifier: String,
    pub kdf_salt: B64,
    pub kdf_m_kib: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
    #[serde(default)]
    pub account_key_required: bool,
    pub upload: B64,
    pub user_key_envelope: B64,
    pub recovery_envelope: Option<B64>,
    /// Registration upload for the Emergency Kit's credential. Written in the same
    /// transaction as the account itself, so there is no instant at which the account
    /// exists without its recovery credential — and no window in which someone else
    /// could claim that slot.
    pub recovery_upload: Option<B64>,
}

#[derive(Debug, Serialize)]
pub struct RegisterFinishResponse {
    pub user_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartRequest {
    pub identifier: String,
    pub request: B64,
}

#[derive(Debug, Serialize)]
pub struct LoginStartResponse {
    pub response: B64,
    /// Identifies the half-finished exchange. Opaque to the client, and it is the only
    /// thing the client is told about server-side login state.
    pub attempt_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRequest {
    pub attempt_id: String,
    pub finalization: B64,
    pub device_id: Option<Uuid>,
    #[serde(default)]
    pub device_name: Option<String>,
    /// The device's Ed25519 public key.
    ///
    /// Required. Without it the device cannot sign a vault head, and an account whose
    /// devices cannot sign has no rollback protection at all. Binding the key at login
    /// also means a device id on its own is not enough to impersonate a device.
    pub device_public_key: B64,
}

#[derive(Debug, Serialize)]
pub struct LoginFinishResponse {
    pub token: String,
    pub expires_at: i64,
    pub user_id: Uuid,
    pub device_id: Uuid,
    /// Client-side configuration the server merely stores.
    ///
    /// It is reported only *after* authentication on purpose. Returning it from
    /// `prelogin` would hand an attacker a per-account bit that differs between real
    /// and unknown identifiers, which is exactly the enumeration oracle `prelogin`
    /// goes out of its way to avoid. The client must therefore remember this for
    /// itself, and must not depend on the server to learn it before logging in.
    pub account_key_required: bool,
}

#[derive(Debug, Serialize)]
pub struct KeyEnvelopeResponse {
    pub user_key_envelope: B64,
    pub recovery_envelope: Option<B64>,
}

/// Step one of replacing the master credential.///
/// Public, and it has to be: the exchange *is* the authentication. The caller proves
/// it holds the current password by completing an OPAQUE login against that record, and
/// asks in the same breath for the registration response that its replacement will need.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsStartRequest {
    pub identifier: String,
    /// OPAQUE login over the credential being replaced.
    pub request: B64,
    /// Registration request for the replacement master credential.
    pub new_request: B64,
    /// Registration request for a replacement recovery credential, when the caller is
    /// rotating its Emergency Kit at the same time.
    #[serde(default)]
    pub recovery_request: Option<B64>,
}

#[derive(Debug, Serialize)]
pub struct CredentialsStartResponse {
    pub response: B64,
    pub attempt_id: String,
    pub registration_response: B64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_response: Option<B64>,
}

/// Step two: the new records and the new envelopes, in one transaction.
///
/// Atomicity is the point. Writing the record and the envelope separately would leave a
/// window in which the account has a new password and the old wrapped user key, and a
/// user who unlocked inside that window would be told their new password is wrong.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsFinishRequest {
    pub attempt_id: String,
    pub finalization: B64,
    /// Registration upload for the replacement master credential.
    pub upload: B64,
    pub kdf_salt: B64,
    pub kdf_m_kib: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
    pub user_key_envelope: B64,
    /// Registration upload for a replacement recovery credential, when rotating the kit.
    pub recovery_upload: Option<B64>,
    pub recovery_envelope: Option<B64>,
}

/// Step one of signing in with a recovery key.
///
/// Public by necessity: a user who has forgotten the master password has no session,
/// and a recovery route that required one would be no route at all. It answers the
/// login request and both registration requests, because everything about the account
/// is about to be replaced and a second round trip would only widen the window in which
/// the old recovery credential is still live.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStartRequest {
    pub identifier: String,
    /// OPAQUE login over the recovery credential.
    pub request: B64,
    /// Registration request for the new master credential.
    pub master_request: B64,
    /// Registration request for the new recovery credential.
    pub recovery_request: B64,
}

#[derive(Debug, Serialize)]
pub struct RecoveryStartResponse {
    pub response: B64,
    pub attempt_id: String,
    pub master_response: B64,
    pub recovery_response: B64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryFinishRequest {
    pub attempt_id: String,
    pub finalization: B64,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub device_public_key: B64,
    /// Registration upload for the new master credential.
    pub upload: B64,
    /// Registration upload for the new recovery credential.
    pub recovery_upload: B64,
    pub kdf_salt: B64,
    pub kdf_m_kib: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
    pub user_key_envelope: B64,
    pub recovery_envelope: B64,
}

#[derive(Debug, Serialize)]
pub struct RecoveryFinishResponse {
    pub token: String,
    pub expires_at: i64,
    pub user_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct DeviceDto {
    pub device_id: Uuid,
    pub name: String,
    /// `None` for a device that has not logged in since signing keys were introduced.
    /// Such a device cannot sign a head, and a client must not count it as trusted.
    pub public_key: Option<B64>,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<DeviceDto>,
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

struct AccountRow {
    user_id: Uuid,
    kdf_salt: Vec<u8>,
    kdf_m_kib: u32,
    kdf_t: u32,
    kdf_p: u32,
    account_key_required: bool,
    opaque_record: Vec<u8>,
}

async fn find_account(pool: &SqlitePool, identifier: &str) -> ApiResult<Option<AccountRow>> {
    let row = sqlx::query(
        "SELECT user_id, kdf_salt, kdf_m_kib, kdf_t, kdf_p, account_key_required, \
         opaque_record FROM accounts WHERE identifier = ?",
    )
    .bind(identifier)
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(account_from_row).transpose()
}

fn account_from_row(row: &sqlx::sqlite::SqliteRow) -> ApiResult<AccountRow> {
    let user_id = Uuid::parse_str(&row.get::<String, _>("user_id"))
        .map_err(|e| ApiError::Internal(format!("stored user id is invalid: {e}")))?;

    Ok(AccountRow {
        user_id,
        kdf_salt: row.get("kdf_salt"),
        kdf_m_kib: row.get::<i64, _>("kdf_m_kib") as u32,
        kdf_t: row.get::<i64, _>("kdf_t") as u32,
        kdf_p: row.get::<i64, _>("kdf_p") as u32,
        account_key_required: row.get::<i64, _>("account_key_required") != 0,
        opaque_record: row.get("opaque_record"),
    })
}

/// Reads a non-master credential's OPAQUE record.
async fn fetch_auth_record(
    pool: &SqlitePool,
    user_id: Uuid,
    purpose: &str,
) -> ApiResult<Option<Vec<u8>>> {
    let record: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT record FROM auth_records WHERE user_id = ? AND purpose = ?")
            .bind(user_id.to_string())
            .bind(purpose)
            .fetch_optional(pool)
            .await?;
    Ok(record)
}

/// A fresh, unguessable id for one half-finished OPAQUE exchange.
fn random_attempt_id() -> String {
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Turns an OPAQUE protocol failure into an HTTP error, logging the real cause.
///
/// A message the server cannot parse is the client's problem and gets a 400; a
/// credential mismatch gets the same 401 as everywhere else.
fn opaque_error(stage: &'static str) -> impl Fn(cloudpass_core::Error) -> ApiError {
    move |error| {
        tracing::debug!(stage, error = %error, "rejected opaque message");
        match error {
            cloudpass_core::Error::AuthFailed => ApiError::InvalidCredentials,
            _ => ApiError::BadRequest(stage),
        }
    }
}

fn validated_params(m_kib: u32, t: u32, p: u32) -> ApiResult<KdfParams> {
    let params = KdfParams {
        m_kib,
        t,
        p,
        output_len: 32,
    };
    params
        .validate()
        .map_err(|_| ApiError::BadRequest("kdf parameters below the accepted floor"))?;
    Ok(params)
}

fn check_envelope(bytes: &[u8]) -> ApiResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(ApiError::BadRequest("envelope has an unacceptable size"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Returns the KDF parameters for an identifier.
///
/// For an unknown identifier this returns a salt derived from a server secret rather
/// than an error or an empty field. Anything else would be an account-enumeration
/// oracle, and the salt is needed before authentication anyway.
pub async fn prelogin(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    let identifier = normalize_identifier(&request.identifier)
        .ok_or(ApiError::BadRequest("identifier is not usable"))?;

    let response = match find_account(&state.pool, &identifier).await? {
        Some(account) => PreloginResponse {
            kdf_salt: B64(account.kdf_salt),
            kdf_m_kib: account.kdf_m_kib,
            kdf_t: account.kdf_t,
            kdf_p: account.kdf_p,
        },
        None => {
            let defaults = KdfParams::RECOMMENDED;
            PreloginResponse {
                kdf_salt: B64(fake_kdf_salt(&state.prelogin_secret, &identifier).to_vec()),
                kdf_m_kib: defaults.m_kib,
                kdf_t: defaults.t,
                kdf_p: defaults.p,
            }
        }
    };

    Ok(Json(response))
}

/// Step one of registration. Stateless on the server.
pub async fn register_start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterStartRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    if !state.registration_open {
        return Err(ApiError::BadRequest("registration is closed"));
    }

    let identifier = normalize_identifier(&request.identifier)
        .ok_or(ApiError::BadRequest("identifier is not usable"))?;

    if find_account(&state.pool, &identifier).await?.is_some() {
        return Err(ApiError::BadRequest("identifier is already registered"));
    }

    let response = opaque_server::registration_start(
        &state.setup,
        request.request.as_slice(),
        identifier.as_bytes(),
    )
    .map_err(opaque_error("server registration start"))?;

    // The recovery credential is answered here, before the account exists, so that both
    // records can be written by the one transaction that creates the account.
    let recovery_response = match &request.recovery_request {
        Some(recovery) => Some(B64(opaque_server::registration_start(
            &state.setup,
            recovery.as_slice(),
            recovery_credential_identifier(&identifier).as_bytes(),
        )
        .map_err(opaque_error("server recovery registration start"))?)),
        None => None,
    };

    Ok(Json(RegisterStartResponse {
        response: B64(response),
        recovery_response,
    }))
}

/// Step two of registration: the account is created here.
pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterFinishRequest>,
) -> ApiResult<Json<RegisterFinishResponse>> {
    if !state.registration_open {
        return Err(ApiError::BadRequest("registration is closed"));
    }

    let identifier = normalize_identifier(&request.identifier)
        .ok_or(ApiError::BadRequest("identifier is not usable"))?;

    // Refuse to record parameters weaker than the floor. A client that insisted on
    // them would otherwise be able to store a vault that is cheap to attack later.
    let params = validated_params(request.kdf_m_kib, request.kdf_t, request.kdf_p)?;

    if request.kdf_salt.as_slice().len() != KDF_SALT_LEN {
        return Err(ApiError::BadRequest("kdf salt has the wrong length"));
    }
    check_envelope(request.upload.as_slice())?;
    check_envelope(request.user_key_envelope.as_slice())?;
    if let Some(recovery) = &request.recovery_envelope {
        check_envelope(recovery.as_slice())?;
    }
    if let Some(recovery) = &request.recovery_upload {
        check_envelope(recovery.as_slice())?;
    }
    // The envelope and the credential that opens it must arrive together. Storing one
    // without the other would leave an account whose kit is a piece of paper covered in
    // a key that does nothing — the failure this mechanism exists to prevent, and the
    // hardest kind to notice.
    if request.recovery_envelope.is_some() != request.recovery_upload.is_some() {
        return Err(ApiError::BadRequest(
            "the recovery envelope and credential must arrive together",
        ));
    }

    let password_file = opaque_server::registration_finish(request.upload.as_slice())
        .map_err(opaque_error("server registration finish"))?;

    // Prepared before the transaction opens: a client that promised a kit must deliver
    // one, and parsing its upload is the only way to know that it did.
    let recovery_file = match &request.recovery_upload {
        Some(upload) => Some(
            opaque_server::registration_finish(upload.as_slice())
                .map_err(opaque_error("server recovery registration finish"))?,
        ),
        None => None,
    };

    let user_id = request.user_id;
    let now = now_unix();
    let mut tx = state.pool.begin().await?;

    let existing: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM accounts WHERE identifier = ?")
            .bind(&identifier)
            .fetch_optional(&mut *tx)
            .await?;
    if existing.is_some() {
        return Err(ApiError::BadRequest("identifier is already registered"));
    }

    let id_taken: Option<String> =
        sqlx::query_scalar("SELECT identifier FROM accounts WHERE user_id = ?")
            .bind(user_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
    if id_taken.is_some() {
        return Err(ApiError::BadRequest("user id is already in use"));
    }

    sqlx::query(
        "INSERT INTO accounts(user_id, identifier, kdf_salt, kdf_m_kib, kdf_t, kdf_p, \
         account_key_required, opaque_record, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id.to_string())
    .bind(&identifier)
    .bind(request.kdf_salt.as_slice())
    .bind(i64::from(params.m_kib))
    .bind(i64::from(params.t))
    .bind(i64::from(params.p))
    .bind(i64::from(request.account_key_required))
    .bind(password_file.serialize())
    .bind(now)
    .execute(&mut *tx)
    .await?;

    insert_key_envelope(
        &mut tx,
        user_id,
        "userkey",
        request.user_key_envelope.as_slice(),
        now,
    )
    .await?;
    if let Some(recovery) = &request.recovery_envelope {
        insert_key_envelope(&mut tx, user_id, "recovery", recovery.as_slice(), now).await?;
    }
    if let Some(file) = &recovery_file {
        upsert_auth_record(&mut tx, user_id, RECOVERY_PURPOSE, &file.serialize(), now).await?;
    }

    tx.commit().await?;

    Ok(Json(RegisterFinishResponse { user_id }))
}

/// Step one of login.
///
/// For an unknown identifier the server still runs the protocol, with `None` as the
/// password file, producing a dummy response of the same shape. The client gets no
/// signal, and neither does anyone watching.
pub async fn login_start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    let identifier = normalize_identifier(&request.identifier)
        .ok_or(ApiError::BadRequest("identifier is not usable"))?;

    let account = find_account(&state.pool, &identifier).await?;
    let password_file = match &account {
        Some(row) => Some(
            cloudpass_core::opaque::server::PasswordFile::deserialize(&row.opaque_record)
                .map_err(|e| ApiError::Internal(format!("stored opaque record is invalid: {e}")))?,
        ),
        None => None,
    };

    let start = opaque_server::LoginStart::start(
        &state.setup,
        password_file.as_ref(),
        request.request.as_slice(),
        identifier.as_bytes(),
    )
    .map_err(opaque_error("server login start"))?;

    // Read the response before consuming `start`: the state that goes into the
    // database contains the server's ephemeral secret and is not the same thing.
    let response = start.response().to_vec();
    let persisted = start.into_persisted();
    let attempt_id = random_attempt_id();

    save_attempt(&state, &attempt_id, &identifier, &persisted, MASTER_PURPOSE).await?;

    Ok(Json(LoginStartResponse {
        response: B64(response),
        attempt_id,
    }))
}

async fn skip_expired_attempts(pool: &SqlitePool, now: i64) -> ApiResult<()> {
    sqlx::query("DELETE FROM login_attempts WHERE expires_at <= ?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

/// Step two of login: verify, then issue a session token.
pub async fn login_finish(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginFinishRequest>,
) -> ApiResult<Json<LoginFinishResponse>> {
    // `take_attempt` refuses an attempt that was begun against the recovery credential,
    // where a token issued here would arrive without the password change recovery owes.
    let attempt = take_attempt(&state, &request.attempt_id, MASTER_PURPOSE).await?;

    let account = find_account(&state.pool, &attempt.identifier)
        .await?
        .ok_or(ApiError::InvalidCredentials)?;

    attempt
        .persisted
        .finish(request.finalization.as_slice())
        .map_err(opaque_error("server login finish"))?;

    let (token, expires_at, device_id) = begin_session(
        &state,
        account.user_id,
        request.device_id,
        request.device_name.as_deref(),
        request.device_public_key.as_slice(),
    )
    .await?;

    Ok(Json(LoginFinishResponse {
        token,
        expires_at,
        user_id: account.user_id,
        device_id,
        account_key_required: account.account_key_required,
    }))
}

/// Registers the calling device and issues it a session token.
///
/// Shared by an ordinary login and a recovery sign-in: both end with the same thing,
/// and the distinction that matters — which credential got them there — lives in
/// `login_attempts`, not here.
async fn begin_session(
    state: &AppState,
    user_id: Uuid,
    requested_device: Option<Uuid>,
    device_name: Option<&str>,
    device_public_key: &[u8],
) -> ApiResult<(String, i64, Uuid)> {
    let device_name = device_name
        .map(str::trim)
        .filter(|name| !name.is_empty() && name.len() <= 64)
        .unwrap_or("unnamed device");

    let device_key = cloudpass_core::device::DevicePublicKey::from_slice(device_public_key)
        .map_err(|_| ApiError::BadRequest("device public key must be 32 bytes"))?;

    let device_id = auth::upsert_device(
        &state.pool,
        user_id,
        requested_device,
        device_name,
        device_key.as_bytes(),
    )
    .await?;
    let (token, expires_at) = auth::issue_token(&state.pool, user_id, device_id).await?;

    Ok((token, expires_at, device_id))
}

/// Step one of replacing the master credential.
///
/// Public, and it has to be: the exchange *is* the authentication. The caller proves it
/// holds the current password by completing an OPAQUE login against that record, and
/// asks in the same breath for the registration response its replacement will need.
pub async fn credentials_start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CredentialsStartRequest>,
) -> ApiResult<Json<CredentialsStartResponse>> {
    let identifier = normalize_identifier(&request.identifier)
        .ok_or(ApiError::BadRequest("identifier is not usable"))?;

    let account = find_account(&state.pool, &identifier).await?;

    // An unknown identifier gets the same dummy response `login/start` gives, so this
    // cannot be used to ask whether an account exists.
    let password_file = match &account {
        Some(row) => Some(
            cloudpass_core::opaque::server::PasswordFile::deserialize(&row.opaque_record)
                .map_err(|e| ApiError::Internal(format!("stored opaque record is invalid: {e}")))?,
        ),
        None => None,
    };

    let start = opaque_server::LoginStart::start(
        &state.setup,
        password_file.as_ref(),
        request.request.as_slice(),
        identifier.as_bytes(),
    )
    .map_err(opaque_error("server credentials start"))?;

    let response = start.response().to_vec();
    let persisted = start.into_persisted();
    let attempt_id = random_attempt_id();

    let registration_response = opaque_server::registration_start(
        &state.setup,
        request.new_request.as_slice(),
        identifier.as_bytes(),
    )
    .map_err(opaque_error("server credentials registration start"))?;

    let recovery_response = match &request.recovery_request {
        Some(recovery) => Some(B64(opaque_server::registration_start(
            &state.setup,
            recovery.as_slice(),
            recovery_credential_identifier(&identifier).as_bytes(),
        )
        .map_err(opaque_error("server recovery registration start"))?)),
        None => None,
    };

    save_attempt(&state, &attempt_id, &identifier, &persisted, MASTER_PURPOSE).await?;

    Ok(Json(CredentialsStartResponse {
        response: B64(response),
        attempt_id,
        registration_response: B64(registration_response),
        recovery_response,
    }))
}

/// Step two: prove the current password, then install the replacement, atomically.
///
/// Nothing in this handler happens for a caller that cannot complete the OPAQUE login
/// begun in [`credentials_start`]. That is what stops a stolen session token from
/// rewriting the wrapped user key — a rewrite the server cannot detect, because the
/// envelope is opaque to it.
pub async fn credentials_finish(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CredentialsFinishRequest>,
) -> ApiResult<()> {
    let attempt = take_attempt(&state, &request.attempt_id, MASTER_PURPOSE).await?;
    let account = find_account(&state.pool, &attempt.identifier)
        .await?
        .ok_or(ApiError::InvalidCredentials)?;

    attempt
        .persisted
        .finish(request.finalization.as_slice())
        .map_err(opaque_error("server credentials finish"))?;

    let params = validated_params(request.kdf_m_kib, request.kdf_t, request.kdf_p)?;
    if request.kdf_salt.as_slice().len() != KDF_SALT_LEN {
        return Err(ApiError::BadRequest("kdf salt has the wrong length"));
    }
    check_envelope(request.upload.as_slice())?;
    check_envelope(request.user_key_envelope.as_slice())?;
    if let Some(upload) = &request.recovery_upload {
        check_envelope(upload.as_slice())?;
    }
    if let Some(envelope) = &request.recovery_envelope {
        check_envelope(envelope.as_slice())?;
    }
    // A replacement kit is either complete or not sent. Storing the envelope without the
    // credential that opens it would leave a piece of paper covered in a key that does
    // nothing — the failure this whole mechanism exists to prevent.
    if request.recovery_envelope.is_some() != request.recovery_upload.is_some() {
        return Err(ApiError::BadRequest(
            "the recovery envelope and credential must arrive together",
        ));
    }

    let password_file = opaque_server::registration_finish(request.upload.as_slice())
        .map_err(opaque_error("server credentials registration finish"))?;
    let recovery_file = match &request.recovery_upload {
        Some(upload) => Some(
            opaque_server::registration_finish(upload.as_slice())
                .map_err(opaque_error("server recovery registration finish"))?,
        ),
        None => None,
    };

    let now = now_unix();
    let mut tx = state.pool.begin().await?;
    apply_credentials(
        &mut tx,
        account.user_id,
        request.kdf_salt.as_slice(),
        params,
        &password_file,
        request.user_key_envelope.as_slice(),
        request.recovery_envelope.as_ref().map(B64::as_slice),
        recovery_file.as_ref(),
        now,
    )
    .await?;
    tx.commit().await?;

    Ok(())
}

/// Step one of signing in with a recovery key.
///
/// Public by necessity: a user who has forgotten the master password has no session,
/// and a recovery route that required one would be no route at all.
///
/// An unknown account and an account with no recovery record both get a dummy response
/// shaped exactly like `login/start`'s, so this cannot be used to ask whether a kit
/// exists. The refusal happens in [`recovery_finish`], where a dummy proves nothing.
pub async fn recovery_start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RecoveryStartRequest>,
) -> ApiResult<Json<RecoveryStartResponse>> {
    let identifier = normalize_identifier(&request.identifier)
        .ok_or(ApiError::BadRequest("identifier is not usable"))?;

    let account = find_account(&state.pool, &identifier).await?;

    let password_file = match &account {
        Some(row) => fetch_auth_record(&state.pool, row.user_id, RECOVERY_PURPOSE)
            .await?
            .map(|record| {
                cloudpass_core::opaque::server::PasswordFile::deserialize(&record).map_err(|e| {
                    ApiError::Internal(format!("stored recovery record is invalid: {e}"))
                })
            })
            .transpose()?,
        None => None,
    };

    // The credential identifier must be the one the record was registered under, or the
    // OPRF key differs and no correct key can ever authenticate. It is derived from the
    // account identifier, which is available here whether or not the account exists.
    let credential_identifier = recovery_credential_identifier(&identifier);

    let start = opaque_server::LoginStart::start(
        &state.setup,
        password_file.as_ref(),
        request.request.as_slice(),
        credential_identifier.as_bytes(),
    )
    .map_err(opaque_error("server recovery start"))?;

    let response = start.response().to_vec();
    let persisted = start.into_persisted();
    let attempt_id = random_attempt_id();

    // Both replacements are answered now. OPAQUE's registration half is stateless, so
    // this costs nothing, and it means the whole reset lands in one transaction instead
    // of leaving the retired credential live for another round trip.
    let master_response = opaque_server::registration_start(
        &state.setup,
        request.master_request.as_slice(),
        identifier.as_bytes(),
    )
    .map_err(opaque_error("server recovery registration start"))?;

    let recovery_response = opaque_server::registration_start(
        &state.setup,
        request.recovery_request.as_slice(),
        credential_identifier.as_bytes(),
    )
    .map_err(opaque_error("server recovery registration start"))?;

    save_attempt(
        &state,
        &attempt_id,
        &identifier,
        &persisted,
        RECOVERY_PURPOSE,
    )
    .await?;

    Ok(Json(RecoveryStartResponse {
        response: B64(response),
        attempt_id,
        master_response: B64(master_response),
        recovery_response: B64(recovery_response),
    }))
}

/// Step two of a recovery: prove the recovery key, then replace everything at once.
///
/// Every session the account already had is destroyed first. A recovery is a credential
/// reset by definition — the old password is either forgotten or in someone else's hands
/// — and leaving live tokens behind would undo the point.
pub async fn recovery_finish(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RecoveryFinishRequest>,
) -> ApiResult<Json<RecoveryFinishResponse>> {
    let attempt = take_attempt(&state, &request.attempt_id, RECOVERY_PURPOSE).await?;
    let account = find_account(&state.pool, &attempt.identifier)
        .await?
        .ok_or(ApiError::InvalidCredentials)?;

    // No record means no credential. Refusing here is what stops a recovery attempt
    // against an account that never had a kit from being turned into a session: the
    // dummy response above proves nothing on its own.
    if fetch_auth_record(&state.pool, account.user_id, RECOVERY_PURPOSE)
        .await?
        .is_none()
    {
        return Err(ApiError::InvalidCredentials);
    }

    attempt
        .persisted
        .finish(request.finalization.as_slice())
        .map_err(opaque_error("server recovery finish"))?;

    let params = validated_params(request.kdf_m_kib, request.kdf_t, request.kdf_p)?;
    if request.kdf_salt.as_slice().len() != KDF_SALT_LEN {
        return Err(ApiError::BadRequest("kdf salt has the wrong length"));
    }
    check_envelope(request.upload.as_slice())?;
    check_envelope(request.recovery_upload.as_slice())?;
    check_envelope(request.user_key_envelope.as_slice())?;
    check_envelope(request.recovery_envelope.as_slice())?;

    let password_file = opaque_server::registration_finish(request.upload.as_slice())
        .map_err(opaque_error("server recovery registration finish"))?;
    let recovery_file = opaque_server::registration_finish(request.recovery_upload.as_slice())
        .map_err(opaque_error("server recovery registration finish"))?;

    let now = now_unix();
    let mut tx = state.pool.begin().await?;
    apply_credentials(
        &mut tx,
        account.user_id,
        request.kdf_salt.as_slice(),
        params,
        &password_file,
        request.user_key_envelope.as_slice(),
        Some(request.recovery_envelope.as_slice()),
        Some(&recovery_file),
        now,
    )
    .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(account.user_id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let (token, expires_at, device_id) = begin_session(
        &state,
        account.user_id,
        request.device_id,
        request.device_name.as_deref(),
        request.device_public_key.as_slice(),
    )
    .await?;

    Ok(Json(RecoveryFinishResponse {
        token,
        expires_at,
        user_id: account.user_id,
        device_id,
    }))
}

/// Writes a credential replacement and the envelopes that go with it.
///
/// Private on purpose: every caller has to have proved something first, and keeping the
/// write in one function is what makes "the proof and the write are inseparable" a
/// property of the code rather than a rule to remember.
#[allow(clippy::too_many_arguments)]
async fn apply_credentials(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: Uuid,
    kdf_salt: &[u8],
    params: KdfParams,
    password_file: &cloudpass_core::opaque::server::PasswordFile,
    user_key_envelope: &[u8],
    recovery_envelope: Option<&[u8]>,
    recovery_file: Option<&cloudpass_core::opaque::server::PasswordFile>,
    now: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE accounts SET kdf_salt = ?, kdf_m_kib = ?, kdf_t = ?, kdf_p = ?, \
         opaque_record = ? WHERE user_id = ?",
    )
    .bind(kdf_salt)
    .bind(i64::from(params.m_kib))
    .bind(i64::from(params.t))
    .bind(i64::from(params.p))
    .bind(password_file.serialize())
    .bind(user_id.to_string())
    .execute(&mut **tx)
    .await?;

    insert_key_envelope(tx, user_id, "userkey", user_key_envelope, now).await?;
    if let Some(envelope) = recovery_envelope {
        insert_key_envelope(tx, user_id, "recovery", envelope, now).await?;
    }
    if let Some(file) = recovery_file {
        upsert_auth_record(tx, user_id, RECOVERY_PURPOSE, &file.serialize(), now).await?;
    }

    Ok(())
}

/// Records a half-finished OPAQUE login.
async fn save_attempt(
    state: &AppState,
    attempt_id: &str,
    identifier: &str,
    persisted: &cloudpass_core::opaque::server::PersistedLogin,
    purpose: &str,
) -> ApiResult<()> {
    skip_expired_attempts(&state.pool, now_unix()).await?;

    sqlx::query(
        "INSERT INTO login_attempts(attempt_id, identifier, state, expires_at, purpose) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(attempt_id)
    .bind(identifier)
    .bind(persisted.serialize())
    .bind(now_unix() + LOGIN_ATTEMPT_TTL_SECONDS)
    .bind(purpose)
    .execute(&state.pool)
    .await?;

    Ok(())
}

/// One half-finished OPAQUE login, read back and consumed.
struct Attempt {
    identifier: String,
    persisted: cloudpass_core::opaque::server::PersistedLogin,
}

/// Reads an attempt, checks what it was started for, and deletes it.
///
/// Single use by construction, and the purpose check is what keeps the two flows from
/// being mixed: an attempt begun against the recovery credential must not be finished
/// at an endpoint that would leave the account with a password nobody reset.
async fn take_attempt(state: &AppState, attempt_id: &str, purpose: &str) -> ApiResult<Attempt> {
    let row = sqlx::query(
        "SELECT identifier, state, expires_at, purpose FROM login_attempts WHERE attempt_id = ?",
    )
    .bind(attempt_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::InvalidCredentials)?;

    let expires_at: i64 = row.get("expires_at");
    let stored_purpose: String = row.get("purpose");
    if expires_at <= now_unix() || stored_purpose != purpose {
        return Err(ApiError::InvalidCredentials);
    }

    // Whatever happens next, this attempt is gone.
    sqlx::query("DELETE FROM login_attempts WHERE attempt_id = ?")
        .bind(attempt_id)
        .execute(&state.pool)
        .await?;

    let state_bytes: Vec<u8> = row.get("state");
    let persisted = cloudpass_core::opaque::server::PersistedLogin::deserialize(&state_bytes)
        .map_err(|e| ApiError::Internal(format!("stored login state is invalid: {e}")))?;

    Ok(Attempt {
        identifier: row.get("identifier"),
        persisted,
    })
}

/// Installs a non-master credential, replacing any previous one.
async fn upsert_auth_record(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: Uuid,
    purpose: &str,
    record: &[u8],
    now: i64,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO auth_records(user_id, purpose, record, updated_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT(user_id, purpose) DO UPDATE SET record = excluded.record, \
         updated_at = excluded.updated_at",
    )
    .bind(user_id.to_string())
    .bind(purpose)
    .bind(record)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Returns the stored key envelopes.
///
/// They are opaque: the server cannot tell a wrapped user key from random bytes, and
/// the only thing it enforces is that they fit.
pub async fn get_key_envelope(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
) -> ApiResult<Json<KeyEnvelopeResponse>> {
    let user_key = fetch_key_envelope(&state.pool, session.user_id, "userkey")
        .await?
        .ok_or(ApiError::NotFound)?;
    let recovery = fetch_key_envelope(&state.pool, session.user_id, "recovery").await?;

    Ok(Json(KeyEnvelopeResponse {
        user_key_envelope: B64(user_key),
        recovery_envelope: recovery.map(B64),
    }))
}

/// Lists the account's devices together with their signing keys.
///
/// A client needs this to decide whether a head signature comes from a device it
/// trusts. Revoked devices are listed rather than filtered out on purpose: a client
/// that never saw the revocation would keep trusting them, and learning about it is
/// the whole point.
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
) -> ApiResult<Json<ListDevicesResponse>> {
    let rows = sqlx::query(
        "SELECT device_id, name, signing_public_key, created_at, last_seen_at, revoked_at \
         FROM devices WHERE user_id = ? ORDER BY created_at",
    )
    .bind(session.user_id.to_string())
    .fetch_all(&state.pool)
    .await?;

    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        let device_id = Uuid::parse_str(&row.get::<String, _>("device_id"))
            .map_err(|e| ApiError::Internal(format!("stored device id is invalid: {e}")))?;
        devices.push(DeviceDto {
            device_id,
            name: row.get("name"),
            public_key: row.get::<Option<Vec<u8>>, _>("signing_public_key").map(B64),
            created_at: row.get("created_at"),
            last_seen_at: row.get("last_seen_at"),
            revoked_at: row.get("revoked_at"),
        });
    }

    Ok(Json(ListDevicesResponse { devices }))
}

async fn fetch_key_envelope(
    pool: &SqlitePool,
    user_id: Uuid,
    kind: &str,
) -> ApiResult<Option<Vec<u8>>> {
    let envelope: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT envelope FROM key_envelopes WHERE user_id = ? AND kind = ?")
            .bind(user_id.to_string())
            .bind(kind)
            .fetch_optional(pool)
            .await?;
    Ok(envelope)
}

async fn insert_key_envelope(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: Uuid,
    kind: &str,
    envelope: &[u8],
    now: i64,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO key_envelopes(user_id, kind, envelope, updated_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT(user_id, kind) DO UPDATE SET envelope = excluded.envelope, \
         updated_at = excluded.updated_at",
    )
    .bind(user_id.to_string())
    .bind(kind)
    .bind(envelope)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
