//! Registering, logging in, and replacing credentials over HTTP.
//!
//! # Where the master password goes
//!
//! Nowhere. It is stretched here with Argon2id and never leaves this process: what
//! crosses the wire is an OPAQUE exchange, and the value fed into it is a
//! domain-separated subkey that unlocks nothing else.
//!
//! # Why registration happens before anything is written locally
//!
//! The caller builds the account material — user id, KDF salt, wrapped user key,
//! device key — and hands it here. It writes the result only once the server has
//! accepted it. Registering first means a failure part-way through cannot leave a
//! half-created account on disk that no server knows about and no password can repair.
//!
//! # Proof, not session tokens
//!
//! Every function here that *replaces* a credential — [`replace_credentials`] and
//! [`recover`] — begins an OPAQUE login against the credential being replaced and
//! finishes it in the same call. No bearer token is sent and none would be accepted.
//!
//! The server side explains why at length; the short version is that an envelope is
//! opaque to the server, so a caller that can rewrite it without proving it holds the
//! key's protector can render an account permanently undecryptable. Proving possession
//! in the same transaction is the only check the server can actually perform.
//!
//! OPAQUE's registration half is stateless, so one `*/start` call answers the login
//! request *and* every registration request the flow will need. That is what lets a
//! wholesale credential replacement be two round trips rather than six, and — more
//! importantly — one transaction.

use uuid::Uuid;

use cloudpass_core::device::DeviceSigningKey;
use cloudpass_core::kdf::RecoveryKey;
use cloudpass_core::opaque::client::{LoginStart, RegistrationStart};
use cloudpass_core::opaque::AuthInput;
use cloudpass_core::params::{KdfParams, KDF_SALT_LEN};

use crate::error::{ClientError, Result};
use crate::store::StoredAccount;
use crate::sync::transport::{HttpRequest, HttpResponse, Transport};
use crate::sync::wire::{
    ErrorBody, KeyEnvelopeResponse, ListVaultsResponse, PreloginResponse, B64,
};
use crate::vault::NewAccount;

/// A logged-in session: everything the sync engine needs from the server.
#[derive(Debug, Clone)]
pub struct RemoteSession {
    pub user_id: Uuid,
    /// The device id the server assigned. Head signatures are bound to it, so this is
    /// not the placeholder generated when the account was created locally.
    pub device_id: Uuid,
    pub token: String,
    pub expires_at: i64,
    /// The server's static OPAQUE key. The caller pins it.
    pub server_static_public_key: Vec<u8>,
}

/// What registration needs from the caller.
pub struct Registration<'a> {
    pub identifier: &'a str,
    pub master_password: &'a [u8],
    /// The locally created account material.
    pub account: &'a NewAccount,
    /// The device key whose public half will verify this device's vault heads.
    pub device: &'a DeviceSigningKey,
    /// The vault's sealed display name, produced by [`crate::Vault::seal_vault_name`].
    pub vault_name_envelope: &'a [u8],
    /// The recovery key from the Emergency Kit that was just created.
    ///
    /// `None` only where a caller genuinely has none. When it is present, the recovery
    /// credential is written by the same transaction that creates the account, so there
    /// is no instant at which the account exists without a second way in — and no window
    /// in which a stranger could claim that slot.
    pub recovery_key: Option<&'a RecoveryKey>,
}

/// What a login needs from the caller.
///
/// Unlike [`Registration`], this does not need the whole account: logging in uses the
/// KDF parameters and the device key, and nothing else.
pub struct Credentials<'a> {
    pub identifier: &'a str,
    pub master_password: &'a [u8],
    pub kdf_salt: &'a [u8; KDF_SALT_LEN],
    pub kdf_params: KdfParams,
    pub device: &'a DeviceSigningKey,
    /// The device id this key was registered under, when the caller has one.
    ///
    /// `None` on a client that cannot keep a device key between runs — the browser,
    /// where the seed lives only as long as the tab. Presenting an id whose key no
    /// longer exists would be refused by the server, and correctly so: the id is bound
    /// to the key, which is what stops a guessed id from impersonating a device.
    ///
    /// A client that *does* keep its key should pass its id here. Otherwise every login
    /// registers a fresh device, and the account's device list grows without bound.
    pub device_id: Option<Uuid>,
}

/// Registers a new account with the server, and its Emergency Kit with it.
pub async fn register<T: Transport>(
    transport: &T,
    request: Registration<'_>,
) -> Result<RemoteSession> {
    let Registration {
        identifier,
        master_password,
        account,
        device,
        vault_name_envelope,
        recovery_key,
    } = request;

    let auth =
        AuthInput::from_master_password(master_password, &account.kdf_salt, &account.kdf_params)?;
    let master_start = RegistrationStart::start(auth)?;

    let recovery_start = match recovery_key {
        Some(key) => Some(RegistrationStart::start(AuthInput::from_recovery_key(
            key,
            account.user_id.as_bytes(),
        )?)?),
        None => None,
    };

    let body = serde_json::to_vec(&serde_json::json!({
        "identifier": identifier,
        "request": B64::new(master_start.request().to_vec()),
        "recovery_request": recovery_start
            .as_ref()
            .map(|start| B64::new(start.request().to_vec())),
    }))?;
    let answer = post(transport, "/api/v1/accounts/register/start", None, body).await?;

    let registration_response: B64 = read(&answer, "response", "registration response")?;
    let finish = master_start.finish(registration_response.as_slice())?;
    let pinned = finish.server_static_public_key().to_vec();

    let recovery_upload = match (recovery_start, answer.get("recovery_response")) {
        (Some(start), Some(response)) => {
            let response: B64 = serde_json::from_value(response.clone())
                .map_err(|e| ClientError::Protocol(format!("recovery response: {e}")))?;
            Some(B64::new(
                start.finish(response.as_slice())?.upload().to_vec(),
            ))
        }
        (Some(_), None) => {
            return Err(ClientError::Protocol(
                "the server did not answer the Emergency Kit registration".into(),
            ))
        }
        (None, _) => None,
    };

    let params = account.kdf_params;
    let body = serde_json::to_vec(&serde_json::json!({
        "user_id": account.user_id,
        "identifier": identifier,
        "kdf_salt": B64::new(account.kdf_salt.to_vec()),
        "kdf_m_kib": params.m_kib,
        "kdf_t": params.t,
        "kdf_p": params.p,
        "account_key_required": false,
        "upload": B64::new(finish.upload().to_vec()),
        "user_key_envelope": B64::new(account.user_key_envelope.clone()),
        // Ciphertext, so the server may hold it; the recovery key that opens it never
        // leaves the paper it was written on.
        "recovery_envelope": account
            .recovery_envelope
            .as_ref()
            .map(|envelope| B64::new(envelope.clone())),
        "recovery_upload": recovery_upload,
    }))?;
    post(transport, "/api/v1/accounts/register/finish", None, body).await?;

    // The account exists; open a session on it, then give it a vault to write into.
    let mut session = login(
        transport,
        Credentials {
            identifier,
            master_password,
            kdf_salt: &account.kdf_salt,
            kdf_params: account.kdf_params,
            device,
            // The id chosen when the account material was built. Passing it means the
            // server binds the device key to the id the client already recorded, rather
            // than issuing one and leaving the two to be reconciled afterwards.
            device_id: Some(account.device_id),
        },
        &pinned,
    )
    .await?;
    session.server_static_public_key = pinned;

    let body = serde_json::to_vec(&serde_json::json!({
        "vault_id": account.vault_id,
        "name_envelope": B64::new(vault_name_envelope.to_vec()),
    }))?;
    post(transport, "/api/v1/vaults", Some(&session.token), body).await?;

    Ok(session)
}

/// What replacing credentials needs from the caller.
///
/// Both halves of the pair are here because the server needs both in one transaction:
/// the credential being retired (to prove the caller may retire it) and the one
/// replacing it.
pub struct CredentialChange<'a> {
    pub identifier: &'a str,
    /// The user id, which salts the recovery key's derivations.
    pub user_id: Uuid,
    /// The password being replaced. Proving it is what authorises the change.
    pub current_password: &'a [u8],
    /// The salt and parameters the account currently uses, needed to derive that proof.
    pub current_kdf_salt: &'a [u8; KDF_SALT_LEN],
    pub current_kdf_params: KdfParams,
    /// The password that replaces it. Passing the same value is legitimate: rotating the
    /// Emergency Kit re-registers the master credential without changing the password.
    pub new_master_password: &'a [u8],
    pub new_kdf_salt: &'a [u8; KDF_SALT_LEN],
    pub new_kdf_params: KdfParams,
    /// The user key re-wrapped under the new password.
    pub user_key_envelope: &'a [u8],
    /// A replacement recovery key and envelope, when the Kit is being rotated.
    pub new_recovery_key: Option<&'a RecoveryKey>,
    pub new_recovery_envelope: Option<&'a [u8]>,
    /// The server's static key, pinned when the account was first registered. An empty
    /// slice means trust on first use, which only a client without a pin may do.
    pub pinned_server_key: &'a [u8],
}

/// Replaces the master credential, and optionally the recovery credential with it.
///
/// The password never crosses the wire: the caller proves the old one through OPAQUE
/// and registers the new one through OPAQUE, and both happen inside this one pair of
/// requests so the server can apply them atomically.
pub async fn replace_credentials<T: Transport>(
    transport: &T,
    request: CredentialChange<'_>,
) -> Result<()> {
    let proof = AuthInput::from_master_password(
        request.current_password,
        request.current_kdf_salt,
        &request.current_kdf_params,
    )?;
    let login_start = LoginStart::start(proof)?;

    let new_auth = AuthInput::from_master_password(
        request.new_master_password,
        request.new_kdf_salt,
        &request.new_kdf_params,
    )?;
    let new_start = RegistrationStart::start(new_auth)?;

    let new_recovery_start = match request.new_recovery_key {
        Some(key) => Some(RegistrationStart::start(AuthInput::from_recovery_key(
            key,
            request.user_id.as_bytes(),
        )?)?),
        None => None,
    };

    let body = serde_json::to_vec(&serde_json::json!({
        "identifier": request.identifier,
        "request": B64::new(login_start.request().to_vec()),
        "new_request": B64::new(new_start.request().to_vec()),
        "recovery_request": new_recovery_start
            .as_ref()
            .map(|start| B64::new(start.request().to_vec())),
    }))?;
    let answer = post(transport, "/api/v1/accounts/credentials/start", None, body).await?;

    let login_response: B64 = read(&answer, "response", "login response")?;
    let attempt_id: String = read(&answer, "attempt_id", "credential exchange")?;
    let registration_response: B64 =
        read(&answer, "registration_response", "registration response")?;

    let login_finish = if request.pinned_server_key.is_empty() {
        login_start
            .finish_trust_on_first_use(login_response.as_slice())?
            .0
    } else {
        login_start.finish(login_response.as_slice(), request.pinned_server_key)?
    };
    let upload = new_start
        .finish(registration_response.as_slice())?
        .upload()
        .to_vec();

    let recovery_upload = match (new_recovery_start, answer.get("recovery_response")) {
        (Some(start), Some(response)) => {
            let response: B64 = serde_json::from_value(response.clone())
                .map_err(|e| ClientError::Protocol(format!("recovery response: {e}")))?;
            Some(B64::new(
                start.finish(response.as_slice())?.upload().to_vec(),
            ))
        }
        (Some(_), None) => {
            return Err(ClientError::Protocol(
                "the server did not answer the Emergency Kit registration".into(),
            ))
        }
        (None, _) => None,
    };

    let params = request.new_kdf_params;
    let body = serde_json::to_vec(&serde_json::json!({
        "attempt_id": attempt_id,
        "finalization": B64::new(login_finish.finalization().to_vec()),
        "upload": B64::new(upload),
        "kdf_salt": B64::new(request.new_kdf_salt.to_vec()),
        "kdf_m_kib": params.m_kib,
        "kdf_t": params.t,
        "kdf_p": params.p,
        "user_key_envelope": B64::new(request.user_key_envelope.to_vec()),
        "recovery_upload": recovery_upload,
        "recovery_envelope": request
            .new_recovery_envelope
            .map(|envelope| B64::new(envelope.to_vec())),
    }))?;
    post(transport, "/api/v1/accounts/credentials/finish", None, body).await?;

    Ok(())
}

/// Everything a recovery needs, most of it produced locally before the server is called.
pub struct Recovery<'a> {
    pub identifier: &'a str,
    pub user_id: Uuid,
    /// The recovery key from the kit the user still holds.
    pub recovery_key: &'a RecoveryKey,
    /// The password that replaces the forgotten one.
    pub new_master_password: &'a [u8],
    pub kdf_salt: &'a [u8; KDF_SALT_LEN],
    pub kdf_params: KdfParams,
    /// The user key re-wrapped under the new password.
    pub user_key_envelope: &'a [u8],
    /// The freshly issued recovery key, and the user key wrapped under it.
    pub new_recovery_key: &'a RecoveryKey,
    pub new_recovery_envelope: &'a [u8],
    pub device: &'a DeviceSigningKey,
    pub device_id: Option<Uuid>,
    pub device_name: &'a str,
    /// The server's static key, pinned when the account was first registered.
    pub pinned_server_key: &'a [u8],
}

/// Signs in with a recovery key and installs a new password and a new kit.
///
/// # The order, and why it is this order
///
/// The local half — re-wrapping the user key, issuing a new kit — belongs to
/// [`crate::Vault::recover`] and must happen *before* this. A caller that told the
/// server first and then failed to write its own record would be locked out of an
/// account whose password it no longer knows.
///
/// This function then does the server half in exactly two requests. The old recovery
/// credential is retired by the same transaction that installs the new one, so there is
/// no instant at which both are live — which matters, because the old kit is often
/// exactly the thing the user is replacing.
pub async fn recover<T: Transport>(transport: &T, request: Recovery<'_>) -> Result<RemoteSession> {
    let proof = AuthInput::from_recovery_key(request.recovery_key, request.user_id.as_bytes())?;
    let login_start = LoginStart::start(proof)?;

    let master_start = RegistrationStart::start(AuthInput::from_master_password(
        request.new_master_password,
        request.kdf_salt,
        &request.kdf_params,
    )?)?;

    let recovery_start = RegistrationStart::start(AuthInput::from_recovery_key(
        request.new_recovery_key,
        request.user_id.as_bytes(),
    )?)?;

    let body = serde_json::to_vec(&serde_json::json!({
        "identifier": request.identifier,
        "request": B64::new(login_start.request().to_vec()),
        "master_request": B64::new(master_start.request().to_vec()),
        "recovery_request": B64::new(recovery_start.request().to_vec()),
    }))?;
    let answer = post(transport, "/api/v1/accounts/recovery/start", None, body).await?;

    let credential: B64 = read(&answer, "response", "recovery response")?;
    let attempt_id: String = read(&answer, "attempt_id", "recovery exchange")?;
    let master_response: B64 = read(&answer, "master_response", "recovery response")?;
    let recovery_response: B64 = read(&answer, "recovery_response", "recovery response")?;

    // Trust on first use pins what it sees, here as everywhere: a recovery on a device
    // that has never met this server leaves with the key it must check next time.
    let (finish, observed) = if request.pinned_server_key.is_empty() {
        let (finish, observed) = login_start.finish_trust_on_first_use(credential.as_slice())?;
        (finish, observed)
    } else {
        (
            login_start.finish(credential.as_slice(), request.pinned_server_key)?,
            request.pinned_server_key.to_vec(),
        )
    };
    let upload = master_start
        .finish(master_response.as_slice())?
        .upload()
        .to_vec();
    let recovery_upload = recovery_start
        .finish(recovery_response.as_slice())?
        .upload()
        .to_vec();

    let params = request.kdf_params;
    let body = serde_json::to_vec(&serde_json::json!({
        "attempt_id": attempt_id,
        "finalization": B64::new(finish.finalization().to_vec()),
        "device_id": request.device_id,
        "device_name": request.device_name,
        "device_public_key": B64::new(request.device.public_key().as_bytes().to_vec()),
        "upload": B64::new(upload),
        "recovery_upload": B64::new(recovery_upload),
        "kdf_salt": B64::new(request.kdf_salt.to_vec()),
        "kdf_m_kib": params.m_kib,
        "kdf_t": params.t,
        "kdf_p": params.p,
        "user_key_envelope": B64::new(request.user_key_envelope.to_vec()),
        "recovery_envelope": B64::new(request.new_recovery_envelope.to_vec()),
    }))?;
    let answer = post(transport, "/api/v1/accounts/recovery/finish", None, body).await?;

    Ok(RemoteSession {
        user_id: read_uuid(&answer, "user_id")?,
        device_id: read_uuid(&answer, "device_id")?,
        token: answer
            .get("token")
            .and_then(|value| value.as_str())
            .ok_or_else(|| ClientError::Protocol("no session token".into()))?
            .to_owned(),
        expires_at: answer
            .get("expires_at")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        server_static_public_key: observed,
    })
}

/// What a second device needs in order to attach to an account that already exists.
///
/// Everything here is something the user has: an identifier, the master password, and a
/// device key this machine generates for itself. Nothing is copied off another device,
/// which is the point — a vault that could only be joined by copying a file would not be
/// reachable from a browser at all.
pub struct Enrolment<'a> {
    pub identifier: &'a str,
    pub master_password: &'a [u8],
    pub device: &'a DeviceSigningKey,
    /// The server's static key, pinned by a device that has seen this account before.
    ///
    /// Empty for a device that has not — the trust-on-first-use case, and the weaker of
    /// the two. There is no way around it without an out-of-band code, and pretending
    /// otherwise would be worse than saying so.
    pub pinned_server_key: &'a [u8],
}

/// An account this device has just attached to: the record to persist, and the session.
#[derive(Debug)]
pub struct Enrolled {
    pub account: StoredAccount,
    pub session: RemoteSession,
}

/// Attaches this device to an account that exists on the server.
///
/// # What it fetches, and why in this order
///
/// 1. `prelogin` for the KDF salt and parameters. They are needed *before* the login,
///    because the OPAQUE credential is a function of them.
/// 2. OPAQUE login, which is the only place the master password is ever checked.
/// 3. `GET /accounts/key-envelope` for the wrapped user key. It is opaque to the server,
///    so fetching it proves nothing on its own; it is opened locally by the caller.
/// 4. `GET /vaults` for the vault to write into.
///
/// The wrapped key is fetched but **not** unwrapped here: this function has no business
/// holding key material it was not asked for, and the caller unlocks the vault with the
/// password it already has.
pub async fn enrol<T: Transport>(transport: &T, request: Enrolment<'_>) -> Result<Enrolled> {
    let prelogin: PreloginResponse = decode(
        post(
            transport,
            "/api/v1/accounts/prelogin",
            None,
            serde_json::to_vec(&serde_json::json!({ "identifier": request.identifier }))?,
        )
        .await?,
        "prelogin",
    )?;

    let kdf_salt: [u8; KDF_SALT_LEN] = prelogin.kdf_salt.as_slice().try_into().map_err(|_| {
        ClientError::Protocol("the server sent a KDF salt of the wrong length".into())
    })?;
    let kdf_params = KdfParams {
        m_kib: prelogin.kdf_m_kib,
        t: prelogin.kdf_t,
        p: prelogin.kdf_p,
        output_len: 32,
    };
    // Checked here rather than trusted: a server that handed out weakened parameters
    // would otherwise produce a weak key, silently and permanently.
    kdf_params.validate().map_err(|e| {
        ClientError::Protocol(format!("the server sent unusable KDF parameters: {e}"))
    })?;

    let session = login(
        transport,
        Credentials {
            identifier: request.identifier,
            master_password: request.master_password,
            kdf_salt: &kdf_salt,
            kdf_params,
            device: request.device,
            // Nothing to offer: this device's key was generated moments ago and has
            // never been registered. The server issues an id and binds the key to it.
            device_id: None,
        },
        request.pinned_server_key,
    )
    .await?;

    let envelope: KeyEnvelopeResponse =
        get(transport, "/api/v1/accounts/key-envelope", &session.token).await?;
    if envelope.user_key_envelope.as_slice().is_empty() {
        return Err(ClientError::Protocol(
            "the account has no wrapped user key on the server".into(),
        ));
    }

    let vaults: ListVaultsResponse = get(transport, "/api/v1/vaults", &session.token).await?;
    let vault = vaults.vaults.first().ok_or_else(|| {
        ClientError::Protocol(
            "this account has no vault yet; open it in a client that can create one".into(),
        )
    })?;

    Ok(Enrolled {
        account: StoredAccount {
            user_id: session.user_id,
            identifier: request.identifier.to_owned(),
            kdf_salt,
            kdf_params,
            user_key_envelope: envelope.user_key_envelope.into_vec(),
            recovery_envelope: envelope.recovery_envelope.map(B64::into_vec),
            vault_id: vault.vault_id,
            device_id: session.device_id,
            server_static_public_key: session.server_static_public_key.clone(),
            head_rev: 0,
            // From the beginning: this device has never seen any of it, and a cursor
            // that skipped ahead would silently drop whatever it skipped.
            sync_cursor: 0,
        },
        session,
    })
}

/// Logs in to an existing account.
///
/// `pinned_server_key` is checked by OPAQUE against the key bound into the registration
/// record. An empty slice means "no pin yet", which is the case only on a client that
/// has never seen this account — the trust-on-first-use case, and the weaker of the two.
pub async fn login<T: Transport>(
    transport: &T,
    credentials: Credentials<'_>,
    pinned_server_key: &[u8],
) -> Result<RemoteSession> {
    let Credentials {
        identifier,
        master_password,
        kdf_salt,
        kdf_params,
        device,
        device_id,
    } = credentials;

    let auth = AuthInput::from_master_password(master_password, kdf_salt, &kdf_params)?;

    let start = LoginStart::start(auth)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "identifier": identifier,
        "request": B64::new(start.request().to_vec()),
    }))?;
    let answer = post(transport, "/api/v1/accounts/login/start", None, body).await?;

    let credential: B64 = read(&answer, "response", "login response")?;
    let attempt_id = answer
        .get("attempt_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| ClientError::Protocol("no login attempt id".into()))?
        .to_owned();

    // The pin check: a server that copied the registration record cannot complete this,
    // because the envelope is bound to the real key.
    //
    // Trust on first use means *pin it now*, not "check it later if convenient". The key
    // observed here is what this session, and every later one, will be measured against.
    let (finish, observed) = if pinned_server_key.is_empty() {
        let (finish, observed) = start
            .finish_trust_on_first_use(credential.as_slice())
            .map_err(as_wrong_password)?;
        (finish, observed)
    } else {
        (
            start
                .finish(credential.as_slice(), pinned_server_key)
                .map_err(as_wrong_password)?,
            pinned_server_key.to_vec(),
        )
    };

    let body = serde_json::to_vec(&serde_json::json!({
        "attempt_id": attempt_id,
        "finalization": B64::new(finish.finalization().to_vec()),
        "device_id": device_id,
        "device_name": "CloudPass desktop",
        "device_public_key": B64::new(device.public_key().as_bytes().to_vec()),
    }))?;
    let answer = post(transport, "/api/v1/accounts/login/finish", None, body).await?;

    Ok(RemoteSession {
        user_id: read_uuid(&answer, "user_id")?,
        device_id: read_uuid(&answer, "device_id")?,
        token: answer
            .get("token")
            .and_then(|value| value.as_str())
            .ok_or_else(|| ClientError::Protocol("no session token".into()))?
            .to_owned(),
        expires_at: answer
            .get("expires_at")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        server_static_public_key: observed,
    })
}

async fn post<T: Transport>(
    transport: &T,
    path: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> Result<serde_json::Value> {
    let response = transport
        .send(HttpRequest::post(
            path.to_owned(),
            token.map(str::to_owned),
            body,
        ))
        .await?;
    let response = expect_success(response, path)?;
    if response.body.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(&response.body)
        .map_err(|e| ClientError::Protocol(format!("{path}: {e}")))
}

/// An authenticated `GET`, decoded into the caller's type.
///
/// Generic over the response rather than returning `serde_json::Value` like [`post`]:
/// these are reads of a fixed shape, and decoding inside means a server that renames a
/// field is a compile-time-adjacent failure here instead of a `None` three layers up.
async fn get<T: Transport, R: serde::de::DeserializeOwned>(
    transport: &T,
    path: &str,
    token: &str,
) -> Result<R> {
    let response = transport
        .send(HttpRequest::get(path.to_owned(), Some(token.to_owned())))
        .await?;
    let response = expect_success(response, path)?;
    serde_json::from_slice(&response.body)
        .map_err(|e| ClientError::Protocol(format!("{path}: {e}")))
}

fn expect_success(response: HttpResponse, what: &str) -> Result<HttpResponse> {
    if response.is_success() {
        return Ok(response);
    }
    let code = serde_json::from_slice::<ErrorBody>(&response.body)
        .map(|body| body.error)
        .unwrap_or_else(|_| format!("{what} failed"));
    Err(ClientError::Http {
        status: response.status,
        code,
    })
}

fn read<R: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
    field: &str,
    what: &str,
) -> Result<R> {
    let raw = value
        .get(field)
        .cloned()
        .ok_or_else(|| ClientError::Protocol(format!("{what} has no {field}")))?;
    serde_json::from_value(raw).map_err(|e| ClientError::Protocol(format!("{what}: {e}")))
}

/// Decodes a whole answer, for the paths that have no envelope around it.
fn decode<R: serde::de::DeserializeOwned>(value: serde_json::Value, what: &str) -> Result<R> {
    serde_json::from_value(value).map_err(|e| ClientError::Protocol(format!("{what}: {e}")))
}

/// Reports a failed OPAQUE exchange as "the credentials did not match".
///
/// OPAQUE fails identically for a wrong password, an account that does not exist, and a
/// tampered record — that is the point of it, and a client that tried to tell those apart
/// would be inventing a distinction the protocol deliberately does not expose. What is
/// left is the one thing the user can act on, and the one thing worth saying: the name
/// and the password do not go together.
///
/// Without this the portal would greet someone who mistyped their password with
/// "authentication failed: ciphertext or associated data was modified", which is true and
/// useless.
fn as_wrong_password(error: cloudpass_core::Error) -> ClientError {
    match error {
        cloudpass_core::Error::AuthFailed => ClientError::WrongPassword,
        other => ClientError::Crypto(other),
    }
}

fn read_uuid(value: &serde_json::Value, field: &str) -> Result<Uuid> {
    value
        .get(field)
        .and_then(|value| value.as_str())
        .and_then(|text| Uuid::parse_str(text).ok())
        .ok_or_else(|| ClientError::Protocol(format!("{field} is missing from the answer")))
}
