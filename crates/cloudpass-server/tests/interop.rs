//! Contract tests: the real client library against the real server.
//!
//! # Why this file exists
//!
//! The client and the server each define the JSON they exchange. Duplicating a wire
//! format is a real cost — a field renamed on one side breaks the other, and no
//! compiler will say so. The mitigation is this test: it drives the actual
//! `cloudpass_client::sync::SyncEngine` against the actual axum router, over a
//! transport that only forwards bytes. Nothing is mocked except the socket.
//!
//! If these tests pass, the two definitions agree on every path they exercise. If they
//! ever fail after a change to either side, that is the duplication announcing itself.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::json;
use tower::ServiceExt;

use cloudpass_client::sync::{
    provision, HttpRequest, HttpResponse, Method, PendingChange, SyncAccount, SyncEngine,
    Transport, B64,
};
use cloudpass_client::{ClientError, ItemDraft, MemoryStore, Store, Vault};
use cloudpass_core::device::DeviceSigningKey;
use cloudpass_core::kdf::RecoveryKey;
use cloudpass_core::opaque::client::{LoginStart, RegistrationStart};
use cloudpass_core::opaque::AuthInput;
use cloudpass_core::params::KdfParams;
use cloudpass_server::app;

const IDENTIFIER: &str = "interop@example.com";
const PASSWORD: &[u8] = b"correct horse battery staple";

/// A transport that talks to the router in process.
///
/// It does exactly what the desktop's HTTP client will do — build a request, hand it
/// over, read the answer — which is what makes this a contract test rather than a unit
/// test with extra steps.
struct RouterTransport {
    router: Router,
}

impl Transport for RouterTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        let mut builder = Request::builder()
            .method(request.method.as_str())
            .uri(&request.path);
        if request.method != Method::Get {
            builder = builder.header("content-type", "application/json");
        }
        if let Some(token) = &request.token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }

        let body = if request.method == Method::Get {
            Body::empty()
        } else {
            Body::from(request.body)
        };

        let response = self
            .router
            .clone()
            .oneshot(
                builder
                    .body(body)
                    .map_err(|e| ClientError::Transport(e.to_string()))?,
            )
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        Ok(HttpResponse {
            status,
            body: bytes.to_vec(),
        })
    }
}

async fn request(
    router: &Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => Body::from(serde_json::to_vec(&value).expect("encode")),
        None => Body::empty(),
    };

    let response = router
        .clone()
        .oneshot(builder.body(body).expect("build"))
        .await
        .expect("router responded");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

fn draft(title: &str, password: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        username: "octocat".to_owned(),
        password: password.to_owned(),
        url: "https://github.com".to_owned(),
        notes: String::new(),
        totp: None,
    }
}

/// Everything a logged-in device needs.
struct Session {
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    token: String,
}

/// Registers an account through the API, using the client crate's own account material.
///
/// This is the sequence a real client performs, written out here because the client
/// library does not yet own the registration flow — only the sync exchange.
async fn register(router: &Router, store: &mut MemoryStore) -> (Vault, Session, Vec<u8>) {
    let (mut vault, created) =
        Vault::create(store, IDENTIFIER, PASSWORD, KdfParams::OWASP_MINIMUM).expect("create");
    let auth = AuthInput::from_master_password(
        PASSWORD,
        &created.account.kdf_salt,
        &created.account.kdf_params,
    )
    .expect("auth input");

    let start = RegistrationStart::start(auth).expect("registration start");
    let (status, body) = request(
        router,
        "POST",
        "/api/v1/accounts/register/start",
        Some(json!({ "identifier": IDENTIFIER, "request": B64::new(start.request().to_vec()) })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register/start: {body}");

    let response: B64 = serde_json::from_value(body["response"].clone()).expect("response");
    let finish = start
        .finish(response.as_slice())
        .expect("client registration finish");
    let pinned = finish.server_static_public_key().to_vec();

    let params = created.account.kdf_params;
    let (status, body) = request(
        router,
        "POST",
        "/api/v1/accounts/register/finish",
        Some(json!({
            "user_id": created.account.user_id,
            "identifier": IDENTIFIER,
            "kdf_salt": B64::new(created.account.kdf_salt.to_vec()),
            "kdf_m_kib": params.m_kib,
            "kdf_t": params.t,
            "kdf_p": params.p,
            "account_key_required": false,
            "upload": B64::new(finish.upload().to_vec()),
            "user_key_envelope": B64::new(created.account.user_key_envelope.clone()),
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register/finish: {body}");

    // Pin the server key, as a real client must: it is what stops an impostor that
    // copied the registration record.
    vault
        .pin_server_key(store, &pinned)
        .expect("pin server key");

    let session = login(router, created.account.user_id, &created.account, &pinned).await;

    // A vault to put items in. The server stores one opaque name envelope.
    let (status, body) = request(
        router,
        "POST",
        "/api/v1/vaults",
        Some(json!({
            "vault_id": created.account.vault_id,
            "name_envelope": B64::new(vec![0x01, 0x01, 0xAB, 0xCD, 0xEF]),
        })),
        Some(&session.token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create vault: {body}");

    (vault, session, pinned)
}

async fn login(
    router: &Router,
    user_id: uuid::Uuid,
    account: &cloudpass_client::NewAccount,
    pinned_server_key: &[u8],
) -> Session {
    let auth = AuthInput::from_master_password(PASSWORD, &account.kdf_salt, &account.kdf_params)
        .expect("auth input");
    let start = LoginStart::start(auth).expect("login start");

    let (status, body) = request(
        router,
        "POST",
        "/api/v1/accounts/login/start",
        Some(json!({ "identifier": IDENTIFIER, "request": B64::new(start.request().to_vec()) })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login/start: {body}");
    let attempt: String = body["attempt_id"].as_str().expect("attempt").to_owned();
    let response: B64 = serde_json::from_value(body["response"].clone()).expect("response");

    // The pin from registration: OPAQUE binds the server's static key into the
    // envelope, and checking it is what rules out a server that copied the record.
    let finish = start
        .finish(response.as_slice(), pinned_server_key)
        .expect("client login finish");

    let (status, body) = request(
        router,
        "POST",
        "/api/v1/accounts/login/finish",
        Some(json!({
            "attempt_id": attempt,
            "finalization": B64::new(finish.finalization().to_vec()),
            "device_name": "interop device",
            "device_public_key": B64::new(account.device_public_key.to_vec()),
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login/finish: {body}");

    Session {
        user_id,
        device_id: serde_json::from_value(body["device_id"].clone()).expect("device id"),
        token: body["token"].as_str().expect("token").to_owned(),
    }
}

fn sync_engine(
    router: &Router,
    session: &Session,
    seed: [u8; 32],
    head_rev: i64,
) -> SyncEngine<RouterTransport> {
    SyncEngine::new(
        RouterTransport {
            router: router.clone(),
        },
        SyncAccount {
            user_id: session.user_id,
            device_id: session.device_id,
            device: DeviceSigningKey::from_seed(&seed),
            token: session.token.clone(),
            head_rev,
            cursor: 0,
        },
    )
}

#[tokio::test]
async fn the_client_library_pushes_and_pulls_against_the_real_server() {
    let state = cloudpass_server::state::init("sqlite::memory:")
        .await
        .expect("server state");
    let router = app(Arc::clone(&state));

    let mut store = MemoryStore::new();
    let (mut vault, session, pinned) = register(&router, &mut store).await;
    assert_eq!(session.user_id, vault.user_id());
    assert!(!pinned.is_empty());

    // A real item, sealed with the client's own key.
    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("at rest");

    let seed = store.load_device_seed().expect("read").expect("present");
    let mut engine = sync_engine(&router, &session, seed, 0);
    let trusted = engine.refresh_trusted_devices().await.expect("devices");
    assert!(trusted >= 1, "the device that logged in must be trusted");

    let outcome = engine
        .push(&mut store, vec![PendingChange::from_stored(&sealed, 0)])
        .await
        .expect("push");
    assert_eq!(outcome.applied, 1, "server refused: {outcome:?}");
    assert!(outcome.head_rejected.is_none());
    assert_eq!(engine.account().head_rev, 1);

    // A second device, sharing the account but with its own signing key and an empty
    // store. It learns the account from the same record, which is what a real second
    // device gets from the first one.
    let account_record = store.load_account().expect("read").expect("present");
    let mut other_store = MemoryStore::new();
    other_store.save_account(&account_record).expect("account");
    other_store.save_device_seed(&[0x5Au8; 32]).expect("seed");
    let mut other_vault = Vault::unlock(&other_store, PASSWORD).expect("unlock");
    assert!(other_vault.item(item_id).is_none());

    let mut other_engine = sync_engine(&router, &session, [0x5Au8; 32], 0);
    other_engine
        .refresh_trusted_devices()
        .await
        .expect("devices");

    let pulled = other_engine
        .pull(&mut other_vault, &mut other_store, true)
        .await
        .expect("pull");
    assert_eq!(pulled.absorbed, 1);
    assert_eq!(pulled.head_rev, Some(1));

    // The item arrived and decrypts on the second device — which is the whole point.
    let item = other_vault.item(item_id).expect("the item came across");
    assert_eq!(item.password, "s3cr3t");
    assert_eq!(item.title, "GitHub");
}

#[tokio::test]
async fn a_client_that_has_not_caught_up_is_told_to_pull() {
    let state = cloudpass_server::state::init("sqlite::memory:")
        .await
        .expect("server state");
    let router = app(Arc::clone(&state));

    let mut store = MemoryStore::new();
    let (mut vault, session, _pinned) = register(&router, &mut store).await;

    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("at rest");

    let seed = store.load_device_seed().expect("read").expect("present");

    // A second engine that has never pulled, so its head revision is behind.
    let mut stale = sync_engine(&router, &session, seed, 0);
    let first = stale
        .push(&mut store, vec![PendingChange::from_stored(&sealed, 0)])
        .await
        .expect("first push");
    assert_eq!(first.applied, 1);

    // Push the same change again from a device that still believes the vault is empty.
    //
    // It has to sign with the key this session's device registered: the server verifies
    // the head against *that* device, so a different key would be refused for the wrong
    // reason and the test would prove nothing about being behind.
    let mut behind = sync_engine(&router, &session, seed, 0);
    let refused = behind
        .push(&mut store, vec![PendingChange::from_stored(&sealed, 0)])
        .await
        .expect("second push");

    assert_eq!(refused.applied, 0);
    assert!(
        refused.should_retry_after_pull(),
        "the client must be told to pull: {refused:?}"
    );

    // Catching up requires knowing which devices may speak for the vault. Without this
    // the pull is refused as coming from an unknown signer — which is exactly what the
    // engine did before the line was added.
    behind.refresh_trusted_devices().await.expect("devices");

    let caught_up = behind
        .pull(&mut vault, &mut store, true)
        .await
        .expect("pull");
    assert_eq!(caught_up.head_rev, Some(1));
    assert_eq!(behind.account().head_rev, 1);
}

#[tokio::test]
async fn the_server_rejects_a_head_signed_by_a_key_it_does_not_know() {
    let state = cloudpass_server::state::init("sqlite::memory:")
        .await
        .expect("server state");
    let router = app(Arc::clone(&state));

    let mut store = MemoryStore::new();
    let (mut vault, session, _pinned) = register(&router, &mut store).await;

    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("at rest");

    // An engine whose signing key is not the one the session's device registered.
    let mut impostor = sync_engine(&router, &session, [0x99u8; 32], 0);
    let outcome = impostor
        .push(&mut store, vec![PendingChange::from_stored(&sealed, 0)])
        .await
        .expect("push");

    assert_eq!(outcome.applied, 0);
    assert_eq!(
        outcome.head_rejected.as_deref(),
        Some("head signature is invalid"),
        "the server must bind the head to the session's own device key"
    );
}

#[tokio::test]
async fn a_token_the_server_does_not_know_is_refused() {
    let state = cloudpass_server::state::init("sqlite::memory:")
        .await
        .expect("server state");
    let router = app(Arc::clone(&state));

    let mut store = MemoryStore::new();
    let (mut vault, mut session, _pinned) = register(&router, &mut store).await;
    session.token = "not-a-real-token".to_owned();

    let seed = store.load_device_seed().expect("read").expect("present");
    let mut engine = sync_engine(&router, &session, seed, 0);

    let error = engine
        .pull(&mut vault, &mut store, true)
        .await
        .expect_err("an unknown token must not open a vault");
    assert!(
        matches!(error, ClientError::Http { status: 401, .. }),
        "unexpected: {error}"
    );
}

/// Registers an account through the client library's own provisioning flow.
///
/// The helper above writes the HTTP out by hand so that the wire format is visible in
/// the test. This one does the opposite on purpose: it uses
/// [`provision::register`], which is the code the desktop application calls, so the
/// recovery credential is installed exactly the way a real client installs it.
async fn register_through_provision(
    router: &Router,
    store: &mut MemoryStore,
) -> (Vault, Vec<u8>, Session) {
    let transport = RouterTransport {
        router: router.clone(),
    };

    let (mut vault, created) =
        Vault::create(store, IDENTIFIER, PASSWORD, KdfParams::OWASP_MINIMUM).expect("create");
    let name_envelope = vault.seal_vault_name("Personal").expect("seal name");
    let seed = store.load_device_seed().expect("read").expect("present");
    let device = DeviceSigningKey::from_seed(&seed);

    let session = provision::register(
        &transport,
        provision::Registration {
            identifier: IDENTIFIER,
            master_password: PASSWORD,
            account: &created.account,
            device: &device,
            vault_name_envelope: &name_envelope,
            recovery_key: Some(created.kit.recovery_key()),
        },
    )
    .await
    .expect("register through the client library");

    vault
        .pin_server_key(store, &session.server_static_public_key)
        .expect("pin server key");

    (
        vault,
        created.kit.recovery_key().expose().to_vec(),
        Session {
            user_id: session.user_id,
            device_id: session.device_id,
            token: session.token,
        },
    )
}

/// Editing an entry and sending the edit must work — the second time, too.
///
/// The failure this pins down was quiet and looked like flakiness: the base revision of a
/// local edit was being dropped, so the push claimed the item was based on nothing. The
/// server refused it as a conflict, correctly, and the edit stayed local forever while
/// every later change to the same item collided with the revision it could not name.
#[tokio::test]
async fn an_edited_item_is_pushed_rather_than_refused_as_a_conflict() {
    let state = cloudpass_server::state::init("sqlite::memory:")
        .await
        .expect("server state");
    let router = app(Arc::clone(&state));

    let mut store = MemoryStore::new();
    let (mut vault, _kit, session) = register_through_provision(&router, &mut store).await;
    let seed = store.load_device_seed().expect("read").expect("present");

    let id = vault
        .add_item(&mut store, draft("GitHub", "first"))
        .expect("add");
    let mut engine = sync_engine(&router, &session, seed, 0);
    engine.refresh_trusted_devices().await.expect("devices");

    let added = engine
        .sync(&mut vault, &mut store)
        .await
        .expect("sync the add");
    assert_eq!(
        added.pushed.as_ref().map(|pushed| pushed.applied),
        Some(1),
        "the create must apply: {added:?}"
    );

    // The edit, through the same engine and the same store.
    vault
        .update_item(&mut store, id, draft("GitHub", "second"))
        .expect("update");

    let edited = engine
        .sync(&mut vault, &mut store)
        .await
        .expect("sync the edit");
    let pushed = edited.pushed.as_ref().expect("there was something to send");
    assert!(
        pushed.conflicts.is_empty(),
        "the edit was refused as a conflict: {pushed:?}"
    );
    assert_eq!(pushed.applied, 1, "the edit must apply: {pushed:?}");

    // And a second device sees the new value, which is the point of sending it at all.
    let account = store.load_account().expect("read").expect("present");
    let mut other_store = MemoryStore::new();
    other_store.save_account(&account).expect("account");
    other_store
        .save_device_seed(&[0x6Bu8; 32])
        .expect("device seed");
    let mut other_vault = Vault::unlock(&other_store, PASSWORD).expect("unlock");
    let mut other_engine = sync_engine(&router, &session, [0x6Bu8; 32], 0);
    other_engine
        .refresh_trusted_devices()
        .await
        .expect("devices");
    other_engine
        .pull(&mut other_vault, &mut other_store, true)
        .await
        .expect("pull");

    assert_eq!(
        other_vault.item(id).expect("the item arrived").password,
        "second"
    );
}

#[tokio::test]
async fn a_password_change_reaches_the_server_and_leaves_the_kit_alone() {
    let state = cloudpass_server::state::init("sqlite::memory:")
        .await
        .expect("server state");
    let router = app(Arc::clone(&state));
    let transport = RouterTransport {
        router: router.clone(),
    };

    let mut store = MemoryStore::new();
    let (mut vault, kit_bytes, _session) = register_through_provision(&router, &mut store).await;
    let kit_key = RecoveryKey::from_slice(&kit_bytes).expect("32 bytes");
    let record = store.load_account().expect("read").expect("present");
    let seed = store.load_device_seed().expect("read").expect("present");
    let device = DeviceSigningKey::from_seed(&seed);

    let new_password = b"a different master password";
    let master = vault
        .plan_master(new_password, KdfParams::OWASP_MINIMUM)
        .expect("plan");

    // The proof is the *current* password. Nothing about a session token would let this
    // through, which is the property `a_session_alone_cannot_write_the_wrapped_user_key`
    // asserts from the other side.
    provision::replace_credentials(
        &transport,
        provision::CredentialChange {
            identifier: IDENTIFIER,
            user_id: record.user_id,
            current_password: PASSWORD,
            current_kdf_salt: &record.kdf_salt,
            current_kdf_params: record.kdf_params,
            new_master_password: new_password,
            new_kdf_salt: master.kdf_salt(),
            new_kdf_params: master.kdf_params(),
            user_key_envelope: master.user_key_envelope(),
            new_recovery_key: None,
            new_recovery_envelope: None,
            pinned_server_key: &record.server_static_public_key,
        },
    )
    .await
    .expect("password change");

    vault
        .commit(&mut store, Some(&master), None)
        .expect("adopt");

    // The server authenticates the new password, and this device opens with it.
    provision::login(
        &transport,
        provision::Credentials {
            identifier: IDENTIFIER,
            master_password: new_password,
            kdf_salt: master.kdf_salt(),
            kdf_params: master.kdf_params(),
            device: &device,
            device_id: None,
        },
        &record.server_static_public_key,
    )
    .await
    .expect("the new password must authenticate");

    let wrong = provision::login(
        &transport,
        provision::Credentials {
            identifier: IDENTIFIER,
            master_password: PASSWORD,
            kdf_salt: master.kdf_salt(),
            kdf_params: master.kdf_params(),
            device: &device,
            device_id: None,
        },
        &record.server_static_public_key,
    )
    .await
    .expect_err("the replaced password must stop working");
    // The client reports a failed OPAQUE exchange as "the credentials did not match", not
    // as a crypto failure: OPAQUE cannot distinguish a wrong password from an account
    // that does not exist, and inventing a distinction the protocol does not expose would
    // only mislead.
    assert!(
        matches!(
            wrong,
            ClientError::WrongPassword | ClientError::Http { status: 401, .. }
        ),
        "unexpected: {wrong}"
    );

    Vault::unlock(&store, new_password).expect("the device opens with the new password");
    // The kit is untouched by a password change, and that is a property of the design
    // rather than a courtesy: the recovery envelope is not a function of the password.
    Vault::unlock_with_recovery_key(&store, &kit_key).expect("the kit still opens the vault");

    // Rotating the kit re-registers the master credential unchanged and replaces the
    // recovery one, so the old paper stops working and the new one starts.
    let kit = vault.plan_kit().expect("plan a new kit");
    provision::replace_credentials(
        &transport,
        provision::CredentialChange {
            identifier: IDENTIFIER,
            user_id: record.user_id,
            current_password: new_password,
            current_kdf_salt: master.kdf_salt(),
            current_kdf_params: master.kdf_params(),
            new_master_password: new_password,
            new_kdf_salt: master.kdf_salt(),
            new_kdf_params: master.kdf_params(),
            user_key_envelope: master.user_key_envelope(),
            new_recovery_key: Some(kit.kit().recovery_key()),
            new_recovery_envelope: Some(kit.recovery_envelope()),
            pinned_server_key: &record.server_static_public_key,
        },
    )
    .await
    .expect("kit rotation");

    vault.commit(&mut store, None, Some(&kit)).expect("adopt");
    let new_kit = kit.into_kit();

    let after = store
        .load_account()
        .expect("read")
        .expect("present")
        .recovery_envelope
        .expect("the new kit");
    assert_ne!(
        after.as_slice(),
        record
            .recovery_envelope
            .as_ref()
            .expect("the original kit")
            .as_slice(),
        "rotation must replace the recovery envelope on the device"
    );
    assert_ne!(
        new_kit.recovery_key_text(),
        cloudpass_client::recovery_code::encode(&kit_key),
        "rotation must issue a different key"
    );
}

#[tokio::test]
async fn a_recovery_key_restores_access_and_retires_the_old_kit() {
    let state = cloudpass_server::state::init("sqlite::memory:")
        .await
        .expect("server state");
    let router = app(Arc::clone(&state));
    let transport = RouterTransport {
        router: router.clone(),
    };

    let mut store = MemoryStore::new();
    let (mut vault, old_key_bytes, _session) =
        register_through_provision(&router, &mut store).await;
    let old_key = RecoveryKey::from_slice(&old_key_bytes).expect("32 bytes");
    let old_record = store.load_account().expect("read").expect("present");
    let seed = store.load_device_seed().expect("read").expect("present");
    let device = DeviceSigningKey::from_seed(&seed);

    // Something worth recovering. It is pushed now and must still open afterwards.
    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("at rest");

    let session = provision::login(
        &transport,
        provision::Credentials {
            identifier: IDENTIFIER,
            master_password: PASSWORD,
            kdf_salt: &old_record.kdf_salt,
            kdf_params: old_record.kdf_params,
            device: &device,
            device_id: None,
        },
        &old_record.server_static_public_key,
    )
    .await
    .expect("login");
    let mut engine = SyncEngine::new(
        RouterTransport {
            router: router.clone(),
        },
        SyncAccount {
            user_id: session.user_id,
            device_id: session.device_id,
            device: DeviceSigningKey::from_seed(&seed),
            token: session.token.clone(),
            head_rev: 0,
            cursor: 0,
        },
    );
    engine.refresh_trusted_devices().await.expect("devices");
    let pushed = engine
        .push(&mut store, vec![PendingChange::from_stored(&sealed, 0)])
        .await
        .expect("push");
    assert_eq!(pushed.applied, 1, "server refused: {pushed:?}");

    // The password is lost; the kit is not. Everything below happens the way the desktop
    // application does it: the replacement credentials are planned in memory, the server
    // is asked to adopt them, and only then does this device write anything. A refusal
    // therefore changes nothing on either side, and the whole thing is retryable.
    let new_password = b"a brand new master password";
    let mut vault = Vault::unlock_with_recovery_key(&store, &old_key)
        .expect("the kit must open the vault without the password");
    assert!(
        vault.item(item_id).is_some(),
        "the item is there before anything is replaced"
    );

    let master = vault
        .plan_master(new_password, KdfParams::OWASP_MINIMUM)
        .expect("plan the new master credential");
    let kit = vault.plan_kit().expect("plan the new kit");

    let record = store.load_account().expect("read").expect("present");
    let recovered_session = provision::recover(
        &transport,
        provision::Recovery {
            identifier: IDENTIFIER,
            user_id: record.user_id,
            recovery_key: &old_key,
            new_master_password: new_password,
            kdf_salt: master.kdf_salt(),
            kdf_params: master.kdf_params(),
            user_key_envelope: master.user_key_envelope(),
            new_recovery_key: kit.kit().recovery_key(),
            new_recovery_envelope: kit.recovery_envelope(),
            device: &device,
            device_id: Some(session.device_id),
            device_name: "interop device",
            pinned_server_key: &record.server_static_public_key,
        },
    )
    .await
    .expect("server recovery");

    // The server has adopted the new credentials, so this device adopts them now.
    vault
        .commit(&mut store, Some(&master), Some(&kit))
        .expect("commit");
    let new_kit = kit.into_kit();
    assert!(vault.item(item_id).is_some(), "the item survives");
    let record = store.load_account().expect("read").expect("present");
    drop(vault);

    // 1. The new password works, both to unlock and to authenticate.
    assert!(Vault::unlock(&store, new_password).is_ok());
    provision::login(
        &transport,
        provision::Credentials {
            identifier: IDENTIFIER,
            master_password: new_password,
            kdf_salt: &record.kdf_salt,
            kdf_params: record.kdf_params,
            device: &device,
            device_id: None,
        },
        &record.server_static_public_key,
    )
    .await
    .expect("the new password must authenticate");

    // 2. The old password does not. This is the assertion that would catch a server
    //    that updated the envelopes but forgot the OPAQUE record.
    let old_password = provision::login(
        &transport,
        provision::Credentials {
            identifier: IDENTIFIER,
            master_password: PASSWORD,
            kdf_salt: &record.kdf_salt,
            kdf_params: record.kdf_params,
            device: &device,
            device_id: None,
        },
        &record.server_static_public_key,
    )
    .await
    .expect_err("the forgotten password must stop working");
    // OPAQUE fails this on the client: the server's answer is computed against the new
    // registration record, so the old password cannot complete the exchange. That is
    // strictly better than a 401, and the assertion accepts both because which side
    // notices first is an implementation detail.
    assert!(
        matches!(
            old_password,
            ClientError::WrongPassword | ClientError::Http { status: 401, .. }
        ),
        "unexpected: {old_password}"
    );

    // 3. Every session issued under the old credential is gone.
    let (status, _) = request(
        &router,
        "GET",
        "/api/v1/devices",
        None,
        Some(&session.token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 4. The old kit no longer opens a session; the new one does.
    let retired = provision::recover(
        &transport,
        provision::Recovery {
            identifier: IDENTIFIER,
            user_id: record.user_id,
            recovery_key: &old_key,
            new_master_password: new_password,
            kdf_salt: master.kdf_salt(),
            kdf_params: master.kdf_params(),
            user_key_envelope: master.user_key_envelope(),
            new_recovery_key: new_kit.recovery_key(),
            new_recovery_envelope: record
                .recovery_envelope
                .as_ref()
                .expect("a fresh recovery envelope"),
            device: &device,
            device_id: Some(recovered_session.device_id),
            device_name: "interop device",
            pinned_server_key: &record.server_static_public_key,
        },
    )
    .await
    .expect_err("the retired kit must not be able to sign in");
    // The client rejects the server's answer locally, because the OPAQUE record it is
    // now proving against belongs to the new key. Either way, no session is issued.
    assert!(
        matches!(
            retired,
            ClientError::Crypto(cloudpass_core::Error::AuthFailed)
                | ClientError::Http { status: 401, .. }
        ),
        "unexpected: {retired}"
    );

    // 4b. And the new kit does open one.
    let renewed = provision::recover(
        &transport,
        provision::Recovery {
            identifier: IDENTIFIER,
            user_id: record.user_id,
            recovery_key: new_kit.recovery_key(),
            new_master_password: new_password,
            kdf_salt: master.kdf_salt(),
            kdf_params: master.kdf_params(),
            user_key_envelope: master.user_key_envelope(),
            new_recovery_key: new_kit.recovery_key(),
            new_recovery_envelope: record
                .recovery_envelope
                .as_ref()
                .expect("a recovery envelope"),
            device: &device,
            device_id: None,
            device_name: "interop device",
            pinned_server_key: &record.server_static_public_key,
        },
    )
    .await
    .expect("the kit issued by recovery must work");
    assert_eq!(renewed.user_id, record.user_id);

    // 5. The vault data is untouched: a fresh device pulls the item and it decrypts,
    //    which only works if the user key never changed.
    let mut fresh_store = MemoryStore::new();
    fresh_store.save_account(&record).expect("account");
    fresh_store
        .save_device_seed(&[0x77u8; 32])
        .expect("device seed");
    let mut fresh_vault = Vault::unlock(&fresh_store, new_password).expect("unlock");
    let mut fresh_engine = sync_engine(
        &router,
        &Session {
            user_id: renewed.user_id,
            device_id: renewed.device_id,
            token: renewed.token,
        },
        [0x77u8; 32],
        1,
    );
    fresh_engine
        .refresh_trusted_devices()
        .await
        .expect("devices");
    let pulled = fresh_engine
        .pull(&mut fresh_vault, &mut fresh_store, true)
        .await
        .expect("pull");
    assert_eq!(pulled.absorbed, 1);
    assert_eq!(
        fresh_vault
            .item(item_id)
            .expect("the item came back")
            .password,
        "s3cr3t"
    );
}

/// A device that has nothing but an identifier and a password must end up with the data.
///
/// This is the web-then-desktop story: an account is created and used in one client, and
/// a second one — which has never seen the first, copied no file, and holds no local
/// record — attaches with nothing but the credentials and pulls everything down.
#[tokio::test]
async fn a_device_with_nothing_but_the_password_attaches_and_pulls() {
    let state = cloudpass_server::state::init("sqlite::memory:")
        .await
        .expect("server state");
    let router = app(Arc::clone(&state));
    let transport = RouterTransport {
        router: router.clone(),
    };

    // The first client: registers, saves a password, pushes it.
    let mut first_store = MemoryStore::new();
    let (mut first_vault, _kit, _session) =
        register_through_provision(&router, &mut first_store).await;
    let item_id = first_vault
        .add_item(&mut first_store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = first_store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("at rest");

    let first_seed = first_store
        .load_device_seed()
        .expect("read")
        .expect("present");
    let first_record = first_store.load_account().expect("read").expect("present");
    let first_session = provision::login(
        &transport,
        provision::Credentials {
            identifier: IDENTIFIER,
            master_password: PASSWORD,
            kdf_salt: &first_record.kdf_salt,
            kdf_params: first_record.kdf_params,
            device: &DeviceSigningKey::from_seed(&first_seed),
            device_id: None,
        },
        &first_record.server_static_public_key,
    )
    .await
    .expect("login");
    let mut engine = SyncEngine::new(
        RouterTransport {
            router: router.clone(),
        },
        SyncAccount {
            user_id: first_session.user_id,
            device_id: first_session.device_id,
            device: DeviceSigningKey::from_seed(&first_seed),
            token: first_session.token.clone(),
            head_rev: 0,
            cursor: 0,
        },
    );
    engine.refresh_trusted_devices().await.expect("devices");
    assert_eq!(
        engine
            .push(
                &mut first_store,
                vec![PendingChange::from_stored(&sealed, 0)]
            )
            .await
            .expect("push")
            .applied,
        1
    );

    // The second device: a fresh store, its own signing key, and no file from the first.
    let mut second_store = MemoryStore::new();
    let second_seed = [0x5Au8; 32];
    second_store
        .save_device_seed(&second_seed)
        .expect("device seed");

    let enrolled = provision::enrol(
        &transport,
        provision::Enrolment {
            identifier: IDENTIFIER,
            master_password: PASSWORD,
            device: &DeviceSigningKey::from_seed(&second_seed),
            // Nothing to pin: this device has never met this server.
            pinned_server_key: &[],
        },
    )
    .await
    .expect("enrol");

    assert!(
        !enrolled.account.user_key_envelope.is_empty(),
        "the wrapped key must come down with the account"
    );
    assert!(
        !enrolled.account.server_static_public_key.is_empty(),
        "trust on first use must *pin*, not merely accept"
    );
    assert_eq!(enrolled.account.identifier, IDENTIFIER);
    assert_eq!(enrolled.session.user_id, first_session.user_id);
    assert_eq!(
        enrolled.account.vault_id, first_record.vault_id,
        "the second device must write into the account's own vault"
    );
    second_store
        .save_account(&enrolled.account)
        .expect("save account");

    let mut second_vault =
        Vault::unlock(&second_store, PASSWORD).expect("the password opens what came down");
    assert!(second_vault.item(item_id).is_none(), "nothing local yet");

    let mut second_engine = SyncEngine::new(
        RouterTransport {
            router: router.clone(),
        },
        SyncAccount {
            user_id: enrolled.session.user_id,
            device_id: enrolled.session.device_id,
            device: DeviceSigningKey::from_seed(&second_seed),
            token: enrolled.session.token.clone(),
            head_rev: enrolled.account.head_rev,
            cursor: enrolled.account.sync_cursor,
        },
    );
    second_engine
        .refresh_trusted_devices()
        .await
        .expect("devices");
    let pulled = second_engine
        .pull(&mut second_vault, &mut second_store, true)
        .await
        .expect("pull");
    assert_eq!(pulled.absorbed, 1);
    assert_eq!(
        second_vault
            .item(item_id)
            .expect("the item arrived")
            .password,
        "s3cr3t"
    );

    // A wrong password must not attach, no matter how the rest of the flow looks.
    let wrong = provision::enrol(
        &transport,
        provision::Enrolment {
            identifier: IDENTIFIER,
            master_password: b"not the password",
            device: &DeviceSigningKey::from_seed(&[0x99u8; 32]),
            pinned_server_key: &[],
        },
    )
    .await
    .expect_err("a wrong password must not enrol a device");
    assert!(
        matches!(
            wrong,
            ClientError::WrongPassword | ClientError::Http { status: 401, .. }
        ),
        "unexpected: {wrong}"
    );
}
