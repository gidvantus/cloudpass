//! End-to-end tests driving the real router in-process.
//!
//! These are not unit tests of handlers: they run the whole sequence a client would
//! run — prelogin, OPAQUE registration, OPAQUE login, device key enrolment, vault
//! creation, signed push, pull and head verification — through the actual HTTP
//! surface, with the actual middleware. The only thing missing compared to a
//! deployment is the socket.
//!
//! The client half is written the way a real client would: it keeps a local mirror of
//! its items, computes the state root over that mirror, signs the commitment with its
//! device key, and verifies the head it gets back. If the tests passed while skipping
//! any of those steps, they would not be testing the property they claim to.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use serde::Deserialize;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use cloudpass_core::aad::{ItemAad, KeyKind};
use cloudpass_core::device::{DevicePublicKey, DeviceSigningKey};
use cloudpass_core::head::{
    state_root, verify_head, HeadCommitment, HeadRecord, ItemDigest, KnownDevice,
};
use cloudpass_core::ids::random_uuid;
use cloudpass_core::kdf::{derive_ukek, stretch_master_password};
use cloudpass_core::opaque::client::{LoginStart, RegistrationStart};
use cloudpass_core::opaque::AuthInput;
use cloudpass_core::params::{KdfParams, KDF_SALT_LEN};
use cloudpass_core::vault::{seal_item, wrap_user_key, UserKey};
use cloudpass_server::codec::B64;
use cloudpass_server::{app, AppState};

const IDENTIFIER: &str = "alice@example.com";
const PASSWORD: &[u8] = b"correct horse battery staple";
const SALT: [u8; KDF_SALT_LEN] = [0x5Au8; KDF_SALT_LEN];
const WRONG_PASSWORD: &[u8] = b"definitely not the password";

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PreloginResponse {
    kdf_salt: B64,
    kdf_m_kib: u32,
    kdf_t: u32,
    kdf_p: u32,
}

#[derive(Debug, Deserialize)]
struct RegisterStartResponse {
    response: B64,
}

#[derive(Debug, Deserialize)]
struct RegisterFinishResponse {
    user_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct LoginStartResponse {
    response: B64,
    attempt_id: String,
}

#[derive(Debug, Deserialize)]
struct LoginFinishResponse {
    token: String,
    user_id: Uuid,
    device_id: Uuid,
    expires_at: i64,
    account_key_required: bool,
}

#[derive(Debug, Deserialize)]
struct ItemJson {
    id: Uuid,
    #[allow(dead_code)]
    vault_id: Uuid,
    rev: i64,
    envelope: B64,
    #[allow(dead_code)]
    meta: serde_json::Value,
    deleted: bool,
    #[allow(dead_code)]
    seq: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct HeadJson {
    head_rev: i64,
    state_root: B64,
    signature: B64,
    signer_device_id: Uuid,
    #[allow(dead_code)]
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct PullResponse {
    items: Vec<ItemJson>,
    next_cursor: i64,
    has_more: bool,
    head: Option<HeadJson>,
}

#[derive(Debug, Deserialize)]
struct AppliedJson {
    #[allow(dead_code)]
    id: Uuid,
    rev: i64,
    #[allow(dead_code)]
    seq: i64,
}

#[derive(Debug, Deserialize)]
struct ConflictJson {
    reason: String,
    current: Option<ItemJson>,
}

#[derive(Debug, Deserialize)]
struct PushResponse {
    applied: Vec<AppliedJson>,
    conflicts: Vec<ConflictJson>,
    head_rejected: Option<String>,
    head: Option<HeadJson>,
}

#[derive(Debug, Deserialize)]
struct ErrorJson {
    error: String,
}

#[derive(Debug, Deserialize)]
struct EnvelopeResponse {
    user_key_envelope: B64,
    recovery_envelope: Option<B64>,
}

#[derive(Debug, Deserialize)]
struct DeviceJson {
    device_id: Uuid,
    #[allow(dead_code)]
    name: String,
    public_key: Option<B64>,
    #[allow(dead_code)]
    created_at: i64,
    #[allow(dead_code)]
    last_seen_at: Option<i64>,
    revoked_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ListDevicesResponse {
    devices: Vec<DeviceJson>,
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A server plus a handle on its state, so tests can do things the API deliberately
/// does not expose yet (such as revoking a device directly).
struct Harness {
    router: Router,
    state: Arc<AppState>,
}

impl Harness {
    async fn start() -> Self {
        let state = cloudpass_server::state::init("sqlite::memory:")
            .await
            .expect("initialise server state");
        let router = app(Arc::clone(&state));
        Self { router, state }
    }

    async fn call(
        &self,
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
            Some(value) => Body::from(serde_json::to_vec(&value).expect("encode request")),
            None => Body::empty(),
        };

        let response = self
            .router
            .clone()
            .oneshot(builder.body(body).expect("build request"))
            .await
            .expect("router responded");

        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, value)
    }

    async fn post(
        &self,
        uri: &str,
        body: serde_json::Value,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        self.call("POST", uri, Some(body), token).await
    }

    async fn get(&self, uri: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
        self.call("GET", uri, None, token).await
    }
}

fn decode<T: for<'de> Deserialize<'de>>(value: &serde_json::Value) -> T {
    serde_json::from_value(value.clone()).expect("response shape")
}

fn auth(password: &[u8]) -> AuthInput {
    AuthInput::from_master_password(password, &SALT, &KdfParams::OWASP_MINIMUM)
        .expect("derive auth input")
}

/// The client's own key material, built exactly as a real client builds it.
struct ClientKeys {
    user_key: UserKey,
    user_key_envelope: Vec<u8>,
}

fn build_client_keys(user_id: Uuid) -> ClientKeys {
    let stretched = stretch_master_password(PASSWORD, &SALT, &KdfParams::OWASP_MINIMUM)
        .expect("stretch master password");
    let ukek = derive_ukek(&stretched, None, &SALT).expect("derive ukek");
    let user_key = UserKey::generate();
    let envelope = wrap_user_key(&ukek, &user_key, user_id, KeyKind::UserKey)
        .expect("wrap user key")
        .to_bytes();

    ClientKeys {
        user_key,
        user_key_envelope: envelope,
    }
}

/// A client with a device key and a local mirror of its items.
///
/// The mirror is what makes the signed head meaningful: the root is computed from it,
/// exactly as a real client would.
struct SyncClient {
    user_id: Uuid,
    device_id: Uuid,
    token: String,
    signing: DeviceSigningKey,
    items: BTreeMap<Uuid, ItemDigest>,
    head_rev: i64,
}

impl SyncClient {
    /// The root the client would have after applying a batch to its own view.
    fn staged_root(&self, batch: &[PendingItem]) -> [u8; 32] {
        let mut items = self.items.clone();
        for change in batch {
            items.insert(
                change.id,
                ItemDigest::from_envelope(change.id, change.rev, change.deleted, &change.envelope),
            );
        }
        state_root(&items.into_values().collect::<Vec<_>>())
    }

    fn apply(&mut self, batch: &[PendingItem]) {
        for change in batch {
            self.items.insert(
                change.id,
                ItemDigest::from_envelope(change.id, change.rev, change.deleted, &change.envelope),
            );
        }
    }

    /// Pushes a batch, committing to the resulting state with a signed head.
    async fn push(&mut self, harness: &Harness, batch: Vec<PendingItem>) -> PushResponse {
        let head_rev = self.head_rev + 1;
        let root = self.staged_root(&batch);
        let commitment = HeadCommitment {
            owner: self.user_id,
            head_rev,
            state_root: root,
        };
        let signature = self.signing.sign(&commitment.canonical());

        let (status, body) = harness
            .post(
                "/api/v1/sync/push",
                json!({
                    "head": {
                        "head_rev": head_rev,
                        "state_root": B64(root.to_vec()),
                        "signature": B64(signature.as_bytes().to_vec()),
                    },
                    "changes": batch.iter().map(PendingItem::json).collect::<Vec<_>>(),
                }),
                Some(&self.token),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "push: {body}");
        let response: PushResponse = decode(&body);

        if response.head_rejected.is_none() && !response.applied.is_empty() {
            self.apply(&batch);
            self.head_rev = head_rev;
        }

        response
    }

    /// Pushes with an explicitly chosen head, to exercise the rejection paths.
    async fn push_with_head(
        &self,
        harness: &Harness,
        batch: &[PendingItem],
        head_rev: i64,
        root: [u8; 32],
        signature: Vec<u8>,
    ) -> PushResponse {
        let (status, body) = harness
            .post(
                "/api/v1/sync/push",
                json!({
                    "head": {
                        "head_rev": head_rev,
                        "state_root": B64(root.to_vec()),
                        "signature": B64(signature),
                    },
                    "changes": batch.iter().map(PendingItem::json).collect::<Vec<_>>(),
                }),
                Some(&self.token),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "push: {body}");
        decode(&body)
    }

    /// Pulls from the beginning and rebuilds the local mirror.
    async fn pull(&mut self, harness: &Harness) -> PullResponse {
        let (status, body) = harness
            .get("/api/v1/sync/pull?cursor=0", Some(&self.token))
            .await;
        assert_eq!(status, StatusCode::OK, "pull: {body}");
        let response: PullResponse = decode(&body);

        self.items = response
            .items
            .iter()
            .map(|item| {
                (
                    item.id,
                    ItemDigest::from_envelope(
                        item.id,
                        item.rev,
                        item.deleted,
                        item.envelope.as_slice(),
                    ),
                )
            })
            .collect();

        if let Some(head) = &response.head {
            self.head_rev = head.head_rev;
        }

        response
    }

    /// Verifies a head exactly as a real client must: trusted signer, valid signature,
    /// and not older than what this client already accepted.
    async fn verify(&self, harness: &Harness, head: &HeadJson) -> cloudpass_core::Result<()> {
        let record = HeadRecord {
            head_rev: head.head_rev,
            state_root: head
                .state_root
                .as_slice()
                .try_into()
                .expect("32-byte state root"),
            signer: head.signer_device_id,
            signature: cloudpass_core::device::HeadSignature::from_slice(head.signature.as_slice())
                .expect("64-byte signature"),
        };

        verify_head(
            self.user_id,
            &record,
            &self.trusted_devices(harness).await,
            self.head_rev,
        )
    }

    async fn trusted_devices(&self, harness: &Harness) -> Vec<KnownDevice> {
        let (status, body) = harness.get("/api/v1/devices", Some(&self.token)).await;
        assert_eq!(status, StatusCode::OK, "devices: {body}");
        let listed: ListDevicesResponse = decode(&body);

        listed
            .devices
            .iter()
            .filter(|device| device.revoked_at.is_none())
            .filter_map(|device| {
                let key = device.public_key.as_ref()?;
                Some(KnownDevice {
                    device_id: device.device_id,
                    public_key: DevicePublicKey::from_slice(key.as_slice()).ok()?,
                })
            })
            .collect()
    }
}

/// Registers an account and logs in, returning a ready-to-sync client.
async fn register_and_login(harness: &Harness) -> (SyncClient, Vec<u8>, ClientKeys) {
    let user_id = random_uuid();
    let keys = build_client_keys(user_id);
    let signing = DeviceSigningKey::generate();

    let start = RegistrationStart::start(auth(PASSWORD)).expect("registration start");
    let (status, body) = harness
        .post(
            "/api/v1/accounts/register/start",
            json!({ "identifier": IDENTIFIER, "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "register/start: {body}");
    let response: RegisterStartResponse = decode(&body);

    let finish = start
        .finish(response.response.as_slice())
        .expect("client registration finish");
    let pinned = finish.server_static_public_key().to_vec();

    let params = KdfParams::OWASP_MINIMUM;
    let (status, body) = harness
        .post(
            "/api/v1/accounts/register/finish",
            json!({
                "user_id": user_id,
                "identifier": IDENTIFIER,
                "kdf_salt": B64(SALT.to_vec()),
                "kdf_m_kib": params.m_kib,
                "kdf_t": params.t,
                "kdf_p": params.p,
                "account_key_required": false,
                "upload": B64(finish.upload().to_vec()),
                "user_key_envelope": B64(keys.user_key_envelope.clone()),
            }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "register/finish: {body}");
    let registered: RegisterFinishResponse = decode(&body);
    assert_eq!(registered.user_id, user_id);

    let client = login_with(harness, IDENTIFIER, PASSWORD, &pinned, signing, None).await;
    assert_eq!(client.user_id, user_id);

    (client, pinned, keys)
}

/// Registers a second account, given a password that will complete the protocol.
async fn register_account(harness: &Harness, identifier: &str, password: &[u8]) -> (Uuid, Vec<u8>) {
    let user_id = random_uuid();
    let keys = build_client_keys(user_id);

    let start = RegistrationStart::start(auth(password)).expect("start");
    let (status, body) = harness
        .post(
            "/api/v1/accounts/register/start",
            json!({ "identifier": identifier, "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "register/start: {body}");
    let response: RegisterStartResponse = decode(&body);

    let finish = start.finish(response.response.as_slice()).expect("finish");
    let params = KdfParams::OWASP_MINIMUM;
    let (status, body) = harness
        .post(
            "/api/v1/accounts/register/finish",
            json!({
                "user_id": user_id,
                "identifier": identifier,
                "kdf_salt": B64(SALT.to_vec()),
                "kdf_m_kib": params.m_kib,
                "kdf_t": params.t,
                "kdf_p": params.p,
                "account_key_required": false,
                "upload": B64(finish.upload().to_vec()),
                "user_key_envelope": B64(keys.user_key_envelope),
            }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "register/finish: {body}");

    (user_id, finish.server_static_public_key().to_vec())
}

/// Logs in, optionally reusing an existing device id and key.
async fn login_with(
    harness: &Harness,
    identifier: &str,
    password: &[u8],
    pinned: &[u8],
    signing: DeviceSigningKey,
    device_id: Option<Uuid>,
) -> SyncClient {
    let start = LoginStart::start(auth(password)).expect("login start");
    let (status, body) = harness
        .post(
            "/api/v1/accounts/login/start",
            json!({ "identifier": identifier, "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "login/start: {body}");
    let started: LoginStartResponse = decode(&body);

    let finish = start
        .finish(started.response.as_slice(), pinned)
        .expect("client login finish");

    let (status, body) = harness
        .post(
            "/api/v1/accounts/login/finish",
            json!({
                "attempt_id": started.attempt_id,
                "finalization": B64(finish.finalization().to_vec()),
                "device_id": device_id,
                "device_name": "test device",
                "device_public_key": B64(signing.public_key().as_bytes().to_vec()),
            }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "login/finish: {body}");
    let session: LoginFinishResponse = decode(&body);
    assert!(session.expires_at > 0);
    assert_ne!(session.device_id, Uuid::nil());
    assert!(!session.account_key_required);

    SyncClient {
        user_id: session.user_id,
        device_id: session.device_id,
        token: session.token,
        signing,
        items: BTreeMap::new(),
        head_rev: 0,
    }
}

async fn create_vault(harness: &Harness, token: &str) -> Uuid {
    let vault_id = random_uuid();
    let (status, body) = harness
        .post(
            "/api/v1/vaults",
            json!({ "vault_id": vault_id, "name_envelope": B64(opaque_blob(48)) }),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create vault: {body}");
    vault_id
}

/// Arbitrary opaque bytes shaped like one of our envelopes. The server must not care
/// what is inside, and this makes sure it does not.
fn opaque_blob(payload_len: usize) -> Vec<u8> {
    let mut envelope = vec![0x01u8, 0x01];
    envelope.extend_from_slice(&[0xAB; 12]);
    envelope.extend_from_slice(&[0xCD; 32]);
    envelope.extend_from_slice(&vec![0xEF; payload_len]);
    envelope
}

/// One item change, as a client would describe it before pushing.
struct PendingItem {
    id: Uuid,
    vault_id: Uuid,
    envelope: Vec<u8>,
    base_rev: i64,
    rev: i64,
    deleted: bool,
}

impl PendingItem {
    /// A change based on the revision immediately before it, which is what a client
    /// that has just seen the current state produces.
    fn new(id: Uuid, vault_id: Uuid, rev: i64, envelope: Vec<u8>) -> Self {
        Self {
            id,
            vault_id,
            envelope,
            base_rev: if rev <= 1 { 0 } else { rev - 1 },
            rev,
            deleted: false,
        }
    }

    /// A change deliberately based on a stale revision.
    fn based_on(mut self, base_rev: i64) -> Self {
        self.base_rev = base_rev;
        self
    }

    fn deleted(mut self) -> Self {
        self.deleted = true;
        self
    }

    fn json(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "vault_id": self.vault_id,
            "base_rev": self.base_rev,
            "rev": self.rev,
            "envelope": B64(self.envelope.clone()),
            "deleted": self.deleted,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_lifecycle_stores_and_returns_an_untouched_envelope() {
    let harness = Harness::start().await;
    let (mut client, _pinned, keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    let item_id = random_uuid();
    let aad = ItemAad::new(client.user_id, vault_id, item_id, 1, false);
    let sealed = seal_item(
        &keys.user_key,
        &aad,
        br#"{"title":"GitHub","password":"s3cr3t"}"#,
    )
    .expect("seal item")
    .to_bytes();

    let pushed = client
        .push(
            &harness,
            vec![PendingItem::new(item_id, vault_id, 1, sealed.clone())],
        )
        .await;
    assert_eq!(pushed.head_rejected, None);
    assert_eq!(pushed.conflicts.len(), 0);
    assert_eq!(pushed.applied.len(), 1);
    assert_eq!(pushed.applied[0].rev, 1);

    let pulled = client.pull(&harness).await;
    assert_eq!(pulled.items.len(), 1);
    assert_eq!(pulled.items[0].id, item_id);

    // The central promise of the server: what came back is byte-for-byte what went in.
    assert_eq!(pulled.items[0].envelope.as_slice(), sealed.as_slice());

    // The head that pull returned verifies against the registered device key.
    let head = pulled.head.as_ref().expect("a head after the first push");
    assert_eq!(head.head_rev, 1);
    assert_eq!(head.signer_device_id, client.device_id);
    client.verify(&harness, head).await.expect("head verifies");

    // And the stored payload really is the client's ciphertext, openable with the
    // client's own key — the server contributed nothing to that.
    let opened = cloudpass_core::vault::open_item(
        &keys.user_key,
        &aad,
        &cloudpass_core::envelope::Envelope::from_bytes(pulled.items[0].envelope.as_slice())
            .expect("parse envelope"),
    )
    .expect("open item");
    assert!(String::from_utf8_lossy(&opened).contains("s3cr3t"));
}

#[tokio::test]
async fn the_head_advances_by_one_per_push_and_the_root_tracks_the_items() {
    let harness = Harness::start().await;
    let (mut client, _pinned, _keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    for expected_rev in 1..=3i64 {
        let item_id = random_uuid();
        let pushed = client
            .push(
                &harness,
                vec![PendingItem::new(item_id, vault_id, 1, opaque_blob(24))],
            )
            .await;
        assert_eq!(pushed.head_rejected, None);
        let head = pushed.head.expect("head after a successful push");
        assert_eq!(head.head_rev, expected_rev);

        // The root the server reports must equal what this client computes from the
        // items it knows about — which is the property the commitment relies on.
        assert_eq!(
            head.state_root.as_slice(),
            client.staged_root(&[]).as_slice(),
            "server root must match the client's own view"
        );
        client.verify(&harness, &head).await.expect("head verifies");
    }
}

#[tokio::test]
async fn a_head_signed_by_an_unregistered_key_is_refused() {
    let harness = Harness::start().await;
    let (mut client, _pinned, _keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    let item_id = random_uuid();
    let batch = vec![PendingItem::new(item_id, vault_id, 1, opaque_blob(16))];
    let root = client.staged_root(&batch);

    // A different device's key: the right shape, the wrong signer.
    let impostor = DeviceSigningKey::generate();
    let signature = impostor.sign(
        &HeadCommitment {
            owner: client.user_id,
            head_rev: 1,
            state_root: root,
        }
        .canonical(),
    );

    let response = client
        .push_with_head(&harness, &batch, 1, root, signature.as_bytes().to_vec())
        .await;

    assert_eq!(
        response.head_rejected.as_deref(),
        Some("head signature is invalid")
    );
    assert!(response.applied.is_empty());

    // Nothing was written.
    let pulled = client.pull(&harness).await;
    assert!(pulled.items.is_empty());
    assert!(
        pulled.head.is_none(),
        "a refused push must not advance the head"
    );
}

#[tokio::test]
async fn a_push_committing_to_the_wrong_state_is_refused_and_changes_nothing() {
    let harness = Harness::start().await;
    let (mut client, _pinned, _keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    let item_id = random_uuid();
    let batch = vec![PendingItem::new(item_id, vault_id, 1, opaque_blob(16))];

    // The client signs a root that does not describe the state it is about to create —
    // exactly what a client with a stale or partial view would produce.
    let honest_root = client.staged_root(&batch);
    let mut wrong_root = honest_root;
    wrong_root[0] ^= 0x01;

    let signature = client.signing.sign(
        &HeadCommitment {
            owner: client.user_id,
            head_rev: 1,
            state_root: wrong_root,
        }
        .canonical(),
    );

    let response = client
        .push_with_head(
            &harness,
            &batch,
            1,
            wrong_root,
            signature.as_bytes().to_vec(),
        )
        .await;

    assert_eq!(
        response.head_rejected.as_deref(),
        Some("state root does not match the server's state; pull and retry")
    );
    assert!(response.applied.is_empty());

    let pulled = client.pull(&harness).await;
    assert!(
        pulled.items.is_empty(),
        "the batch must have been rolled back"
    );
    assert!(pulled.head.is_none());
}

#[tokio::test]
async fn a_push_claiming_a_stale_head_revision_is_refused() {
    let harness = Harness::start().await;
    let (mut client, _pinned, _keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    let first = client
        .push(
            &harness,
            vec![PendingItem::new(
                random_uuid(),
                vault_id,
                1,
                opaque_blob(16),
            )],
        )
        .await;
    assert_eq!(first.head_rejected, None);

    // Claim revision 1 again instead of 2.
    let batch = vec![PendingItem::new(
        random_uuid(),
        vault_id,
        1,
        opaque_blob(16),
    )];
    let root = client.staged_root(&batch);
    let signature = client.signing.sign(
        &HeadCommitment {
            owner: client.user_id,
            head_rev: 1,
            state_root: root,
        }
        .canonical(),
    );

    let response = client
        .push_with_head(&harness, &batch, 1, root, signature.as_bytes().to_vec())
        .await;

    assert_eq!(
        response.head_rejected.as_deref(),
        Some("head revision is not current")
    );
    assert!(response.applied.is_empty());
}

/// The attack the whole feature exists for: the server offers a head the client has
/// already moved past. The signature on it is genuine — that is what makes it
/// dangerous, and what the monotonicity check catches.
#[tokio::test]
async fn a_rolled_back_head_is_detected_even_though_its_signature_is_valid() {
    let harness = Harness::start().await;
    let (mut client, _pinned, _keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    let first = client
        .push(
            &harness,
            vec![PendingItem::new(
                random_uuid(),
                vault_id,
                1,
                opaque_blob(16),
            )],
        )
        .await;
    let old_head = first.head.clone().expect("head after the first push");
    client
        .verify(&harness, &old_head)
        .await
        .expect("fresh head");

    let second = client
        .push(
            &harness,
            vec![PendingItem::new(
                random_uuid(),
                vault_id,
                1,
                opaque_blob(16),
            )],
        )
        .await;
    let new_head = second.head.clone().expect("head after the second push");
    assert_eq!(new_head.head_rev, 2);

    // A server replaying the earlier response would send this. It verifies perfectly
    // on its own — the signature is real — and must still be refused.
    assert_eq!(
        client.verify(&harness, &old_head).await,
        Err(cloudpass_core::Error::StaleHead),
        "an older head must be refused even with a valid signature"
    );
    client
        .verify(&harness, &new_head)
        .await
        .expect("current head");
}

#[tokio::test]
async fn a_head_from_an_unknown_device_is_refused_by_the_client() {
    let harness = Harness::start().await;
    let (mut client, _pinned, _keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    let pushed = client
        .push(
            &harness,
            vec![PendingItem::new(
                random_uuid(),
                vault_id,
                1,
                opaque_blob(16),
            )],
        )
        .await;
    let head = pushed.head.expect("head");

    // Same head, attributed to a device the client has never heard of.
    let forged = HeadJson {
        head_rev: head.head_rev,
        state_root: head.state_root.clone(),
        signature: head.signature.clone(),
        signer_device_id: random_uuid(),
        updated_at: head.updated_at,
    };
    assert_eq!(
        client.verify(&harness, &forged).await,
        Err(cloudpass_core::Error::UnknownSigner)
    );
}

#[tokio::test]
async fn a_tampered_state_root_is_refused_by_the_client() {
    let harness = Harness::start().await;
    let (mut client, _pinned, _keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    let pushed = client
        .push(
            &harness,
            vec![PendingItem::new(
                random_uuid(),
                vault_id,
                1,
                opaque_blob(16),
            )],
        )
        .await;
    let head = pushed.head.expect("head");

    // A server that kept the signature but changed what it claims to commit to.
    let mut tampered_root = head.state_root.0.clone();
    tampered_root[0] ^= 0x01;
    let tampered = HeadJson {
        state_root: B64(tampered_root),
        ..HeadJson {
            head_rev: head.head_rev,
            state_root: head.state_root.clone(),
            signature: head.signature.clone(),
            signer_device_id: head.signer_device_id,
            updated_at: head.updated_at,
        }
    };

    assert_eq!(
        client.verify(&harness, &tampered).await,
        Err(cloudpass_core::Error::BadSignature)
    );
}

#[tokio::test]
async fn a_device_cannot_rebind_its_id_to_a_new_signing_key() {
    let harness = Harness::start().await;
    let (client, pinned, _keys) = register_and_login(&harness).await;

    // Same device id, a different key: the shape of a device-id theft.
    let replacement = DeviceSigningKey::generate();
    let start = LoginStart::start(auth(PASSWORD)).expect("login start");
    let (_, body) = harness
        .post(
            "/api/v1/accounts/login/start",
            json!({ "identifier": IDENTIFIER, "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    let started: LoginStartResponse = decode(&body);
    let finish = start
        .finish(started.response.as_slice(), &pinned)
        .expect("finish");

    let (status, _) = harness
        .post(
            "/api/v1/accounts/login/finish",
            json!({
                "attempt_id": started.attempt_id,
                "finalization": B64(finish.finalization().to_vec()),
                "device_id": client.device_id,
                "device_name": "impostor",
                "device_public_key": B64(replacement.public_key().as_bytes().to_vec()),
            }),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A client whose view is behind is stopped by the head revision check, before any
/// of its changes are examined.
///
/// This is the practical meaning of "pull before push": a device that has not caught
/// up cannot write at all, rather than writing and then discovering a conflict.
#[tokio::test]
async fn a_client_that_has_not_caught_up_is_refused_before_it_writes() {
    let harness = Harness::start().await;
    let (mut first, pinned, keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &first.token).await;
    let item_id = random_uuid();
    // Copied out of the client so the closures below do not borrow it: the client has
    // to stay mutable to push.
    let owner = first.user_id;

    let seal = |rev: u64, text: &[u8]| {
        let aad = ItemAad::new(owner, vault_id, item_id, rev, false);
        seal_item(&keys.user_key, &aad, text)
            .expect("seal")
            .to_bytes()
    };

    // Device A writes revision 1.
    let applied = first
        .push(
            &harness,
            vec![PendingItem::new(item_id, vault_id, 1, seal(1, b"first"))],
        )
        .await;
    assert_eq!(applied.applied.len(), 1);

    // A second device that has never pulled believes the vault is empty, so it claims
    // head revision 1 while the account is already at 1 and expects 2.
    let mut second = login_with(
        &harness,
        IDENTIFIER,
        PASSWORD,
        &pinned,
        DeviceSigningKey::generate(),
        None,
    )
    .await;
    let stale = second
        .push(
            &harness,
            vec![PendingItem::new(item_id, vault_id, 1, seal(1, b"second"))],
        )
        .await;

    assert!(stale.applied.is_empty(), "nothing may be written");
    assert_eq!(
        stale.head_rejected.as_deref(),
        Some("head revision is not current")
    );

    // The first write survives untouched.
    let pulled = first.pull(&harness).await;
    assert_eq!(pulled.items.len(), 1);
    let opened = cloudpass_core::vault::open_item(
        &keys.user_key,
        &ItemAad::new(owner, vault_id, item_id, 1, false),
        &cloudpass_core::envelope::Envelope::from_bytes(pulled.items[0].envelope.as_slice())
            .expect("parse"),
    )
    .expect("open");
    assert_eq!(&opened[..], b"first", "the first write must survive");

    // After catching up, the same edit lands as revision 2.
    second.pull(&harness).await;
    let rebased = second
        .push(
            &harness,
            vec![PendingItem::new(item_id, vault_id, 2, seal(2, b"second"))],
        )
        .await;
    assert_eq!(rebased.head_rejected, None);
    assert_eq!(rebased.applied.len(), 1);
    assert_eq!(rebased.applied[0].rev, 2);
}

/// The per-item compare-and-swap is a second, independent check.
///
/// With the signed head in place a well-behaved client cannot normally reach it — being
/// behind shows up as a stale head first. A buggy or hostile client can still send a
/// stale `base_rev` under a correct head, and the server must refuse it rather than
/// overwrite the newer revision.
#[tokio::test]
async fn per_item_compare_and_swap_refuses_a_stale_base_rev() {
    let harness = Harness::start().await;
    let (mut client, _pinned, keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;
    let item_id = random_uuid();
    let owner = client.user_id;

    let seal = |rev: u64, text: &[u8]| {
        let aad = ItemAad::new(owner, vault_id, item_id, rev, false);
        seal_item(&keys.user_key, &aad, text)
            .expect("seal")
            .to_bytes()
    };

    let applied = client
        .push(
            &harness,
            vec![PendingItem::new(item_id, vault_id, 1, seal(1, b"first"))],
        )
        .await;
    assert_eq!(applied.applied.len(), 1);

    // The head revision is correct — the client has pulled and is at the current
    // point — but this change claims to build on a revision that no longer exists.
    let batch = vec![PendingItem::new(item_id, vault_id, 1, seal(1, b"second")).based_on(0)];
    let head_rev = client.head_rev + 1;
    let root = client.staged_root(&batch);
    let signature = client.signing.sign(
        &HeadCommitment {
            owner,
            head_rev,
            state_root: root,
        }
        .canonical(),
    );

    let refused = client
        .push_with_head(
            &harness,
            &batch,
            head_rev,
            root,
            signature.as_bytes().to_vec(),
        )
        .await;

    assert!(refused.applied.is_empty());
    assert!(refused.head_rejected.is_some());
    assert_eq!(refused.conflicts.len(), 1);
    assert!(
        refused.conflicts[0]
            .reason
            .contains("base_rev does not match"),
        "unexpected reason: {}",
        refused.conflicts[0].reason
    );

    // The newer revision is handed back, and it is still the first write.
    let current = refused.conflicts[0]
        .current
        .as_ref()
        .expect("server must report what it holds");
    assert_eq!(current.rev, 1);
    let opened = cloudpass_core::vault::open_item(
        &keys.user_key,
        &ItemAad::new(owner, vault_id, item_id, 1, false),
        &cloudpass_core::envelope::Envelope::from_bytes(current.envelope.as_slice())
            .expect("parse"),
    )
    .expect("open");
    assert_eq!(&opened[..], b"first", "the first write must survive");
}

#[tokio::test]
async fn pull_is_incremental_and_reports_tombstones() {
    let harness = Harness::start().await;
    let (mut client, _pinned, keys) = register_and_login(&harness).await;
    let vault_id = create_vault(&harness, &client.token).await;

    for index in 0..3u64 {
        let item_id = random_uuid();
        let aad = ItemAad::new(client.user_id, vault_id, item_id, 1, false);
        let envelope = seal_item(&keys.user_key, &aad, format!("item {index}").as_bytes())
            .expect("seal")
            .to_bytes();
        let pushed = client
            .push(
                &harness,
                vec![PendingItem::new(item_id, vault_id, 1, envelope)],
            )
            .await;
        assert_eq!(pushed.applied.len(), 1);
    }

    let (_, body) = harness
        .get("/api/v1/sync/pull?cursor=0&limit=2", Some(&client.token))
        .await;
    let first_page: PullResponse = decode(&body);
    assert_eq!(first_page.items.len(), 2);
    assert!(first_page.has_more);

    let (_, body) = harness
        .get(
            &format!("/api/v1/sync/pull?cursor={}", first_page.next_cursor),
            Some(&client.token),
        )
        .await;
    let second_page: PullResponse = decode(&body);
    assert_eq!(second_page.items.len(), 1);
    assert!(!second_page.has_more);

    // A tombstone is a change like any other and must be delivered.
    let item_id = random_uuid();
    let aad = ItemAad::new(client.user_id, vault_id, item_id, 1, true);
    let tombstone = seal_item(&keys.user_key, &aad, b"")
        .expect("seal")
        .to_bytes();
    let pushed = client
        .push(
            &harness,
            vec![PendingItem::new(item_id, vault_id, 1, tombstone).deleted()],
        )
        .await;
    assert_eq!(pushed.applied.len(), 1);

    let (_, body) = harness
        .get(
            &format!("/api/v1/sync/pull?cursor={}", second_page.next_cursor),
            Some(&client.token),
        )
        .await;
    let deleted: PullResponse = decode(&body);
    assert_eq!(deleted.items.len(), 1);
    assert!(deleted.items[0].deleted);
    assert_eq!(deleted.items[0].id, item_id);
}

#[tokio::test]
async fn one_account_cannot_see_or_write_into_another() {
    let harness = Harness::start().await;
    let (mut alice, _pinned, keys) = register_and_login(&harness).await;
    let alice_vault = create_vault(&harness, &alice.token).await;

    let bob_identifier = "bob@example.com";
    let (bob_id, bob_pinned) = register_account(&harness, bob_identifier, PASSWORD).await;
    assert_ne!(bob_id, alice.user_id);
    let mut bob = login_with(
        &harness,
        bob_identifier,
        PASSWORD,
        &bob_pinned,
        DeviceSigningKey::generate(),
        None,
    )
    .await;

    let item_id = random_uuid();
    let aad = ItemAad::new(alice.user_id, alice_vault, item_id, 1, false);
    let envelope = seal_item(&keys.user_key, &aad, b"alice only")
        .expect("seal")
        .to_bytes();
    let pushed = alice
        .push(
            &harness,
            vec![PendingItem::new(item_id, alice_vault, 1, envelope)],
        )
        .await;
    assert_eq!(pushed.applied.len(), 1);

    let bob_pull = bob.pull(&harness).await;
    assert!(bob_pull.items.is_empty(), "bob must not see alice's items");

    // Bob cannot write into Alice's vault either. His own root is honest — it just
    // describes a batch that will not be applied.
    let refused = bob
        .push(
            &harness,
            vec![PendingItem::new(
                random_uuid(),
                alice_vault,
                1,
                opaque_blob(32),
            )],
        )
        .await;
    assert!(refused.applied.is_empty());
    assert_eq!(refused.conflicts.len(), 1);
    assert!(refused.conflicts[0]
        .reason
        .contains("vault does not belong"));
}

#[tokio::test]
async fn key_envelopes_are_stored_and_returned_byte_identically() {
    let harness = Harness::start().await;
    let (client, _pinned, keys) = register_and_login(&harness).await;

    let (status, body) = harness
        .get("/api/v1/accounts/key-envelope", Some(&client.token))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fetched: EnvelopeResponse = decode(&body);
    assert_eq!(
        fetched.user_key_envelope.as_slice(),
        &keys.user_key_envelope[..]
    );
    assert!(fetched.recovery_envelope.is_none());

    // There is deliberately no way to *write* an envelope with a session token: see
    // `a_session_alone_cannot_write_the_wrapped_user_key` for why, and where the write
    // does happen instead.
}

/// A stolen session token must not be able to rewrite the wrapped user key.
///
/// The server cannot tell a re-wrap of the real user key from random bytes — that is
/// the whole point of the envelope being opaque. So if a bearer token were enough to
/// write that slot, anyone who lifted one could render the account permanently
/// undecryptable: the owner would lose their vault and the attacker would gain nothing.
/// Not being able to do it is the only safe answer, and it is enforced by the route not
/// existing rather than by a check that could be forgotten.
#[tokio::test]
async fn a_session_alone_cannot_write_the_wrapped_user_key() {
    let harness = Harness::start().await;
    let (client, _pinned, keys) = register_and_login(&harness).await;

    let (status, _) = harness
        .call(
            "PUT",
            "/api/v1/accounts/key-envelope",
            Some(json!({ "user_key_envelope": B64(vec![0xEE; 48]) })),
            Some(&client.token),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "the envelope must not be writable with a token alone"
    );

    // Nor through the credential route: that one is authorised by an OPAQUE exchange
    // against the *current* password, so a token buys nothing there either.
    let (status, body) = harness
        .call(
            "POST",
            "/api/v1/accounts/credentials/finish",
            Some(json!({
                "attempt_id": "not-an-attempt",
                "finalization": B64(vec![1, 2, 3]),
                "upload": B64(opaque_blob(64)),
                "kdf_salt": B64(SALT.to_vec()),
                "kdf_m_kib": 19456, "kdf_t": 2, "kdf_p": 1,
                "user_key_envelope": B64(vec![0xEE; 48]),
            })),
            Some(&client.token),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // And the envelope the account actually holds is exactly what registration wrote.
    let (_, body) = harness
        .get("/api/v1/accounts/key-envelope", Some(&client.token))
        .await;
    let fetched: EnvelopeResponse = decode(&body);
    assert_eq!(
        fetched.user_key_envelope.as_slice(),
        &keys.user_key_envelope[..]
    );
}

#[tokio::test]
async fn the_device_list_reports_signing_keys_and_revocations() {
    let harness = Harness::start().await;
    let (client, pinned, _keys) = register_and_login(&harness).await;

    let listed: ListDevicesResponse =
        decode(&harness.get("/api/v1/devices", Some(&client.token)).await.1);
    assert_eq!(listed.devices.len(), 1);
    assert_eq!(listed.devices[0].device_id, client.device_id);
    assert_eq!(
        listed.devices[0]
            .public_key
            .as_ref()
            .expect("key")
            .as_slice(),
        client.signing.public_key().as_bytes().as_slice()
    );
    assert!(listed.devices[0].revoked_at.is_none());

    // A second device joins, and both are visible.
    let second = login_with(
        &harness,
        IDENTIFIER,
        PASSWORD,
        &pinned,
        DeviceSigningKey::generate(),
        None,
    )
    .await;
    let listed: ListDevicesResponse =
        decode(&harness.get("/api/v1/devices", Some(&client.token)).await.1);
    assert_eq!(listed.devices.len(), 2);
    assert!(listed
        .devices
        .iter()
        .any(|device| device.device_id == second.device_id));

    // Revocation is visible, because a client that never saw it would keep trusting
    // the device.
    sqlx::query("UPDATE devices SET revoked_at = 1 WHERE device_id = ?")
        .bind(second.device_id.to_string())
        .execute(&harness.state.pool)
        .await
        .expect("revoke");

    let listed: ListDevicesResponse =
        decode(&harness.get("/api/v1/devices", Some(&client.token)).await.1);
    let revoked = listed
        .devices
        .iter()
        .find(|device| device.device_id == second.device_id)
        .expect("revoked device is still listed");
    assert!(revoked.revoked_at.is_some());
}

/// The invariant this whole crate is built around, expressed as a test.
///
/// The API cannot accept key material — not because it ignores such fields, but
/// because every request type rejects unknown fields outright. A client that tried to
/// upload a raw user key, a master password or a device private key gets a 422, and
/// the value never reaches a statement.
#[tokio::test]
async fn requests_carrying_key_material_are_rejected_outright() {
    let harness = Harness::start().await;
    let (client, _pinned, _keys) = register_and_login(&harness).await;

    let key_material = B64(vec![0xAAu8; 32]);

    let attempts = [
        (
            "POST",
            "/api/v1/accounts/register/finish",
            None,
            json!({
                "user_id": random_uuid(),
                "identifier": "someone@example.com",
                "kdf_salt": B64(SALT.to_vec()),
                "kdf_m_kib": 19456, "kdf_t": 2, "kdf_p": 1,
                "upload": B64(vec![1, 2, 3]),
                "user_key_envelope": B64(vec![1, 2, 3]),
                "user_key": key_material,
            }),
        ),
        (
            "POST",
            "/api/v1/accounts/login/finish",
            None,
            json!({
                "attempt_id": "x",
                "finalization": B64(vec![1, 2, 3]),
                "device_public_key": B64(vec![0u8; 32]),
                "master_password": "hunter2",
            }),
        ),
        (
            "POST",
            "/api/v1/sync/push",
            Some(client.token.as_str()),
            json!({
                "head": { "head_rev": 1, "state_root": B64(vec![0u8; 32]), "signature": B64(vec![0u8; 64]) },
                "changes": [],
                "device_private_key": B64(vec![0u8; 32]),
            }),
        ),
        (
            "POST",
            "/api/v1/accounts/credentials/finish",
            Some(client.token.as_str()),
            json!({
                "attempt_id": "x",
                "finalization": B64(vec![1, 2, 3]),
                "upload": B64(vec![1, 2, 3]),
                "kdf_salt": B64(SALT.to_vec()),
                "kdf_m_kib": 19456, "kdf_t": 2, "kdf_p": 1,
                "user_key_envelope": B64(vec![1, 2, 3]),
                "raw_user_key": key_material,
            }),
        ),
    ];

    for (method, uri, token, body) in attempts {
        let (status, response) = harness.call(method, uri, Some(body), token).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{uri} accepted a request carrying key material: {response}"
        );
    }
}

#[tokio::test]
async fn endpoints_holding_data_require_a_session() {
    let harness = Harness::start().await;

    for uri in [
        "/api/v1/accounts/key-envelope",
        "/api/v1/sync/pull?cursor=0",
        "/api/v1/vaults",
        "/api/v1/devices",
    ] {
        let (status, body) = harness.get(uri, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}: {body}");
    }

    let (status, _) = harness
        .post(
            "/api/v1/sync/push",
            json!({
                "head": { "head_rev": 1, "state_root": B64(vec![0u8; 32]), "signature": B64(vec![0u8; 64]) },
                "changes": [],
            }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A made-up token is no better than none.
    let (status, _) = harness
        .get("/api/v1/accounts/key-envelope", Some("not-a-real-token"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn prelogin_answers_identically_for_known_and_unknown_identifiers() {
    let harness = Harness::start().await;
    let _ = register_and_login(&harness).await;

    let (status, known) = harness
        .post(
            "/api/v1/accounts/prelogin",
            json!({ "identifier": IDENTIFIER }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let known: PreloginResponse = decode(&known);

    let (status, unknown) = harness
        .post(
            "/api/v1/accounts/prelogin",
            json!({ "identifier": "nobody@example.com" }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let unknown: PreloginResponse = decode(&unknown);

    assert_eq!(
        known.kdf_salt.as_slice().len(),
        unknown.kdf_salt.as_slice().len()
    );
    assert_eq!(known.kdf_salt.as_slice().len(), KDF_SALT_LEN);
    assert!(unknown.kdf_m_kib > 0 && unknown.kdf_t > 0 && unknown.kdf_p > 0);

    // The fake salt is stable across calls, so repeated probing reveals nothing.
    let (_, unknown_again) = harness
        .post(
            "/api/v1/accounts/prelogin",
            json!({ "identifier": "nobody@example.com" }),
            None,
        )
        .await;
    let unknown_again: PreloginResponse = decode(&unknown_again);
    assert_eq!(unknown.kdf_salt.0, unknown_again.kdf_salt.0);
}

#[tokio::test]
async fn wrong_password_gets_the_same_answer_as_an_unknown_account() {
    let harness = Harness::start().await;
    let (_client, pinned, _keys) = register_and_login(&harness).await;

    // Wrong password, existing account: `login/start` must still answer normally.
    let wrong = LoginStart::start(auth(WRONG_PASSWORD)).expect("login start");
    let (status, body) = harness
        .post(
            "/api/v1/accounts/login/start",
            json!({ "identifier": IDENTIFIER, "request": B64(wrong.request().to_vec()) }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let wrong_start: LoginStartResponse = decode(&body);
    assert!(
        wrong
            .finish(wrong_start.response.as_slice(), &pinned)
            .is_err(),
        "a wrong password must not complete the exchange"
    );

    // Unknown account, same code path and the same shape of answer.
    let unknown = LoginStart::start(auth(PASSWORD)).expect("login start");
    let (status, body) = harness
        .post(
            "/api/v1/accounts/login/start",
            json!({ "identifier": "nobody@example.com", "request": B64(unknown.request().to_vec()) }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let unknown_start: LoginStartResponse = decode(&body);
    assert_eq!(
        wrong_start.response.as_slice().len(),
        unknown_start.response.as_slice().len(),
        "a dummy response must be the same size as a real one"
    );
    assert!(unknown
        .finish(unknown_start.response.as_slice(), &pinned)
        .is_err());
}

#[tokio::test]
async fn a_login_attempt_cannot_be_replayed() {
    let harness = Harness::start().await;
    let (_client, pinned, _keys) = register_and_login(&harness).await;

    let signing = DeviceSigningKey::generate();
    let start = LoginStart::start(auth(PASSWORD)).expect("login start");
    let (_, body) = harness
        .post(
            "/api/v1/accounts/login/start",
            json!({ "identifier": IDENTIFIER, "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    let started: LoginStartResponse = decode(&body);
    let finish = start
        .finish(started.response.as_slice(), &pinned)
        .expect("finish");

    let request = json!({
        "attempt_id": started.attempt_id,
        "finalization": B64(finish.finalization().to_vec()),
        "device_name": "first",
        "device_public_key": B64(signing.public_key().as_bytes().to_vec()),
    });
    let (status, _) = harness
        .post("/api/v1/accounts/login/finish", request.clone(), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // The attempt was consumed by the first call.
    let (status, _) = harness
        .post("/api/v1/accounts/login/finish", request, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoking_a_device_cuts_off_its_existing_session() {
    let harness = Harness::start().await;
    let (client, _pinned, _keys) = register_and_login(&harness).await;

    let (status, _) = harness
        .get("/api/v1/accounts/key-envelope", Some(&client.token))
        .await;
    assert_eq!(status, StatusCode::OK);

    sqlx::query("UPDATE devices SET revoked_at = 1")
        .execute(&harness.state.pool)
        .await
        .expect("revoke");

    // The token is unexpired and otherwise valid, and must nevertheless be refused.
    let (status, _) = harness
        .get("/api/v1/accounts/key-envelope", Some(&client.token))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn weak_kdf_parameters_are_refused_at_registration() {
    let harness = Harness::start().await;

    let start = RegistrationStart::start(auth(PASSWORD)).expect("start");
    let (_, body) = harness
        .post(
            "/api/v1/accounts/register/start",
            json!({ "identifier": "weak@example.com", "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    let response: RegisterStartResponse = decode(&body);
    let finish = start.finish(response.response.as_slice()).expect("finish");

    let (status, body) = harness
        .post(
            "/api/v1/accounts/register/finish",
            json!({
                "user_id": random_uuid(),
                "identifier": "weak@example.com",
                "kdf_salt": B64(SALT.to_vec()),
                "kdf_m_kib": 1024,
                "kdf_t": 1,
                "kdf_p": 1,
                "upload": B64(finish.upload().to_vec()),
                "user_key_envelope": B64(opaque_blob(48)),
            }),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: ErrorJson = decode(&body);
    assert_eq!(error.error, "bad_request");

    // Nothing was written: the identifier is still free.
    let start = RegistrationStart::start(auth(PASSWORD)).expect("start");
    let (status, _) = harness
        .post(
            "/api/v1/accounts/register/start",
            json!({ "identifier": "weak@example.com", "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn an_abandoned_registration_leaves_no_account() {
    let harness = Harness::start().await;

    let start = RegistrationStart::start(auth(PASSWORD)).expect("start");
    let (status, _) = harness
        .post(
            "/api/v1/accounts/register/start",
            json!({ "identifier": "abandoned@example.com", "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Nothing was persisted, so the identifier is still free.
    let start = RegistrationStart::start(auth(PASSWORD)).expect("start again");
    let (status, body) = harness
        .post(
            "/api/v1/accounts/register/start",
            json!({ "identifier": "abandoned@example.com", "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_second_registration_for_the_same_identifier_is_refused() {
    let harness = Harness::start().await;
    let _ = register_and_login(&harness).await;

    let start = RegistrationStart::start(auth(PASSWORD)).expect("start");
    let (status, body) = harness
        .post(
            "/api/v1/accounts/register/start",
            json!({ "identifier": IDENTIFIER, "request": B64(start.request().to_vec()) }),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn meta_describes_the_protocol() {
    let harness = Harness::start().await;

    #[derive(Deserialize)]
    struct Meta {
        protocol_version: u8,
        registration_open: bool,
        server_time: i64,
        kdf_default: KdfDefaultJson,
    }
    #[derive(Deserialize)]
    struct KdfDefaultJson {
        m_kib: u32,
        t: u32,
        p: u32,
    }

    let (status, body) = harness.get("/api/v1/meta", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let meta: Meta = decode(&body);

    assert_eq!(meta.protocol_version, cloudpass_core::PROTOCOL_VERSION);
    assert!(meta.registration_open);
    assert!(meta.server_time > 0);
    let params = KdfParams {
        m_kib: meta.kdf_default.m_kib,
        t: meta.kdf_default.t,
        p: meta.kdf_default.p,
        output_len: 32,
    };
    assert!(params.validate().is_ok());
}
