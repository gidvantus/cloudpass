//! Sync behaviour against a scripted transport.
//!
//! Every test here builds real envelopes, real heads and real Ed25519 signatures with
//! the same core the application uses. Nothing is stubbed except the socket, which is
//! the point of the transport trait: the security decisions are exercised for real.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use serde_json::json;
use uuid::Uuid;

use cloudpass_client::sync::{
    HttpRequest, HttpResponse, PendingChange, SyncAccount, SyncEngine, Transport, B64,
};
use cloudpass_client::{
    ClientError, ItemDraft, MemoryStore, Store, StoredAccount, StoredItem, Vault,
};
use cloudpass_core::device::DeviceSigningKey;
use cloudpass_core::head::{state_root, HeadCommitment, ItemDigest};
use cloudpass_core::ids::random_uuid;
use cloudpass_core::params::KdfParams;

const IDENTIFIER: &str = "alice@example.com";
const PASSWORD: &[u8] = b"correct horse battery staple";

fn params() -> KdfParams {
    KdfParams::OWASP_MINIMUM
}

fn draft(title: &str, password: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        project: String::new(),
        username: "octocat".to_owned(),
        password: password.to_owned(),
        url: String::new(),
        notes: String::new(),
        totp: None,
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// A transport that answers from a queue and records what it was asked.
#[derive(Default)]
struct MockTransport {
    queued: RefCell<VecDeque<HttpResponse>>,
    seen: RefCell<Vec<HttpRequest>>,
}

impl MockTransport {
    fn new() -> Rc<Self> {
        Rc::new(Self::default())
    }

    /// Queues the next answer.
    fn answer(&self, status: u16, body: &serde_json::Value) {
        self.queued.borrow_mut().push_back(HttpResponse {
            status,
            body: serde_json::to_vec(body).expect("encode"),
        });
    }

    fn paths(&self) -> Vec<String> {
        self.seen
            .borrow()
            .iter()
            .map(|request| request.path.clone())
            .collect()
    }
}

impl Transport for MockTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        self.seen.borrow_mut().push(request);
        self.queued
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| ClientError::Transport("the test queued no answer".to_owned()))
    }
}

/// A handle the engine can own while the test keeps the same queue to inspect.
#[derive(Clone)]
struct SharedMock(Rc<MockTransport>);

impl Transport for SharedMock {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        self.0.send(request).await
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A device's key and id, plus the device-list entry that makes it trusted.
struct Device {
    id: Uuid,
    key: DeviceSigningKey,
}

impl Device {
    fn new() -> Self {
        Self {
            id: random_uuid(),
            key: DeviceSigningKey::generate(),
        }
    }

    fn list_entry(&self) -> serde_json::Value {
        json!({
            "device_id": self.id,
            "name": "test device",
            "public_key": B64::new(self.key.public_key().as_bytes().to_vec()),
            "created_at": 1,
            "last_seen_at": 1,
            "revoked_at": null,
        })
    }
}

fn device_list(devices: &[&Device]) -> serde_json::Value {
    json!({
        "devices": devices.iter().map(|device| device.list_entry()).collect::<Vec<_>>()
    })
}

/// The head a device would sign for a given set of items.
fn signed_head(
    signer: &Device,
    owner: Uuid,
    head_rev: i64,
    digests: &[ItemDigest],
) -> serde_json::Value {
    let root = state_root(digests);
    let commitment = HeadCommitment {
        owner,
        head_rev,
        state_root: root,
    };
    let signature = signer.key.sign(&commitment.canonical());

    json!({
        "head_rev": head_rev,
        "state_root": B64::new(root.to_vec()),
        "signature": B64::new(signature.as_bytes().to_vec()),
        "signer_device_id": signer.id,
        "updated_at": 1,
    })
}

/// A client that owns a vault, its store, and its own device key.
struct Client {
    vault: Vault,
    store: MemoryStore,
    user_id: Uuid,
    seed: [u8; 32],
}

/// Builds a second device for an existing account.
fn client_from(account: &StoredAccount, seed: [u8; 32]) -> Client {
    let mut store = MemoryStore::new();
    store.save_account(account).expect("write account");
    store.save_device_seed(&seed).expect("write seed");
    let vault = Vault::unlock(&store, PASSWORD).expect("unlock");
    let user_id = vault.user_id();
    Client {
        vault,
        store,
        user_id,
        seed,
    }
}

/// The first device, with a freshly created account.
fn first_client() -> (Client, StoredAccount) {
    let mut store = MemoryStore::new();
    let (vault, _created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let seed = store.load_device_seed().expect("read").expect("present");
    let account = store.load_account().expect("read").expect("present");
    let user_id = vault.user_id();

    (
        Client {
            vault,
            store,
            user_id,
            seed,
        },
        account,
    )
}

fn engine_for(mock: &Rc<MockTransport>, client: &Client, head_rev: i64) -> SyncEngine<SharedMock> {
    SyncEngine::new(
        SharedMock(Rc::clone(mock)),
        SyncAccount {
            user_id: client.user_id,
            device_id: random_uuid(),
            device: DeviceSigningKey::from_seed(&client.seed),
            token: "test-token".to_owned(),
            head_rev,
            cursor: 0,
        },
    )
}

/// The sealed form of the one item a client holds.
fn only_item(client: &Client) -> StoredItem {
    let mut items = client.store.load_items().expect("read");
    assert_eq!(items.len(), 1, "the fixture expects exactly one item");
    items.pop().expect("present")
}

// ---------------------------------------------------------------------------
// Pull
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pull_applies_new_items_and_accepts_the_head() {
    let (mut alice, account) = first_client();
    let item_id = alice
        .vault
        .add_item(&mut alice.store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = only_item(&alice);

    // A second device, sharing the account but starting with an empty store.
    let mut bob = client_from(&account, [7u8; 32]);
    let signer = Device::new();

    let digest = ItemDigest::from_envelope(item_id, 1, false, &sealed.envelope);

    let mock = MockTransport::new();
    mock.answer(200, &device_list(&[&signer]));
    mock.answer(
        200,
        &json!({
            "items": [{
                "id": item_id,
                "vault_id": sealed.vault_id,
                "rev": 1,
                "envelope": B64::new(sealed.envelope.clone()),
                "meta": {},
                "deleted": false,
                "seq": 1,
                "updated_at": 1,
            }],
            "next_cursor": 1,
            "has_more": false,
            "head": signed_head(&signer, bob.user_id, 1, &[digest]),
        }),
    );

    let mut engine = engine_for(&mock, &bob, 0);
    engine.refresh_trusted_devices().await.expect("devices");

    // No local edits, so the items the server sent must hash to the state it signed.
    let outcome = engine
        .pull(&mut bob.vault, &mut bob.store, true)
        .await
        .expect("pull");

    assert_eq!(outcome.absorbed, 1);
    assert_eq!(outcome.skipped_stale, 0);
    assert_eq!(outcome.head_rev, Some(1));

    // The item really arrived, decrypted by the second device's own key.
    let item = bob.vault.item(item_id).expect("the item came across");
    assert_eq!(item.password, "s3cr3t");
}

#[tokio::test]
async fn pull_refuses_a_head_older_than_one_already_accepted() {
    let (_alice, account) = first_client();
    let mut bob = client_from(&account, [7u8; 32]);
    let signer = Device::new();

    let mock = MockTransport::new();
    mock.answer(200, &device_list(&[&signer]));
    mock.answer(
        200,
        &json!({ "items": [], "next_cursor": 0, "has_more": false,
                 "head": signed_head(&signer, bob.user_id, 1, &[]) }),
    );

    // This device has already accepted revision 5.
    let mut engine = engine_for(&mock, &bob, 5);
    engine.refresh_trusted_devices().await.expect("devices");

    let error = engine
        .pull(&mut bob.vault, &mut bob.store, true)
        .await
        .expect_err("a rollback must be refused");

    // The signature on that head is genuinely valid — that is what makes the check
    // worth having.
    assert!(
        matches!(error, ClientError::Protocol(ref message) if message.contains("head rejected")),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn pull_refuses_a_head_from_an_unknown_device() {
    let (_alice, account) = first_client();
    let mut bob = client_from(&account, [7u8; 32]);

    let known = Device::new();
    let stranger = Device::new();

    let mock = MockTransport::new();
    mock.answer(200, &device_list(&[&known]));
    mock.answer(
        200,
        &json!({ "items": [], "next_cursor": 0, "has_more": false,
                 "head": signed_head(&stranger, bob.user_id, 1, &[]) }),
    );

    let mut engine = engine_for(&mock, &bob, 0);
    engine.refresh_trusted_devices().await.expect("devices");

    let error = engine
        .pull(&mut bob.vault, &mut bob.store, true)
        .await
        .expect_err("a stranger must not be able to speak for the vault");
    assert!(
        matches!(error, ClientError::Protocol(_)),
        "unexpected: {error}"
    );
}

#[tokio::test]
async fn a_clean_pull_refuses_items_that_do_not_match_the_signed_state() {
    let (mut alice, account) = first_client();
    let item_id = alice
        .vault
        .add_item(&mut alice.store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = only_item(&alice);

    let mut bob = client_from(&account, [7u8; 32]);
    let signer = Device::new();

    let mock = MockTransport::new();
    mock.answer(200, &device_list(&[&signer]));
    // The head commits to an *empty* vault while the page carries an item: the server
    // is serving something other than the state it signed.
    mock.answer(
        200,
        &json!({
            "items": [{
                "id": item_id, "vault_id": sealed.vault_id, "rev": 1,
                "envelope": B64::new(sealed.envelope.clone()),
                "meta": {}, "deleted": false, "seq": 1, "updated_at": 1,
            }],
            "next_cursor": 1, "has_more": false,
            "head": signed_head(&signer, bob.user_id, 1, &[]),
        }),
    );

    let mut engine = engine_for(&mock, &bob, 0);
    engine.refresh_trusted_devices().await.expect("devices");

    let error = engine
        .pull(&mut bob.vault, &mut bob.store, true)
        .await
        .expect_err("a mismatched state must be refused");
    assert!(
        matches!(error, ClientError::Protocol(ref m) if m.contains("do not match the state it signed")),
        "unexpected: {error}"
    );
}

#[tokio::test]
async fn a_stale_page_does_not_overwrite_a_newer_local_revision() {
    let (mut alice, account) = first_client();
    let item_id = alice
        .vault
        .add_item(&mut alice.store, draft("GitHub", "old"))
        .expect("add");
    alice
        .vault
        .update_item(&mut alice.store, item_id, draft("GitHub", "new"))
        .expect("update");
    let current = only_item(&alice); // revision 2

    // A second device that already holds revision 2.
    let mut bob = client_from(&account, [7u8; 32]);
    bob.vault
        .absorb(&mut bob.store, current.clone())
        .expect("absorb revision 2");

    let signer = Device::new();
    let mock = MockTransport::new();
    mock.answer(200, &device_list(&[&signer]));
    mock.answer(
        200,
        &json!({
            "items": [{
                "id": item_id, "vault_id": current.vault_id, "rev": 1,
                // Deliberately unusable bytes: the engine must not even look at them,
                // because it already holds a newer revision.
                "envelope": B64::new(vec![0u8; 94]),
                "meta": {}, "deleted": false, "seq": 1, "updated_at": 1,
            }],
            "next_cursor": 1, "has_more": false, "head": null,
        }),
    );

    let mut engine = engine_for(&mock, &bob, 0);
    engine.refresh_trusted_devices().await.expect("devices");
    let outcome = engine
        .pull(&mut bob.vault, &mut bob.store, true)
        .await
        .expect("pull");

    assert_eq!(outcome.absorbed, 0);
    assert_eq!(outcome.skipped_stale, 1);
    // The newer local revision is untouched.
    assert_eq!(bob.vault.item(item_id).expect("present").password, "new");
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

#[tokio::test]
async fn push_commits_to_the_resulting_state_and_adopts_the_head() {
    let (mut alice, _account) = first_client();
    let item_id = alice
        .vault
        .add_item(&mut alice.store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = only_item(&alice);

    let mock = MockTransport::new();
    mock.answer(
        200,
        &json!({
            "applied": [{ "id": item_id, "rev": 1, "seq": 1 }],
            "conflicts": [],
            "head_rejected": null,
            "head": { "head_rev": 1, "state_root": B64::new(vec![0u8; 32]),
                      "signature": B64::new(vec![0u8; 64]),
                      "signer_device_id": random_uuid(), "updated_at": 1 },
        }),
    );

    let mut engine = engine_for(&mock, &alice, 0);
    let outcome = engine
        .push(
            &mut alice.store,
            vec![PendingChange::from_stored(&sealed, 0)],
        )
        .await
        .expect("push");

    assert_eq!(outcome.applied, 1);
    assert!(outcome.head_rejected.is_none());
    assert!(!outcome.should_retry_after_pull());
    assert_eq!(engine.account().head_rev, 1);

    // The request carried a signature over the state the push produces, not a guess.
    let requests = mock.seen.borrow();
    let push = requests.last().expect("a push was sent");
    let body: serde_json::Value = serde_json::from_slice(&push.body).expect("json");
    assert_eq!(body["head"]["head_rev"], 1);
    assert_eq!(body["changes"].as_array().expect("changes").len(), 1);
}

#[tokio::test]
async fn a_refused_head_reports_itself_and_tells_the_caller_to_pull() {
    let (mut alice, _account) = first_client();
    let _ = alice
        .vault
        .add_item(&mut alice.store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let sealed = only_item(&alice);

    let mock = MockTransport::new();
    mock.answer(
        200,
        &json!({
            "applied": [], "conflicts": [],
            "head_rejected": "head revision is not current",
            "head": { "head_rev": 4, "state_root": B64::new(vec![0u8; 32]),
                      "signature": B64::new(vec![0u8; 64]),
                      "signer_device_id": random_uuid(), "updated_at": 1 },
        }),
    );

    let mut engine = engine_for(&mock, &alice, 0);
    let outcome = engine
        .push(
            &mut alice.store,
            vec![PendingChange::from_stored(&sealed, 0)],
        )
        .await
        .expect("push");

    assert_eq!(outcome.applied, 0);
    assert_eq!(
        outcome.head_rejected.as_deref(),
        Some("head revision is not current")
    );
    assert!(
        outcome.should_retry_after_pull(),
        "the caller must be told to pull and try again"
    );
    // The server reported what it actually holds. Adopting that revision is not
    // acceptance of it: the next pull verifies the signature before anything is trusted.
    assert_eq!(engine.account().head_rev, 4);
}

// ---------------------------------------------------------------------------
// Shape of the exchange
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_pull_follows_the_cursor_one_page_at_a_time() {
    let (_alice, account) = first_client();
    let mut bob = client_from(&account, [7u8; 32]);

    let mock = MockTransport::new();
    mock.answer(
        200,
        &json!({ "items": [], "next_cursor": 7, "has_more": true, "head": null }),
    );
    mock.answer(
        200,
        &json!({ "items": [], "next_cursor": 9, "has_more": false, "head": null }),
    );

    let mut engine = engine_for(&mock, &bob, 0);
    let outcome = engine
        .pull(&mut bob.vault, &mut bob.store, true)
        .await
        .expect("pull");

    assert_eq!(outcome.absorbed, 0);
    assert_eq!(engine.account().cursor, 9);

    let paths = mock.paths();
    assert_eq!(paths.len(), 2);
    assert!(paths[0].contains("cursor=0"), "{}", paths[0]);
    assert!(paths[1].contains("cursor=7"), "{}", paths[1]);
}

#[tokio::test]
async fn a_server_error_surfaces_with_its_code() {
    let (_alice, account) = first_client();
    let mut bob = client_from(&account, [7u8; 32]);

    let mock = MockTransport::new();
    mock.answer(401, &json!({ "error": "unauthorized" }));

    let mut engine = engine_for(&mock, &bob, 0);
    let error = engine
        .pull(&mut bob.vault, &mut bob.store, true)
        .await
        .expect_err("an unauthorised pull must fail");

    assert!(
        matches!(error, ClientError::Http { status: 401, ref code } if code == "unauthorized"),
        "unexpected: {error}"
    );
}

#[tokio::test]
async fn devices_without_a_key_or_that_are_revoked_are_not_trusted() {
    let (_alice, account) = first_client();
    let bob = client_from(&account, [7u8; 32]);

    let with_key = Device::new();
    let revoked = Device::new();

    let mock = MockTransport::new();
    mock.answer(
        200,
        &json!({ "devices": [
            with_key.list_entry(),
            { "device_id": random_uuid(), "name": "no key", "public_key": null,
              "created_at": 1, "last_seen_at": null, "revoked_at": null },
            { "device_id": revoked.id, "name": "revoked",
              "public_key": B64::new(revoked.key.public_key().as_bytes().to_vec()),
              "created_at": 1, "last_seen_at": 1, "revoked_at": 2 },
        ] }),
    );

    let mut engine = engine_for(&mock, &bob, 0);
    let trusted = engine.refresh_trusted_devices().await.expect("devices");

    // Only the usable device counts. Counting the others would widen the set of
    // signatures accepted for no benefit.
    assert_eq!(trusted, 1);
}
