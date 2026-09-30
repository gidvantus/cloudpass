//! The API the page calls.
//!
//! Every entry point is a thin shell: it takes the session out of its slot, runs one
//! operation, and puts it back. Holding a borrow across an `await` would be the obvious
//! alternative and the wrong one — a second click during a slow sync would then panic
//! instead of reporting that the client is busy.

use std::cell::RefCell;

use serde::Serialize;
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use cloudpass_client::sync::{pending_changes, provision, SyncAccount, SyncEngine};
use cloudpass_client::{ClientError, ItemDraft, MemoryStore, Store, Vault};
use cloudpass_core::device::DeviceSigningKey;
use cloudpass_core::params::KdfParams;

use crate::transport::{write_clipboard, FetchTransport};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// What the page is told when something goes wrong: a code to branch on and a sentence
/// to show. Never a key, a path or a stack.
#[derive(Debug, Serialize)]
struct ErrorDto {
    code: String,
    message: String,
}

fn error_code(error: &ClientError) -> &'static str {
    match error {
        ClientError::Locked => "locked",
        ClientError::NoAccount => "no_account",
        ClientError::AccountExists => "account_exists",
        ClientError::WrongPassword => "wrong_password",
        ClientError::NoRecoveryKit => "no_recovery_kit",
        ClientError::WrongRecoveryKey => "wrong_recovery_key",
        ClientError::ItemNotFound => "item_not_found",
        ClientError::EmptyItem => "empty_item",
        ClientError::Crypto(_) => "crypto",
        ClientError::Storage(_) => "storage",
        ClientError::Corrupt(_) => "corrupt",
        ClientError::Serialization(_) => "serialization",
        ClientError::Transport(_) => "network",
        ClientError::Http { .. } => "server_refused",
        ClientError::Protocol(_) => "protocol",
    }
}

/// Turns an error into the JSON string the page parses out of the exception.
fn fail(error: ClientError) -> JsValue {
    let dto = ErrorDto {
        code: error_code(&error).to_owned(),
        message: error.to_string(),
    };
    reject(&dto)
}

fn reject<T: Serialize>(dto: &T) -> JsValue {
    JsValue::from_str(
        &serde_json::to_string(dto).unwrap_or_else(|_| {
            r#"{"code":"unknown","message":"the operation failed"}"#.to_owned()
        }),
    )
}

fn busy() -> JsValue {
    reject(&ErrorDto {
        code: "busy".to_owned(),
        message: "another operation is still running".to_owned(),
    })
}

fn encode<T: Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|e| fail(ClientError::Serialization(e)))
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// One unlocked vault, and everything needed to keep talking to the server.
struct Session {
    server_url: String,
    store: MemoryStore,
    vault: Vault,
    remote: provision::RemoteSession,
    last_sync: Option<String>,
}

thread_local! {
    /// The only piece of state this module has. `None` means locked, which is also what a
    /// fresh page load looks like.
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

/// Hands the session to an operation, leaving the slot empty.
///
/// The emptiness is the mutual exclusion: a second entry point arriving while one is in
/// flight finds nothing here and says so, instead of racing the first one over one vault.
fn take_session() -> Result<Session, JsValue> {
    SESSION
        .with(|slot| slot.borrow_mut().take())
        .ok_or_else(busy)
}

fn put_session(session: Session) {
    SESSION.with(|slot| *slot.borrow_mut() = Some(session));
}

// ---------------------------------------------------------------------------
// Shapes the page consumes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct StatusDto {
    unlocked: bool,
    identifier: Option<String>,
    item_count: usize,
    pending_count: usize,
    server_url: Option<String>,
    last_sync: Option<String>,
}

#[derive(Debug, Serialize)]
struct ItemSummary {
    id: String,
    title: String,
    /// The project the entry is filed under, or empty. A name, not an identifier: projects
    /// have no identity of their own anywhere in the system.
    project: String,
    username: String,
    url: String,
    has_totp: bool,
    pending: bool,
}

impl StatusDto {
    fn locked() -> Self {
        Self {
            unlocked: false,
            identifier: None,
            item_count: 0,
            pending_count: 0,
            server_url: None,
            last_sync: None,
        }
    }

    fn of(session: &Session) -> Result<Self, ClientError> {
        Ok(Self {
            unlocked: true,
            identifier: Some(session.vault.account().identifier.clone()),
            item_count: session.vault.items().len(),
            pending_count: pending_changes(&session.store)?.len(),
            server_url: Some(session.server_url.clone()),
            last_sync: session.last_sync.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

fn transport_for(server_url: &str) -> FetchTransport {
    FetchTransport::new(server_url)
}

/// Creates an account, registers it, and leaves the portal unlocked.
async fn create_account_inner(
    server_url: &str,
    identifier: &str,
    password: &str,
) -> Result<(Session, String), ClientError> {
    let transport = transport_for(server_url);
    let mut store = MemoryStore::new();

    let (vault, created) = Vault::create(
        &mut store,
        identifier,
        password.as_bytes(),
        // The recommendation, as on the desktop: this is a real vault.
        KdfParams::RECOMMENDED,
    )?;
    let name_envelope = vault.seal_vault_name("Personal")?;
    let seed = store
        .load_device_seed()?
        .ok_or_else(|| ClientError::Storage("the new device seed was not stored".into()))?;
    let device = DeviceSigningKey::from_seed(&seed);

    let remote = provision::register(
        &transport,
        provision::Registration {
            identifier,
            master_password: password.as_bytes(),
            account: &created.account,
            device: &device,
            vault_name_envelope: &name_envelope,
            // The kit is written by the same transaction that creates the account, and
            // shown to the user once, here.
            recovery_key: Some(created.kit.recovery_key()),
        },
    )
    .await?;

    // The record the vault was created from, with what the server issued. Written back
    // before the vault is reopened, so the vault in memory and the stored record agree.
    let mut stored = store
        .load_account()?
        .ok_or_else(|| ClientError::Storage("the new account record was not stored".into()))?;
    stored.device_id = remote.device_id;
    stored.server_static_public_key = remote.server_static_public_key.clone();
    store.save_account(&stored)?;

    let kit = created.kit.as_document(server_url);
    let vault = Vault::unlock(&store, password.as_bytes())?;

    Ok((
        Session {
            server_url: server_url.to_owned(),
            store,
            vault,
            remote,
            last_sync: Some("account registered".to_owned()),
        },
        kit,
    ))
}

/// Attaches to an account that already exists — the normal path for a returning user.
async fn unlock_inner(
    server_url: &str,
    identifier: &str,
    password: &str,
) -> Result<Session, ClientError> {
    let transport = transport_for(server_url);
    let mut store = MemoryStore::new();

    // A device key for this tab. It is not persisted: see the crate documentation for
    // why a key in `localStorage` would be a worse trade than asking again.
    let device = DeviceSigningKey::generate();
    store.save_device_seed(&device.to_seed())?;

    let enrolled = provision::enrol(
        &transport,
        provision::Enrolment {
            identifier,
            master_password: password.as_bytes(),
            device: &device,
            // Nothing to pin yet; `enrol` pins whatever OPAQUE reveals, and this tab
            // measures every later answer in this session against it.
            pinned_server_key: &[],
        },
    )
    .await?;

    store.save_account(&enrolled.account)?;
    let vault = Vault::unlock(&store, password.as_bytes())?;

    let mut session = Session {
        server_url: server_url.to_owned(),
        store,
        vault,
        remote: enrolled.session,
        last_sync: None,
    };

    // Pull immediately: an empty list with a Sync button would look like a failed sign-in.
    session.last_sync = Some(match synchronize(&mut session).await {
        Ok(note) => note,
        Err(error) => format!("вход выполнен, но первая синхронизация не удалась: {error}"),
    });

    Ok(session)
}

/// One round of synchronization, and the sentence that describes it.
async fn synchronize(session: &mut Session) -> Result<String, ClientError> {
    let account = session
        .store
        .load_account()?
        .ok_or(ClientError::NoAccount)?;
    let seed = session
        .store
        .load_device_seed()?
        .ok_or(ClientError::NoAccount)?;

    let mut engine = SyncEngine::new(
        transport_for(&session.server_url),
        SyncAccount {
            user_id: session.remote.user_id,
            device_id: session.remote.device_id,
            device: DeviceSigningKey::from_seed(&seed),
            token: session.remote.token.clone(),
            head_rev: account.head_rev,
            cursor: account.sync_cursor,
        },
    );

    engine.refresh_trusted_devices().await?;
    let outcome = engine.sync(&mut session.vault, &mut session.store).await?;

    session.vault.record_sync_progress(
        &mut session.store,
        engine.account().head_rev,
        engine.account().cursor,
    )?;

    Ok(describe(&outcome))
}

/// A one-line summary of what a synchronization did, for the status line.
///
/// The portal's own strings are in Russian, like the rest of the page. The messages that come
/// out of `ClientError` are not, and are not translated here: those sentences come from crates
/// shared with the desktop client, and the page maps their stable `code` instead of trying to
/// rewrite someone else's prose.
fn describe(outcome: &cloudpass_client::sync::SyncOutcome) -> String {
    let mut parts = vec![format!("получено {}", outcome.pulled.absorbed)];
    match &outcome.pushed {
        Some(pushed) if pushed.applied > 0 => parts.push(format!("отправлено {}", pushed.applied)),
        Some(pushed) if !pushed.conflicts.is_empty() => {
            parts.push(format!("конфликтов: {}", pushed.conflicts.len()));
        }
        Some(pushed) if pushed.head_rejected.is_some() => {
            parts.push("сервер отказался принять изменение".to_owned());
        }
        _ => {}
    }
    parts.join(" · ")
}

/// Tries to send what was just changed, and never fails the edit over it.
///
/// A failed sync is not a failed edit: the change is already in the store and is marked
/// as unsent, so the next sync carries it. Reporting that is the point; discarding the
/// user's work because the network blinked would not be.
async fn after_change(session: &mut Session) -> Option<String> {
    match synchronize(session).await {
        Ok(note) => Some(note),
        Err(error) => Some(format!("сохранено во вкладке, ещё не отправлено: {error}")),
    }
}

fn parse_id(id: &str) -> Result<Uuid, ClientError> {
    Uuid::parse_str(id).map_err(|_| ClientError::ItemNotFound)
}

fn parse_draft(draft: &str) -> Result<ItemDraft, ClientError> {
    serde_json::from_str(draft).map_err(ClientError::Serialization)
}

// ---------------------------------------------------------------------------
// The page-facing API
// ---------------------------------------------------------------------------

/// Creates an account and returns the Emergency Kit, which the page shows once.
#[wasm_bindgen]
pub async fn create_account(
    server_url: String,
    identifier: String,
    password: String,
) -> Result<String, JsValue> {
    let identifier = identifier.trim().to_lowercase();
    let (session, kit) = create_account_inner(&server_url, &identifier, &password)
        .await
        .map_err(fail)?;
    let status = StatusDto::of(&session).map_err(fail)?;
    put_session(session);

    encode(&serde_json::json!({ "emergency_kit": kit, "status": status }))
}

/// Signs in to an existing account and pulls what is already there.
#[wasm_bindgen]
pub async fn unlock(
    server_url: String,
    identifier: String,
    password: String,
) -> Result<String, JsValue> {
    let identifier = identifier.trim().to_lowercase();
    let session = unlock_inner(&server_url, &identifier, &password)
        .await
        .map_err(fail)?;
    let status = StatusDto::of(&session).map_err(fail)?;
    put_session(session);
    encode(&status)
}

/// Forgets everything this tab was holding.
#[wasm_bindgen]
pub fn lock() -> Result<String, JsValue> {
    SESSION.with(|slot| *slot.borrow_mut() = None);
    encode(&StatusDto::locked())
}

/// What the page needs in order to decide which screen to show.
#[wasm_bindgen]
pub fn status() -> Result<String, JsValue> {
    SESSION.with(|slot| match slot.borrow().as_ref() {
        Some(session) => StatusDto::of(session)
            .map_err(fail)
            .and_then(|s| encode(&s)),
        None => encode(&StatusDto::locked()),
    })
}

/// Lists entries without their secrets.
#[wasm_bindgen]
pub fn list_items() -> Result<String, JsValue> {
    SESSION.with(|slot| {
        let borrowed = slot.borrow();
        let session = borrowed.as_ref().ok_or_else(busy)?;

        let pending: std::collections::BTreeSet<Uuid> = session
            .store
            .pending_items()
            .map_err(fail)?
            .into_iter()
            .map(|item| item.id)
            .collect();

        // `Item` carries the password, and this map drops it: only the four fields below
        // reach the page. The clone is unavoidable with the current accessor and is
        // exactly the sort of thing a future `Item::summary()` would remove.
        let items: Vec<ItemSummary> = session
            .vault
            .items()
            .into_iter()
            .map(|item| ItemSummary {
                pending: pending.contains(&item.id),
                id: item.id.to_string(),
                title: item.title,
                project: item.project,
                username: item.username,
                url: item.url,
                has_totp: item.totp.is_some(),
            })
            .collect();

        encode(&items)
    })
}

/// The project names in use, for the project list and the editor's suggestions.
///
/// A separate call rather than a field on `list_items`, so that the shape of the list the page
/// renders stays an array of entries — that shape is what the smoke test asserts on.
#[wasm_bindgen]
pub fn list_projects() -> Result<String, JsValue> {
    SESSION.with(|slot| {
        let borrowed = slot.borrow();
        let session = borrowed.as_ref().ok_or_else(busy)?;
        encode(&session.vault.projects())
    })
}

/// Returns one entry in full, for the editor.
///
/// Separate from [`list_items`] on purpose: revealing a secret is a deliberate act, and
/// the code should read like one.
#[wasm_bindgen]
pub fn reveal_item(id: String) -> Result<String, JsValue> {
    let id = parse_id(&id).map_err(fail)?;
    SESSION.with(|slot| {
        let borrowed = slot.borrow();
        let session = borrowed.as_ref().ok_or_else(busy)?;
        let item = session
            .vault
            .item(id)
            .ok_or_else(|| fail(ClientError::ItemNotFound))?;
        encode(&item.draft())
    })
}

/// Copies an entry's password to the clipboard without putting it on the page.
///
/// This is the whole of "hidden copying": the value is read from the vault here, handed
/// to the browser's clipboard from here, and zeroized. It is never returned to
/// JavaScript, so it cannot be rendered, logged, or captured out of the DOM.
#[wasm_bindgen]
pub async fn copy_password(id: String) -> Result<(), JsValue> {
    let id = parse_id(&id).map_err(fail)?;
    let session = take_session()?;

    // The borrow of the vault ends before the session is put back, so the secret is the
    // only thing that survives the block — and it is a `Zeroizing`, not a plain `String`.
    let secret = match session.vault.item(id) {
        Some(item) => Zeroizing::new(item.password.clone()),
        None => {
            put_session(session);
            return Err(fail(ClientError::ItemNotFound));
        }
    };

    let outcome = write_clipboard(secret.as_str()).await;
    put_session(session);
    outcome.map_err(fail)
}

/// The same, for the username, which is not a secret but is just as tedious to retype.
#[wasm_bindgen]
pub async fn copy_username(id: String) -> Result<(), JsValue> {
    let id = parse_id(&id).map_err(fail)?;
    let session = take_session()?;

    let value = match session.vault.item(id) {
        Some(item) => Zeroizing::new(item.username.clone()),
        None => {
            put_session(session);
            return Err(fail(ClientError::ItemNotFound));
        }
    };

    let outcome = write_clipboard(value.as_str()).await;
    put_session(session);
    outcome.map_err(fail)
}

/// Adds an entry and tries to send it.
#[wasm_bindgen]
pub async fn add_item(draft: String) -> Result<String, JsValue> {
    let draft = parse_draft(&draft).map_err(fail)?;
    let mut session = take_session()?;

    let id = match session.vault.add_item(&mut session.store, draft) {
        Ok(id) => id,
        Err(error) => {
            put_session(session);
            return Err(fail(error));
        }
    };

    session.last_sync = after_change(&mut session).await;
    let status = StatusDto::of(&session).map_err(fail)?;
    put_session(session);

    encode(&serde_json::json!({ "id": id.to_string(), "status": status }))
}

/// Replaces an entry's contents and tries to send it.
#[wasm_bindgen]
pub async fn update_item(id: String, draft: String) -> Result<String, JsValue> {
    let id = parse_id(&id).map_err(fail)?;
    let draft = parse_draft(&draft).map_err(fail)?;
    let mut session = take_session()?;

    if let Err(error) = session.vault.update_item(&mut session.store, id, draft) {
        put_session(session);
        return Err(fail(error));
    }

    session.last_sync = after_change(&mut session).await;
    let status = StatusDto::of(&session).map_err(fail)?;
    put_session(session);

    encode(&status)
}

/// Marks an entry deleted and tries to send it.
#[wasm_bindgen]
pub async fn delete_item(id: String) -> Result<String, JsValue> {
    let id = parse_id(&id).map_err(fail)?;
    let mut session = take_session()?;

    if let Err(error) = session.vault.delete_item(&mut session.store, id) {
        put_session(session);
        return Err(fail(error));
    }

    session.last_sync = after_change(&mut session).await;
    let status = StatusDto::of(&session).map_err(fail)?;
    put_session(session);

    encode(&status)
}

/// Catches up and sends what is local.
#[wasm_bindgen]
pub async fn sync_now() -> Result<String, JsValue> {
    let mut session = take_session()?;
    let outcome = synchronize(&mut session).await;

    let encoded = match outcome {
        Ok(note) => {
            session.last_sync = Some(note);
            StatusDto::of(&session)
                .map_err(fail)
                .and_then(|status| encode(&status))
        }
        Err(error) => Err(fail(error)),
    };

    put_session(session);
    encoded
}
