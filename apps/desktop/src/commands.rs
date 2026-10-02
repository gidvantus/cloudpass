//! Tauri commands: the only way the frontend can reach the vault.
//!
//! # The rule this module exists to enforce
//!
//! The web view never sees a key, and it does not see every password either. Listing
//! items returns titles, usernames and URLs; a password crosses the boundary only when
//! the user explicitly asks for that one item. A frontend rendering a list has no reason
//! to hold a secret, so it is not given one, and a compromised frontend has that much
//! less to steal.
//!
//! # Master passwords over IPC
//!
//! The password arrives as a JavaScript string, which cannot be zeroized on the JS side
//! — a property of the platform, not something this code can fix. What it can do is stop
//! making it worse: the string is wrapped in [`Zeroizing`] immediately, and the frontend
//! clears its input as soon as the call returns.
//!
//! # Blocking and locking
//!
//! Every command is `async` and takes the state lock with `await`. The lock is a `tokio`
//! mutex precisely so it can be held across the network calls in `create_vault`,
//! `unlock_vault` and `sync_now`: those must not interleave with an edit, and a `std`
//! mutex guard is not `Send`, so a future holding one would not compile in an async
//! command.
//!
//! Argon2id at the recommended parameters takes a few hundred milliseconds and is meant
//! to. Those two commands block one runtime worker for that time rather than the event
//! loop. A background re-derivation would need `spawn_blocking` around the derivation
//! itself, which is not worth the complexity while the only caller is a user pressing a
//! button.

use serde::Serialize;
use tauri::State;

use cloudpass_client::recovery_code;
use cloudpass_client::sync::{pending_changes, provision, SyncAccount, SyncEngine, SyncOutcome};
use cloudpass_client::{ClientError, ItemDraft, MemoryStore, Store, StoredAccount, Vault};
use cloudpass_core::device::DeviceSigningKey;
use cloudpass_core::params::KdfParams;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::state::{AppState, SharedState};
use crate::transport::HttpTransport;

/// What the frontend is told when something goes wrong.
///
/// A `key` it can branch on — and, more to the point, translate: the wording belongs to the
/// interface, which is the only side that knows what language the reader chose. `detail` is
/// the English sentence from the crates shared with the portal; it is for a log or a bug
/// report and is never rendered, because the frontend shows the sentence for `key` instead.
#[derive(Debug, Serialize)]
pub struct CommandError {
    pub key: &'static str,
    pub detail: Option<String>,
}

impl CommandError {
    /// A failure the interface has a sentence for, with nothing extra to say.
    fn of_key(key: &'static str) -> Self {
        Self { key, detail: None }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Some(detail) => write!(formatter, "{}: {detail}", self.key),
            None => write!(formatter, "{}", self.key),
        }
    }
}

impl From<ClientError> for CommandError {
    fn from(error: ClientError) -> Self {
        let key = match &error {
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
        };
        Self {
            key,
            detail: Some(error.to_string()),
        }
    }
}

type CommandResult<T> = Result<T, CommandError>;

/// What the last synchronization did, as a key and the numbers that go with it.
///
/// The commands do not write the status note. They report *which* situation happened and *how
/// much* moved, and the interface turns that into a sentence in whatever language it is
/// showing — the only place a sentence may live, because the interface is the only thing that
/// knows the language.
///
/// `error_detail` is the one field carrying prose, and it is never rendered: it is the English
/// wording from the crates shared with the portal, kept for the record while the person reads
/// the localized sentence for `key`.
#[derive(Debug, Clone, Serialize)]
pub struct SyncNote {
    /// `sync-ok` for a synchronization that ran, or the key of the state that stopped one.
    key: &'static str,
    received: Option<usize>,
    sent: Option<usize>,
    conflicts: Option<usize>,
    head_rejected: bool,
    error_detail: Option<String>,
}

impl SyncNote {
    /// A note that is only a key: a state with no counts to report.
    fn of_key(key: &'static str) -> Self {
        Self {
            key,
            received: None,
            sent: None,
            conflicts: None,
            head_rejected: false,
            error_detail: None,
        }
    }

    /// A key plus why it happened. The interface shows the key; the detail stays off screen.
    fn with_detail(key: &'static str, detail: impl std::fmt::Display) -> Self {
        Self {
            error_detail: Some(detail.to_string()),
            ..Self::of_key(key)
        }
    }

    /// The same numbers under the key of the state that produced them — joining an account
    /// is a successful synchronization, but it is not one the user started by pressing Sync.
    fn with_key(mut self, key: &'static str) -> Self {
        self.key = key;
        self
    }
}

/// What the frontend needs in order to decide which screen to show.
#[derive(Debug, Serialize)]
pub struct VaultStatus {
    pub has_account: bool,
    pub unlocked: bool,
    pub item_count: usize,
    /// Items the server has not acknowledged yet.
    pub pending_count: usize,
    pub identifier: Option<String>,
    pub user_id: Option<String>,
    /// Where the server is, for the one message that names it when it is unreachable. The
    /// directory the vault is written to is deliberately not reported: it was carried for a
    /// line at the bottom of the window, and a path on someone's screen is not worth the
    /// thing it describes.
    pub server_url: String,
    /// Whether a session token is held.
    pub connected: bool,
    /// Whether this device holds a recovery envelope, so the interface knows whether
    /// offering "use a recovery key" would be anything but a dead end.
    pub has_recovery_kit: bool,
    /// What the last synchronization did, if there was one.
    pub last_sync: Option<SyncNote>,
}

/// An item as shown in a list. Deliberately without the password.
#[derive(Debug, Serialize)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub has_totp: bool,
    /// Whether this item still has to be sent to the server.
    pub pending: bool,
}

/// What the interface needs after an operation that issues an Emergency Kit.
#[derive(Debug, Serialize)]
pub struct KitResponse {
    /// The kit as a printable document. It is shown once and stored nowhere, so the
    /// interface has to treat it as something the user may never see again.
    pub emergency_kit: String,
}

/// The result of creating or recovering an account: the new status, and the kit.
#[derive(Debug, Serialize)]
pub struct CreatedVault {
    pub status: VaultStatus,
    /// The kit, as a printable document.
    ///
    /// Always present on the paths that issue one. A failure that would have lost it is
    /// an error instead, because a key that exists nowhere else must not be dropped on
    /// the floor of a half-finished operation.
    pub emergency_kit: String,
}

fn status_of(state: &AppState) -> Result<VaultStatus, ClientError> {
    let account: Option<StoredAccount> = state.store.load_account()?;
    let pending = state.store.pending_items()?.len();

    let (item_count, identifier, user_id) = match (&state.vault, &account) {
        (Some(vault), _) => (
            vault.items().len(),
            Some(vault.account().identifier.clone()),
            Some(vault.user_id().to_string()),
        ),
        (None, Some(account)) => (
            0,
            Some(account.identifier.clone()),
            Some(account.user_id.to_string()),
        ),
        (None, None) => (0, None, None),
    };

    Ok(VaultStatus {
        has_account: account.is_some(),
        unlocked: state.vault.is_some(),
        item_count,
        pending_count: pending,
        identifier,
        user_id,
        server_url: state.server_url.clone(),
        connected: state.session.is_some(),
        has_recovery_kit: account
            .as_ref()
            .is_some_and(|account| account.recovery_envelope.is_some()),
        last_sync: state.last_sync.clone(),
    })
}

/// Reports whether an account exists and whether it is unlocked.
#[tauri::command]
pub async fn vault_status(state: State<'_, SharedState>) -> CommandResult<VaultStatus> {
    let state = state.lock().await;
    status_of(&state).map_err(CommandError::from)
}

/// Creates a new vault and registers it with the server.
///
/// The account is built in memory first and written only after the server has accepted
/// it. A registration that fails part-way therefore leaves nothing behind, rather than an
/// account on disk that no server knows about and no password can repair.
#[tauri::command]
pub async fn create_vault(
    state: State<'_, SharedState>,
    identifier: String,
    master_password: String,
) -> CommandResult<CreatedVault> {
    let master_password = Zeroizing::new(master_password);
    let account_identifier = identifier.trim().to_lowercase();

    let mut state = state.lock().await;
    let app: &mut AppState = &mut state;

    if app.store.load_account()?.is_some() {
        return Err(CommandError::from(ClientError::AccountExists));
    }

    // Build against a scratch store: nothing reaches disk until registration succeeds.
    let mut scratch = MemoryStore::new();
    let (vault, created) = Vault::create(
        &mut scratch,
        &account_identifier,
        master_password.as_bytes(),
        // The recommendation, not the floor: this is a real vault, not a test.
        KdfParams::RECOMMENDED,
    )?;
    let seed = scratch
        .load_device_seed()?
        .ok_or_else(|| ClientError::Storage("the new device seed was not stored".into()))?;
    let device = DeviceSigningKey::from_seed(&seed);
    let name_envelope = vault.seal_vault_name("Personal")?;

    let transport = HttpTransport::new(&app.server_url)?;
    let session = provision::register(
        &transport,
        provision::Registration {
            identifier: &account_identifier,
            master_password: master_password.as_bytes(),
            account: &created.account,
            device: &device,
            vault_name_envelope: &name_envelope,
            // The second credential is installed on the session registration opens, so
            // every account has both ways in from the moment it exists.
            recovery_key: Some(created.kit.recovery_key()),
        },
    )
    .await?;

    // The record the vault was created from, with the two values only the server knows.
    let mut stored = scratch
        .load_account()?
        .ok_or_else(|| ClientError::Storage("the new account record was not stored".into()))?;
    stored.device_id = session.device_id;
    stored.server_static_public_key = session.server_static_public_key.clone();
    app.store.save_account(&stored)?;
    app.store.save_device_seed(&seed)?;

    // Reopened from the real store, so the vault the application holds is the one that
    // was actually written.
    app.vault = Some(Vault::unlock(&app.store, master_password.as_bytes())?);
    app.session = Some(session);
    app.last_sync = Some(SyncNote::of_key("sync-registered"));

    Ok(CreatedVault {
        status: status_of(app)?,
        emergency_kit: created.kit.as_document(&app.server_url),
    })
}

/// Joins an account that already exists on the server.
///
/// # What this is for
///
/// An account is created where it is convenient and used where it is needed. Somebody
/// registers in the browser, saves a few passwords there, and then wants them on their
/// own machine — where the vault is not a tab that can be closed by a misclick. This is
/// that step, and it is the *only* way this device can come to hold an account it did
/// not create.
///
/// # What it deliberately does not take
///
/// No file, no backup, no code copied off the other device. The identifier and the
/// master password are enough, because the server holds only ciphertext: the wrapped
/// user key comes down unusable, and the password the user already knows is what opens
/// it. A transfer that required a file would be a transfer that cannot be done from a
/// browser at all.
///
/// # Order, and the check that matters
///
/// The wrapped key is fetched, then **opened in a scratch store before anything is
/// written**. A device that persisted an account whose envelope does not match the
/// password would be a locked door with the key thrown away: every later unlock fails,
/// and the only way out is to delete the record. Checking first costs one Argon2id
/// evaluation and removes that entirely.
#[tauri::command]
pub async fn enrol_vault(
    state: State<'_, SharedState>,
    identifier: String,
    master_password: String,
) -> CommandResult<VaultStatus> {
    let master_password = Zeroizing::new(master_password);
    let account_identifier = identifier.trim().to_lowercase();

    let mut state = state.lock().await;
    let app: &mut AppState = &mut state;

    if app.store.load_account()?.is_some() {
        return Err(CommandError::from(ClientError::AccountExists));
    }

    // A device key of this machine's own. It is never copied: the whole point of a
    // per-device key is that one device's compromise is one device's.
    let device = DeviceSigningKey::generate();
    let seed = device.to_seed();

    let transport = HttpTransport::new(&app.server_url)?;
    let enrolled = provision::enrol(
        &transport,
        provision::Enrolment {
            identifier: &account_identifier,
            master_password: master_password.as_bytes(),
            device: &device,
            // Nothing to pin: this device has never met this server. Whatever OPAQUE
            // reveals is pinned by `enrol`, and every later login is measured against it.
            pinned_server_key: &[],
        },
    )
    .await?;

    // Prove the password opens what came down, before writing any of it.
    let mut scratch = MemoryStore::new();
    scratch.save_account(&enrolled.account)?;
    scratch.save_device_seed(&seed)?;
    drop(Vault::unlock(&scratch, master_password.as_bytes())?);

    app.store.save_account(&enrolled.account)?;
    app.store.save_device_seed(&seed)?;
    app.vault = Some(Vault::unlock(&app.store, master_password.as_bytes())?);
    app.session = Some(enrolled.session);

    // Pull immediately. An empty list with a Sync button would look like a failed
    // sign-in, when in fact the account is fine and the data is one request away.
    match synchronize(app).await {
        Ok(note) => app.last_sync = Some(note.with_key("sync-joined")),
        Err(error) => app.last_sync = Some(SyncNote::with_detail("sync-join-failed", &error)),
    }

    status_of(app).map_err(CommandError::from)
}

/// Recovers an account whose master password is lost.
///
/// # Why this reads the way it does
///
/// The device and the server cannot be changed atomically, so the design removes the
/// need to try: the new credentials are *planned* in memory, the server is asked to
/// adopt them, and only if it agrees does this device write anything. A failure
/// therefore changes nothing at all, and pressing the button again — with the same kit —
/// is a complete retry rather than a repair.
///
/// The alternative orders are both worse. Writing locally first leaves a device that
/// opens with a password the server has never heard of; writing remotely first leaves a
/// server holding envelopes this device has not adopted. Neither is fixable by retrying,
/// because the two sides no longer agree on which password is current.
#[tauri::command]
pub async fn recover_vault(
    state: State<'_, SharedState>,
    recovery_key: String,
    new_master_password: String,
) -> CommandResult<CreatedVault> {
    let new_master_password = Zeroizing::new(new_master_password);
    let mut state = state.lock().await;
    let app: &mut AppState = &mut state;

    // Decoding first means a mistyped key is reported as a mistyped key — the checksum
    // exists precisely so the user is not told their kit is wrong when it merely came
    // out of a pocket illegible.
    let key = recovery_code::decode(&recovery_key)
        .map_err(|_| CommandError::of_key("bad_recovery_key"))?;

    // Opens the vault through the kit and computes the replacements. Nothing is written:
    // `unlock_with_recovery_key` only reads, and the plans are plain values.
    let mut vault = Vault::unlock_with_recovery_key(&app.store, &key)?;
    let master = vault.plan_master(new_master_password.as_bytes(), KdfParams::RECOMMENDED)?;
    let kit = vault.plan_kit()?;

    let seed = app
        .store
        .load_device_seed()?
        .ok_or(ClientError::NoAccount)?;
    let device = DeviceSigningKey::from_seed(&seed);
    let record = app.store.load_account()?.ok_or(ClientError::NoAccount)?;

    let transport = HttpTransport::new(&app.server_url)?;
    let session = provision::recover(
        &transport,
        provision::Recovery {
            identifier: &record.identifier,
            user_id: record.user_id,
            recovery_key: &key,
            new_master_password: new_master_password.as_bytes(),
            kdf_salt: master.kdf_salt(),
            kdf_params: master.kdf_params(),
            user_key_envelope: master.user_key_envelope(),
            new_recovery_key: kit.kit().recovery_key(),
            new_recovery_envelope: kit.recovery_envelope(),
            device: &device,
            device_id: Some(record.device_id),
            device_name: "CloudPass desktop",
            pinned_server_key: &record.server_static_public_key,
        },
    )
    .await
    // The `?` is the whole point: the server refused, so this device has not changed
    // either, and the old kit still works.
    ?;

    // The server has adopted the new credentials; this device adopts them now.
    vault.commit(&mut app.store, Some(&master), Some(&kit))?;
    let document = kit.into_kit().as_document(&app.server_url);

    app.vault = Some(vault);
    app.session = Some(session);
    app.last_sync = Some(SyncNote::of_key("sync-recovered"));

    Ok(CreatedVault {
        status: status_of(app)?,
        emergency_kit: document,
    })
}

/// Issues a new Emergency Kit, retiring the old one.
///
/// A kit is worth replacing when it has been read aloud, photographed, or left somewhere
/// it should not have been. The old key stops working the moment the server accepts the
/// new credential, so the previous piece of paper becomes scrap.
///
/// # Why this asks for the master password
///
/// Rotating a kit writes a second way into the account, and the server's rule is that
/// such a write proves the credential it sits beside — a session token is not enough.
/// That rule exists because the wrapped user key is opaque to the server: it cannot tell
/// a re-wrap of the real key from random bytes, so the only actor it can allow to rewrite
/// the slot is one that already holds the key's protector.
///
/// The master credential is re-registered unchanged in the same request. It is the same
/// password, but OPAQUE registrations are randomised, so this is a fresh record rather
/// than a replay.
#[tauri::command]
pub async fn revive_emergency_kit(
    state: State<'_, SharedState>,
    master_password: String,
) -> CommandResult<KitResponse> {
    let master_password = Zeroizing::new(master_password);
    let mut state = state.lock().await;
    let app: &mut AppState = &mut state;

    let vault = app.vault.as_ref().ok_or(ClientError::Locked)?;
    let record = app.store.load_account()?.ok_or(ClientError::NoAccount)?;
    let kit = vault.plan_kit()?;

    let transport = HttpTransport::new(&app.server_url)?;
    provision::replace_credentials(
        &transport,
        provision::CredentialChange {
            identifier: &record.identifier,
            user_id: record.user_id,
            current_password: master_password.as_bytes(),
            current_kdf_salt: &record.kdf_salt,
            current_kdf_params: record.kdf_params,
            new_master_password: master_password.as_bytes(),
            new_kdf_salt: &record.kdf_salt,
            new_kdf_params: record.kdf_params,
            user_key_envelope: &record.user_key_envelope,
            new_recovery_key: Some(kit.kit().recovery_key()),
            new_recovery_envelope: Some(kit.recovery_envelope()),
            pinned_server_key: &record.server_static_public_key,
        },
    )
    .await?;

    // The server has retired the old credential; this device adopts the new envelope.
    let vault = app.vault.as_mut().ok_or(ClientError::Locked)?;
    vault.commit(&mut app.store, None, Some(&kit))?;

    app.last_sync = Some(SyncNote::of_key("sync-kit-issued"));

    Ok(KitResponse {
        emergency_kit: kit.into_kit().as_document(&app.server_url),
    })
}

/// Replaces the master password, on the server and on this device.
///
/// Both halves are needed and only one of them is local. Changing the record here alone
/// would produce a vault that opens with the new password and an account that can never
/// be signed into again, because the server authenticates against the OPAQUE record for
/// the *old* one.
///
/// Planned first, then the server, then the write — so a server that refuses costs the
/// user nothing and the same call can simply be made again.
#[tauri::command]
pub async fn change_master_password(
    state: State<'_, SharedState>,
    current_password: String,
    new_master_password: String,
) -> CommandResult<VaultStatus> {
    let current_password = Zeroizing::new(current_password);
    let new_master_password = Zeroizing::new(new_master_password);
    let mut state = state.lock().await;
    let app: &mut AppState = &mut state;

    let vault = app.vault.as_ref().ok_or(ClientError::Locked)?;
    let record = app.store.load_account()?.ok_or(ClientError::NoAccount)?;
    let master = vault.plan_master(new_master_password.as_bytes(), KdfParams::RECOMMENDED)?;

    let transport = HttpTransport::new(&app.server_url)?;
    provision::replace_credentials(
        &transport,
        provision::CredentialChange {
            identifier: &record.identifier,
            user_id: record.user_id,
            current_password: current_password.as_bytes(),
            current_kdf_salt: &record.kdf_salt,
            current_kdf_params: record.kdf_params,
            new_master_password: new_master_password.as_bytes(),
            new_kdf_salt: master.kdf_salt(),
            new_kdf_params: master.kdf_params(),
            user_key_envelope: master.user_key_envelope(),
            // The recovery envelope is not a function of the password, so it is left
            // exactly as it is: the user's existing kit keeps working, and that is a
            // property of the design rather than a convenience.
            new_recovery_key: None,
            new_recovery_envelope: None,
            pinned_server_key: &record.server_static_public_key,
        },
    )
    .await?;

    let vault = app.vault.as_mut().ok_or(ClientError::Locked)?;
    vault.commit(&mut app.store, Some(&master), None)?;

    app.last_sync = Some(SyncNote::of_key("sync-password-changed"));
    status_of(app).map_err(CommandError::from)
}

/// Unlocks an existing vault and, if the server is reachable, logs in.
///
/// A failed login is not a failed unlock. The vault is local first: the user's passwords
/// are on this machine, and a server that is down must not stand between them and their
/// data. The status reports `connected: false` so the interface can say so.
#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, SharedState>,
    master_password: String,
) -> CommandResult<VaultStatus> {
    let master_password = Zeroizing::new(master_password);

    let mut state = state.lock().await;
    let app: &mut AppState = &mut state;

    let account = app.store.load_account()?.ok_or(ClientError::NoAccount)?;
    let seed = app
        .store
        .load_device_seed()?
        .ok_or(ClientError::NoAccount)?;
    let device = DeviceSigningKey::from_seed(&seed);

    app.vault = Some(Vault::unlock(&app.store, master_password.as_bytes())?);
    app.last_sync = None;

    let transport = HttpTransport::new(&app.server_url)?;
    let outcome = provision::login(
        &transport,
        provision::Credentials {
            identifier: &account.identifier,
            master_password: master_password.as_bytes(),
            kdf_salt: &account.kdf_salt,
            kdf_params: account.kdf_params,
            device: &device,
            // The id this device's key was registered under. Without it every unlock
            // would register another device row, and the account's device list would
            // grow with each sign-in.
            device_id: Some(account.device_id),
        },
        &account.server_static_public_key,
    )
    .await;

    match outcome {
        Ok(session) => {
            app.session = Some(session);
            app.last_sync = Some(SyncNote::of_key("sync-signed-in"));
        }
        Err(error) => {
            app.session = None;
            // The vault is open and usable; only the server is out of reach. The reason is
            // English prose from a shared crate and stays in `error_detail`, unrendered.
            app.last_sync = Some(SyncNote::with_detail("sync-offline", &error));
        }
    }

    status_of(app).map_err(CommandError::from)
}

/// Locks the vault by dropping it, and forgets the session with it.
#[tauri::command]
pub async fn lock_vault(state: State<'_, SharedState>) -> CommandResult<VaultStatus> {
    let mut state = state.lock().await;
    state.vault = None;
    state.session = None;
    state.last_sync = None;
    status_of(&state).map_err(CommandError::from)
}

/// Points the application at a different server.
///
/// Only meaningful before an account exists: once registered, an account belongs to the
/// server that holds it, and quietly redirecting it elsewhere would turn a configuration
/// change into a data-loss incident.
#[tauri::command]
pub async fn set_server_url(
    state: State<'_, SharedState>,
    url: String,
) -> CommandResult<VaultStatus> {
    let mut state = state.lock().await;
    if state.store.load_account()?.is_some() {
        return Err(CommandError::of_key("server_fixed"));
    }
    state.server_url = url.trim().trim_end_matches('/').to_owned();
    status_of(&state).map_err(CommandError::from)
}

/// Lists items without their passwords.
#[tauri::command]
pub async fn list_items(state: State<'_, SharedState>) -> CommandResult<Vec<ItemSummary>> {
    let mut state = state.lock().await;
    let pending: std::collections::BTreeSet<Uuid> = state
        .store
        .pending_items()
        .map_err(CommandError::from)?
        .into_iter()
        .map(|item| item.id)
        .collect();

    let vault = state.unlocked().map_err(CommandError::from)?;

    Ok(vault
        .items()
        .into_iter()
        .map(|item| ItemSummary {
            pending: pending.contains(&item.id),
            id: item.id.to_string(),
            title: item.title,
            username: item.username,
            url: item.url,
            has_totp: item.totp.is_some(),
        })
        .collect())
}

/// Returns one item's full contents, including the password.
///
/// Separate from [`list_items`] on purpose: revealing a secret is a deliberate act, and
/// the code should read like one.
#[tauri::command]
pub async fn reveal_item(state: State<'_, SharedState>, id: String) -> CommandResult<ItemDraft> {
    let mut state = state.lock().await;
    let id = parse_id(&id)?;
    let vault = state.unlocked().map_err(CommandError::from)?;

    let item = vault.item(id).ok_or(ClientError::ItemNotFound)?;
    Ok(item.draft())
}

/// Adds an item and returns its id.
#[tauri::command]
pub async fn add_item(state: State<'_, SharedState>, draft: ItemDraft) -> CommandResult<String> {
    let mut state = state.lock().await;
    // Disjoint fields of one value, borrowed together: the vault writes through the
    // store, so both are needed at once and neither may own the other.
    let app: &mut AppState = &mut state;
    let store = &mut app.store;
    let vault = app.vault.as_mut().ok_or(ClientError::Locked)?;

    let id = vault.add_item(store, draft)?;
    app.last_sync = None;
    Ok(id.to_string())
}

/// Replaces an item's contents.
#[tauri::command]
pub async fn update_item(
    state: State<'_, SharedState>,
    id: String,
    draft: ItemDraft,
) -> CommandResult<()> {
    let mut state = state.lock().await;
    let id = parse_id(&id)?;
    let app: &mut AppState = &mut state;
    let store = &mut app.store;
    let vault = app.vault.as_mut().ok_or(ClientError::Locked)?;

    vault.update_item(store, id, draft)?;
    app.last_sync = None;
    Ok(())
}

/// Marks an item deleted.
#[tauri::command]
pub async fn delete_item(state: State<'_, SharedState>, id: String) -> CommandResult<()> {
    let mut state = state.lock().await;
    let id = parse_id(&id)?;
    let app: &mut AppState = &mut state;
    let store = &mut app.store;
    let vault = app.vault.as_mut().ok_or(ClientError::Locked)?;

    vault.delete_item(store, id)?;
    app.last_sync = None;
    Ok(())
}

/// Synchronizes with the server: catch up, then send what is local.
#[tauri::command]
pub async fn sync_now(state: State<'_, SharedState>) -> CommandResult<VaultStatus> {
    let mut state = state.lock().await;
    let app: &mut AppState = &mut state;

    let note = synchronize(app).await?;
    app.last_sync = Some(note);

    status_of(app).map_err(CommandError::from)
}

/// One synchronization, and the note that describes it.
///
/// Separate from the command so that joining an account can pull immediately: the first
/// thing a user should see after signing in on a new machine is their own data, not an
/// empty list and a Sync button.
async fn synchronize(app: &mut AppState) -> Result<SyncNote, CommandError> {
    let session = app
        .session
        .clone()
        .ok_or_else(|| CommandError::of_key("not_signed_in"))?;

    let account = app
        .store
        .load_account()
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::from(ClientError::NoAccount))?;
    let seed = app
        .store
        .load_device_seed()
        .map_err(CommandError::from)?
        .ok_or_else(|| CommandError::from(ClientError::NoAccount))?;

    let transport = HttpTransport::new(&app.server_url).map_err(CommandError::from)?;
    let mut engine = SyncEngine::new(
        transport,
        SyncAccount {
            user_id: session.user_id,
            device_id: session.device_id,
            device: DeviceSigningKey::from_seed(&seed),
            token: session.token,
            head_rev: account.head_rev,
            cursor: account.sync_cursor,
        },
    );

    engine
        .refresh_trusted_devices()
        .await
        .map_err(CommandError::from)?;

    let store = &mut app.store;
    let vault = app.vault.as_mut().ok_or(ClientError::Locked)?;
    let outcome = engine
        .sync(vault, store)
        .await
        .map_err(CommandError::from)?;

    // The head revision is the memory that makes a rollback detectable, so it has to
    // outlive the process.
    vault
        .record_sync_progress(store, engine.account().head_rev, engine.account().cursor)
        .map_err(CommandError::from)?;

    Ok(describe(&outcome))
}

/// What a synchronization did, as a key and the numbers that describe it.
///
/// The interface composes the line: `sync-received`, `sync-sent`, `sync-conflicts` and
/// `sync-head-rejected` are its words for these numbers, in the language it is showing. The
/// one thing this function must not do is decide a wording — it did once, and the result was
/// an English phrase that showed up verbatim in a Russian interface.
fn describe(outcome: &SyncOutcome) -> SyncNote {
    let mut note = SyncNote {
        received: Some(outcome.pulled.absorbed),
        ..SyncNote::of_key("sync-ok")
    };

    if let Some(pushed) = &outcome.pushed {
        if pushed.applied > 0 {
            note.sent = Some(pushed.applied);
        } else if pushed.head_rejected.is_some() {
            // A refusal by the server is reported as the fact of it. The reason it gave is
            // English prose from a shared crate, and the interface shows this key instead.
            note.head_rejected = true;
        } else if !pushed.conflicts.is_empty() {
            note.conflicts = Some(pushed.conflicts.len());
        }
    }

    note
}

/// The number of changes waiting to be sent, for the interface to show.
#[tauri::command]
pub async fn pending_count(state: State<'_, SharedState>) -> CommandResult<usize> {
    let state = state.lock().await;
    let pending = pending_changes(&state.store).map_err(CommandError::from)?;
    Ok(pending.len())
}

fn parse_id(value: &str) -> CommandResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| CommandError::of_key("bad_id"))
}
