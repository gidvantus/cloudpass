//! Application state and the on-disk store.
//!
//! # What is written where
//!
//! ```text
//! %APPDATA%\dev.cloudpass.desktop\
//!   account.json    version, account record — salt, parameters, wrapped user key, ids
//!   items.json      version, sealed item envelopes
//!   device.seed     32 raw bytes — the device's Ed25519 seed. SECRET.
//! ```
//!
//! Only one of those three is a secret, and it is the one deliberately kept in its own
//! file so that a platform keychain can replace it without touching anything else.
//!
//! Everything else is safe to leave readable: the salt and KDF parameters are public by
//! design, the wrapped user key is useless without the master password, and the item
//! envelopes are ciphertext. That is the same reason the server can store them.
//!
//! # Known gap
//!
//! `device.seed` currently sits in a file with default permissions. On Windows it
//! belongs in DPAPI (`CryptProtectData`) or the Credential Manager, so that reading it
//! requires the user's logon credentials. It is not the vault key — an attacker who
//! takes it cannot decrypt anything — but it is the key that signs vault heads, so it
//! is key material and must not stay in a plain file. Tracked in `docs/ROADMAP.md`.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use cloudpass_client::sync::RemoteSession;
use cloudpass_client::{
    ClientError, Result as ClientResult, Store, StoredAccount, StoredItem, Vault,
};

/// Bumped when the on-disk shape changes.
///
/// Version 1 had no `synced_rev`, so everything in a version 1 file loads as "never
/// pushed". That is the correct migration rather than a hopeful one: version 1 was
/// written by a build that could not push at all, so nothing in it had ever been sent.
///
/// Version 3 added `recovery_envelope` to the account record. It carries
/// `#[serde(default)]`, so a version 2 file loads with no recovery envelope — which is
/// exactly what it has: an account created before the Emergency Kit existed cannot be
/// opened with a recovery key, and pretending otherwise would only fail later.
const STORE_VERSION: u32 = 3;

#[derive(Debug, Serialize, Deserialize)]
struct AccountFile {
    version: u32,
    account: StoredAccount,
}

#[derive(Debug, Serialize, Deserialize)]
struct ItemsFile {
    version: u32,
    items: Vec<StoredItem>,
}

/// The device's persistence, backed by files under one directory.
#[derive(Debug)]
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// Uses `root` as the storage directory, creating it if needed.
    pub fn new(root: PathBuf) -> ClientResult<Self> {
        fs::create_dir_all(&root).map_err(storage)?;
        Ok(Self { root })
    }

    fn account_path(&self) -> PathBuf {
        self.root.join("account.json")
    }

    fn items_path(&self) -> PathBuf {
        self.root.join("items.json")
    }

    fn seed_path(&self) -> PathBuf {
        self.root.join("device.seed")
    }

    /// Where the vault lives, for display and for backups.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Store for FileStore {
    fn load_account(&self) -> ClientResult<Option<StoredAccount>> {
        let file: Option<AccountFile> = read_json(&self.account_path())?;
        match file {
            Some(file) if file.version <= STORE_VERSION => Ok(Some(file.account)),
            Some(file) => Err(ClientError::Corrupt(format!(
                "account file has version {}, this build understands up to {STORE_VERSION}",
                file.version
            ))),
            None => Ok(None),
        }
    }

    fn save_account(&mut self, account: &StoredAccount) -> ClientResult<()> {
        write_json(
            &self.account_path(),
            &AccountFile {
                version: STORE_VERSION,
                account: account.clone(),
            },
        )
    }

    fn load_device_seed(&self) -> ClientResult<Option<[u8; 32]>> {
        match fs::read(self.seed_path()) {
            Ok(bytes) => {
                let seed: [u8; 32] = bytes.try_into().map_err(|_| {
                    ClientError::Corrupt("the device seed file is not 32 bytes".to_owned())
                })?;
                Ok(Some(seed))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(storage(error)),
        }
    }

    fn save_device_seed(&mut self, seed: &[u8; 32]) -> ClientResult<()> {
        // Raw bytes rather than text: no encoding to get wrong, and no chance of a
        // trailing newline making the seed the wrong length on the way back in.
        write_atomic(&self.seed_path(), seed)
    }

    fn load_items(&self) -> ClientResult<Vec<StoredItem>> {
        let file: Option<ItemsFile> = read_json(&self.items_path())?;
        match file {
            Some(file) if file.version <= STORE_VERSION => Ok(file.items),
            Some(file) => Err(ClientError::Corrupt(format!(
                "items file has version {}, this build understands up to {STORE_VERSION}",
                file.version
            ))),
            None => Ok(Vec::new()),
        }
    }

    fn upsert_item(&mut self, item: &StoredItem) -> ClientResult<()> {
        let mut items = self.load_items()?;
        match items.iter_mut().find(|existing| existing.id == item.id) {
            Some(existing) => *existing = item.clone(),
            None => items.push(item.clone()),
        }
        write_json(
            &self.items_path(),
            &ItemsFile {
                version: STORE_VERSION,
                items,
            },
        )
    }

    fn remove_item(&mut self, id: Uuid) -> ClientResult<()> {
        let mut items = self.load_items()?;
        items.retain(|item| item.id != id);
        write_json(
            &self.items_path(),
            &ItemsFile {
                version: STORE_VERSION,
                items,
            },
        )
    }
}

/// The whole application's state, guarded by one lock.
///
/// A single lock rather than one per field on purpose: the vault and the store it
/// writes through must not be reachable independently, or a command could hold an
/// unlocked vault while another rewrites the account under it.
#[derive(Debug)]
pub struct AppState {
    pub store: FileStore,
    /// Present only while unlocked. Dropping it is what locks the vault.
    pub vault: Option<Vault>,
    /// Where the sync server lives.
    pub server_url: String,
    /// The session token, held in memory only.
    ///
    /// Deliberately not written to disk. A bearer token on disk is a standing
    /// credential, and the alternative costs the user nothing: unlocking already asks
    /// for the master password, which is exactly when a fresh token can be obtained.
    pub session: Option<RemoteSession>,
    /// What the last synchronization did, as a key and the numbers that go with it.
    ///
    /// A key rather than a sentence: the interface owns the wording, and this side does not
    /// know what language the reader chose. `commands::SyncNote` is the shape.
    pub last_sync: Option<crate::commands::SyncNote>,
}

impl AppState {
    #[must_use]
    pub fn new(store: FileStore, server_url: String) -> Self {
        Self {
            store,
            vault: None,
            server_url,
            session: None,
            last_sync: None,
        }
    }

    /// The vault, or an error that tells the caller exactly what to do about it.
    pub fn unlocked(&mut self) -> ClientResult<&mut Vault> {
        self.vault.as_mut().ok_or(ClientError::Locked)
    }

    /// The server URL from the environment, or the local default.
    ///
    /// Mode A with the server on this machine is the intended setup before a VPS
    /// exists, so the default points at loopback rather than at some hosted service.
    #[must_use]
    pub fn default_server_url() -> String {
        std::env::var("CLOUDPASS_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned())
    }
}

/// Shared state type registered with Tauri.
///
/// A `tokio` mutex rather than `std`'s, because synchronization holds the lock across
/// network awaits — and `std`'s guard is not `Send`, so the future would not compile.
/// The practical effect is the same: one command mutates the vault at a time.
pub type SharedState = Arc<tokio::sync::Mutex<AppState>>;

fn storage(error: impl std::fmt::Display) -> ClientError {
    ClientError::Storage(error.to_string())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> ClientResult<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| ClientError::Corrupt(format!("{}: {error}", path.display()))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(storage(error)),
    }
}

/// Writes through a temporary file and renames it into place.
///
/// A password manager that truncates its only copy of an account because the machine
/// died mid-write is not a password manager. `fs::rename` replaces an existing
/// destination atomically on both Windows and Unix, so a reader sees either the old
/// file or the new one and never a half-written one.
fn write_json<T: Serialize>(path: &Path, value: &T) -> ClientResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> ClientResult<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(storage)?;
    fs::rename(&temporary, path).map_err(storage)
}
