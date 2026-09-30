//! What a device persists, and the seam through which it does so.

use cloudpass_core::params::{KdfParams, KDF_SALT_LEN};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

/// Everything a device must remember about the account, apart from the signing seed.
///
/// None of this is secret in the cryptographic sense — the salt and parameters are
/// public by design, and the wrapped user key is opaque without the master password.
/// The one genuinely sensitive field, the device signing seed, is deliberately kept
/// out of this record and behind its own pair of storage calls, because a real client
/// stores it in the OS keychain rather than in the same file as everything else.
///
/// `Serialize`/`Deserialize` are derived here because this type *is* the at-rest
/// record; a separate storage DTO would be a second definition to keep in sync for no
/// benefit. Writing the bytes is still the store's job, not this crate's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAccount {
    pub user_id: Uuid,
    /// The identifier used for OPAQUE, already normalised.
    pub identifier: String,
    pub kdf_salt: [u8; KDF_SALT_LEN],
    pub kdf_params: KdfParams,
    /// `AEAD(UKEK, UK)`. Opaque, and useless without the master password.
    pub user_key_envelope: Vec<u8>,
    /// The same user key wrapped under the recovery key instead.
    ///
    /// Stored alongside the account because it is ciphertext: it is useless without the
    /// recovery key from the Emergency Kit, and having it here is what lets a forgotten
    /// master password be recovered on a device that already holds the account, with no
    /// network involved.
    #[serde(default)]
    pub recovery_envelope: Option<Vec<u8>>,
    /// The default vault items are created in.
    pub vault_id: Uuid,
    pub device_id: Uuid,
    /// The server's static OPAQUE public key, pinned at registration.
    ///
    /// OPAQUE binds this into the envelope, so a server that copied a registration
    /// record cannot impersonate the real one — but only if the client remembers
    /// which key it saw first. An empty value means "not yet known".
    pub server_static_public_key: Vec<u8>,
    /// The highest head revision this device has accepted.
    ///
    /// The value that makes a rollback detectable: a server offering anything lower is
    /// refused even though its signature may be perfectly valid.
    pub head_rev: i64,
    /// The sync cursor, so a pull only asks for what changed.
    pub sync_cursor: i64,
}

impl StoredAccount {
    /// Whether a server key has been pinned yet.
    #[must_use]
    pub fn has_pinned_server_key(&self) -> bool {
        !self.server_static_public_key.is_empty()
    }
}

/// One sealed item as it sits at rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredItem {
    pub id: Uuid,
    pub vault_id: Uuid,
    /// The revision this envelope was written at. Part of its associated data, so it
    /// must be preserved exactly.
    pub rev: i64,
    /// The sealed envelope, exactly as `cloudpass-core` produced it.
    pub envelope: Vec<u8>,
    /// Whether this revision is a tombstone.
    pub deleted: bool,
    /// The revision the server has acknowledged, if any.
    ///
    /// `None` means this item has never been pushed. Comparing it with `rev` is how a
    /// client knows what to send, and it survives a restart — a separate in-memory
    /// dirty set would not, and a client that forgot what it had sent would either
    /// re-send everything or silently skip changes.
    #[serde(default)]
    pub synced_rev: Option<i64>,
}

impl StoredItem {
    /// Whether this revision differs from the last one the server acknowledged.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.synced_rev != Some(self.rev)
    }
}

/// The device's own persistence, whatever it is backed by.
///
/// Deliberately small. Every method is either "read what is there" or "write this",
/// because anything cleverer belongs in [`crate::Vault`], which can be tested against an
/// in-memory implementation.
///
/// `Send` is a supertrait because synchronization holds the store across network awaits
/// in an async command. Without it, `&mut dyn Store` could not be held across an await
/// by a future that has to be `Send`, which is every command in the desktop client.
pub trait Store: Send {
    fn load_account(&self) -> Result<Option<StoredAccount>>;
    fn save_account(&mut self, account: &StoredAccount) -> Result<()>;

    /// The device's Ed25519 seed, for signing vault heads.
    fn load_device_seed(&self) -> Result<Option<[u8; 32]>>;
    fn save_device_seed(&mut self, seed: &[u8; 32]) -> Result<()>;

    /// Every item at rest, tombstones included.
    fn load_items(&self) -> Result<Vec<StoredItem>>;
    fn upsert_item(&mut self, item: &StoredItem) -> Result<()>;
    fn remove_item(&mut self, id: Uuid) -> Result<()>;

    /// Records that the server acknowledged this item at `rev`.
    ///
    /// Has a default implementation so a backend only has to provide the three
    /// primitives above. A store that can do it in one write should override this.
    fn mark_synced(&mut self, id: Uuid, rev: i64) -> Result<()> {
        let mut items = self.load_items()?;
        let Some(item) = items.iter_mut().find(|item| item.id == id) else {
            return Ok(());
        };
        item.synced_rev = Some(rev);
        let updated = item.clone();
        self.upsert_item(&updated)
    }

    /// Every item whose current revision the server has not acknowledged.
    fn pending_items(&self) -> Result<Vec<StoredItem>> {
        Ok(self
            .load_items()?
            .into_iter()
            .filter(StoredItem::is_pending)
            .collect())
    }
}

/// An in-memory store.
///
/// Used by the tests here and by anything that needs a vault without a filesystem —
/// and it is the shape a browser-backed implementation will mirror.
#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    account: Option<StoredAccount>,
    device_seed: Option<[u8; 32]>,
    items: std::collections::BTreeMap<Uuid, StoredItem>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of items at rest, tombstones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl Store for MemoryStore {
    fn load_account(&self) -> Result<Option<StoredAccount>> {
        Ok(self.account.clone())
    }

    fn save_account(&mut self, account: &StoredAccount) -> Result<()> {
        self.account = Some(account.clone());
        Ok(())
    }

    fn load_device_seed(&self) -> Result<Option<[u8; 32]>> {
        Ok(self.device_seed)
    }

    fn save_device_seed(&mut self, seed: &[u8; 32]) -> Result<()> {
        self.device_seed = Some(*seed);
        Ok(())
    }

    fn load_items(&self) -> Result<Vec<StoredItem>> {
        Ok(self.items.values().cloned().collect())
    }

    fn upsert_item(&mut self, item: &StoredItem) -> Result<()> {
        self.items.insert(item.id, item.clone());
        Ok(())
    }

    fn remove_item(&mut self, id: Uuid) -> Result<()> {
        self.items.remove(&id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> StoredAccount {
        StoredAccount {
            user_id: Uuid::from_u128(1),
            identifier: "alice@example.com".to_owned(),
            kdf_salt: [0u8; KDF_SALT_LEN],
            kdf_params: KdfParams::OWASP_MINIMUM,
            user_key_envelope: vec![1, 2, 3],
            recovery_envelope: None,
            vault_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3),
            server_static_public_key: Vec::new(),
            head_rev: 0,
            sync_cursor: 0,
        }
    }

    #[test]
    fn the_memory_store_round_trips() {
        let mut store = MemoryStore::new();
        assert!(store.load_account().expect("read").is_none());

        store.save_account(&account()).expect("write");
        store.save_device_seed(&[7u8; 32]).expect("write seed");
        store
            .upsert_item(&StoredItem {
                id: Uuid::from_u128(9),
                vault_id: Uuid::from_u128(2),
                rev: 1,
                envelope: vec![1, 2, 3],
                deleted: false,
                synced_rev: None,
            })
            .expect("write item");

        assert_eq!(
            store.load_account().expect("read").expect("present"),
            account()
        );
        assert_eq!(
            store.load_device_seed().expect("read").expect("present"),
            [7u8; 32]
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_server_key_is_only_pinned_once_one_arrives() {
        let mut record = account();
        assert!(!record.has_pinned_server_key());
        record.server_static_public_key = vec![1, 2, 3];
        assert!(record.has_pinned_server_key());
    }
}
