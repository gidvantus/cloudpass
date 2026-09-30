//! The unlocked vault: what a client can do once the master password has been
//! accepted.
//!
//! # The lifecycle
//!
//! ```text
//!   create(store, identifier, password, params)  ->  (Vault, NewAccount)
//!   unlock(store, password)                      ->  Vault
//!   add_item / update_item / delete_item         ->  sealed and written to the store
//! ```
//!
//! A [`Vault`] exists only while it is unlocked, and it owns the user key and the
//! device signing key for exactly that lifetime. There is no `lock()` method that
//! leaves a half-initialised object behind: dropping the value is locking it, because
//! the key types zeroize on drop. That removes a whole class of bug where a locked
//! vault still holds usable key material.
//!
//! # Why every write takes the store
//!
//! Persistence is an explicit argument rather than a hidden field, so that reading
//! this code tells you when data reaches disk. It also lets the same logic run against
//! an in-memory store in tests, a filesystem on the desktop, and IndexedDB in the
//! browser without any of them being special-cased.

use std::collections::BTreeMap;

use cloudpass_core::aad::{ItemAad, KeyKind};
use cloudpass_core::device::DeviceSigningKey;
use cloudpass_core::envelope::Envelope;
use cloudpass_core::ids::random_uuid;
use cloudpass_core::kdf::{
    derive_recovery_ukek, derive_ukek, stretch_master_password, RecoveryKey,
};
use cloudpass_core::params::{KdfParams, KDF_SALT_LEN};
use cloudpass_core::secret::fill_random;
use cloudpass_core::vault::{open_item, seal_item, unwrap_user_key, wrap_user_key, UserKey};
use uuid::Uuid;

use crate::emergency::EmergencyKit;
use crate::error::{ClientError, Result};
use crate::item::{Item, ItemDraft};
use crate::store::{Store, StoredAccount, StoredItem};

/// What the caller sends to the server to register the account.
///
/// Deliberately carries the private half of nothing: the wrapped user key is opaque,
/// and the device's public key is public. The device signing seed and the recovery key
/// never appear here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccount {
    pub user_id: Uuid,
    pub identifier: String,
    pub kdf_salt: [u8; KDF_SALT_LEN],
    pub kdf_params: KdfParams,
    pub user_key_envelope: Vec<u8>,
    /// The same user key, wrapped under the recovery key. Ciphertext, so the server may
    /// hold it; the recovery key that opens it stays on paper.
    pub recovery_envelope: Option<Vec<u8>>,
    pub vault_id: Uuid,
    pub device_id: Uuid,
    pub device_public_key: [u8; 32],
}

/// A freshly created account: what to register, and what to write down.
#[derive(Debug)]
pub struct CreatedAccount {
    pub account: NewAccount,
    pub kit: EmergencyKit,
}

/// A replacement master credential, computed but not yet written.
///
/// The split between planning and committing exists because the server and the device
/// have to end up agreeing, and they cannot be made atomic across a network. Writing
/// locally first would leave a device that opens with a password the server has never
/// heard of; writing remotely first would leave a server holding envelopes the device
/// has not adopted. Planning writes nothing, so a failure on either side fails the
/// whole operation and the next attempt starts from exactly the same place.
pub struct MasterPlan {
    kdf_salt: [u8; KDF_SALT_LEN],
    kdf_params: KdfParams,
    user_key_envelope: Vec<u8>,
}

impl MasterPlan {
    /// The salt the account will use, which the server stores alongside it.
    #[must_use]
    pub fn kdf_salt(&self) -> &[u8; KDF_SALT_LEN] {
        &self.kdf_salt
    }

    /// The parameters the account will use.
    #[must_use]
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf_params
    }

    /// The user key re-wrapped under the new password.
    #[must_use]
    pub fn user_key_envelope(&self) -> &[u8] {
        &self.user_key_envelope
    }
}

/// A replacement Emergency Kit, computed but not yet written.
pub struct KitPlan {
    kit: EmergencyKit,
    recovery_envelope: Vec<u8>,
}

impl KitPlan {
    /// The kit to show the user. It exists nowhere else until [`Vault::commit`] runs,
    /// and committing does not store the key itself — only the envelope it opens.
    #[must_use]
    pub fn kit(&self) -> &EmergencyKit {
        &self.kit
    }

    /// The user key wrapped under the new recovery key.
    #[must_use]
    pub fn recovery_envelope(&self) -> &[u8] {
        &self.recovery_envelope
    }

    /// Takes the kit, for a caller that has finished committing.
    #[must_use]
    pub fn into_kit(self) -> EmergencyKit {
        self.kit
    }
}

/// An item together with the revision and tombstone state its envelope is bound to.
struct ItemRecord {
    item: Item,
    rev: i64,
    deleted: bool,
}

/// An unlocked vault.
pub struct Vault {
    account: StoredAccount,
    device: DeviceSigningKey,
    user_key: UserKey,
    items: BTreeMap<Uuid, ItemRecord>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("user_id", &self.account.user_id)
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates a new account and leaves the vault unlocked.
    ///
    /// Generates everything the account needs — user id, vault id, KDF salt, user key,
    /// device key — and persists what the device must remember. Nothing here contacts a
    /// server: registration is a separate step, and doing it in this order is what lets
    /// the account be created offline and registered later.
    ///
    /// The returned [`CreatedAccount`] carries both what to register and the Emergency
    /// Kit to show **once**. The recovery key inside it is stored nowhere: if the caller
    /// drops it without showing the user, that way back into the vault is gone.
    pub fn create(
        store: &mut dyn Store,
        identifier: &str,
        master_password: &[u8],
        kdf_params: KdfParams,
    ) -> Result<(Self, CreatedAccount)> {
        if store.load_account()?.is_some() {
            return Err(ClientError::AccountExists);
        }
        // Reject a weakened parameter set before it is written anywhere: these values
        // are load-bearing for both the wrapped key and the server-side OPAQUE record.
        kdf_params.validate()?;

        let user_id = random_uuid();
        let vault_id = random_uuid();

        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        fill_random(&mut kdf_salt);

        let stretched = stretch_master_password(master_password, &kdf_salt, &kdf_params)?;
        let ukek = derive_ukek(&stretched, None, &kdf_salt)?;
        let user_key = UserKey::generate();
        let user_key_envelope =
            wrap_user_key(&ukek, &user_key, user_id, KeyKind::UserKey)?.to_bytes();

        // The second way in. The recovery key is generated here, used to wrap the same
        // user key, and then handed to the caller to show once — it is stored nowhere.
        let recovery_key = RecoveryKey::generate();
        let recovery_ukek = derive_recovery_ukek(&recovery_key, user_id.as_bytes())?;
        let recovery_envelope =
            wrap_user_key(&recovery_ukek, &user_key, user_id, KeyKind::RecoveryKey)?.to_bytes();

        let device = DeviceSigningKey::generate();
        let device_id = random_uuid();
        let device_public_key = *device.public_key().as_bytes();

        let account = StoredAccount {
            user_id,
            identifier: identifier.to_owned(),
            kdf_salt,
            kdf_params,
            user_key_envelope: user_key_envelope.clone(),
            recovery_envelope: Some(recovery_envelope.clone()),
            vault_id,
            device_id,
            server_static_public_key: Vec::new(),
            head_rev: 0,
            sync_cursor: 0,
        };

        store.save_account(&account)?;
        // Written separately, because a real client keeps this in the OS keychain and
        // not in the same file as the rest of the account record.
        store.save_device_seed(&device.to_seed())?;

        let kit = EmergencyKit::new(
            user_id,
            identifier.to_owned(),
            recovery_key,
            crate::now_unix(),
        );

        let new_account = NewAccount {
            user_id,
            identifier: identifier.to_owned(),
            kdf_salt,
            kdf_params,
            user_key_envelope,
            recovery_envelope: Some(recovery_envelope),
            vault_id,
            device_id,
            device_public_key,
        };

        Ok((
            Self {
                account,
                device,
                user_key,
                items: BTreeMap::new(),
            },
            CreatedAccount {
                account: new_account,
                kit,
            },
        ))
    }

    /// Unlocks an existing account.
    ///
    /// Every way this can fail because of what the user typed — a wrong password, a
    /// tampered envelope — collapses to [`ClientError::WrongPassword`]. Saying which
    /// one it was would tell an attacker whether they are guessing against the right
    /// account.
    pub fn unlock(store: &dyn Store, master_password: &[u8]) -> Result<Self> {
        let account = store.load_account()?.ok_or(ClientError::NoAccount)?;

        let stretched =
            stretch_master_password(master_password, &account.kdf_salt, &account.kdf_params)?;
        let ukek = derive_ukek(&stretched, None, &account.kdf_salt)?;
        let envelope = Envelope::from_bytes(&account.user_key_envelope)?;
        let user_key = unwrap_user_key(&ukek, &envelope, account.user_id, KeyKind::UserKey)
            .map_err(|_| ClientError::WrongPassword)?;

        Self::assemble(store, account, user_key)
    }

    /// Unlocks with the recovery key from the Emergency Kit.
    ///
    /// This is the whole point of the kit: the same user key, reached by a different
    /// route. No master password is involved, which is exactly why this path must only
    /// be offered where the user has physical possession of the kit.
    pub fn unlock_with_recovery_key(store: &dyn Store, recovery_key: &RecoveryKey) -> Result<Self> {
        let account = store.load_account()?.ok_or(ClientError::NoAccount)?;
        let stored = account
            .recovery_envelope
            .as_ref()
            .ok_or(ClientError::NoRecoveryKit)?;

        let ukek = derive_recovery_ukek(recovery_key, account.user_id.as_bytes())?;
        let envelope = Envelope::from_bytes(stored)?;
        let user_key = unwrap_user_key(&ukek, &envelope, account.user_id, KeyKind::RecoveryKey)
            .map_err(|_| ClientError::WrongRecoveryKey)?;

        Self::assemble(store, account, user_key)
    }

    /// Recovers an account whose master password is lost.
    ///
    /// Sets a new password and issues a new kit, writing both in one go. The old kit
    /// stops working at the same moment: a recovery key that has been read aloud,
    /// photographed or written in a notebook should not stay live once it has served its
    /// purpose.
    ///
    /// This is the **local** half only. A caller that also has to tell a server — see
    /// [`crate::sync::provision::recover`] — should plan, talk to the server, and commit
    /// only on success, so that a network failure cannot leave the two disagreeing.
    pub fn recover(
        store: &mut dyn Store,
        recovery_key: &RecoveryKey,
        new_master_password: &[u8],
        kdf_params: KdfParams,
    ) -> Result<(Self, EmergencyKit)> {
        let mut vault = Self::unlock_with_recovery_key(store, recovery_key)?;
        let master = vault.plan_master(new_master_password, kdf_params)?;
        let kit = vault.plan_kit()?;
        vault.commit(store, Some(&master), Some(&kit))?;
        Ok((vault, kit.into_kit()))
    }

    /// Computes a replacement master credential without writing anything.
    ///
    /// Cheap by construction: the user key does not change, so no item is touched and no
    /// ciphertext is rewritten. A fresh salt is generated, because reusing the old one
    /// with a new password would let the two be compared.
    pub fn plan_master(
        &self,
        new_master_password: &[u8],
        kdf_params: KdfParams,
    ) -> Result<MasterPlan> {
        kdf_params.validate()?;

        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        fill_random(&mut kdf_salt);

        let stretched = stretch_master_password(new_master_password, &kdf_salt, &kdf_params)?;
        let ukek = derive_ukek(&stretched, None, &kdf_salt)?;
        let user_key_envelope = wrap_user_key(
            &ukek,
            &self.user_key,
            self.account.user_id,
            KeyKind::UserKey,
        )?
        .to_bytes();

        Ok(MasterPlan {
            kdf_salt,
            kdf_params,
            user_key_envelope,
        })
    }

    /// Computes a replacement Emergency Kit without writing anything.
    ///
    /// The new key is generated here and returned inside the plan; it reaches the user
    /// only through [`KitPlan::into_kit`], and the account record keeps only the
    /// envelope it opens.
    pub fn plan_kit(&self) -> Result<KitPlan> {
        let key = RecoveryKey::generate();
        let ukek = derive_recovery_ukek(&key, self.account.user_id.as_bytes())?;
        let recovery_envelope = wrap_user_key(
            &ukek,
            &self.user_key,
            self.account.user_id,
            KeyKind::RecoveryKey,
        )?
        .to_bytes();

        Ok(KitPlan {
            kit: EmergencyKit::new(
                self.account.user_id,
                self.account.identifier.clone(),
                key,
                crate::now_unix(),
            ),
            recovery_envelope,
        })
    }

    /// Adopts planned credentials and writes the account record once.
    ///
    /// One write, not two, so the record is never a mixture of old and new. Passing
    /// `None` for a half leaves it exactly as it was, which is what makes a password
    /// change and a kit rotation two uses of the same operation.
    pub fn commit(
        &mut self,
        store: &mut dyn Store,
        master: Option<&MasterPlan>,
        kit: Option<&KitPlan>,
    ) -> Result<()> {
        if let Some(master) = master {
            self.account.kdf_salt = master.kdf_salt;
            self.account.kdf_params = master.kdf_params;
            self.account.user_key_envelope = master.user_key_envelope.clone();
        }
        if let Some(kit) = kit {
            self.account.recovery_envelope = Some(kit.recovery_envelope.clone());
        }
        store.save_account(&self.account)
    }

    /// Re-wraps the user key under a new master password.
    ///
    /// The recovery envelope is deliberately left alone: it does not depend on the
    /// password, so a password change must not cost the user a new piece of paper.
    pub fn change_master_password(
        &mut self,
        store: &mut dyn Store,
        new_master_password: &[u8],
        kdf_params: KdfParams,
    ) -> Result<()> {
        let master = self.plan_master(new_master_password, kdf_params)?;
        self.commit(store, Some(&master), None)
    }

    /// Issues a new recovery key, invalidating the previous kit.
    pub fn regenerate_recovery_key(&mut self, store: &mut dyn Store) -> Result<EmergencyKit> {
        let kit = self.plan_kit()?;
        self.commit(store, None, Some(&kit))?;
        Ok(kit.into_kit())
    }

    /// Whether this account has a recovery envelope on this device.
    #[must_use]
    pub fn has_recovery_envelope(&self) -> bool {
        self.account.recovery_envelope.is_some()
    }

    /// Builds the in-memory vault once the user key is in hand.
    fn assemble(store: &dyn Store, account: StoredAccount, user_key: UserKey) -> Result<Self> {
        let seed = store.load_device_seed()?.ok_or(ClientError::NoAccount)?;
        let device = DeviceSigningKey::from_seed(&seed);

        let mut items = BTreeMap::new();
        for stored in store.load_items()? {
            let rev = revision_to_u64(stored.rev)?;
            let aad = ItemAad::new(
                account.user_id,
                stored.vault_id,
                stored.id,
                rev,
                stored.deleted,
            );
            let envelope = Envelope::from_bytes(&stored.envelope)?;
            let plaintext = open_item(&user_key, &aad, &envelope)?;
            let item: Item = serde_json::from_slice(&plaintext)?;

            items.insert(
                stored.id,
                ItemRecord {
                    item,
                    rev: stored.rev,
                    deleted: stored.deleted,
                },
            );
        }

        Ok(Self {
            account,
            device,
            user_key,
            items,
        })
    }

    /// The account record this vault was unlocked from.
    #[must_use]
    pub fn account(&self) -> &StoredAccount {
        &self.account
    }

    /// The account's user id.
    #[must_use]
    pub fn user_id(&self) -> Uuid {
        self.account.user_id
    }

    /// The device key used to sign vault heads.
    #[must_use]
    pub fn device(&self) -> &DeviceSigningKey {
        &self.device
    }

    /// The vault new items are created in.
    #[must_use]
    pub fn vault_id(&self) -> Uuid {
        self.account.vault_id
    }

    /// Every item that is not deleted, ordered by title.
    ///
    /// Sorting is case-insensitive and tie-broken by id, so the order is stable across
    /// runs and platforms — a list that reshuffles itself between launches is the kind
    /// of detail that makes a password manager feel untrustworthy.
    #[must_use]
    pub fn items(&self) -> Vec<Item> {
        let mut items: Vec<Item> = self
            .items
            .values()
            .filter(|record| !record.deleted)
            .map(|record| record.item.clone())
            .collect();
        items.sort_by(|left, right| {
            left.title
                .to_lowercase()
                .cmp(&right.title.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        items
    }

    /// One item by id, if it exists and is not deleted.
    #[must_use]
    pub fn item(&self, id: Uuid) -> Option<&Item> {
        self.items
            .get(&id)
            .filter(|record| !record.deleted)
            .map(|record| &record.item)
    }

    /// Adds an item and writes it to the store.
    pub fn add_item(&mut self, store: &mut dyn Store, draft: ItemDraft) -> Result<Uuid> {
        let draft = draft.normalised();
        if draft.is_empty() {
            return Err(ClientError::EmptyItem);
        }

        let now = crate::now_unix();
        let id = random_uuid();
        let item = Item {
            id,
            vault_id: self.account.vault_id,
            title: draft.title,
            username: draft.username,
            password: draft.password,
            url: draft.url,
            notes: draft.notes,
            totp: draft.totp,
            created_at: now,
            updated_at: now,
        };

        self.write(store, item, 1, false)?;
        Ok(id)
    }

    /// Replaces an item's contents, moving it to the next revision.
    pub fn update_item(&mut self, store: &mut dyn Store, id: Uuid, draft: ItemDraft) -> Result<()> {
        let draft = draft.normalised();
        if draft.is_empty() {
            return Err(ClientError::EmptyItem);
        }

        let record = self
            .items
            .get(&id)
            .filter(|record| !record.deleted)
            .ok_or(ClientError::ItemNotFound)?;

        let item = Item {
            id,
            vault_id: record.item.vault_id,
            title: draft.title,
            username: draft.username,
            password: draft.password,
            url: draft.url,
            notes: draft.notes,
            totp: draft.totp,
            created_at: record.item.created_at,
            updated_at: crate::now_unix(),
        };
        let rev = record.rev + 1;

        self.write(store, item, rev, false)
    }

    /// Marks an item deleted, as a tombstone at the next revision.
    ///
    /// The contents are re-sealed rather than discarded. The server sees a tombstone
    /// either way, and keeping the plaintext locally means a deletion made by mistake
    /// is recoverable on the device that made it — without the server ever learning
    /// anything it did not already have.
    pub fn delete_item(&mut self, store: &mut dyn Store, id: Uuid) -> Result<()> {
        let record = self
            .items
            .get(&id)
            .filter(|record| !record.deleted)
            .ok_or(ClientError::ItemNotFound)?;

        let item = record.item.clone();
        let rev = record.rev + 1;

        self.write(store, item, rev, true)
    }

    /// Records the server's static public key, pinning it for future logins.
    pub fn pin_server_key(&mut self, store: &mut dyn Store, public_key: &[u8]) -> Result<()> {
        self.account.server_static_public_key = public_key.to_vec();
        store.save_account(&self.account)
    }

    /// Records the device id the server assigned at login.
    ///
    /// The value generated at account creation is only a placeholder: the server issues
    /// the id that the session, and therefore every head signature, is bound to.
    pub fn set_device_id(&mut self, store: &mut dyn Store, device_id: Uuid) -> Result<()> {
        self.account.device_id = device_id;
        store.save_account(&self.account)
    }

    /// Records how far synchronization has got.
    ///
    /// `head_rev` in particular must outlive the process: it is the memory that makes a
    /// rollback detectable. A client that forgot it would accept any older head the
    /// next time it started, which is precisely the attack the value exists to stop.
    pub fn record_sync_progress(
        &mut self,
        store: &mut dyn Store,
        head_rev: i64,
        cursor: i64,
    ) -> Result<()> {
        self.account.head_rev = head_rev;
        self.account.sync_cursor = cursor;
        store.save_account(&self.account)
    }

    /// Seals the vault's display name for the server to store.
    ///
    /// The same machinery as an item, with a placeholder item id that no real item can
    /// collide with. The name of a vault is as much the user's business as its
    /// contents, so the server gets an opaque envelope here too.
    pub fn seal_vault_name(&self, name: &str) -> Result<Vec<u8>> {
        let aad = ItemAad::new(
            self.account.user_id,
            self.account.vault_id,
            Uuid::from_u128(0),
            1,
            false,
        );
        Ok(seal_item(&self.user_key, &aad, name.as_bytes())?.to_bytes())
    }

    /// Records an item that came from the server.
    ///
    /// The envelope is opened *before* it is written. A server therefore cannot put a
    /// record into the local store that this device cannot read: a mismatched
    /// associated data or a tampered envelope fails here, while the caller still knows
    /// which item caused it, rather than on the next unlock with no context at all.
    pub fn absorb(&mut self, store: &mut dyn Store, item: StoredItem) -> Result<()> {
        let rev = revision_to_u64(item.rev)?;
        let aad = ItemAad::new(
            self.account.user_id,
            item.vault_id,
            item.id,
            rev,
            item.deleted,
        );
        let envelope = Envelope::from_bytes(&item.envelope)?;
        let plaintext = open_item(&self.user_key, &aad, &envelope)?;
        let decoded: Item = serde_json::from_slice(&plaintext)?;

        // What came from the server is, by definition, already on the server.
        let stored = StoredItem {
            synced_rev: Some(item.rev),
            ..item
        };
        store.upsert_item(&stored)?;
        self.items.insert(
            stored.id,
            ItemRecord {
                item: decoded,
                rev: stored.rev,
                deleted: stored.deleted,
            },
        );
        Ok(())
    }

    /// Seals an item, writes it, and updates the in-memory view.
    fn write(&mut self, store: &mut dyn Store, item: Item, rev: i64, deleted: bool) -> Result<()> {
        let envelope = self.seal(&item, rev, deleted)?;

        // What the server last acknowledged for this item, read from the store rather
        // than from memory. It is the base revision the next push states, and losing it
        // is not a cosmetic bug: a pushed-then-edited item would claim to be based on
        // nothing, the server would see a revision it never issued, and it would refuse
        // the change as a conflict — correctly, because that is exactly what a base of
        // zero means for an item that already exists.
        //
        // Read from the store because that is where a push records it: the engine calls
        // `mark_synced` when the server applies a change, and a copy in memory would be
        // one more place to keep in step.
        let synced_rev = store
            .load_items()?
            .into_iter()
            .find(|stored| stored.id == item.id)
            .and_then(|stored| stored.synced_rev);

        store.upsert_item(&StoredItem {
            id: item.id,
            vault_id: item.vault_id,
            rev,
            envelope,
            deleted,
            synced_rev,
        })?;

        self.items
            .insert(item.id, ItemRecord { item, rev, deleted });
        Ok(())
    }

    fn seal(&self, item: &Item, rev: i64, deleted: bool) -> Result<Vec<u8>> {
        // The revision and tombstone flag are part of the associated data, which is why
        // they are persisted alongside the envelope and never recomputed from context.
        let aad = ItemAad::new(
            self.account.user_id,
            item.vault_id,
            item.id,
            revision_to_u64(rev)?,
            deleted,
        );
        let plaintext = serde_json::to_vec(item)?;
        Ok(seal_item(&self.user_key, &aad, &plaintext)?.to_bytes())
    }
}

fn revision_to_u64(rev: i64) -> Result<u64> {
    u64::try_from(rev).map_err(|_| {
        ClientError::Corrupt(format!("stored revision {rev} is not a positive number"))
    })
}
