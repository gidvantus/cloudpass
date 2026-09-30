//! The key hierarchy in practice: wrapping the user key, deriving per-item keys, and
//! sealing individual records.
//!
//! ```text
//!   UKEK  --wraps-->  UserKey  --HKDF(item_id)-->  ItemKey  --AEAD-->  item
//! ```
//!
//! Two properties fall out of this shape and are covered by tests:
//!
//! * **Changing the master password re-wraps one 32-byte key.** The items are never
//!   touched, because they are not encrypted under anything derived from the password.
//! * **An item key is a function of the item id.** Two items never share a key, so a
//!   random 96-bit nonce per seal is safe without any global counter.

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::aad::{ItemAad, KeyEnvelopeAad, KeyKind};
use crate::envelope::Envelope;
use crate::error::Result;
use crate::kdf::{hkdf_expand, UserKeyEncryptionKey, INFO_ITEM};
use crate::key_newtype;

key_newtype!(
    #[doc = "Root data key of a user. Random, wrapped by the UKEK, never derived from the password."]
    pub UserKey
);
key_newtype!(
    #[doc = "Key for a single item, derived from the user key and the item id."]
    pub ItemKey
);

/// Wraps the user key so it can be stored on the server.
///
/// The associated data includes the slot (`userkey` / `recovery-key`) and the user id,
/// so a wrapped key cannot be replayed into another slot or another account.
pub fn wrap_user_key(
    ukek: &UserKeyEncryptionKey,
    user_key: &UserKey,
    user_id: Uuid,
    kind: KeyKind,
) -> Result<Envelope> {
    let aad = KeyEnvelopeAad::new(kind, user_id);
    Envelope::seal_key(ukek.inner(), &aad.canonical()?, user_key.inner())
}

/// Unwraps the user key.
///
/// A wrong master password, a wrong account key, a tampered envelope and a mismatched
/// slot are all indistinguishable here — they produce [`crate::Error::AuthFailed`] or
/// [`crate::Error::AadMismatch`] without revealing which of the inputs was wrong.
pub fn unwrap_user_key(
    ukek: &UserKeyEncryptionKey,
    envelope: &Envelope,
    user_id: Uuid,
    kind: KeyKind,
) -> Result<UserKey> {
    let aad = KeyEnvelopeAad::new(kind, user_id);
    Ok(UserKey::from_secret(
        envelope.open_key(ukek.inner(), &aad.canonical()?)?,
    ))
}

/// Derives the key for a single item.
///
/// The item id is used as the HKDF salt, which gives a unique key per record. Note
/// that the vault is *not* part of the derivation: moving an item between vaults must
/// not break decryption of its own key, only fail the associated-data check, which is
/// the behaviour we want.
pub fn item_key(user_key: &UserKey, item_id: Uuid) -> Result<ItemKey> {
    Ok(ItemKey::from_secret(hkdf_expand(
        user_key.expose(),
        item_id.as_bytes(),
        INFO_ITEM,
    )?))
}

/// Encrypts an item payload.
pub fn seal_item(user_key: &UserKey, aad: &ItemAad, plaintext: &[u8]) -> Result<Envelope> {
    let key = item_key(user_key, aad.item)?;
    Envelope::seal(key.inner(), &aad.canonical()?, plaintext)
}

/// Decrypts an item payload, verifying that it belongs to the given position.
pub fn open_item(
    user_key: &UserKey,
    aad: &ItemAad,
    envelope: &Envelope,
) -> Result<Zeroizing<Vec<u8>>> {
    let key = item_key(user_key, aad.item)?;
    envelope.open(key.inner(), &aad.canonical()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::kdf::{stretch_master_password, AccountKey, StretchedKey};
    use crate::params::{KdfParams, KDF_SALT_LEN};

    const SALT: [u8; KDF_SALT_LEN] = [0x5Au8; KDF_SALT_LEN];

    fn stretched() -> StretchedKey {
        stretch_master_password(b"master password", &SALT, &KdfParams::OWASP_MINIMUM).unwrap()
    }

    fn fixtures() -> (UserKey, Uuid, Uuid, Uuid, Uuid) {
        (
            UserKey::generate(),
            Uuid::from_u128(0x1000),
            Uuid::from_u128(0x2000),
            Uuid::from_u128(0x3000),
            Uuid::from_u128(0x4000),
        )
    }

    #[test]
    fn item_keys_are_unique_per_item() {
        let user_key = UserKey::generate();
        let a = item_key(&user_key, Uuid::from_u128(1)).unwrap();
        let b = item_key(&user_key, Uuid::from_u128(2)).unwrap();
        assert_ne!(a.expose(), b.expose());

        // Same item id, same key: decryption after a re-sync must still work.
        let a_again = item_key(&user_key, Uuid::from_u128(1)).unwrap();
        assert_eq!(a, a_again);
    }

    #[test]
    fn different_user_keys_produce_different_item_keys() {
        let item = Uuid::from_u128(7);
        let k1 = item_key(&UserKey::generate(), item).unwrap();
        let k2 = item_key(&UserKey::generate(), item).unwrap();
        assert_ne!(k1.expose(), k2.expose());
    }

    #[test]
    fn seal_and_open_item_roundtrip() {
        let (uk, user, vault, item, _) = fixtures();
        let aad = ItemAad::new(user, vault, item, 1, false);
        let envelope = seal_item(&uk, &aad, b"{\"password\":\"hunter2\"}").unwrap();

        // Survives a trip through storage.
        let stored = envelope.to_bytes();
        let reloaded = Envelope::from_bytes(&stored).unwrap();
        let opened = open_item(&uk, &aad, &reloaded).unwrap();
        assert_eq!(&opened[..], b"{\"password\":\"hunter2\"}");
    }

    #[test]
    fn item_cannot_be_moved_to_another_vault() {
        let (uk, user, vault, item, other_vault) = fixtures();
        let aad = ItemAad::new(user, vault, item, 1, false);
        let envelope = seal_item(&uk, &aad, b"payload").unwrap();

        let moved = ItemAad::new(user, other_vault, item, 1, false);
        assert_eq!(
            open_item(&uk, &moved, &envelope).unwrap_err(),
            Error::AadMismatch
        );
    }

    #[test]
    fn item_cannot_be_moved_to_another_user() {
        let (uk, user, vault, item, _) = fixtures();
        let aad = ItemAad::new(user, vault, item, 1, false);
        let envelope = seal_item(&uk, &aad, b"payload").unwrap();

        let stolen = ItemAad::new(Uuid::from_u128(0xDEAD), vault, item, 1, false);
        assert_eq!(
            open_item(&uk, &stolen, &envelope).unwrap_err(),
            Error::AadMismatch
        );
    }

    #[test]
    fn item_revision_cannot_be_replayed() {
        let (uk, user, vault, item, _) = fixtures();
        let old = ItemAad::new(user, vault, item, 1, false);
        let envelope = seal_item(&uk, &old, b"old password").unwrap();

        let newer = ItemAad::new(user, vault, item, 2, false);
        assert_eq!(
            open_item(&uk, &newer, &envelope).unwrap_err(),
            Error::AadMismatch
        );
    }

    #[test]
    fn tombstone_cannot_be_undeleted() {
        let (uk, user, vault, item, _) = fixtures();
        let deleted = ItemAad::new(user, vault, item, 2, true);
        let envelope = seal_item(&uk, &deleted, b"").unwrap();

        let revived = ItemAad::new(user, vault, item, 2, false);
        assert_eq!(
            open_item(&uk, &revived, &envelope).unwrap_err(),
            Error::AadMismatch
        );
    }

    #[test]
    fn user_key_wrapping_roundtrip() {
        let (uk, user, _, _, _) = fixtures();
        let ukek = crate::kdf::derive_ukek(&stretched(), None, &SALT).unwrap();

        let envelope = wrap_user_key(&ukek, &uk, user, KeyKind::UserKey).unwrap();
        // Exactly one 32-byte key plus tag: changing the master password rewrites this
        // and nothing else.
        assert_eq!(envelope.serialized_len(), 2 + 12 + 32 + 48);

        let unwrapped = unwrap_user_key(&ukek, &envelope, user, KeyKind::UserKey).unwrap();
        assert_eq!(unwrapped, uk);
    }

    #[test]
    fn user_key_cannot_be_replayed_into_the_recovery_slot() {
        let (uk, user, _, _, _) = fixtures();
        let ukek = crate::kdf::derive_ukek(&stretched(), None, &SALT).unwrap();
        let envelope = wrap_user_key(&ukek, &uk, user, KeyKind::UserKey).unwrap();

        assert_eq!(
            unwrap_user_key(&ukek, &envelope, user, KeyKind::RecoveryKey).unwrap_err(),
            Error::AadMismatch
        );
    }

    #[test]
    fn user_key_cannot_be_unwrapped_for_another_account() {
        let (uk, user, _, _, _) = fixtures();
        let ukek = crate::kdf::derive_ukek(&stretched(), None, &SALT).unwrap();
        let envelope = wrap_user_key(&ukek, &uk, user, KeyKind::UserKey).unwrap();

        assert_eq!(
            unwrap_user_key(&ukek, &envelope, Uuid::from_u128(0xBEEF), KeyKind::UserKey)
                .unwrap_err(),
            Error::AadMismatch
        );
    }

    #[test]
    fn wrong_master_password_cannot_unwrap() {
        let (uk, user, _, _, _) = fixtures();
        let good = crate::kdf::derive_ukek(&stretched(), None, &SALT).unwrap();
        let envelope = wrap_user_key(&good, &uk, user, KeyKind::UserKey).unwrap();

        let bad_stretched =
            stretch_master_password(b"wrong password", &SALT, &KdfParams::OWASP_MINIMUM).unwrap();
        let bad = crate::kdf::derive_ukek(&bad_stretched, None, &SALT).unwrap();

        assert_eq!(
            unwrap_user_key(&bad, &envelope, user, KeyKind::UserKey).unwrap_err(),
            Error::AuthFailed
        );
    }

    #[test]
    fn account_key_is_required_when_enabled() {
        let (uk, user, _, _, _) = fixtures();
        let account_key = AccountKey::generate();
        let ukek = crate::kdf::derive_ukek(&stretched(), Some(&account_key), &SALT).unwrap();
        let envelope = wrap_user_key(&ukek, &uk, user, KeyKind::UserKey).unwrap();

        // Without the account key the derived UKEK differs, so unwrapping must fail.
        let without = crate::kdf::derive_ukek(&stretched(), None, &SALT).unwrap();
        assert_eq!(
            unwrap_user_key(&without, &envelope, user, KeyKind::UserKey).unwrap_err(),
            Error::AuthFailed
        );

        let with = crate::kdf::derive_ukek(&stretched(), Some(&account_key), &SALT).unwrap();
        assert_eq!(
            unwrap_user_key(&with, &envelope, user, KeyKind::UserKey).unwrap(),
            uk
        );
    }
}
