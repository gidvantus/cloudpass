//! Associated data: the binding between a ciphertext and its identity.
//!
//! The server stores metadata (`rev`, `deleted`, ids) next to opaque ciphertext.
//! Those fields are fed into the AEAD as associated data, so the ciphertext is only
//! decryptable in exactly the position it was written to. A malicious or compromised
//! server cannot:
//!
//! * move an item between vaults or users,
//! * flip a `deleted` tombstone back into a live record,
//! * replay an older revision under a newer revision number,
//! * swap a wrapped user key into the recovery slot,
//!
//! because each of those changes the associated data and makes authentication fail.
//!
//! The canonical form is JSON produced from a struct, which serializes fields in
//! declaration order and therefore is byte-stable across builds and platforms. That
//! stability is load-bearing: an unstable encoding would make old ciphertext
//! undecryptable.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::Result;
use crate::PROTOCOL_VERSION;

/// Which slot a wrapped user key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// Normal path: unlocked by the master password.
    UserKey,
    /// Recovery path: unlocked by the recovery key from the Emergency Kit.
    RecoveryKey,
}

impl KeyKind {
    /// Stable string used inside the canonical associated data.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserKey => "userkey",
            Self::RecoveryKey => "recovery-key",
        }
    }
}

/// Associated data for a stored item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemAad {
    /// Record kind discriminator. Always `"item"`.
    pub t: String,
    /// Owning user.
    pub u: Uuid,
    /// Owning vault.
    pub vault: Uuid,
    /// The item itself.
    pub item: Uuid,
    /// Client-assigned revision. Strictly increasing per item.
    pub rev: u64,
    /// Whether this revision is a tombstone.
    pub deleted: bool,
    /// Protocol version, so a future format cannot be replayed into this one.
    pub protocol: u8,
}

impl ItemAad {
    #[must_use]
    pub fn new(user_id: Uuid, vault_id: Uuid, item_id: Uuid, rev: u64, deleted: bool) -> Self {
        Self {
            t: "item".to_owned(),
            u: user_id,
            vault: vault_id,
            item: item_id,
            rev,
            deleted,
            protocol: PROTOCOL_VERSION,
        }
    }

    /// Byte-stable encoding fed to the AEAD.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// SHA-256 of the canonical form, stored beside the ciphertext so metadata
    /// tampering is detected before any decryption is attempted.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(sha256(&self.canonical()?))
    }
}

/// Associated data for a wrapped key envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEnvelopeAad {
    /// Which slot: `"userkey"` or `"recovery-key"`.
    pub t: String,
    /// Owning user.
    pub u: Uuid,
    /// Protocol version.
    pub v: u8,
}

impl KeyEnvelopeAad {
    #[must_use]
    pub fn new(kind: KeyKind, user_id: Uuid) -> Self {
        Self {
            t: kind.as_str().to_owned(),
            u: user_id,
            v: PROTOCOL_VERSION,
        }
    }

    pub fn canonical(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(sha256(&self.canonical()?))
    }
}

/// SHA-256 helper used for associated-data digests and vault integrity roots.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (Uuid, Uuid, Uuid) {
        (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3))
    }

    #[test]
    fn canonical_form_is_stable_across_calls() {
        let (u, v, i) = ids();
        let aad = ItemAad::new(u, v, i, 7, false);
        assert_eq!(aad.canonical().unwrap(), aad.canonical().unwrap());
        assert_eq!(aad.digest().unwrap(), aad.digest().unwrap());
    }

    #[test]
    fn canonical_form_includes_expected_fields_and_versions() {
        let (u, v, i) = ids();
        let aad = ItemAad::new(u, v, i, 7, false);
        let json = String::from_utf8(aad.canonical().unwrap()).unwrap();
        assert!(json.contains("\"t\":\"item\""));
        assert!(json.contains("\"rev\":7"));
        assert!(json.contains("\"deleted\":false"));
        assert!(json.contains(&format!("\"protocol\":{PROTOCOL_VERSION}")));
    }

    /// Every field that a server could tamper with must change the associated data.
    /// This is the test that proves the anti-swap property holds.
    #[test]
    fn every_tampered_field_changes_the_digest() {
        let (u, v, i) = ids();
        let base = ItemAad::new(u, v, i, 7, false).digest().unwrap();

        let variants = [
            ItemAad::new(Uuid::from_u128(99), v, i, 7, false),
            ItemAad::new(u, Uuid::from_u128(99), i, 7, false),
            ItemAad::new(u, v, Uuid::from_u128(99), 7, false),
            ItemAad::new(u, v, i, 8, false),
            ItemAad::new(u, v, i, 7, true),
        ];
        for variant in variants {
            assert_ne!(
                base,
                variant.digest().unwrap(),
                "tampering with a filed must change the digest: {variant:?}"
            );
        }
    }

    /// A wrapped user key must not be replayable into the recovery slot.
    #[test]
    fn key_kind_is_part_of_the_binding() {
        let user = Uuid::from_u128(1);
        let normal = KeyEnvelopeAad::new(KeyKind::UserKey, user);
        let recovery = KeyEnvelopeAad::new(KeyKind::RecoveryKey, user);
        assert_ne!(normal.canonical().unwrap(), recovery.canonical().unwrap());
        assert_ne!(normal.digest().unwrap(), recovery.digest().unwrap());
    }

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256 of the empty string, a universally published vector.
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
