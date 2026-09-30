//! The signed vault head: what makes a rollback detectable.
//!
//! # The problem
//!
//! Without this module the server is trusted to tell the truth about *which* revision
//! is current. A malicious or compromised server can answer a pull with a consistent
//! but old set of items — restoring a password the user replaced, or resurrecting one
//! they deleted — and nothing in the sync protocol notices. The user sees a working
//! vault with wrong contents, which is the worst possible failure mode for a password
//! manager: silent and plausible.
//!
//! # The fix
//!
//! After every write the account has a **head**: a monotone revision number plus a
//! commitment to the complete item set at that revision. The device that made the
//! change signs the commitment with its own Ed25519 key, which the server never sees.
//! A client then refuses any head that
//!
//! 1. is not signed by a device it trusts, or
//! 2. is older than the newest head it has already accepted, or
//! 3. commits to a different item set than the one it actually received.
//!
//! A server that cannot forge signatures can therefore only ever present the newest
//! state, or be caught. What it can still do is refuse to serve anything at all —
//! denial of service stays possible, silent corruption does not.
//!
//! # What this is not
//!
//! The commitment is a hash over the *sorted* list of per-item digests, not a Merkle
//! tree. It proves "this exact set of items", which is all the sync protocol needs;
//! it does not support inclusion proofs, and it is not called a Merkle root because
//! it is not one.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::device::{verify, DevicePublicKey, HeadSignature};
use crate::error::{Error, Result};

/// Domain separator for the signed head commitment.
pub const HEAD_DOMAIN: &[u8] = b"cloudpass/v1/head-commitment";

/// Domain separator for a single item digest.
pub const ITEM_DIGEST_DOMAIN: &[u8] = b"cloudpass/v1/item-digest";

/// Domain separator for the state root.
pub const STATE_ROOT_DOMAIN: &[u8] = b"cloudpass/v1/state-root";

/// The statement a device signs when it publishes a new vault state.
///
/// The owner is included so that a head signed for one account cannot be replayed
/// into another: a signature is only meaningful in the context it was made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadCommitment {
    /// The account the state belongs to.
    pub owner: Uuid,
    /// Monotone revision of this head, starting at 1.
    pub head_rev: i64,
    /// Commitment to the complete item set at this revision.
    pub state_root: [u8; 32],
}

impl HeadCommitment {
    /// The exact bytes that get signed.
    ///
    /// Fixed-width and domain-separated, so no two different commitments can produce
    /// the same byte string.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_DOMAIN.len() + 16 + 8 + 32);
        out.extend_from_slice(HEAD_DOMAIN);
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(&self.head_rev.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out
    }
}

/// One item, reduced to what the state root commits to.
///
/// The envelope is hashed rather than embedded, so comparing states never requires
/// holding every ciphertext in memory, and two clients that agree on the root are
/// guaranteed to agree on the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemDigest {
    /// Item identifier.
    pub id: Uuid,
    /// Item revision, as assigned by the client that wrote it.
    pub rev: i64,
    /// Whether this revision is a tombstone.
    pub deleted: bool,
    /// SHA-256 of the stored envelope.
    pub envelope_hash: [u8; 32],
}

impl ItemDigest {
    /// Hashes an envelope and builds the digest.
    #[must_use]
    pub fn from_envelope(id: Uuid, rev: i64, deleted: bool, envelope: &[u8]) -> Self {
        Self {
            id,
            rev,
            deleted,
            envelope_hash: sha256(envelope),
        }
    }

    fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ITEM_DIGEST_DOMAIN);
        hasher.update(self.id.as_bytes());
        hasher.update(self.rev.to_be_bytes());
        hasher.update([u8::from(self.deleted)]);
        hasher.update(self.envelope_hash);
        hasher.finalize().into()
    }
}

/// The commitment to a complete item set, independent of ordering.
///
/// Tombstones are included. A root that ignored deletions would not notice a server
/// dropping a tombstone, which is exactly how a deleted password comes back.
#[must_use]
pub fn state_root(items: &[ItemDigest]) -> [u8; 32] {
    let mut digests: Vec<[u8; 32]> = items.iter().map(ItemDigest::hash).collect();
    digests.sort_unstable();

    let mut hasher = Sha256::new();
    hasher.update(STATE_ROOT_DOMAIN);
    // Length-prefixed: the empty set must not share a root with anything else, and a
    // future change to the digest width cannot silently alias.
    hasher.update((items.len() as u64).to_be_bytes());
    for digest in digests {
        hasher.update(digest);
    }
    hasher.finalize().into()
}

/// A head as stored by the server and served to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadRecord {
    /// Monotone revision.
    pub head_rev: i64,
    /// Commitment to the item set at this revision.
    pub state_root: [u8; 32],
    /// The device that signed it.
    pub signer: Uuid,
    /// Signature over [`HeadCommitment::canonical`].
    pub signature: HeadSignature,
}

/// A device the client is willing to accept signatures from.
///
/// The caller is responsible for excluding revoked devices — this type carries no
/// revocation state, because only the client knows its own policy.
#[derive(Debug, Clone, Copy)]
pub struct KnownDevice {
    /// Device identifier, as assigned at login.
    pub device_id: Uuid,
    /// The device's Ed25519 public key.
    pub public_key: DevicePublicKey,
}

/// Verifies a head: trusted signer, valid signature, and not older than one already
/// accepted.
///
/// `minimum_head_rev` is the newest head revision this client has already accepted,
/// usually remembered locally. Zero means "nothing seen yet", which is the case on a
/// brand-new client — and that case is worth naming: a client with no history cannot
/// detect a rollback that happened before its first sync. That is trust on first use,
/// and it is why a desktop client persists this value.
pub fn verify_head(
    owner: Uuid,
    head: &HeadRecord,
    known_devices: &[KnownDevice],
    minimum_head_rev: i64,
) -> Result<()> {
    if head.head_rev < minimum_head_rev {
        return Err(Error::StaleHead);
    }

    let device = known_devices
        .iter()
        .find(|candidate| candidate.device_id == head.signer)
        .ok_or(Error::UnknownSigner)?;

    let commitment = HeadCommitment {
        owner,
        head_rev: head.head_rev,
        state_root: head.state_root,
    };

    verify(&device.public_key, &commitment.canonical(), &head.signature)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceSigningKey;

    fn item(id: u128, rev: i64, deleted: bool, envelope: &[u8]) -> ItemDigest {
        ItemDigest::from_envelope(Uuid::from_u128(id), rev, deleted, envelope)
    }

    fn signed_head(
        owner: Uuid,
        head_rev: i64,
        root: [u8; 32],
        signer: Uuid,
        key: &DeviceSigningKey,
    ) -> HeadRecord {
        let commitment = HeadCommitment {
            owner,
            head_rev,
            state_root: root,
        };
        HeadRecord {
            head_rev,
            state_root: root,
            signer,
            signature: key.sign(&commitment.canonical()),
        }
    }

    #[test]
    fn the_root_does_not_depend_on_item_order() {
        let mut items = vec![
            item(1, 1, false, b"one"),
            item(2, 3, false, b"two"),
            item(3, 1, true, b""),
        ];
        let expected = state_root(&items);
        items.reverse();
        assert_eq!(state_root(&items), expected);
        items.swap(0, 1);
        assert_eq!(state_root(&items), expected);
    }

    #[test]
    fn the_root_changes_when_any_part_of_an_item_changes() {
        let base = state_root(&[item(1, 1, false, b"payload")]);

        assert_ne!(base, state_root(&[item(2, 1, false, b"payload")]), "id");
        assert_ne!(base, state_root(&[item(1, 2, false, b"payload")]), "rev");
        assert_ne!(base, state_root(&[item(1, 1, true, b"payload")]), "deleted");
        assert_ne!(base, state_root(&[item(1, 1, false, b"other")]), "envelope");
    }

    #[test]
    fn a_dropped_item_changes_the_root() {
        let full = vec![item(1, 1, false, b"one"), item(2, 1, false, b"two")];
        let truncated = vec![full[0]];
        assert_ne!(state_root(&full), state_root(&truncated));
    }

    /// The specific rollback that matters: an item deleted and then silently restored.
    #[test]
    fn dropping_a_tombstone_changes_the_root() {
        let with_tombstone = vec![item(1, 2, true, b""), item(2, 1, false, b"other")];
        let without = vec![
            item(1, 1, false, b"old password"),
            item(2, 1, false, b"other"),
        ];
        assert_ne!(state_root(&with_tombstone), state_root(&without));
    }

    #[test]
    fn the_empty_set_has_a_stable_root() {
        assert_eq!(state_root(&[]), state_root(&[]));
        assert_ne!(state_root(&[]), state_root(&[item(1, 1, true, b"")]));
    }

    #[test]
    fn a_head_signed_by_a_known_device_verifies() {
        let owner = Uuid::from_u128(0xAA);
        let device_id = Uuid::from_u128(0xBB);
        let key = DeviceSigningKey::generate();
        let head = signed_head(owner, 1, [7u8; 32], device_id, &key);

        let devices = [KnownDevice {
            device_id,
            public_key: key.public_key(),
        }];
        assert!(verify_head(owner, &head, &devices, 0).is_ok());
        assert!(verify_head(owner, &head, &devices, 1).is_ok());
    }

    #[test]
    fn a_head_from_an_unknown_device_is_refused() {
        let owner = Uuid::from_u128(0xAA);
        let key = DeviceSigningKey::generate();
        let head = signed_head(owner, 1, [7u8; 32], Uuid::from_u128(0xBB), &key);

        let devices = [KnownDevice {
            device_id: Uuid::from_u128(0xCC),
            public_key: key.public_key(),
        }];
        assert_eq!(
            verify_head(owner, &head, &devices, 0),
            Err(Error::UnknownSigner)
        );
    }

    #[test]
    fn a_head_older_than_one_already_accepted_is_refused() {
        let owner = Uuid::from_u128(0xAA);
        let device_id = Uuid::from_u128(0xBB);
        let key = DeviceSigningKey::generate();
        let head = signed_head(owner, 3, [7u8; 32], device_id, &key);

        let devices = [KnownDevice {
            device_id,
            public_key: key.public_key(),
        }];

        // A client that has already accepted revision 5 must reject revision 3 even
        // though the signature is perfectly valid. This is the rollback check.
        assert_eq!(
            verify_head(owner, &head, &devices, 5),
            Err(Error::StaleHead)
        );
    }

    #[test]
    fn a_tampered_head_is_refused() {
        let owner = Uuid::from_u128(0xAA);
        let device_id = Uuid::from_u128(0xBB);
        let key = DeviceSigningKey::generate();
        let head = signed_head(owner, 4, [7u8; 32], device_id, &key);
        let devices = [KnownDevice {
            device_id,
            public_key: key.public_key(),
        }];

        // Every field of the commitment is covered by the signature.
        let other_root = HeadRecord {
            state_root: [8u8; 32],
            ..head
        };
        assert_eq!(
            verify_head(owner, &other_root, &devices, 0),
            Err(Error::BadSignature)
        );

        let other_rev = HeadRecord {
            head_rev: 5,
            ..head
        };
        assert_eq!(
            verify_head(owner, &other_rev, &devices, 0),
            Err(Error::BadSignature)
        );

        // A head signed for one account must not be replayable into another.
        assert_eq!(
            verify_head(Uuid::from_u128(0xDEAD), &head, &devices, 0),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn commitments_are_domain_separated() {
        let commitment = HeadCommitment {
            owner: Uuid::from_u128(1),
            head_rev: 1,
            state_root: [0u8; 32],
        };
        let canonical = commitment.canonical();
        assert!(canonical.starts_with(HEAD_DOMAIN));
        assert_eq!(canonical.len(), HEAD_DOMAIN.len() + 16 + 8 + 32);
    }
}
