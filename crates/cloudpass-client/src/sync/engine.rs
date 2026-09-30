//! The sync exchange: pull, verify, push.

use uuid::Uuid;

use cloudpass_core::device::{DevicePublicKey, DeviceSigningKey, HeadSignature};
use cloudpass_core::head::{
    state_root, verify_head, HeadCommitment, HeadRecord, ItemDigest, KnownDevice,
};

use crate::error::{ClientError, Result};
use crate::store::{Store, StoredItem};
use crate::sync::transport::{HttpRequest, HttpResponse, Transport};
use crate::sync::wire::{
    ErrorBody, HeadDto, ItemChange, ListDevicesResponse, PullResponse, PushRequest, PushResponse,
    SignedHead, B64,
};
use crate::vault::Vault;

/// How many items to ask for per pull request.
const PULL_PAGE_SIZE: i64 = 200;

/// What this device must remember between syncs.
///
/// Deliberately not `Clone`: it holds a signing key, and the key types in this project
/// have no `Clone` so that key material cannot be duplicated by accident.
#[derive(Debug)]
pub struct SyncAccount {
    pub user_id: Uuid,
    pub device_id: Uuid,
    /// The device key that signs head commitments. Never leaves the device.
    pub device: DeviceSigningKey,
    /// The bearer token from the last login.
    pub token: String,
    /// The highest head revision this device has accepted.
    pub head_rev: i64,
    /// The pull cursor, so a sync only asks for what changed.
    pub cursor: i64,
}

/// What a pull did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullOutcome {
    /// Items that were new, or newer than what this device held.
    pub absorbed: usize,
    /// Items the server offered at a revision this device had already moved past.
    pub skipped_stale: usize,
    /// The head after the pull, if the account has one yet.
    pub head_rev: Option<i64>,
}

/// What a push did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    pub applied: usize,
    /// Human-readable reasons, one per refused change.
    pub conflicts: Vec<String>,
    /// Set when the server refused the signed head. **Nothing was applied.**
    pub head_rejected: Option<String>,
    pub head_rev: Option<i64>,
}

impl PushOutcome {
    /// Whether the caller should pull and try the same changes again.
    ///
    /// True both when the head was refused (the view is behind) and when any change
    /// conflicted (the change was based on a revision that moved).
    #[must_use]
    pub fn should_retry_after_pull(&self) -> bool {
        self.head_rejected.is_some() || !self.conflicts.is_empty()
    }
}

/// A change to send, described the way the vault sees it.
#[derive(Debug, Clone)]
pub struct PendingChange {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub base_rev: i64,
    pub rev: i64,
    pub envelope: Vec<u8>,
    pub deleted: bool,
}

impl PendingChange {
    /// Turns a sealed item into a change based on its previous revision.
    #[must_use]
    pub fn from_stored(item: &StoredItem, base_rev: i64) -> Self {
        Self {
            id: item.id,
            vault_id: item.vault_id,
            base_rev,
            rev: item.rev,
            envelope: item.envelope.clone(),
            deleted: item.deleted,
        }
    }
}

/// Every local change the server has not acknowledged.
///
/// The answer is read from the items themselves rather than from a separate dirty list:
/// `synced_rev` survives a restart, an in-memory set does not, and a client that forgot
/// what it had sent would either re-send everything or silently skip changes.
pub fn pending_changes(store: &dyn Store) -> Result<Vec<PendingChange>> {
    Ok(store
        .pending_items()?
        .iter()
        .map(|item| PendingChange::from_stored(item, item.synced_rev.unwrap_or(0)))
        .collect())
}

/// What a full synchronization did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    pub pulled: PullOutcome,
    /// `None` when there was nothing local to send.
    pub pushed: Option<PushOutcome>,
}

impl SyncOutcome {
    /// Whether the server refused something the caller should look at before retrying.
    #[must_use]
    pub fn has_refusals(&self) -> bool {
        self.pushed
            .as_ref()
            .is_some_and(PushOutcome::should_retry_after_pull)
    }
}

/// Drives the sync protocol against a server.
///
/// Generic over the transport rather than holding a trait object: the trait has async
/// methods, which are not object-safe, and every caller knows its own concrete
/// transport anyway.
pub struct SyncEngine<T> {
    transport: T,
    account: SyncAccount,
    /// Devices whose head signatures this client will accept. Revoked ones are
    /// excluded when the list is fetched.
    trusted: Vec<KnownDevice>,
}

impl<T> std::fmt::Debug for SyncEngine<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncEngine")
            .field("user_id", &self.account.user_id)
            .field("device_id", &self.account.device_id)
            .field("head_rev", &self.account.head_rev)
            .field("cursor", &self.account.cursor)
            .field("trusted_devices", &self.trusted.len())
            .finish_non_exhaustive()
    }
}

impl<T: Transport> SyncEngine<T> {
    #[must_use]
    pub fn new(transport: T, account: SyncAccount) -> Self {
        Self {
            transport,
            account,
            trusted: Vec::new(),
        }
    }

    #[must_use]
    pub fn account(&self) -> &SyncAccount {
        &self.account
    }

    /// The signing seed, for the caller to persist.
    ///
    /// Returned rather than stored here because the sync engine must not become a
    /// second place where key material lives.
    #[must_use]
    pub fn device_seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.account.device.to_seed()
    }

    /// Fetches the account's devices and rebuilds the trusted signer list.
    ///
    /// Revoked devices and devices without a registered key are left out. A device with
    /// no key cannot sign, so treating it as trusted would only widen the set of
    /// signatures accepted for no benefit.
    pub async fn refresh_trusted_devices(&mut self) -> Result<usize> {
        let response = self
            .transport
            .send(HttpRequest::get(
                "/api/v1/devices",
                Some(self.account.token.clone()),
            ))
            .await?;
        let listed: ListDevicesResponse = decode(&response, "device list")?;

        self.trusted = listed
            .devices
            .iter()
            .filter(|device| device.revoked_at.is_none())
            .filter_map(|device| {
                let key = device.public_key.as_ref()?;
                let public_key = DevicePublicKey::from_slice(key.as_slice()).ok()?;
                Some(KnownDevice {
                    device_id: device.device_id,
                    public_key,
                })
            })
            .collect();

        Ok(self.trusted.len())
    }

    /// Applies every change the server has that this device does not.
    ///
    /// `expect_clean` says whether this device has no local edits waiting to be pushed.
    /// When it does have some, the state root cannot match — the local view is ahead of
    /// the server by definition — so the root is checked only when the caller says the
    /// view is clean. Signature and monotonicity are always checked: those are what
    /// make a rollback detectable, and they do not depend on local state.
    pub async fn pull(
        &mut self,
        vault: &mut Vault,
        store: &mut dyn Store,
        expect_clean: bool,
    ) -> Result<PullOutcome> {
        let mut absorbed = 0usize;
        let mut skipped_stale = 0usize;
        let local: std::collections::BTreeMap<Uuid, i64> = store
            .load_items()?
            .into_iter()
            .map(|item| (item.id, item.rev))
            .collect();

        loop {
            let path = format!(
                "/api/v1/sync/pull?cursor={}&limit={PULL_PAGE_SIZE}",
                self.account.cursor
            );
            let response = self
                .transport
                .send(HttpRequest::get(path, Some(self.account.token.clone())))
                .await?;
            let page: PullResponse = decode(&response, "pull response")?;

            for item in &page.items {
                let known = local.get(&item.id).copied().unwrap_or(0);
                if item.rev <= known {
                    // This device has moved past what the server is offering: either a
                    // local edit not yet pushed, or a page that arrived out of order.
                    // Overwriting would discard the newer revision.
                    skipped_stale += 1;
                    continue;
                }

                vault.absorb(
                    store,
                    StoredItem {
                        id: item.id,
                        vault_id: item.vault_id,
                        rev: item.rev,
                        envelope: item.envelope.clone().into_vec(),
                        deleted: item.deleted,
                        // `absorb` records the acknowledged revision itself.
                        synced_rev: None,
                    },
                )?;
                absorbed += 1;
            }

            if let Some(head) = &page.head {
                self.accept_head(head, store, expect_clean)?;
            }

            self.account.cursor = page.next_cursor;
            if !page.has_more {
                break;
            }
        }

        Ok(PullOutcome {
            absorbed,
            skipped_stale,
            head_rev: (self.account.head_rev > 0).then_some(self.account.head_rev),
        })
    }

    /// Sends a batch of local changes, committing to the state it produces.
    ///
    /// The commitment is computed over the **whole** item set this device holds with
    /// the batch applied. That is what makes the push verifiable: the server recomputes
    /// the same commitment over what it actually ends up storing, and refuses the batch
    /// if the two disagree.
    pub async fn push(
        &mut self,
        store: &mut dyn Store,
        changes: Vec<PendingChange>,
    ) -> Result<PushOutcome> {
        let next_head_rev = self.account.head_rev + 1;

        let mut digests: std::collections::BTreeMap<Uuid, ItemDigest> = store
            .load_items()?
            .into_iter()
            .map(|item| {
                let digest =
                    ItemDigest::from_envelope(item.id, item.rev, item.deleted, &item.envelope);
                (item.id, digest)
            })
            .collect();

        for change in &changes {
            digests.insert(
                change.id,
                ItemDigest::from_envelope(change.id, change.rev, change.deleted, &change.envelope),
            );
        }

        let root = state_root(&digests.into_values().collect::<Vec<_>>());
        let commitment = HeadCommitment {
            owner: self.account.user_id,
            head_rev: next_head_rev,
            state_root: root,
        };
        let signature = self.account.device.sign(&commitment.canonical());

        let request = PushRequest {
            head: SignedHead {
                head_rev: next_head_rev,
                state_root: B64::new(root.to_vec()),
                signature: B64::new(signature.as_bytes().to_vec()),
            },
            changes: changes
                .iter()
                .map(|change| ItemChange {
                    id: change.id,
                    vault_id: change.vault_id,
                    base_rev: change.base_rev,
                    rev: change.rev,
                    envelope: B64::new(change.envelope.clone()),
                    meta: None,
                    deleted: change.deleted,
                })
                .collect(),
        };

        let body = serde_json::to_vec(&request)?;
        let response = self
            .transport
            .send(HttpRequest::post(
                "/api/v1/sync/push",
                Some(self.account.token.clone()),
                body,
            ))
            .await?;
        let answer: PushResponse = decode(&response, "push response")?;

        if answer.head_rejected.is_none() && !answer.applied.is_empty() {
            self.account.head_rev = next_head_rev;

            // Record what the server took, so the next run knows what is still local.
            // A failure here is reported rather than ignored: silently leaving items
            // marked as pending would re-send them forever, and silently marking them
            // synced would lose the change.
            for applied in &answer.applied {
                store.mark_synced(applied.id, applied.rev)?;
            }
        } else if let Some(head) = &answer.head {
            // The server is telling us what it actually holds, which is newer than what
            // this device believed. Adopting it is not a security decision — the next
            // pull verifies the signature before anything is trusted.
            self.account.head_rev = head.head_rev;
        }

        Ok(PushOutcome {
            applied: answer.applied.len(),
            conflicts: answer
                .conflicts
                .iter()
                .map(|conflict| format!("{}: {}", conflict.id, conflict.reason))
                .collect(),
            head_rejected: answer.head_rejected,
            head_rev: answer.head.map(|head| head.head_rev),
        })
    }

    /// One synchronization: catch up, then send what is still local.
    ///
    /// A conflict is reported, not resolved. Merging two edits to the same item means
    /// re-sealing it at a new revision, and deciding what the merged value should be is
    /// the user's call — silently picking one would be exactly the data loss this
    /// protocol is built to avoid.
    pub async fn sync(&mut self, vault: &mut Vault, store: &mut dyn Store) -> Result<SyncOutcome> {
        // Pull first, and tell it whether the local view is clean: with unpushed edits
        // the roots cannot match, and claiming otherwise would fail every time.
        let before = pending_changes(store)?;
        let pulled = self.pull(vault, store, before.is_empty()).await?;

        // The pull may have absorbed changes, so recompute rather than reusing `before`.
        let pending = pending_changes(store)?;
        let pushed = if pending.is_empty() {
            None
        } else {
            Some(self.push(store, pending).await?)
        };

        Ok(SyncOutcome { pulled, pushed })
    }

    /// Verifies a head the server just offered and adopts its revision.
    fn accept_head(&mut self, head: &HeadDto, store: &dyn Store, expect_clean: bool) -> Result<()> {
        let record = HeadRecord {
            head_rev: head.head_rev,
            state_root: to_array(head.state_root.as_slice(), "state root")?,
            signer: head.signer_device_id,
            signature: HeadSignature::from_slice(head.signature.as_slice())
                .map_err(|_| ClientError::Protocol("head signature has the wrong length".into()))?,
        };

        // Signature, trusted signer and monotonicity. This is the rollback check, and
        // it runs before anything else is believed.
        verify_head(
            self.account.user_id,
            &record,
            &self.trusted,
            self.account.head_rev,
        )
        .map_err(|error| ClientError::Protocol(format!("head rejected: {error}")))?;

        if expect_clean {
            // With no local edits the two views must be identical. A mismatch means the
            // server served a set of items that does not hash to the state it signed —
            // an incomplete page, a dropped tombstone, or a rollback to an older state
            // re-signed by a device that has since made changes.
            let local: Vec<ItemDigest> = store
                .load_items()?
                .into_iter()
                .map(|item| {
                    ItemDigest::from_envelope(item.id, item.rev, item.deleted, &item.envelope)
                })
                .collect();

            if state_root(&local) != record.state_root {
                return Err(ClientError::Protocol(
                    "the items the server sent do not match the state it signed".to_owned(),
                ));
            }
        }

        self.account.head_rev = record.head_rev;
        Ok(())
    }
}

fn decode<R: serde::de::DeserializeOwned>(response: &HttpResponse, what: &str) -> Result<R> {
    if !response.is_success() {
        return Err(http_error(response));
    }
    serde_json::from_slice(&response.body)
        .map_err(|error| ClientError::Protocol(format!("{what} could not be read: {error}")))
}

fn http_error(response: &HttpResponse) -> ClientError {
    let code = serde_json::from_slice::<ErrorBody>(&response.body)
        .map(|body| body.error)
        .unwrap_or_else(|_| "unreadable".to_owned());
    ClientError::Http {
        status: response.status,
        code,
    }
}

fn to_array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| {
        ClientError::Protocol(format!(
            "{what} should be {N} bytes but was {}",
            bytes.len()
        ))
    })
}
