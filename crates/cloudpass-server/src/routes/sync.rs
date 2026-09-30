//! Vault and item synchronisation, and the signed head that makes a rollback
//! detectable.
//!
//! # The contract
//!
//! The server is a dumb, ordered, per-user log of opaque records. It never parses an
//! envelope, never resolves a conflict on its own, never invents a revision, and
//! **cannot produce a valid head signature**. What it enforces is ordering, ownership
//! and consistency: revisions must move forward, a change must be based on the
//! revision it claims, an item must live in a vault the caller owns, and a push must
//! commit to exactly the state it produces.
//!
//! # Why compare-and-swap instead of last-write-wins
//!
//! Last-write-wins silently discards data. For a password manager "silently" is the
//! operative word: the user would have no way to know a password they saved on one
//! device was overwritten by a stale copy from another. Here a mismatched `base_rev`
//! produces a conflict, both versions survive, and the client decides what to show.
//!
//! # Why the push carries a signed head
//!
//! Per-item compare-and-swap stops a client from clobbering a newer item, but it says
//! nothing about the *set* of items. A server that answers a pull with an older, still
//! internally consistent set — a deleted password restored, a replaced one rolled back
//! — passes every per-item check.
//!
//! So each push carries a commitment to the complete resulting item set, signed by the
//! pushing device. The server verifies the signature, applies the batch, and then
//! checks that the state it actually produced matches the commitment. If it does not,
//! the whole transaction is rolled back and nothing is applied.
//!
//! The consequence for clients is a rule worth stating plainly: **pull before push.**
//! A client whose view is missing an item another device added will compute a
//! different root and be refused, which is the correct outcome — it should catch up
//! rather than write blind.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqliteConnection};
use std::sync::Arc;
use uuid::Uuid;

use cloudpass_core::device::{verify, DevicePublicKey, HeadSignature};
use cloudpass_core::head::{state_root, HeadCommitment, ItemDigest};

use crate::auth::{self, AuthSession};
use crate::codec::{now_unix, B64};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Largest envelope the server will store for one item.
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// Default and maximum page size for a pull.
const DEFAULT_PULL_LIMIT: i64 = 200;
const MAX_PULL_LIMIT: i64 = 1000;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVaultRequest {
    pub vault_id: Uuid,
    pub name_envelope: B64,
}

#[derive(Debug, Serialize)]
pub struct VaultDto {
    pub vault_id: Uuid,
    pub name_envelope: B64,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ListVaultsResponse {
    pub vaults: Vec<VaultDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemChange {
    pub id: Uuid,
    pub vault_id: Uuid,
    /// The revision this change is based on. Zero means "I believe this is new".
    pub base_rev: i64,
    /// The revision this change produces. Must be strictly greater than `base_rev`.
    pub rev: i64,
    pub envelope: B64,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
    #[serde(default)]
    pub deleted: bool,
}

/// A device's signed commitment to the state a push produces.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHead {
    /// Must be exactly the current head revision plus one.
    pub head_rev: i64,
    /// The state root the client computed over its post-push view.
    pub state_root: B64,
    /// Ed25519 signature over the canonical head commitment.
    pub signature: B64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushRequest {
    pub head: SignedHead,
    pub changes: Vec<ItemChange>,
}

#[derive(Debug, Serialize)]
pub struct ItemDto {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub rev: i64,
    pub envelope: B64,
    pub meta: serde_json::Value,
    pub deleted: bool,
    pub seq: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct AppliedChange {
    pub id: Uuid,
    pub rev: i64,
    pub seq: i64,
}

/// A change the server refused, together with what it currently holds.
///
/// The client is expected to keep both. `current` is `None` when the client claimed
/// to be updating an item that does not exist.
#[derive(Debug, Serialize)]
pub struct Conflict {
    pub id: Uuid,
    pub reason: &'static str,
    pub current: Option<ItemDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeadDto {
    pub head_rev: i64,
    pub state_root: B64,
    pub signature: B64,
    pub signer_device_id: Uuid,
    pub updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct PushResponse {
    pub applied: Vec<AppliedChange>,
    pub conflicts: Vec<Conflict>,
    /// Why the signed head was refused, if it was. When this is set, **nothing was
    /// applied**: the client must pull, re-base and try again.
    pub head_rejected: Option<&'static str>,
    /// The head the server currently holds, so a refused client can resynchronise
    /// without a separate round trip.
    pub head: Option<HeadDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullQuery {
    #[serde(default)]
    pub cursor: i64,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PullResponse {
    pub items: Vec<ItemDto>,
    pub next_cursor: i64,
    pub has_more: bool,
    /// The signed head. `None` only before the account's first push.
    ///
    /// A client must verify this before trusting what it received: a signature from a
    /// device it does not trust, or a revision older than one it has already accepted,
    /// means the server is not telling the truth.
    pub head: Option<HeadDto>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn check_envelope(bytes: &[u8]) -> ApiResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(ApiError::BadRequest("envelope has an unacceptable size"));
    }
    Ok(())
}

fn meta_json(value: &Option<serde_json::Value>) -> String {
    // Anything that is not an object is not worth storing, and is normalised away.
    match value {
        Some(serde_json::Value::Object(_)) => {
            serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned())
        }
        _ => "{}".to_owned(),
    }
}

fn parse_uuid_stored(value: &str, what: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(value).map_err(|e| ApiError::Internal(format!("stored {what} is invalid: {e}")))
}

async fn user_owns_vault(
    conn: &mut SqliteConnection,
    user_id: Uuid,
    vault_id: Uuid,
) -> ApiResult<bool> {
    let found: Option<String> =
        sqlx::query_scalar("SELECT vault_id FROM vaults WHERE vault_id = ? AND user_id = ?")
            .bind(vault_id.to_string())
            .bind(user_id.to_string())
            .fetch_optional(conn)
            .await?;
    Ok(found.is_some())
}

async fn load_head(conn: &mut SqliteConnection, user_id: Uuid) -> ApiResult<Option<HeadDto>> {
    let row = sqlx::query(
        "SELECT head_rev, state_root, signature, signer_device_id, updated_at \
         FROM vault_heads WHERE user_id = ?",
    )
    .bind(user_id.to_string())
    .fetch_optional(conn)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    Ok(Some(HeadDto {
        head_rev: row.get("head_rev"),
        state_root: B64(row.get("state_root")),
        signature: B64(row.get("signature")),
        signer_device_id: parse_uuid_stored(
            &row.get::<String, _>("signer_device_id"),
            "device id",
        )?,
        updated_at: row.get("updated_at"),
    }))
}

/// Recomputes the state root from what the server actually stores.
///
/// This is the check that makes the client's commitment meaningful: the server cannot
/// accept a signed root and then hold a different item set.
async fn compute_state_root(conn: &mut SqliteConnection, user_id: Uuid) -> ApiResult<[u8; 32]> {
    let rows = sqlx::query("SELECT id, rev, deleted, envelope FROM items WHERE user_id = ?")
        .bind(user_id.to_string())
        .fetch_all(conn)
        .await?;

    let mut digests = Vec::with_capacity(rows.len());
    for row in rows {
        let id = parse_uuid_stored(&row.get::<String, _>("id"), "item id")?;
        digests.push(ItemDigest::from_envelope(
            id,
            row.get("rev"),
            row.get::<i64, _>("deleted") != 0,
            &row.get::<Vec<u8>, _>("envelope"),
        ));
    }

    Ok(state_root(&digests))
}

async fn store_head(
    conn: &mut SqliteConnection,
    user_id: Uuid,
    head_rev: i64,
    root: &[u8; 32],
    signature: &HeadSignature,
    signer: Uuid,
    now: i64,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO vault_heads(user_id, head_rev, state_root, signature, signer_device_id, \
         updated_at) VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(user_id) DO UPDATE SET head_rev = excluded.head_rev, \
         state_root = excluded.state_root, signature = excluded.signature, \
         signer_device_id = excluded.signer_device_id, updated_at = excluded.updated_at",
    )
    .bind(user_id.to_string())
    .bind(head_rev)
    .bind(root.as_slice())
    .bind(signature.as_bytes().as_slice())
    .bind(signer.to_string())
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

fn row_to_item(id: Uuid, row: &sqlx::sqlite::SqliteRow) -> ApiResult<ItemDto> {
    let vault_id = parse_uuid_stored(&row.get::<String, _>("vault_id"), "vault id")?;
    let meta: String = row.get("meta");

    Ok(ItemDto {
        id,
        vault_id,
        rev: row.get("rev"),
        envelope: B64(row.get("envelope")),
        meta: serde_json::from_str(&meta).unwrap_or_else(|_| serde_json::json!({})),
        deleted: row.get::<i64, _>("deleted") != 0,
        seq: row.get("seq"),
        updated_at: row.get("updated_at"),
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn create_vault(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    Json(request): Json<CreateVaultRequest>,
) -> ApiResult<()> {
    check_envelope(request.name_envelope.as_slice())?;

    sqlx::query(
        "INSERT INTO vaults(vault_id, user_id, name_envelope, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(request.vault_id.to_string())
    .bind(session.user_id.to_string())
    .bind(request.name_envelope.as_slice())
    .bind(now_unix())
    .execute(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db) if db.is_unique_violation() => {
            ApiError::BadRequest("vault already exists")
        }
        other => other.into(),
    })?;

    Ok(())
}

pub async fn list_vaults(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
) -> ApiResult<Json<ListVaultsResponse>> {
    let rows = sqlx::query(
        "SELECT vault_id, name_envelope, created_at FROM vaults WHERE user_id = ? ORDER BY created_at",
    )
    .bind(session.user_id.to_string())
    .fetch_all(&state.pool)
    .await?;

    let mut vaults = Vec::with_capacity(rows.len());
    for row in rows {
        vaults.push(VaultDto {
            vault_id: parse_uuid_stored(&row.get::<String, _>("vault_id"), "vault id")?,
            name_envelope: B64(row.get("name_envelope")),
            created_at: row.get("created_at"),
        });
    }

    Ok(Json(ListVaultsResponse { vaults }))
}

/// Applies a batch of client changes, but only if the result matches the signed head
/// the client committed to.
pub async fn push(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    Json(request): Json<PushRequest>,
) -> ApiResult<Json<PushResponse>> {
    // The connection is released before the transaction starts. On a single-connection
    // database — which is what `:memory:` gives us — holding one while opening a
    // transaction would deadlock.
    let mut conn = state.pool.acquire().await?;
    let current = load_head(&mut conn, session.user_id).await?;
    drop(conn);

    let reject = |reason: &'static str, head: Option<HeadDto>| {
        Json(PushResponse {
            applied: Vec::new(),
            conflicts: Vec::new(),
            head_rejected: Some(reason),
            head,
        })
    };

    // The head revision is a counter, not a guess: exactly one advance per change.
    let expected_rev = current.as_ref().map_or(1, |head| head.head_rev + 1);
    if request.head.head_rev != expected_rev {
        return Ok(reject("head revision is not current", current));
    }

    let Ok(claimed_root) = <[u8; 32]>::try_from(request.head.state_root.as_slice()) else {
        return Ok(reject("state root has the wrong length", current));
    };
    let Ok(signature) = HeadSignature::from_slice(request.head.signature.as_slice()) else {
        return Ok(reject("signature has the wrong length", current));
    };

    // The signature must come from *this* device. A device that never registered a
    // signing key cannot commit to anything, so it is refused rather than trusted.
    let Some(device_key) = auth::device_signing_key(&state.pool, session.device_id).await? else {
        return Ok(reject("device has no registered signing key", current));
    };

    let commitment = HeadCommitment {
        owner: session.user_id,
        head_rev: request.head.head_rev,
        state_root: claimed_root,
    };
    if verify(
        &DevicePublicKey::from_bytes(device_key),
        &commitment.canonical(),
        &signature,
    )
    .is_err()
    {
        return Ok(reject("head signature is invalid", current));
    }

    let mut applied = Vec::new();
    let mut conflicts = Vec::new();
    let mut tx = state.pool.begin().await?;

    for change in &request.changes {
        if change.rev < 1 || change.base_rev < 0 || change.rev <= change.base_rev {
            conflicts.push(Conflict {
                id: change.id,
                reason: "revision must be greater than base_rev and at least 1",
                current: None,
            });
            continue;
        }

        if check_envelope(change.envelope.as_slice()).is_err() {
            conflicts.push(Conflict {
                id: change.id,
                reason: "envelope has an unacceptable size",
                current: None,
            });
            continue;
        }

        // Everything below stays on the transaction's own connection. Holding a
        // transaction open while borrowing a second pooled connection would deadlock
        // on a single-connection database, which is what the test harness uses.
        if !user_owns_vault(&mut tx, session.user_id, change.vault_id).await? {
            conflicts.push(Conflict {
                id: change.id,
                reason: "vault does not belong to this account",
                current: None,
            });
            continue;
        }

        let existing = sqlx::query(
            "SELECT vault_id, rev, envelope, meta, deleted, seq, updated_at FROM items \
             WHERE id = ? AND user_id = ?",
        )
        .bind(change.id.to_string())
        .bind(session.user_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;

        let now = now_unix();

        match existing {
            None => {
                if change.base_rev != 0 {
                    conflicts.push(Conflict {
                        id: change.id,
                        reason: "client expected an existing revision",
                        current: None,
                    });
                    continue;
                }
                // Sequence numbers are allocated only when something is written, so a
                // rejected change leaves no gap behind it.
                let seq = crate::db::next_seq(&mut tx).await?;
                sqlx::query(
                    "INSERT INTO items(id, user_id, vault_id, rev, base_rev, envelope, meta, \
                     deleted, seq, updated_at, device_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(change.id.to_string())
                .bind(session.user_id.to_string())
                .bind(change.vault_id.to_string())
                .bind(change.rev)
                .bind(change.base_rev)
                .bind(change.envelope.as_slice())
                .bind(meta_json(&change.meta))
                .bind(i64::from(change.deleted))
                .bind(seq)
                .bind(now)
                .bind(session.device_id.to_string())
                .execute(&mut *tx)
                .await?;

                applied.push(AppliedChange {
                    id: change.id,
                    rev: change.rev,
                    seq,
                });
            }
            Some(row) => {
                let current_item = row_to_item(change.id, &row)?;
                let stored_rev: i64 = row.get("rev");

                if change.base_rev != stored_rev {
                    // The client edited a version that is no longer current. This is
                    // the case last-write-wins would have destroyed.
                    conflicts.push(Conflict {
                        id: change.id,
                        reason: "base_rev does not match the current revision",
                        current: Some(current_item),
                    });
                    continue;
                }

                let seq = crate::db::next_seq(&mut tx).await?;
                sqlx::query(
                    "UPDATE items SET vault_id = ?, rev = ?, base_rev = ?, envelope = ?, meta = ?, \
                     deleted = ?, seq = ?, updated_at = ?, device_id = ? WHERE id = ? AND user_id = ?",
                )
                .bind(change.vault_id.to_string())
                .bind(change.rev)
                .bind(change.base_rev)
                .bind(change.envelope.as_slice())
                .bind(meta_json(&change.meta))
                .bind(i64::from(change.deleted))
                .bind(seq)
                .bind(now)
                .bind(session.device_id.to_string())
                .bind(change.id.to_string())
                .bind(session.user_id.to_string())
                .execute(&mut *tx)
                .await?;

                applied.push(AppliedChange {
                    id: change.id,
                    rev: change.rev,
                    seq,
                });
            }
        }
    }

    if applied.is_empty() {
        // Nothing changed, so the head must not advance. The conflicts are returned
        // rather than swallowed: they are how the client learns what it is missing,
        // and dropping them would turn a recoverable situation into a mystery.
        tx.rollback().await?;
        return Ok(Json(PushResponse {
            applied,
            conflicts,
            head_rejected: Some("no change was applied, so the head must not advance"),
            head: current,
        }));
    }

    let actual_root = compute_state_root(&mut tx, session.user_id).await?;
    if actual_root != claimed_root {
        // The client's picture of the vault differs from the result of its own push —
        // almost always because it had not caught up. Refusing is the point: silently
        // accepting would let the client sign a state the server then contradicts.
        tx.rollback().await?;
        return Ok(reject(
            "state root does not match the server's state; pull and retry",
            current,
        ));
    }

    store_head(
        &mut tx,
        session.user_id,
        request.head.head_rev,
        &claimed_root,
        &signature,
        session.device_id,
        now_unix(),
    )
    .await?;

    tx.commit().await?;

    let mut conn = state.pool.acquire().await?;
    let head = load_head(&mut conn, session.user_id).await?;
    drop(conn);

    Ok(Json(PushResponse {
        applied,
        conflicts,
        head_rejected: None,
        head,
    }))
}

/// Returns everything this account has changed since a cursor, plus the signed head.
///
/// Tombstones are included: a deleted item is a change like any other, and a client
/// that never learns about it would keep showing it forever.
pub async fn pull(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    Query(query): Query<PullQuery>,
) -> ApiResult<Json<PullResponse>> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_PULL_LIMIT)
        .clamp(1, MAX_PULL_LIMIT);
    let cursor = query.cursor.max(0);

    // Fetch one extra row to answer `has_more` without a second count query.
    let rows = sqlx::query(
        "SELECT id, vault_id, rev, envelope, meta, deleted, seq, updated_at FROM items \
         WHERE user_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
    )
    .bind(session.user_id.to_string())
    .bind(cursor)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    let mut next_cursor = cursor;

    for row in rows.into_iter().take(limit as usize) {
        let id = parse_uuid_stored(&row.get::<String, _>("id"), "item id")?;
        let item = row_to_item(id, &row)?;
        next_cursor = item.seq;
        items.push(item);
    }

    let mut conn = state.pool.acquire().await?;
    let head = load_head(&mut conn, session.user_id).await?;
    drop(conn);

    Ok(Json(PullResponse {
        items,
        next_cursor,
        has_more,
        head,
    }))
}
