//! The JSON this client exchanges with the server.
//!
//! # A note on duplication
//!
//! These types mirror the server's request and response bodies, which are defined in
//! `cloudpass-server`. Duplicating them is a real cost: a field renamed on one side
//! breaks the other, and nothing but a test will notice.
//!
//! That test exists — `cloudpass-server/tests/interop.rs` drives these exact types
//! against the real router — so the two definitions cannot drift without a failure. If
//! the surface grows much further (registration and login add roughly as much again),
//! the right move is to extract a shared `cloudpass-protocol` crate and delete both
//! copies rather than add a third.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

/// A byte string carried as base64 in JSON.
///
/// Every opaque blob crosses the wire as one of these, and this client never looks
/// inside any of them: it moves bytes between the server and the store.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct B64(pub Vec<u8>);

impl B64 {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for B64 {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map(Self)
            .map_err(|_| D::Error::custom("invalid base64"))
    }
}

/// The server's error body: a stable code, never prose.
#[derive(Debug, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/// The KDF parameters for an identifier.
///
/// For an identifier the server does not know this is a decoy salt derived from a
/// server secret, and the parameters are the defaults. That is deliberate on the
/// server's side — an error instead would be an account-enumeration oracle — which means
/// a client must not treat a successful `prelogin` as proof that the account exists.
#[derive(Debug, Clone, Deserialize)]
pub struct PreloginResponse {
    pub kdf_salt: B64,
    pub kdf_m_kib: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
}

/// The account's wrapped user key, as the server holds it.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyEnvelopeResponse {
    pub user_key_envelope: B64,
    pub recovery_envelope: Option<B64>,
}

/// A vault as the server lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct VaultDto {
    pub vault_id: Uuid,
    /// The sealed vault name. Opaque to the server, and to this client until it is
    /// unlocked — which is why nothing here tries to read it.
    pub name_envelope: B64,
    pub created_at: i64,
}

/// The answer to a vault listing.
#[derive(Debug, Clone, Deserialize)]
pub struct ListVaultsResponse {
    pub vaults: Vec<VaultDto>,
}

/// The signed head of an account's vault.
#[derive(Debug, Clone, Deserialize)]
pub struct HeadDto {
    pub head_rev: i64,
    pub state_root: B64,
    pub signature: B64,
    pub signer_device_id: Uuid,
    pub updated_at: i64,
}

/// One item as the server holds it.
#[derive(Debug, Clone, Deserialize)]
pub struct ItemDto {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub rev: i64,
    pub envelope: B64,
    #[serde(default)]
    pub meta: Value,
    pub deleted: bool,
    pub seq: i64,
    pub updated_at: i64,
}

/// The answer to a pull.
#[derive(Debug, Clone, Deserialize)]
pub struct PullResponse {
    pub items: Vec<ItemDto>,
    pub next_cursor: i64,
    pub has_more: bool,
    /// `None` only before the account's first push.
    pub head: Option<HeadDto>,
}

/// A device's signed commitment to the state a push produces.
#[derive(Debug, Clone, Serialize)]
pub struct SignedHead {
    /// Must be exactly the current head revision plus one.
    pub head_rev: i64,
    /// The commitment the client computed over its post-push view.
    pub state_root: B64,
    /// Ed25519 signature over the canonical head commitment.
    pub signature: B64,
}

/// One change to push.
#[derive(Debug, Clone, Serialize)]
pub struct ItemChange {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub base_rev: i64,
    pub rev: i64,
    pub envelope: B64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
    pub deleted: bool,
}

/// The body of a push.
#[derive(Debug, Clone, Serialize)]
pub struct PushRequest {
    pub head: SignedHead,
    pub changes: Vec<ItemChange>,
}

/// A change the server applied.
#[derive(Debug, Clone, Deserialize)]
pub struct AppliedChange {
    pub id: Uuid,
    pub rev: i64,
    pub seq: i64,
}

/// A change the server refused, and what it holds instead.
#[derive(Debug, Clone, Deserialize)]
pub struct Conflict {
    pub id: Uuid,
    pub reason: String,
    pub current: Option<ItemDto>,
}

/// The answer to a push.
#[derive(Debug, Clone, Deserialize)]
pub struct PushResponse {
    pub applied: Vec<AppliedChange>,
    pub conflicts: Vec<Conflict>,
    /// Why the signed head was refused, if it was. When set, **nothing was applied**.
    pub head_rejected: Option<String>,
    pub head: Option<HeadDto>,
}

/// One device, as the server reports it.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceDto {
    pub device_id: Uuid,
    pub name: String,
    pub public_key: Option<B64>,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// The answer to a device listing.
#[derive(Debug, Clone, Deserialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<DeviceDto>,
}
