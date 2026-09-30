//! CloudPass cryptographic core.
//!
//! This crate is the **only** place in CloudPass where key material is handled.
//! Both the native desktop client and the WASM web client compile this same code,
//! so there is exactly one implementation of the cryptographic protocol to audit.
//!
//! # Invariants enforced by this crate
//!
//! * Every derived key is domain-separated by a distinct HKDF `info` label
//!   ([`kdf::INFO_UKEK`], [`kdf::INFO_OPAQUE_INPUT`], [`kdf::INFO_ITEM`]).
//! * Every ciphertext is bound to its identity and revision through the AEAD
//!   associated data ([`aad`]). Moving a ciphertext to another item, vault or user
//!   makes decryption fail.
//! * Every nonce is drawn from `OsRng` at seal time. A `(key, nonce)` pair is never
//!   reused.
//! * Key material lives in [`SecretKey`], which zeroizes on drop and whose `Debug`
//!   implementation never prints bytes.
//! * The server never receives anything this crate cannot afford to lose: the
//!   payloads produced here are opaque byte strings.
//!
//! # What this crate deliberately does not do
//!
//! It has no network, filesystem, clock or logging dependencies. It never formats a
//! key, a password or a plaintext into an error. Everything secret is a byte slice
//! owned by the caller.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod aad;
pub mod device;
pub mod envelope;
pub mod error;
pub mod head;
pub mod ids;
pub mod kdf;
pub mod opaque;
pub mod params;
pub mod secret;
pub mod vault;

/// Version of the stored-data format. Bumped only for incompatible changes.
pub const PROTOCOL_VERSION: u8 = 1;

/// Constant-time byte-slice comparison, re-exported so callers never reach for `==`.
pub use subtle::ConstantTimeEq;

pub use error::{Error, Result};
pub use params::KdfParams;
pub use secret::SecretKey;
