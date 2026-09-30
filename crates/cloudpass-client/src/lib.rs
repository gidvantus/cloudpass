//! Client-side vault logic, shared by every CloudPass client.
//!
//! # What lives here, and what does not
//!
//! This crate owns the parts of a client that are the same everywhere: the account
//! material a device must remember, the plaintext shape of an item, sealing and
//! opening items with the vault key, and the storage interface everything is written
//! through. It does **no** input/output of its own — no files, no network, no clock it
//! cannot be told about — so it is testable in memory and identical when compiled for
//! the desktop binary or for the browser.
//!
//! What it does not do: talk to the server. The sync protocol is a separate concern
//! with its own sequencing rules (pull before push, verify the head), and keeping it
//! out of here means the vault can be exercised without a network.
//!
//! # Why the storage is a trait
//!
//! The desktop writes to disk, the browser will write to IndexedDB, and tests write
//! to memory. The trait is the seam. It is deliberately small: an account record and
//! a set of sealed items, nothing else.

#![forbid(unsafe_code)]

pub mod emergency;
pub mod error;
pub mod item;
pub mod recovery_code;
pub mod store;
pub mod sync;
pub mod vault;

pub use emergency::EmergencyKit;
pub use error::{ClientError, Result};
pub use item::{Item, ItemDraft};
pub use store::{MemoryStore, Store, StoredAccount, StoredItem};
pub use vault::{CreatedAccount, KitPlan, MasterPlan, NewAccount, Vault};

/// Current Unix time in seconds.
///
/// Kept here rather than reaching for a clock inside the vault: time is an input, and a
/// value the caller supplies is a value a test can pin. Everything that needs a timestamp
/// takes it through this one function so that a platform with a different clock — or no
/// clock at all — has one place to be handled.
///
/// # Why wasm is not the `std` path
///
/// `SystemTime::now()` is not "slow" or "inaccurate" on `wasm32-unknown-unknown`, it is
/// **unimplemented**, and it panics. A browser has a perfectly good clock; it is simply
/// not the one `std` reaches for, so on that target the browser is asked directly.
#[must_use]
pub fn now_unix() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        // `Date.now()` is milliseconds since the epoch, as a float.
        (js_sys::Date::now() / 1000.0) as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0)
    }
}
