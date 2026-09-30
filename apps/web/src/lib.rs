//! The CloudPass web portal.
//!
//! # What runs where
//!
//! Everything cryptographic runs in Rust, compiled to WebAssembly, exactly as it does on
//! the desktop. The page is a rendering layer: it never sees a key, and it does not see
//! every password either. Listing entries returns titles and usernames; a secret crosses
//! into JavaScript only when the user opens the editor for that one entry.
//!
//! # Hidden copying
//!
//! [`copy_password`] is the interesting case. It writes the secret straight to the
//! Clipboard API from inside the wasm module and returns nothing but whether it worked.
//! The password is therefore never in a JavaScript variable this code controls and never
//! in the DOM — it cannot end up in a screenshot, a rendered node, or a crash report that
//! captures page state. It does pass through the browser's own clipboard call, which is
//! unavoidable: the clipboard *is* a browser API.
//!
//! # What the browser does not keep
//!
//! Nothing. The account record, the wrapped user key and the device seed live in memory
//! for as long as the tab is open and are gone when it closes. The vault itself is on the
//! server, encrypted, and is re-fetched on every unlock. Persisting a device signing key
//! to `localStorage` would survive a reload and would also be readable by any script on
//! this origin, which is a worse trade than asking for the master password again.
//!
//! # Why the whole crate is gated
//!
//! `src` compiles only for `wasm32`. On any other target this crate is empty, so a
//! workspace build does not drag a browser stack into the desktop or the server.

#[cfg(target_arch = "wasm32")]
mod portal;
#[cfg(target_arch = "wasm32")]
mod transport;

#[cfg(target_arch = "wasm32")]
pub use portal::*;
