//! CloudPass desktop application.
//!
//! # Trusted client
//!
//! This is the client the threat model treats as the *trusted* one. Unlike the web
//! client, whose code is delivered by the server on every load, the desktop binary is
//! installed once and can be verified. That is why the web client is the convenience
//! path and this is the one the design leans on.
//!
//! # Where the cryptography happens
//!
//! Here, in Rust, through `cloudpass-core` and `cloudpass-client` — not in the web view.
//! The frontend is a rendering layer that sends commands and receives plain JSON; it
//! never sees a key and never performs a cryptographic operation. A compromised
//! frontend can lie about what it displays, but it cannot exfiltrate key material it was
//! never given, and listing items does not hand it the passwords either.
//!
//! # Configuration surface
//!
//! Every Tauri application is a local web server with a capability system in front of
//! it. The capability in `capabilities/default.json` grants only the core defaults — no
//! filesystem, shell or HTTP plugins. Anything this app needs, it gets through an
//! explicit command, which is the whole point of the split above.

#![forbid(unsafe_code)]

mod commands;
pub mod state;
pub mod transport;

use std::sync::Arc;

use tauri::Manager;

use crate::state::{AppState, FileStore};

/// Starts the application.
///
/// `mobile_entry_point` matters only when this crate is compiled for iOS or Android;
/// on desktop the attribute expands to nothing and `main.rs` calls this directly.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Tauri resolves this per platform from the bundle identifier in
            // `tauri.conf.json`: %APPDATA%\dev.cloudpass.desktop on Windows.
            let directory = app.path().app_data_dir()?;
            let store = FileStore::new(directory)?;
            let state = AppState::new(store, AppState::default_server_url());
            app.manage(Arc::new(tokio::sync::Mutex::new(state)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::create_vault,
            commands::enrol_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::recover_vault,
            commands::revive_emergency_kit,
            commands::change_master_password,
            commands::set_server_url,
            commands::list_items,
            commands::reveal_item,
            commands::copy_password,
            commands::add_item,
            commands::update_item,
            commands::delete_item,
            commands::sync_now,
            commands::pending_count,
        ])
        .run(tauri::generate_context!())
        .expect("the CloudPass window failed to start");
}
