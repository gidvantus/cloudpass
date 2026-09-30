//! Tauri build script.
//!
//! Generates the context that `tauri::generate_context!()` consumes: the parsed
//! configuration, the embedded frontend assets and the Windows resources (icon,
//! manifest).

fn main() {
    tauri_build::build()
}
