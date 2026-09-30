//! Desktop entry point.
//!
//! The real application lives in `lib.rs` so that the same code can later be compiled
//! for mobile, where the platform loads a library rather than running a binary.

// Keeps a console window from opening alongside the app in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    cloudpass_desktop_lib::run();
}
