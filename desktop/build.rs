//! Tauri build script.
//!
//! Generates the context that `tauri::generate_context!()` consumes: the parsed
//! configuration, the embedded frontend assets and the Windows resources (icon,
//! manifest).
//!
//! It also bakes in the address a fresh client points at, read from `server-url.toml`. That
//! belongs at compile time rather than at run time: a published installer has to carry the
//! server it was built for, and an environment variable on somebody else's machine is not a
//! configuration channel this application has.

use std::path::PathBuf;

/// Which entry of `server-url.toml` a build uses when nothing says otherwise.
///
/// Local, because the surprises are not symmetric. A stray `cargo build` that quietly produced
/// a client pointing at a production server would be a surprise nobody asked for, while a
/// client pointing at loopback is what a developer expects and can see immediately. The
/// scripts that produce something publishable ask for `production` explicitly.
const DEFAULT_PROFILE: &str = "local";

fn main() {
    bake_default_server_url();
    tauri_build::build()
}

/// Reads `server-url.toml` and hands the chosen address to the crate as a compile-time
/// variable.
///
/// Both `rerun-if` lines matter. Without the file one, editing an address would rebuild
/// nothing. Without the environment one, building local and then production into the same
/// `target/` directory would keep the first address — cargo caches a build script's output by
/// the inputs it declares, and an input it was not told about is an input it does not notice.
/// The build scripts check the finished artifact for the same reason; see
/// `scripts/server-url.ps1`.
fn bake_default_server_url() {
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let config = manifest.join("server-url.toml");

    println!("cargo:rerun-if-changed={}", config.display());
    println!("cargo:rerun-if-env-changed=CLOUDPASS_PROFILE");

    let profile = std::env::var("CLOUDPASS_PROFILE").unwrap_or_else(|_| DEFAULT_PROFILE.to_owned());

    let text = std::fs::read_to_string(&config)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", config.display()));
    let parsed: toml::Value = text
        .parse()
        .unwrap_or_else(|error| panic!("{} is not valid TOML: {error}", config.display()));

    // A typo in the profile fails here rather than falling back to something: a build that
    // asked for `prod` and silently got loopback is the mistake this file exists to prevent.
    let url = parsed
        .get(&profile)
        .and_then(|entry| entry.get("url"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "{} has no [{profile}] url; known profiles: {}",
                config.display(),
                parsed
                    .as_table()
                    .map(|table| table.keys().cloned().collect::<Vec<_>>().join(", "))
                    .unwrap_or_default()
            )
        });

    println!("cargo:rustc-env=CLOUDPASS_DEFAULT_SERVER_URL={url}");
}
