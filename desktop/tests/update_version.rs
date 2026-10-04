//! The application's version has one source, and this is what keeps it that way.
//!
//! `tauri.conf.json` is the version the installed program reports and the one the update
//! notice compares against; `Cargo.toml` is the version the crate was built as, which
//! `env!("CARGO_PKG_VERSION")` hands to the running binary. When those two drift, the
//! notice compares a version against itself and is silently wrong in both directions —
//! a build that never learns about an update, or one that announces every update forever.
//!
//! Nothing else in the project would notice. The version reaches the interface through
//! `app.package_info()`, which is populated from the bundled configuration, so the
//! disagreement shows up only as a behaviour nobody has any way to attribute. A test is
//! the only thing that can catch it, and it catches it at the moment the files disagree
//! rather than at the moment a release is mislabelled.

use std::fs;

#[test]
fn the_configured_version_is_the_version_the_crate_was_built_as() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tauri.conf.json");
    let text = fs::read_to_string(path).expect("read tauri.conf.json");
    let config: serde_json::Value = serde_json::from_str(&text).expect("tauri.conf.json is JSON");

    let configured = config["version"]
        .as_str()
        .expect("tauri.conf.json declares a version string");

    assert_eq!(
        configured,
        env!("CARGO_PKG_VERSION"),
        "tauri.conf.json says {configured} while the crate was built as {}; \
         the update notice would compare this build against itself",
        env!("CARGO_PKG_VERSION")
    );
}
