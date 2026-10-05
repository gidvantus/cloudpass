//! Whether this build of the application is behind the one the server offers.
//!
//! # Why the decision lives apart
//!
//! This module knows neither the window nor the network. It reads the server's
//! `/api/v1/meta` answer and compares two versions, and both of those are pure functions
//! of their arguments — which is the only reason the rules below can be tested
//! exhaustively instead of being checked by hand, once, on the machine of whoever wrote
//! them.
//!
//! # What "there is an update" means
//!
//! Exactly one thing: the server published a version that parses as semantic versioning
//! and is strictly greater than the version this binary was built as. Everything else —
//! no server, a server that has never heard of the field, an installer whose name carries
//! no version, a name that carries something that is not a version — is the same answer as
//! "you are up to date", and the interface draws nothing. A password manager that raised a
//! complaint because it could not reach a server it does not need would be a worse
//! application than one that keeps quiet.

use semver::Version;
use serde::Deserialize;

/// The part of `/api/v1/meta` this client reads.
///
/// Deliberately not the whole answer: the protocol version and the KDF defaults are
/// matters for the vault, which reads them itself. Unknown fields are ignored, so a server
/// that grows a field this client has never heard of is not a server this client
/// misunderstands.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MetaResponse {
    /// The desktop build the server offers, or `null` when it has none to offer.
    #[serde(default)]
    pub desktop: Option<DesktopBuild>,
}

/// A desktop build, as the server describes it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DesktopBuild {
    /// File name inside the server's download directory.
    pub file: String,
    /// Fetch path, relative to the server's origin.
    pub url: String,
    pub size: u64,
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
    /// The version the artifact was built as.
    ///
    /// Absent on a server older than the field, and `null` on one whose installer name
    /// carries no version. Both mean the same thing here: there is nothing to compare.
    #[serde(default)]
    pub version: Option<String>,
}

/// The build the server offers, or `None` when it offers none or the answer is unreadable.
///
/// An unreadable answer is not an error the user needs to hear about. The portal is a
/// static page served by the same application; a body this client cannot parse means a
/// proxy, a captive portal or a much older server, and none of those is a reason to
/// interrupt someone looking at their passwords.
#[must_use]
pub fn offered_build(body: &[u8]) -> Option<DesktopBuild> {
    serde_json::from_slice::<MetaResponse>(body).ok()?.desktop
}

/// The version the server offers, when the answer names a readable one.
#[must_use]
pub fn offered_version(body: &[u8]) -> Option<String> {
    offered_build(body)?.version
}

/// The version to announce, or `None` when the interface should say nothing.
///
/// `offered` is the version as it arrived from the server — a string rather than a
/// [`Version`], because "absent" and "unreadable" are answers this function has to handle
/// and not errors that happen before it is called.
///
/// `dismissed` is the version the user last hid, if there is one. Hiding is about one
/// version and not about the feature: a version *above* the hidden one is news again, which
/// is why this is a comparison rather than a flag. Hiding something newer than what the
/// server now offers — a server that was rolled back — leaves the notice hidden, which is
/// what "I have seen this one" should mean.
#[must_use]
pub fn should_notify(
    current: &Version,
    offered: Option<&str>,
    dismissed: Option<&str>,
) -> Option<Version> {
    let offered = Version::parse(offered?).ok()?;

    if offered <= *current {
        return None;
    }

    if let Some(dismissed) = dismissed.and_then(|dismissed| Version::parse(dismissed).ok()) {
        if offered <= dismissed {
            return None;
        }
    }

    Some(offered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> Version {
        Version::parse(text).expect("a version this test wrote")
    }

    #[test]
    fn a_servers_newer_version_is_announced() {
        assert_eq!(
            should_notify(&version("0.1.0"), Some("0.1.1"), None),
            Some(version("0.1.1"))
        );
        assert_eq!(
            should_notify(&version("0.1.0"), Some("1.0.0"), None),
            Some(version("1.0.0"))
        );
    }

    /// An announcement for the version already installed is a lie the user acts on: they
    /// download an installer that turns out to be the program they are running.
    #[test]
    fn the_version_already_installed_is_not_announced() {
        assert_eq!(should_notify(&version("0.1.0"), Some("0.1.0"), None), None);
    }

    #[test]
    fn an_older_version_is_not_announced() {
        assert_eq!(should_notify(&version("0.1.0"), Some("0.0.9"), None), None);
    }

    /// The three ways a server can have nothing to compare, all of which are silence.
    #[test]
    fn a_version_that_is_absent_or_unreadable_is_not_announced() {
        let current = version("0.1.0");
        assert_eq!(should_notify(&current, None, None), None);
        assert_eq!(should_notify(&current, Some(""), None), None);
        assert_eq!(should_notify(&current, Some("newest"), None), None);
        assert_eq!(should_notify(&current, Some("1.2"), None), None);
        assert_eq!(should_notify(&current, Some("v0.2.0"), None), None);
    }

    #[test]
    fn a_hidden_version_stays_hidden_until_something_is_newer_again() {
        let current = version("0.1.0");
        assert_eq!(should_notify(&current, Some("0.2.0"), Some("0.2.0")), None);
        // A server rolled back to something at or below what the user hid is not news.
        assert_eq!(should_notify(&current, Some("0.2.0"), Some("0.3.0")), None);
        // And a dismissal is not a decision to stop being told about the future.
        assert_eq!(
            should_notify(&current, Some("0.3.0"), Some("0.2.0")),
            Some(version("0.3.0"))
        );
    }

    #[test]
    fn a_build_is_read_out_of_the_servers_answer() {
        let body = br#"{
            "protocol_version": 1,
            "registration_open": true,
            "server_time": 1767225600,
            "kdf_default": {"m_kib": 65536, "t": 3, "p": 1, "salt": ""},
            "desktop": {
                "file": "CloudPass_1.2.3_x64-setup.exe",
                "url": "/download/CloudPass_1.2.3_x64-setup.exe",
                "size": 1234,
                "sha256": "ab",
                "version": "1.2.3"
            }
        }"#;

        let build = offered_build(body).expect("a build is described");
        assert_eq!(build.file, "CloudPass_1.2.3_x64-setup.exe");
        assert_eq!(build.url, "/download/CloudPass_1.2.3_x64-setup.exe");
        assert_eq!(build.size, 1234);
        assert_eq!(offered_version(body).as_deref(), Some("1.2.3"));
    }

    /// A server that has never heard of the field, and one whose installer name carries no
    /// version, both answer with something a client must read as "nothing to compare".
    #[test]
    fn a_server_that_names_no_version_offers_nothing_to_compare() {
        let old_server = br#"{
            "desktop": {
                "file": "CloudPass_x64-setup.exe",
                "url": "/download/CloudPass_x64-setup.exe",
                "size": 1,
                "sha256": "ab"
            }
        }"#;
        assert_eq!(offered_version(old_server), None);

        let unreadable = br#"{"desktop": {"file": "x", "url": "/x", "size": 1, "sha256": "ab", "version": null}}"#;
        assert_eq!(offered_version(unreadable), None);
    }

    #[test]
    fn a_server_with_no_build_offers_nothing() {
        assert_eq!(offered_build(br#"{"desktop": null}"#), None);
        assert_eq!(offered_build(br#"{}"#), None);
    }

    #[test]
    fn an_answer_that_is_not_json_offers_nothing() {
        assert_eq!(offered_build(b"<html>a captive portal</html>"), None);
        assert_eq!(offered_build(b""), None);
    }
}
