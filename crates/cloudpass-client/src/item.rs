//! The plaintext shape of a stored item.
//!
//! This is what gets sealed into an envelope. It is never written anywhere in the
//! clear and never leaves the device: the server only ever sees the sealed bytes.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A stored credential.
///
/// Every field except `title` is defaulted on deserialisation. That is deliberate: an
/// item written by an older build must still open in a newer one, and a missing field
/// is not a reason to lose a password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub title: String,
    /// The project this entry is filed under, or empty for none.
    ///
    /// A project is only ever a name inside the sealed record: there is no project list on
    /// the device and none on the server, so the set of projects is exactly the set of names
    /// in use. That keeps the grouping as private as the entries it groups — the server
    /// cannot tell that projects exist at all — and leaves no second structure to keep in
    /// step when an entry is edited, deleted, or pulled from another device.
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    /// An `otpauth://` URI. Kept here rather than on the server so that codes are
    /// generated on the device that holds the secret.
    #[serde(default)]
    pub totp: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Item {
    /// The editable fields, for prefilling an edit form.
    #[must_use]
    pub fn draft(&self) -> ItemDraft {
        ItemDraft {
            title: self.title.clone(),
            project: self.project.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            url: self.url.clone(),
            notes: self.notes.clone(),
            totp: self.totp.clone(),
        }
    }
}

/// The editable fields of an item, as a form would supply them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemDraft {
    pub title: String,
    /// See [`Item::project`]. Defaulted, so a caller that predates projects — the desktop
    /// client's form, or an older page — still produces a valid draft.
    #[serde(default)]
    pub project: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp: Option<String>,
}

impl ItemDraft {
    /// Normalises what a user typed into something worth storing.
    ///
    /// Only whitespace is trimmed and optional fields are dropped when empty; nothing
    /// is validated away, because rejecting a password shape is not this layer's job
    /// and silently altering a secret would be worse than storing an odd one.
    #[must_use]
    pub fn normalised(mut self) -> Self {
        self.title = self.title.trim().to_owned();
        // Trimmed like a title: a project name is a filing label, and " Work" filed
        // separately from "Work" is two projects that nobody meant to create.
        self.project = self.project.trim().to_owned();
        self.username = self.username.trim().to_owned();
        self.url = self.url.trim().to_owned();
        self.totp = self
            .totp
            .map(|totp| totp.trim().to_owned())
            .filter(|totp| !totp.is_empty());
        self
    }

    /// Whether this draft has nothing worth saving.
    ///
    /// The project is deliberately not consulted: a project name on its own describes where
    /// an entry would go, not an entry, and a "project" created that way would be a password
    /// with nothing in it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.title.is_empty()
            && self.username.is_empty()
            && self.password.is_empty()
            && self.url.is_empty()
            && self.notes.is_empty()
            && self.totp.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_trims_but_never_alters_a_secret() {
        let draft = ItemDraft {
            title: "  GitHub  ".to_owned(),
            project: "  Work  ".to_owned(),
            username: " octocat ".to_owned(),
            // A password may legitimately contain leading or trailing spaces.
            password: "  hunter2  ".to_owned(),
            url: " https://github.com ".to_owned(),
            notes: " note ".to_owned(),
            totp: Some("   ".to_owned()),
        }
        .normalised();

        assert_eq!(draft.title, "GitHub");
        assert_eq!(draft.project, "Work");
        assert_eq!(draft.username, "octocat");
        assert_eq!(draft.password, "  hunter2  ", "passwords are not trimmed");
        assert_eq!(draft.url, "https://github.com");
        assert_eq!(draft.notes, " note ", "notes keep their formatting");
        assert_eq!(draft.totp, None, "a blank totp field means no totp");
    }

    #[test]
    fn a_project_alone_is_not_an_entry() {
        // A project name says where an entry would be filed; on its own it is still an
        // empty entry, and saving it would create a password with nothing in it.
        let draft = ItemDraft {
            project: "Work".to_owned(),
            ..ItemDraft::default()
        };

        assert!(draft.is_empty());
    }

    #[test]
    fn items_written_by_an_older_build_still_open() {
        // Only the fields that existed then.
        let json = r#"{
            "id": "8f14e45f-ceea-467a-9a3c-1c0e1a2b3c4d",
            "vault_id": "00000000-0000-0000-0000-000000000001",
            "title": "Old",
            "created_at": 1,
            "updated_at": 2
        }"#;
        let item: Item = serde_json::from_str(json).expect("forward compatible");
        assert_eq!(item.title, "Old");
        assert_eq!(item.username, "");
        assert_eq!(item.totp, None);
        assert_eq!(item.project, "", "an entry from before projects has none");
    }

    #[test]
    fn a_draft_from_before_projects_still_parses() {
        // The desktop form and any older page send exactly this, with no `project` key.
        let json = r#"{
            "title": "GitHub",
            "username": "octocat",
            "password": "s3cr3t",
            "url": "https://github.com",
            "notes": "",
            "totp": null
        }"#;
        let draft: ItemDraft = serde_json::from_str(json).expect("forward compatible");
        assert_eq!(draft.project, "");
    }

    #[test]
    fn a_project_survives_a_draft_round_trip() {
        let item = Item {
            id: Uuid::from_u128(1),
            vault_id: Uuid::from_u128(2),
            title: "GitHub".to_owned(),
            project: "Work".to_owned(),
            username: "octocat".to_owned(),
            password: "s3cr3t".to_owned(),
            url: "https://github.com".to_owned(),
            notes: String::new(),
            totp: None,
            created_at: 1,
            updated_at: 2,
        };

        assert_eq!(item.draft().project, "Work");
    }
}
