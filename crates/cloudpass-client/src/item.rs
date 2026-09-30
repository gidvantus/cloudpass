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
        self.username = self.username.trim().to_owned();
        self.url = self.url.trim().to_owned();
        self.totp = self
            .totp
            .map(|totp| totp.trim().to_owned())
            .filter(|totp| !totp.is_empty());
        self
    }

    /// Whether this draft has nothing worth saving.
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
            username: " octocat ".to_owned(),
            // A password may legitimately contain leading or trailing spaces.
            password: "  hunter2  ".to_owned(),
            url: " https://github.com ".to_owned(),
            notes: " note ".to_owned(),
            totp: Some("   ".to_owned()),
        }
        .normalised();

        assert_eq!(draft.title, "GitHub");
        assert_eq!(draft.username, "octocat");
        assert_eq!(draft.password, "  hunter2  ", "passwords are not trimmed");
        assert_eq!(draft.url, "https://github.com");
        assert_eq!(draft.notes, " note ", "notes keep their formatting");
        assert_eq!(draft.totp, None, "a blank totp field means no totp");
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
    }
}
