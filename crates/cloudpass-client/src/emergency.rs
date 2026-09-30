//! The Emergency Kit: the one secret a user is expected to write down.
//!
//! # What it is for
//!
//! A vault is encrypted under a key derived from the master password, and nothing else
//! can produce that key. That is the design working as intended — a password manager
//! that can reset your password can also open your vault — but it means a forgotten
//! password is total loss, which is not an acceptable answer for something people keep
//! their whole digital life in.
//!
//! So a second, independent way in exists: a recovery key generated at account creation,
//! stored nowhere, printed once, and wrapped around the same user key. Losing the master
//! password then costs the user the kit rather than everything.
//!
//! # What it deliberately does not contain
//!
//! The master password, the user key, or anything else that would let the kit open the
//! vault by itself. What it holds is the recovery key, the account identifier and the
//! user id — enough to find the vault and unwrap it, and nothing more.

use core::fmt;

use cloudpass_core::kdf::RecoveryKey;
use uuid::Uuid;

use crate::recovery_code;

/// The document a user is shown once and told to keep.
pub struct EmergencyKit {
    user_id: Uuid,
    identifier: String,
    key: RecoveryKey,
    /// Unix time the kit was issued.
    pub created_at: i64,
}

impl EmergencyKit {
    pub(crate) fn new(
        user_id: Uuid,
        identifier: String,
        key: RecoveryKey,
        created_at: i64,
    ) -> Self {
        Self {
            user_id,
            identifier,
            key,
            created_at,
        }
    }

    /// The account this kit belongs to.
    #[must_use]
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// The account identifier, as typed at the login screen.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// The key itself, for wrapping into the document or storing in a password manager.
    #[must_use]
    pub fn recovery_key(&self) -> &RecoveryKey {
        &self.key
    }

    /// The key written the way a person can transcribe it.
    #[must_use]
    pub fn recovery_key_text(&self) -> String {
        recovery_code::encode(&self.key)
    }

    /// The kit as a printable document.
    ///
    /// Plain text on purpose: it has to survive being pasted into any note-taking tool,
    /// printed, or copied by hand, and a format that needs a viewer is one nobody can
    /// open in ten years.
    #[must_use]
    pub fn as_document(&self, server_url: &str) -> String {
        format!(
            "CloudPass Emergency Kit\n\
             =======================\n\
             \n\
             Account:      {identifier}\n\
             User ID:      {user_id}\n\
             Recovery key: {key}\n\
             Server:       {server}\n\
             Issued:       {issued}\n\
             \n\
             Keep this somewhere safe and offline — printed, or in another password\n\
             manager. Anyone who has this key can open the vault, and CloudPass keeps\n\
             no copy of it: if it is lost, the master password is the only way in.\n\
             \n\
             To use it: open CloudPass, choose \"Use a recovery key\", and type the key\n\
             above. You will then set a new master password, and a new kit will be\n\
             issued — this one stops working at that moment.\n",
            identifier = self.identifier,
            user_id = self.user_id,
            key = self.recovery_key_text(),
            server = server_url,
            issued = self.created_at,
        )
    }
}

impl fmt::Debug for EmergencyKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The kit holds a key that opens the vault. Printing it in a log, a panic
        // message or a test failure would be the same mistake as printing the key itself.
        f.debug_struct("EmergencyKit")
            .field("user_id", &self.user_id)
            .field("identifier", &self.identifier)
            .field("recovery_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_code;

    fn kit() -> EmergencyKit {
        let key = RecoveryKey::from_slice(&[9u8; 32]).expect("32 bytes");
        EmergencyKit::new(
            Uuid::from_u128(42),
            "alice@example.com".to_owned(),
            key,
            1_700_000_000,
        )
    }

    #[test]
    fn the_document_identifies_the_account_and_the_server() {
        let text = kit().as_document("https://vault.example.com");
        assert!(text.contains("alice@example.com"));
        assert!(text.contains("https://vault.example.com"));
        assert!(text.contains("Recovery key: CPRK1-"));
    }

    #[test]
    fn the_document_carries_a_key_that_decodes_back() {
        let kit = kit();
        let text = kit.as_document("http://127.0.0.1:8080");

        // The key as printed must be the key that was issued, or the kit is worthless in
        // exactly the situation it exists for.
        let printed = text
            .lines()
            .find_map(|line| line.strip_prefix("Recovery key: "))
            .expect("the document has a key line");
        assert_eq!(
            recovery_code::decode(printed).expect("decodes"),
            *kit.recovery_key()
        );
    }

    #[test]
    fn debug_never_prints_the_key() {
        let rendered = format!("{:?}", kit());
        assert!(rendered.contains("<redacted>"));
        let key = kit().recovery_key_text();
        assert!(!rendered.contains(&key), "{rendered}");
    }
}
