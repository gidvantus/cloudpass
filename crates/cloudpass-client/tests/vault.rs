//! Vault behaviour, exercised against an in-memory store.
//!
//! These run the real cryptography — Argon2id, the key hierarchy, sealed envelopes —
//! through the same API the desktop and web clients will use. The store is the only
//! thing swapped out.

use cloudpass_client::{ClientError, ItemDraft, MemoryStore, Store, StoredItem, Vault};
use cloudpass_core::params::KdfParams;

const IDENTIFIER: &str = "alice@example.com";
const PASSWORD: &[u8] = b"correct horse battery staple";

fn params() -> KdfParams {
    // The floor rather than the recommendation: these tests run Argon2id many times,
    // and the parameter choice is not what they are testing.
    KdfParams::OWASP_MINIMUM
}

fn draft(title: &str, password: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        username: "octocat".to_owned(),
        password: password.to_owned(),
        url: "https://github.com".to_owned(),
        notes: String::new(),
        totp: None,
    }
}

#[test]
fn an_account_survives_a_lock_and_unlock_cycle() {
    let mut store = MemoryStore::new();
    let (mut vault, created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    assert_eq!(created.account.identifier, IDENTIFIER);
    assert_eq!(vault.user_id(), created.account.user_id);

    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");

    // Locking is dropping: the key material is gone, and a fresh unlock rebuilds it.
    drop(vault);

    let vault = Vault::unlock(&store, PASSWORD).expect("unlock");
    let item = vault.item(item_id).expect("the item came back");
    assert_eq!(item.title, "GitHub");
    assert_eq!(item.password, "s3cr3t");
    assert_eq!(item.vault_id, created.account.vault_id);
}

#[test]
fn a_wrong_password_is_refused() {
    let mut store = MemoryStore::new();
    let _ = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");

    assert!(matches!(
        Vault::unlock(&store, b"not the password"),
        Err(ClientError::WrongPassword)
    ));
}

#[test]
fn nothing_in_the_store_resembles_the_plaintext() {
    let mut store = MemoryStore::new();
    let (mut vault, _) = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let item_id = vault
        .add_item(&mut store, draft("GitHub", "hunter2-very-secret"))
        .expect("add");

    let stored = store.load_items().expect("read");
    let record: &StoredItem = stored
        .iter()
        .find(|item| item.id == item_id)
        .expect("the item is at rest");

    // The server, and anyone reading the file, sees only this.
    let haystack = String::from_utf8_lossy(&record.envelope);
    assert!(!haystack.contains("hunter2"));
    assert!(!haystack.contains("GitHub"));
    assert!(!haystack.contains("octocat"));
}

#[test]
fn an_edit_moves_the_item_to_a_new_revision() {
    let mut store = MemoryStore::new();
    let (mut vault, _) = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let item_id = vault
        .add_item(&mut store, draft("GitHub", "first"))
        .expect("add");

    let before = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("at rest");

    vault
        .update_item(&mut store, item_id, draft("GitHub", "second"))
        .expect("update");

    let after = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("at rest");

    assert_eq!(before.rev, 1);
    assert_eq!(after.rev, 2);
    // A new revision means a new nonce and new associated data, so the bytes differ.
    assert_ne!(before.envelope, after.envelope);

    // And the newer content is what unlocks.
    drop(vault);
    let vault = Vault::unlock(&store, PASSWORD).expect("unlock");
    assert_eq!(vault.item(item_id).expect("present").password, "second");
}

#[test]
fn a_deletion_leaves_a_tombstone_rather_than_erasing_anything() {
    let mut store = MemoryStore::new();
    let (mut vault, _) = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let _ = vault
        .add_item(&mut store, draft("GitLab", "other"))
        .expect("add");

    vault.delete_item(&mut store, item_id).expect("delete");

    // Gone from the list the user sees.
    assert!(vault.item(item_id).is_none());
    assert_eq!(vault.items().len(), 1);
    assert_eq!(vault.items()[0].title, "GitLab");

    // But still at rest, as a tombstone the server can be told about.
    let stored = store.load_items().expect("read");
    let tombstone = stored
        .iter()
        .find(|item| item.id == item_id)
        .expect("the tombstone is at rest");
    assert!(tombstone.deleted);
    assert_eq!(tombstone.rev, 2);

    // A client restarting must not resurrect it.
    drop(vault);
    let vault = Vault::unlock(&store, PASSWORD).expect("unlock");
    assert!(vault.item(item_id).is_none());
    assert_eq!(vault.items().len(), 1);
}

#[test]
fn items_are_listed_in_a_stable_case_insensitive_order() {
    let mut store = MemoryStore::new();
    let (mut vault, _) = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");

    for title in ["zeta", "Alpha", "beta", "Gamma"] {
        vault.add_item(&mut store, draft(title, "x")).expect("add");
    }

    let titles: Vec<String> = vault.items().into_iter().map(|item| item.title).collect();
    assert_eq!(titles, vec!["Alpha", "beta", "Gamma", "zeta"]);
}

#[test]
fn an_empty_draft_is_refused_rather_than_stored() {
    let mut store = MemoryStore::new();
    let (mut vault, _) = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");

    let blank = ItemDraft {
        title: "   ".to_owned(),
        ..ItemDraft::default()
    };
    assert!(matches!(
        vault.add_item(&mut store, blank),
        Err(ClientError::EmptyItem)
    ));
    assert!(store.is_empty(), "nothing may reach the store");
}

#[test]
fn a_second_account_cannot_be_created_over_an_existing_one() {
    let mut store = MemoryStore::new();
    let _ = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");

    assert!(matches!(
        Vault::create(&mut store, "bob@example.com", PASSWORD, params()),
        Err(ClientError::AccountExists)
    ));
}

#[test]
fn unlocking_without_an_account_says_so() {
    let store = MemoryStore::new();
    assert!(matches!(
        Vault::unlock(&store, PASSWORD),
        Err(ClientError::NoAccount)
    ));
}

#[test]
fn a_tampered_envelope_is_detected() {
    let mut store = MemoryStore::new();
    let (mut vault, _) = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");

    // Someone with write access to the file flips a byte of the ciphertext.
    let mut record = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == item_id)
        .expect("at rest");
    let last = record.envelope.len() - 1;
    record.envelope[last] ^= 0x01;
    store.upsert_item(&record).expect("write");

    // Authentication fails, and the failure does not pretend to be a wrong password.
    assert!(matches!(
        Vault::unlock(&store, PASSWORD),
        Err(ClientError::Crypto(cloudpass_core::Error::AuthFailed))
    ));
}

#[test]
fn an_envelope_cannot_be_moved_to_another_item() {
    let mut store = MemoryStore::new();
    let (mut vault, _) = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let first = vault.add_item(&mut store, draft("A", "one")).expect("add");
    let second = vault.add_item(&mut store, draft("B", "two")).expect("add");

    // Take A's envelope and file it under B's id and revision.
    let record_a = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|item| item.id == first)
        .expect("at rest");

    store
        .upsert_item(&StoredItem {
            id: second,
            ..record_a
        })
        .expect("write");

    // The associated data binds the envelope to its item, so this must not open — and
    // crucially not as a *wrong password*, which would suggest retrying is useful.
    assert!(matches!(
        Vault::unlock(&store, PASSWORD),
        Err(ClientError::Crypto(
            cloudpass_core::Error::AadMismatch | cloudpass_core::Error::AuthFailed
        ))
    ));
}

#[test]
fn the_server_key_is_pinned_after_registration() {
    let mut store = MemoryStore::new();
    let (mut vault, _) = Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    assert!(!vault.account().has_pinned_server_key());

    let server_key = vec![0xABu8; 32];
    vault.pin_server_key(&mut store, &server_key).expect("pin");

    // Persisted, not just held in memory.
    drop(vault);
    let vault = Vault::unlock(&store, PASSWORD).expect("unlock");
    assert_eq!(vault.account().server_static_public_key, server_key);
}

#[test]
fn a_weakened_parameter_set_is_refused_before_anything_is_written() {
    let mut store = MemoryStore::new();
    let weak = KdfParams {
        m_kib: 1024,
        t: 1,
        p: 1,
        output_len: 32,
    };

    assert!(Vault::create(&mut store, IDENTIFIER, PASSWORD, weak).is_err());
    assert!(
        store.load_account().expect("read").is_none(),
        "a rejected account must leave no trace"
    );
}

#[test]
fn created_accounts_are_independent() {
    let mut first_store = MemoryStore::new();
    let mut second_store = MemoryStore::new();

    let (mut first, first_created) =
        Vault::create(&mut first_store, IDENTIFIER, PASSWORD, params()).expect("create");
    let (mut second, second_created) =
        Vault::create(&mut second_store, "bob@example.com", PASSWORD, params()).expect("create");

    let first_account = first_created.account;
    let second_account = second_created.account;

    assert_ne!(first_account.user_id, second_account.user_id);
    assert_ne!(first_account.vault_id, second_account.vault_id);
    assert_ne!(first_account.device_id, second_account.device_id);
    assert_ne!(
        first_account.device_public_key, second_account.device_public_key,
        "each device must have its own signing key"
    );
    assert_ne!(
        first_created.kit.recovery_key_text(),
        second_created.kit.recovery_key_text(),
        "each account must have its own recovery key"
    );

    let _ = first
        .add_item(&mut first_store, draft("First", "a"))
        .expect("add");
    let _ = second
        .add_item(&mut second_store, draft("Second", "b"))
        .expect("add");

    assert_eq!(first.items().len(), 1);
    assert_eq!(second.items().len(), 1);
    assert_eq!(first.items()[0].title, "First");
    assert_eq!(second.items()[0].title, "Second");
}

// ---------------------------------------------------------------------------
// What a local edit must remember
// ---------------------------------------------------------------------------

/// An edited item must still know which revision the server holds.
///
/// This is the value a push states as its base. Dropping it on edit — which is what
/// `synced_rev: None` on every write did — makes a pushed-then-edited item claim to be
/// based on nothing, and the server refuses it as a conflict. Correctly: for an item that
/// already exists, a base of zero is exactly what a revision it never issued looks like.
///
/// The consequence was that the *second* edit of any item could never be sent, which is
/// the sort of bug that looks like "sync is flaky" until someone reads the base revision.
#[test]
fn an_edited_item_still_knows_the_revision_it_was_based_on() {
    let mut store = MemoryStore::new();
    let (mut vault, _created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let id = vault
        .add_item(&mut store, draft("GitHub", "first"))
        .expect("add");

    // A brand-new item has no acknowledged revision, so its first push is a create.
    let first = cloudpass_client::sync::pending_changes(&store).expect("pending");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].base_rev, 0, "nothing to be based on yet");

    // What the engine does when the server applies the change.
    store.mark_synced(id, 1).expect("mark synced");

    vault
        .update_item(&mut store, id, draft("GitHub", "second"))
        .expect("update");

    let stored = store
        .load_items()
        .expect("read")
        .into_iter()
        .find(|stored| stored.id == id)
        .expect("present");
    assert_eq!(stored.rev, 2);
    assert_eq!(
        stored.synced_rev,
        Some(1),
        "the edit carries the acknowledged revision across"
    );
    assert!(stored.is_pending(), "and is still waiting to be sent");

    let second = cloudpass_client::sync::pending_changes(&store).expect("pending");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].rev, 2);
    assert_eq!(
        second[0].base_rev, 1,
        "the push must say which revision it is replacing, not zero"
    );
}

/// The same rule for a tombstone: deleting has to say what it is deleting.
#[test]
fn a_deleted_item_still_knows_the_revision_it_was_based_on() {
    let mut store = MemoryStore::new();
    let (mut vault, _created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let id = vault
        .add_item(&mut store, draft("GitHub", "first"))
        .expect("add");
    store.mark_synced(id, 1).expect("mark synced");

    vault.delete_item(&mut store, id).expect("delete");

    let pending = cloudpass_client::sync::pending_changes(&store).expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].base_rev, 1);
    assert!(pending[0].deleted);
}

// ---------------------------------------------------------------------------
// The Emergency Kit
// ---------------------------------------------------------------------------

fn recovery_key_from(kit: &cloudpass_client::EmergencyKit) -> cloudpass_core::kdf::RecoveryKey {
    // The key type deliberately has no `Clone`: copying key material around is the
    // habit the type exists to discourage. A test can go through the paper form, which
    // is also the route a real user takes.
    cloudpass_client::recovery_code::decode(&kit.recovery_key_text())
        .expect("the printed key must decode")
}

#[test]
fn a_recovery_key_opens_the_same_vault_the_password_does() {
    let mut store = MemoryStore::new();
    let (mut vault, created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let kit = created.kit;

    // The password is forgotten; the paper in the drawer is not.
    drop(vault);
    assert!(matches!(
        Vault::unlock(&store, b"something else entirely"),
        Err(ClientError::WrongPassword)
    ));

    let recovered = Vault::unlock_with_recovery_key(&store, &recovery_key_from(&kit))
        .expect("the kit must open this vault");
    assert_eq!(recovered.user_id(), created.account.user_id);
    assert_eq!(
        recovered
            .item(item_id)
            .expect("the item came back")
            .password,
        "s3cr3t"
    );
}

#[test]
fn the_wrong_recovery_key_is_refused() {
    let mut store = MemoryStore::new();
    let (vault, _created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    drop(vault);

    let other = cloudpass_core::kdf::RecoveryKey::from_slice(&[0x11u8; 32]).expect("32 bytes");
    assert!(matches!(
        Vault::unlock_with_recovery_key(&store, &other),
        Err(ClientError::WrongRecoveryKey)
    ));
}

#[test]
fn recovering_issues_a_new_kit_and_retires_the_old_one() {
    let mut store = MemoryStore::new();
    let (mut vault, created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let item_id = vault
        .add_item(&mut store, draft("GitHub", "s3cr3t"))
        .expect("add");
    let old_kit = created.kit;
    let old_key = recovery_key_from(&old_kit);
    drop(vault);

    let new_password = b"a brand new master password";
    let (vault, new_kit) =
        Vault::recover(&mut store, &old_key, new_password, params()).expect("recover");
    assert_ne!(old_kit.recovery_key_text(), new_kit.recovery_key_text());
    assert_eq!(vault.item(item_id).expect("kept").password, "s3cr3t");
    drop(vault);

    // The old paper is scrap, and the new paper works.
    assert!(matches!(
        Vault::unlock_with_recovery_key(&store, &old_key),
        Err(ClientError::WrongRecoveryKey)
    ));
    assert!(Vault::unlock_with_recovery_key(&store, &recovery_key_from(&new_kit)).is_ok());
}

#[test]
fn a_new_password_takes_effect_and_leaves_the_kit_working() {
    let mut store = MemoryStore::new();
    let (mut vault, created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    let kit = created.kit;

    let new_password = b"a different master password";
    vault
        .change_master_password(&mut store, new_password, params())
        .expect("change password");
    drop(vault);

    assert!(matches!(
        Vault::unlock(&store, PASSWORD),
        Err(ClientError::WrongPassword)
    ));
    assert!(Vault::unlock(&store, new_password).is_ok());

    // The recovery envelope is deliberately not a function of the password, so a
    // password change must not force the user to write down a new kit.
    assert!(
        Vault::unlock_with_recovery_key(&store, &recovery_key_from(&kit)).is_ok(),
        "changing the password must not invalidate the kit"
    );
}

#[test]
fn an_account_without_a_recovery_envelope_says_so() {
    let mut store = MemoryStore::new();
    let (vault, _created) =
        Vault::create(&mut store, IDENTIFIER, PASSWORD, params()).expect("create");
    drop(vault);

    // The record as an older build wrote it: no recovery envelope at all.
    let mut account = store.load_account().expect("read").expect("present");
    account.recovery_envelope = None;
    store.save_account(&account).expect("save");

    let key = cloudpass_core::kdf::RecoveryKey::from_slice(&[0x22u8; 32]).expect("32 bytes");
    assert!(matches!(
        Vault::unlock_with_recovery_key(&store, &key),
        Err(ClientError::NoRecoveryKit)
    ));
    assert!(!Vault::unlock(&store, PASSWORD)
        .expect("the password still works")
        .has_recovery_envelope());
}
