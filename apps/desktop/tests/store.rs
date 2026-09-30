//! The on-disk store, exercised against a real directory.
//!
//! These are the tests that catch the mistakes a trait-level fake cannot: a version
//! field that is written but never checked, a seed file that comes back a byte short,
//! an upsert that appends instead of replacing, or a temporary file left behind when a
//! write completes.

use std::fs;
use std::path::PathBuf;

use cloudpass_client::{ClientError, Store, StoredAccount, StoredItem};
use cloudpass_core::ids::random_uuid;
use cloudpass_core::params::{KdfParams, KDF_SALT_LEN};
use cloudpass_desktop_lib::state::FileStore;
use uuid::Uuid;

/// A fresh directory per test, removed when the guard drops.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("cloudpass-{label}-{}", random_uuid()));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn account() -> StoredAccount {
    StoredAccount {
        user_id: Uuid::from_u128(0xAA),
        identifier: "alice@example.com".to_owned(),
        kdf_salt: [7u8; KDF_SALT_LEN],
        kdf_params: KdfParams::RECOMMENDED,
        user_key_envelope: vec![1, 2, 3, 4],
        recovery_envelope: Some(vec![5, 6, 7, 8]),
        vault_id: Uuid::from_u128(0xBB),
        device_id: Uuid::from_u128(0xCC),
        server_static_public_key: vec![9u8; 32],
        head_rev: 4,
        sync_cursor: 11,
    }
}

fn item(id: u128, rev: i64, deleted: bool) -> StoredItem {
    StoredItem {
        id: Uuid::from_u128(id),
        vault_id: Uuid::from_u128(0xBB),
        rev,
        envelope: vec![0xAB; 94],
        deleted,
        synced_rev: None,
    }
}

#[test]
fn an_empty_directory_reports_no_account_and_no_items() {
    let dir = TempDir::new("empty");
    let store = FileStore::new(dir.path.clone()).expect("open");

    assert!(store.load_account().expect("read").is_none());
    assert!(store.load_device_seed().expect("read").is_none());
    assert!(store.load_items().expect("read").is_empty());
}

#[test]
fn the_account_survives_a_write_and_read() {
    let dir = TempDir::new("account");
    let mut store = FileStore::new(dir.path.clone()).expect("open");

    let original = account();
    store.save_account(&original).expect("write");

    // A different instance, as if the application had been restarted.
    let reopened = FileStore::new(dir.path.clone()).expect("reopen");
    assert_eq!(
        reopened.load_account().expect("read").expect("present"),
        original
    );
}

#[test]
fn the_device_seed_round_trips_exactly() {
    let dir = TempDir::new("seed");
    let mut store = FileStore::new(dir.path.clone()).expect("open");

    // A seed with high and low bytes, so a sign error or a truncation cannot hide.
    let seed: [u8; 32] = std::array::from_fn(|index| (index * 7) as u8);
    store.save_device_seed(&seed).expect("write");

    assert_eq!(
        store.load_device_seed().expect("read").expect("present"),
        seed
    );
}

#[test]
fn a_truncated_seed_file_is_reported_rather_than_used() {
    let dir = TempDir::new("shortseed");
    let store = FileStore::new(dir.path.clone()).expect("open");

    fs::write(dir.path.join("device.seed"), [1u8; 31]).expect("write a short seed");

    // The alternative — padding to 32 bytes — would silently produce a *different*
    // device key, which is far worse than refusing to start.
    assert!(matches!(
        store.load_device_seed(),
        Err(ClientError::Corrupt(_))
    ));
}

#[test]
fn items_are_upserted_rather_than_appended() {
    let dir = TempDir::new("items");
    let mut store = FileStore::new(dir.path.clone()).expect("open");

    store.upsert_item(&item(1, 1, false)).expect("insert");
    store.upsert_item(&item(2, 1, false)).expect("insert");
    store.upsert_item(&item(1, 2, false)).expect("update");

    let items = store.load_items().expect("read");
    assert_eq!(items.len(), 2, "the update must replace, not add");

    let first = items
        .iter()
        .find(|i| i.id == Uuid::from_u128(1))
        .expect("present");
    assert_eq!(first.rev, 2);
}

#[test]
fn tombstones_stay_on_disk() {
    let dir = TempDir::new("tombstone");
    let mut store = FileStore::new(dir.path.clone()).expect("open");

    store.upsert_item(&item(1, 1, false)).expect("insert");
    store.upsert_item(&item(1, 2, true)).expect("delete");

    let items = store.load_items().expect("read");
    assert_eq!(items.len(), 1);
    assert!(items[0].deleted, "a deletion is a record, not an absence");
    assert_eq!(items[0].rev, 2);
}

#[test]
fn removing_an_item_takes_only_that_one() {
    let dir = TempDir::new("remove");
    let mut store = FileStore::new(dir.path.clone()).expect("open");

    store.upsert_item(&item(1, 1, false)).expect("insert");
    store.upsert_item(&item(2, 1, false)).expect("insert");
    store.remove_item(Uuid::from_u128(1)).expect("remove");

    let items = store.load_items().expect("read");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, Uuid::from_u128(2));
}

#[test]
fn an_unknown_store_version_is_refused() {
    let dir = TempDir::new("version");
    let mut store = FileStore::new(dir.path.clone()).expect("open");
    store.save_account(&account()).expect("write");

    // Rewrite the version, as a future build would. Parsed rather than string-replaced,
    // so this keeps working when the current version number moves — and says so loudly
    // if the field disappears.
    let path = dir.path.join("account.json");
    let mut written: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read")).expect("json");
    assert!(
        written.get("version").is_some(),
        "the version field must be present to begin with"
    );
    written["version"] = serde_json::json!(99);
    fs::write(&path, serde_json::to_vec(&written).expect("encode")).expect("write");

    // Reading a shape this build does not understand must fail loudly. Guessing would
    // risk misreading a field that moved.
    assert!(matches!(store.load_account(), Err(ClientError::Corrupt(_))));
}

/// A store written by the previous format version must still open.
///
/// Version 1 had no `synced_rev`, and the honest reading of a missing field is "never
/// pushed": that build could not push at all, so nothing in such a file had ever been
/// sent. Treating it as synced would silently strand the user's existing passwords.
#[test]
fn a_version_one_file_loads_with_every_item_pending() {
    let dir = TempDir::new("v1");
    let mut store = FileStore::new(dir.path.clone()).expect("open");

    store.save_account(&account()).expect("write");
    store.upsert_item(&item(1, 1, false)).expect("write");

    // Strip the version back to 1 and remove the field version 1 did not have.
    let items_path = dir.path.join("items.json");
    let mut written: serde_json::Value =
        serde_json::from_slice(&fs::read(&items_path).expect("read")).expect("json");
    written["version"] = serde_json::json!(1);
    let entries = written["items"].as_array_mut().expect("items");
    for entry in entries.iter_mut() {
        entry.as_object_mut().expect("object").remove("synced_rev");
    }
    fs::write(&items_path, serde_json::to_vec(&written).expect("encode")).expect("write");

    let loaded = store.load_items().expect("read");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].synced_rev, None);
    assert!(
        loaded[0].is_pending(),
        "an item from before sync existed must be sent, not assumed to be already there"
    );
}

/// A version 2 account file has no recovery envelope, and must load as one that does
/// not — an account created before the Emergency Kit exists cannot be opened with a
/// recovery key, and inventing one would only fail later, at the worst moment.
#[test]
fn a_version_two_account_loads_without_a_recovery_envelope() {
    let dir = TempDir::new("v2");
    let mut store = FileStore::new(dir.path.clone()).expect("open");
    store.save_account(&account()).expect("write");

    let path = dir.path.join("account.json");
    let mut written: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read")).expect("json");
    written["version"] = serde_json::json!(2);
    written["account"]
        .as_object_mut()
        .expect("account object")
        .remove("recovery_envelope");
    fs::write(&path, serde_json::to_vec(&written).expect("encode")).expect("write");

    let loaded = store.load_account().expect("read").expect("present");
    assert_eq!(loaded.recovery_envelope, None);
    assert_eq!(loaded.identifier, account().identifier);
}

#[test]
fn a_completed_write_leaves_no_temporary_file_behind() {
    let dir = TempDir::new("tmpfile");
    let mut store = FileStore::new(dir.path.clone()).expect("open");

    store.save_account(&account()).expect("write");
    store.upsert_item(&item(1, 1, false)).expect("write");
    store.save_device_seed(&[3u8; 32]).expect("write");

    let leftovers: Vec<String> = fs::read_dir(&dir.path)
        .expect("list")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();

    assert!(
        leftovers.is_empty(),
        "temporary files left behind: {leftovers:?}"
    );
    assert!(dir.path.join("account.json").exists());
    assert!(dir.path.join("items.json").exists());
    assert!(dir.path.join("device.seed").exists());
}
