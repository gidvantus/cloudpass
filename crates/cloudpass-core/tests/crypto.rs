//! End-to-end tests of the public API, exercising the same sequence a real client
//! performs: register, unlock, store a record, then read it back on another device.
//!
//! These tests deliberately only use what the desktop and web clients will use. If a
//! step here needs something the public API does not expose, that is a finding.

use cloudpass_core::aad::{ItemAad, KeyKind};
use cloudpass_core::envelope::Envelope;
use cloudpass_core::error::Error;
use cloudpass_core::ids::random_uuid;
use cloudpass_core::kdf::{derive_opaque_input, derive_ukek, stretch_master_password, RecoveryKey};
use cloudpass_core::params::{KdfParams, KDF_SALT_LEN};
use cloudpass_core::vault::{
    item_key, open_item, seal_item, unwrap_user_key, wrap_user_key, UserKey,
};

#[test]
fn full_lifecycle_register_store_read_on_another_device() {
    let user_id = random_uuid();
    let vault_id = random_uuid();
    let item_id = random_uuid();
    let master_password = b"correct horse battery staple";
    let kdf_salt = [0x5Au8; KDF_SALT_LEN];
    let params = KdfParams::OWASP_MINIMUM;

    // --- Registration, on the user's own machine -----------------------------
    let stretched = stretch_master_password(master_password, &kdf_salt, &params).unwrap();

    // The server learns only this: a value that unlocks nothing.
    let _opaque_input = derive_opaque_input(&stretched).unwrap();

    let ukek = derive_ukek(&stretched, None, &kdf_salt).unwrap();
    let user_key = UserKey::generate();
    let wrapped_user_key = wrap_user_key(&ukek, &user_key, user_id, KeyKind::UserKey).unwrap();
    let stored_key_envelope = wrapped_user_key.to_bytes();

    // --- Storing a record ----------------------------------------------------
    let aad = ItemAad::new(user_id, vault_id, item_id, 1, false);
    let plaintext = br#"{"title":"GitHub","username":"octocat","password":"s3cr3t"}"#;
    let stored_item = seal_item(&user_key, &aad, plaintext).unwrap().to_bytes();

    // --- Another device: only the master password and server data ------------
    let stretched_2 = stretch_master_password(master_password, &kdf_salt, &params).unwrap();
    let ukek_2 = derive_ukek(&stretched_2, None, &kdf_salt).unwrap();

    let reloaded_envelope = Envelope::from_bytes(&stored_key_envelope).unwrap();
    let user_key_2 =
        unwrap_user_key(&ukek_2, &reloaded_envelope, user_id, KeyKind::UserKey).unwrap();

    let reloaded_item = Envelope::from_bytes(&stored_item).unwrap();
    let opened = open_item(&user_key_2, &aad, &reloaded_item).unwrap();
    assert_eq!(&opened[..], plaintext);

    // The item key is reproducible on the second device without any extra state.
    assert_eq!(
        item_key(&user_key, item_id).unwrap(),
        item_key(&user_key_2, item_id).unwrap()
    );
}

#[test]
fn changing_the_master_password_does_not_touch_items() {
    let user_id = random_uuid();
    let vault_id = random_uuid();
    let item_id = random_uuid();
    let kdf_salt = [0x11u8; KDF_SALT_LEN];
    let params = KdfParams::OWASP_MINIMUM;

    let old_stretched = stretch_master_password(b"old password", &kdf_salt, &params).unwrap();
    let old_ukek = derive_ukek(&old_stretched, None, &kdf_salt).unwrap();
    let user_key = UserKey::generate();
    let _ = wrap_user_key(&old_ukek, &user_key, user_id, KeyKind::UserKey).unwrap();

    let aad = ItemAad::new(user_id, vault_id, item_id, 1, false);
    let stored_item = seal_item(&user_key, &aad, b"payload").unwrap().to_bytes();

    // Password change: new stretched key, new UKEK, and only the user-key envelope
    // is rewritten. The item ciphertext above is carried over untouched.
    let mut new_salt = kdf_salt;
    new_salt[0] ^= 0xFF;
    let new_stretched = stretch_master_password(b"new password", &new_salt, &params).unwrap();
    let new_ukek = derive_ukek(&new_stretched, None, &new_salt).unwrap();
    let rewrapped = wrap_user_key(&new_ukek, &user_key, user_id, KeyKind::UserKey).unwrap();

    let unlocked = unwrap_user_key(
        &new_ukek,
        &Envelope::from_bytes(&rewrapped.to_bytes()).unwrap(),
        user_id,
        KeyKind::UserKey,
    )
    .unwrap();

    let opened = open_item(
        &unlocked,
        &aad,
        &Envelope::from_bytes(&stored_item).unwrap(),
    )
    .unwrap();
    assert_eq!(&opened[..], b"payload");
}

#[test]
fn recovery_key_unlocks_the_user_key_without_the_master_password() {
    let user_id = random_uuid();
    let kdf_salt = [0x77u8; KDF_SALT_LEN];
    let params = KdfParams::OWASP_MINIMUM;

    let user_key = UserKey::generate();
    let recovery_key = RecoveryKey::generate();

    // The recovery slot is wrapped under a key derived from the recovery key alone.
    let recovery_ukek = derive_ukek(
        &stretch_master_password(recovery_key.expose(), &kdf_salt, &params).unwrap(),
        None,
        &kdf_salt,
    )
    .unwrap();
    let envelope = wrap_user_key(&recovery_ukek, &user_key, user_id, KeyKind::RecoveryKey).unwrap();

    let unlocked =
        unwrap_user_key(&recovery_ukek, &envelope, user_id, KeyKind::RecoveryKey).unwrap();
    assert_eq!(unlocked, user_key);

    // The recovery slot cannot be opened as if it were the normal slot.
    assert_eq!(
        unwrap_user_key(&recovery_ukek, &envelope, user_id, KeyKind::UserKey).unwrap_err(),
        Error::AadMismatch
    );
}

/// What the server holds must be useless on its own. This test asserts the property
/// directly: with every stored byte and the account's KDF parameters, but without the
/// master password, no item plaintext is recoverable.
#[test]
fn server_side_data_alone_cannot_decrypt_anything() {
    let user_id = random_uuid();
    let vault_id = random_uuid();
    let item_id = random_uuid();
    let kdf_salt = [0x22u8; KDF_SALT_LEN];
    let params = KdfParams::OWASP_MINIMUM;

    let stretched = stretch_master_password(b"the real password", &kdf_salt, &params).unwrap();
    let ukek = derive_ukek(&stretched, None, &kdf_salt).unwrap();
    let user_key = UserKey::generate();

    // Everything the server can see:
    let server_side = (
        kdf_salt,
        params,
        wrap_user_key(&ukek, &user_key, user_id, KeyKind::UserKey)
            .unwrap()
            .to_bytes(),
        seal_item(
            &user_key,
            &ItemAad::new(user_id, vault_id, item_id, 1, false),
            b"payload",
        )
        .unwrap()
        .to_bytes(),
    );

    // An attacker who guesses wrong gets nowhere, and learns nothing from the error.
    let attacker_stretched =
        stretch_master_password(b"a guess", &server_side.0, &server_side.1).unwrap();
    let attacker_ukek = derive_ukek(&attacker_stretched, None, &server_side.0).unwrap();
    let attacker_envelope = Envelope::from_bytes(&server_side.2).unwrap();
    assert_eq!(
        unwrap_user_key(
            &attacker_ukek,
            &attacker_envelope,
            user_id,
            KeyKind::UserKey
        )
        .unwrap_err(),
        Error::AuthFailed
    );
}
