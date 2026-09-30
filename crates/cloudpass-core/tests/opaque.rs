//! End-to-end tests of the OPAQUE registration and login exchange.
//!
//! These drive the same sequence the desktop and web clients will use, with the
//! "server" side called directly. They are built only when the `server` feature is
//! on, which it is by default; see `Cargo.toml`.

use cloudpass_core::error::Error;
use cloudpass_core::opaque::client::{LoginStart, RegistrationStart};
use cloudpass_core::opaque::server::{self, PasswordFile, ServerSetupState};
use cloudpass_core::opaque::AuthInput;
use cloudpass_core::params::{KdfParams, KDF_SALT_LEN};

const SALT: [u8; KDF_SALT_LEN] = [0x3Cu8; KDF_SALT_LEN];
const USER: &[u8] = b"user-7f3a9c";
const PASSWORD: &[u8] = b"correct horse battery staple";

fn auth(password: &[u8]) -> AuthInput {
    AuthInput::from_master_password(password, &SALT, &KdfParams::OWASP_MINIMUM)
        .expect("auth input derivation")
}

/// Runs the full registration and returns what the server stores plus what the
/// client must pin.
fn register(setup: &ServerSetupState, password: &[u8]) -> (PasswordFile, Vec<u8>) {
    let start = RegistrationStart::start(auth(password)).expect("client registration start");
    let response = server::registration_start(setup, start.request(), USER)
        .expect("server registration start");
    let finish = start.finish(&response).expect("client registration finish");
    let file = server::registration_finish(finish.upload()).expect("server registration finish");
    (file, finish.server_static_public_key().to_vec())
}

#[test]
fn registration_then_login_yields_matching_session_keys() {
    let setup = ServerSetupState::generate();
    let (password_file, pinned) = register(&setup, PASSWORD);

    let login = LoginStart::start(auth(PASSWORD)).expect("client login start");
    let server_login =
        server::LoginStart::start(&setup, Some(&password_file), login.request(), USER)
            .expect("server login start");

    let client_finish = login
        .finish(server_login.response(), &pinned)
        .expect("client login finish");
    let server_session = server_login
        .finish(client_finish.finalization())
        .expect("server login finish");

    // The whole point of the exchange: both sides end up with the same key, which is
    // only possible if the transcripts matched.
    assert_eq!(client_finish.session_key(), &server_session);
}

#[test]
fn wrong_password_is_rejected() {
    let setup = ServerSetupState::generate();
    let (password_file, pinned) = register(&setup, PASSWORD);

    let login = LoginStart::start(auth(b"not the password")).expect("client login start");
    let server_login =
        server::LoginStart::start(&setup, Some(&password_file), login.request(), USER)
            .expect("server login start");

    // The client detects the failure itself: the envelope cannot be opened with a key
    // derived from the wrong password.
    assert_eq!(
        login.finish(server_login.response(), &pinned).unwrap_err(),
        Error::AuthFailed
    );
}

#[test]
fn unknown_account_response_is_indistinguishable_by_length() {
    let setup = ServerSetupState::generate();
    let (password_file, _) = register(&setup, PASSWORD);

    let known = LoginStart::start(auth(PASSWORD)).expect("client login start");
    let known_server =
        server::LoginStart::start(&setup, Some(&password_file), known.request(), USER)
            .expect("server login start");

    let unknown = LoginStart::start(auth(PASSWORD)).expect("client login start");
    let unknown_server =
        server::LoginStart::start(&setup, None, unknown.request(), b"no-such-user")
            .expect("server login start");

    // A server that answered differently for unknown accounts would be an account
    // enumeration oracle. The dummy response must be the same shape.
    assert_eq!(
        known_server.response().len(),
        unknown_server.response().len()
    );
}

#[test]
fn credential_identifier_is_bound_to_the_account() {
    let setup = ServerSetupState::generate();
    let (password_file, pinned) = register(&setup, PASSWORD);

    let login = LoginStart::start(auth(PASSWORD)).expect("client login start");
    let server_login = server::LoginStart::start(
        &setup,
        Some(&password_file),
        login.request(),
        b"some-other-identifier",
    )
    .expect("server login start");

    // The OPRF key is derived from the identifier, so answering with the wrong one
    // produces an evaluation the client cannot open.
    assert_eq!(
        login.finish(server_login.response(), &pinned).unwrap_err(),
        Error::AuthFailed
    );
}

#[test]
fn a_different_server_setup_cannot_serve_an_existing_account() {
    let setup = ServerSetupState::generate();
    let (password_file, pinned) = register(&setup, PASSWORD);
    let impostor = ServerSetupState::generate();

    let login = LoginStart::start(auth(PASSWORD)).expect("client login start");
    let server_login =
        server::LoginStart::start(&impostor, Some(&password_file), login.request(), USER)
            .expect("server login start");

    assert_eq!(
        login.finish(server_login.response(), &pinned).unwrap_err(),
        Error::AuthFailed
    );
}

#[test]
fn a_mismatched_pinned_server_key_is_rejected() {
    let setup = ServerSetupState::generate();
    let (password_file, pinned) = register(&setup, PASSWORD);

    let login = LoginStart::start(auth(PASSWORD)).expect("client login start");
    let server_login =
        server::LoginStart::start(&setup, Some(&password_file), login.request(), USER)
            .expect("server login start");

    let mut wrong_pin = pinned;
    wrong_pin[0] ^= 0x01;

    assert_eq!(
        login
            .finish(server_login.response(), &wrong_pin)
            .unwrap_err(),
        Error::Opaque(
            "client login finish: server static public key does not match the pinned value"
        )
    );
}

#[test]
fn setup_and_password_file_survive_a_storage_roundtrip() {
    let setup = ServerSetupState::generate();
    let (password_file, pinned) = register(&setup, PASSWORD);

    // Everything the server persists goes through serialization, so this is the test
    // that proves restarting the server does not lock everyone out.
    let restored_setup =
        ServerSetupState::deserialize(&setup.serialize()).expect("setup deserialize");
    let restored_file =
        PasswordFile::deserialize(&password_file.serialize()).expect("password file deserialize");

    let login = LoginStart::start(auth(PASSWORD)).expect("client login start");
    let server_login =
        server::LoginStart::start(&restored_setup, Some(&restored_file), login.request(), USER)
            .expect("server login start");

    let client_finish = login
        .finish(server_login.response(), &pinned)
        .expect("client login finish");
    let server_session = server_login
        .finish(client_finish.finalization())
        .expect("server login finish");

    assert_eq!(client_finish.session_key(), &server_session);
}

#[test]
fn trust_on_first_use_reports_the_same_key_that_a_pin_would_have_held() {
    let setup = ServerSetupState::generate();
    let (password_file, pinned) = register(&setup, PASSWORD);

    let login = LoginStart::start(auth(PASSWORD)).expect("client login start");
    let server_login =
        server::LoginStart::start(&setup, Some(&password_file), login.request(), USER)
            .expect("server login start");

    let (_finish, observed) = login
        .finish_trust_on_first_use(server_login.response())
        .expect("client login finish");

    assert_eq!(observed, pinned);
}

/// A registration is randomised, so two registrations of the same password must not
/// produce the same stored record. If they did, the record would leak that two
/// accounts share a password.
#[test]
fn two_registrations_of_the_same_password_produce_different_records() {
    let setup = ServerSetupState::generate();
    let (first, _) = register(&setup, PASSWORD);
    let (second, _) = register(&setup, PASSWORD);
    assert_ne!(first.serialize(), second.serialize());
}
