//! Server half of the OPAQUE exchange.
//!
//! The server never receives a password, a password hash, or anything else that
//! verifies a guess on its own. What it persists is a [`PasswordFile`], whose
//! contents are opaque to it, and a [`ServerSetupState`], which is secret and must
//! be protected accordingly — it is the key to the OPRF.

use core::fmt;

use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};

use super::{derive_session_key, map_protocol_error, CloudPassOpaque, SessionKey};
use crate::error::Result;

/// The server's long-lived OPAQUE state.
///
/// Secret: it contains the OPRF seed and the server's static key pair. Losing it
/// makes every account unable to log in; leaking it together with a password file
/// lets an attacker mount an offline dictionary attack against that one account —
/// which is precisely why the Argon2id parameters in front of OPAQUE are
/// load-bearing.
pub struct ServerSetupState(ServerSetup<CloudPassOpaque>);

impl fmt::Debug for ServerSetupState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerSetupState(<secret>)")
    }
}

impl ServerSetupState {
    /// Generates a fresh setup from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self(ServerSetup::<CloudPassOpaque>::new(&mut rng))
    }

    /// Serializes the setup for storage.
    ///
    /// The bytes are secret and must not be logged or sent anywhere.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    /// Restores a setup produced by [`ServerSetupState::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            ServerSetup::<CloudPassOpaque>::deserialize(bytes)
                .map_err(|e| map_protocol_error("server setup deserialize", e))?,
        ))
    }
}

/// A stored registration for one account, keyed by credential identifier.
pub struct PasswordFile(ServerRegistration<CloudPassOpaque>);

impl fmt::Debug for PasswordFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordFile(<opaque>)")
    }
}

impl PasswordFile {
    /// Serializes the file for storage.
    ///
    /// Not secret in the way a private key is, but confidential: it is roughly as
    /// sensitive as a password hash and must be protected accordingly.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    /// Restores a file produced by [`PasswordFile::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            ServerRegistration::<CloudPassOpaque>::deserialize(bytes)
                .map_err(|e| map_protocol_error("password file deserialize", e))?,
        ))
    }
}

/// Server side of registration, step one.
///
/// Returns the `RegistrationResponse` to send back. Stateless: nothing needs to be
/// kept between this call and [`registration_finish`].
///
/// `credential_identifier` must be the same value at registration and at every
/// login. The OPRF key is derived from it, so changing it silently breaks the
/// account. Use a stable server-side identifier such as the user id.
pub fn registration_start(
    setup: &ServerSetupState,
    request: &[u8],
    credential_identifier: &[u8],
) -> Result<Vec<u8>> {
    let request = RegistrationRequest::<CloudPassOpaque>::deserialize(request)
        .map_err(|e| map_protocol_error("server registration start: request", e))?;

    let result =
        ServerRegistration::<CloudPassOpaque>::start(&setup.0, request, credential_identifier)
            .map_err(|e| map_protocol_error("server registration start", e))?;

    Ok(result.message.serialize().to_vec())
}

/// Server side of registration, step two: turns the client's upload into a stored
/// [`PasswordFile`].
pub fn registration_finish(upload: &[u8]) -> Result<PasswordFile> {
    let upload = opaque_ke::RegistrationUpload::<CloudPassOpaque>::deserialize(upload)
        .map_err(|e| map_protocol_error("server registration finish: upload", e))?;

    Ok(PasswordFile(ServerRegistration::finish(upload)))
}

/// Server state for a login in progress.
pub struct LoginStart {
    response: Vec<u8>,
    state: ServerLogin<CloudPassOpaque>,
}

impl fmt::Debug for LoginStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginStart")
            .field("response_len", &self.response.len())
            .finish_non_exhaustive()
    }
}

impl LoginStart {
    /// Answers a `CredentialRequest`.
    ///
    /// Passing `None` for `password_file` is not an error and is not a shortcut: it
    /// produces a dummy response that is indistinguishable from a real one, which is
    /// how the server avoids revealing whether an account exists.
    pub fn start(
        setup: &ServerSetupState,
        password_file: Option<&PasswordFile>,
        request: &[u8],
        credential_identifier: &[u8],
    ) -> Result<Self> {
        let request = CredentialRequest::<CloudPassOpaque>::deserialize(request)
            .map_err(|e| map_protocol_error("server login start: request", e))?;

        let mut rng = rand::rngs::OsRng;
        let result = ServerLogin::start(
            &mut rng,
            &setup.0,
            password_file.map(|file| file.0.clone()),
            request,
            credential_identifier,
            ServerLoginParameters::default(),
        )
        .map_err(|e| map_protocol_error("server login start", e))?;

        Ok(Self {
            response: result.message.serialize().to_vec(),
            state: result.state,
        })
    }

    /// The `CredentialResponse` to send back to the client.
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// Extracts the state that must survive between answering and verifying.
    ///
    /// A real server cannot keep this in memory: the two halves of a login arrive in
    /// separate HTTP requests, possibly handled by different processes. The state
    /// contains the server's ephemeral Diffie-Hellman secret, which is exactly why it
    /// stays server-side and is never handed to the client, not even encrypted.
    #[must_use]
    pub fn into_persisted(self) -> PersistedLogin {
        PersistedLogin(self.state.serialize().to_vec())
    }

    /// Verifies the client's finalization and yields the session key.
    ///
    /// A wrong password is reported as [`crate::Error::AuthFailed`], the same error
    /// as any other authentication failure, so nothing here can be used to tell
    /// "wrong password" apart from "no such account" or "tampered message".
    pub fn finish(self, finalization: &[u8]) -> Result<SessionKey> {
        self.into_persisted().finish(finalization)
    }
}

/// Serialized [`ServerLogin`] state, to be stored between the two login requests.
///
/// Round-tripping through bytes is the normal path here, not a special case: the same
/// code runs in tests and in production, so a change to the serialized form cannot
/// pass tests while breaking real logins.
pub struct PersistedLogin(Vec<u8>);

impl fmt::Debug for PersistedLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedLogin")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl PersistedLogin {
    /// Borrows the bytes to store.
    #[must_use]
    pub fn serialize(&self) -> &[u8] {
        &self.0
    }

    /// Restores state written by [`PersistedLogin::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }

    /// Verifies the client's `CredentialFinalization`.
    pub fn finish(self, finalization: &[u8]) -> Result<SessionKey> {
        let state = ServerLogin::<CloudPassOpaque>::deserialize(&self.0)
            .map_err(|e| map_protocol_error("server login finish: state", e))?;

        let finalization = CredentialFinalization::<CloudPassOpaque>::deserialize(finalization)
            .map_err(|e| map_protocol_error("server login finish: finalization", e))?;

        let result = state
            .finish(finalization, ServerLoginParameters::default())
            .map_err(|e| map_protocol_error("server login finish", e))?;

        derive_session_key(result.session_key.as_slice())
    }
}
