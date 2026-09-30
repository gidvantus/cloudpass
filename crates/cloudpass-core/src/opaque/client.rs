//! Client half of the OPAQUE exchange.
//!
//! Every step that consumes a server message is a constructor that parses and
//! validates it first, so a malformed or replayed message is rejected at the
//! boundary rather than deep inside the protocol.

use core::fmt;

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};

use super::{derive_session_key, map_protocol_error, AuthInput, CloudPassOpaque, SessionKey};
use crate::error::{Error, Result};

/// Client state for a registration in progress.
///
/// Holds the [`AuthInput`] because OPAQUE re-reads the password at the final step.
/// The value is zeroized when this state is dropped, which happens as soon as
/// registration finishes.
pub struct RegistrationStart {
    auth: AuthInput,
    request: Vec<u8>,
    state: ClientRegistration<CloudPassOpaque>,
}

impl fmt::Debug for RegistrationStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationStart")
            .field("request_len", &self.request.len())
            .finish_non_exhaustive()
    }
}

impl RegistrationStart {
    /// Begins registration, consuming the derived credentials.
    pub fn start(auth: AuthInput) -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let result = ClientRegistration::<CloudPassOpaque>::start(&mut rng, auth.expose())
            .map_err(|e| map_protocol_error("client registration start", e))?;

        Ok(Self {
            auth,
            request: result.message.serialize().to_vec(),
            state: result.state,
        })
    }

    /// The `RegistrationRequest` to send to the server.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// Consumes the server's `RegistrationResponse` and produces the final upload.
    pub fn finish(self, response: &[u8]) -> Result<RegistrationFinish> {
        let response = RegistrationResponse::<CloudPassOpaque>::deserialize(response)
            .map_err(|e| map_protocol_error("client registration finish: response", e))?;

        let mut rng = rand::rngs::OsRng;
        let result = self
            .state
            .finish(
                &mut rng,
                self.auth.expose(),
                response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|e| map_protocol_error("client registration finish", e))?;

        Ok(RegistrationFinish {
            upload: result.message.serialize().to_vec(),
            server_static_public_key: result.server_s_pk.serialize().to_vec(),
        })
    }
}

/// Result of a completed client-side registration.
pub struct RegistrationFinish {
    upload: Vec<u8>,
    server_static_public_key: Vec<u8>,
}

impl fmt::Debug for RegistrationFinish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationFinish")
            .field("upload_len", &self.upload.len())
            .field(
                "server_static_public_key_len",
                &self.server_static_public_key.len(),
            )
            .finish_non_exhaustive()
    }
}

impl RegistrationFinish {
    /// The `RegistrationUpload` to send to the server.
    ///
    /// This is about as sensitive as a password hash and must be transported over a
    /// confidential channel.
    #[must_use]
    pub fn upload(&self) -> &[u8] {
        &self.upload
    }

    /// The server's static public key, to be pinned for every later login.
    ///
    /// OPAQUE binds this key into the envelope during registration. Without pinning
    /// it, a server that copied the registration record could impersonate the real
    /// server at login, so callers should persist this value.
    #[must_use]
    pub fn server_static_public_key(&self) -> &[u8] {
        &self.server_static_public_key
    }
}

/// Client state for a login in progress.
pub struct LoginStart {
    auth: AuthInput,
    request: Vec<u8>,
    state: ClientLogin<CloudPassOpaque>,
}

impl fmt::Debug for LoginStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginStart")
            .field("request_len", &self.request.len())
            .finish_non_exhaustive()
    }
}

impl LoginStart {
    /// Begins a login, consuming the derived credentials.
    pub fn start(auth: AuthInput) -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let result = ClientLogin::<CloudPassOpaque>::start(&mut rng, auth.expose())
            .map_err(|e| map_protocol_error("client login start", e))?;

        Ok(Self {
            auth,
            request: result.message.serialize().to_vec(),
            state: result.state,
        })
    }

    /// The `CredentialRequest` to send to the server.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// Completes the login, verifying the server against a pinned public key.
    ///
    /// This is the method to use. It fails unless the server proves possession of the
    /// static key that was observed at registration, which is what stops a
    /// record-copying impostor.
    pub fn finish(
        self,
        response: &[u8],
        pinned_server_static_public_key: &[u8],
    ) -> Result<LoginFinish> {
        let finish = self.finish_unpinned(response)?;
        if finish.server_static_public_key != pinned_server_static_public_key {
            return Err(Error::Opaque(
                "client login finish: server static public key does not match the pinned value",
            ));
        }
        Ok(finish)
    }

    /// Completes the login without checking the server's identity.
    ///
    /// Use this only when there is no pin yet — a first login on a client that has
    /// none — and persist the returned key immediately. A fresh browser session that
    /// has never seen this account is exactly that case, which is why the web client
    /// carries a "trust on first use" caveat that the desktop client does not.
    pub fn finish_trust_on_first_use(self, response: &[u8]) -> Result<(LoginFinish, Vec<u8>)> {
        let finish = self.finish_unpinned(response)?;
        let observed = finish.server_static_public_key.clone();
        Ok((finish, observed))
    }

    fn finish_unpinned(self, response: &[u8]) -> Result<LoginFinish> {
        let response = CredentialResponse::<CloudPassOpaque>::deserialize(response)
            .map_err(|e| map_protocol_error("client login finish: response", e))?;

        let mut rng = rand::rngs::OsRng;
        let result = self
            .state
            .finish(
                &mut rng,
                self.auth.expose(),
                response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|e| map_protocol_error("client login finish", e))?;

        Ok(LoginFinish {
            finalization: result.message.serialize().to_vec(),
            session_key: derive_session_key(result.session_key.as_slice())?,
            server_static_public_key: result.server_s_pk.serialize().to_vec(),
        })
    }
}

/// Result of a completed client-side login.
pub struct LoginFinish {
    finalization: Vec<u8>,
    session_key: SessionKey,
    server_static_public_key: Vec<u8>,
}

impl fmt::Debug for LoginFinish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginFinish")
            .field("finalization_len", &self.finalization.len())
            .finish_non_exhaustive()
    }
}

impl LoginFinish {
    /// The `CredentialFinalization` that completes the exchange on the server.
    #[must_use]
    pub fn finalization(&self) -> &[u8] {
        &self.finalization
    }

    /// The session key, which equals the server's key if and only if the exchange
    /// completed with matching transcripts.
    #[must_use]
    pub fn session_key(&self) -> &SessionKey {
        &self.session_key
    }

    /// The server's static public key as observed during this login.
    #[must_use]
    pub fn server_static_public_key(&self) -> &[u8] {
        &self.server_static_public_key
    }
}
