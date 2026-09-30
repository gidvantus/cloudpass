//! Account authentication with OPAQUE, an augmented password-authenticated key
//! exchange ([RFC 9807]).
//!
//! [RFC 9807]: https://www.rfc-editor.org/rfc/rfc9807
//!
//! # Why OPAQUE rather than "send us the password hash"
//!
//! The common shortcut is for the client to derive a hash of the master password and
//! send that to the server. It has two defects that matter here:
//!
//! * The hash becomes a **bearer credential**. Anyone who reads it from the database
//!   can log in as that user without knowing the password.
//! * It gives an attacker who steals the database **cheap offline material**: every
//!   guess can be verified locally with one hash computation.
//!
//! OPAQUE is an aPAKE. The server keeps a registration record from which no verifier
//! can be extracted, the password itself never crosses the wire, and an attacker who
//! steals the record gains nothing verifiable without also paying the full key
//! stretching cost for every guess. It also authenticates the *server* to the client,
//! which a password hash can never do.
//!
//! # Where the stretching happens, and why `Ksf = Identity`
//!
//! OPAQUE has a built-in key stretching function slot, and this crate sets it to
//! [`opaque_ke::ksf::Identity`]. That is deliberate, not an oversight.
//!
//! What we feed OPAQUE is not the master password but [`AuthInput`]:
//!
//! ```text
//! AuthInput = HKDF( Argon2id(master_password, kdf_salt, params), "opaque-input" )
//! ```
//!
//! So the password is already stretched — by the same Argon2id whose parameters live
//! in [`crate::params`] — before it reaches the protocol. Enabling OPAQUE's own KSF
//! as well would run a second memory-hard pass on every login, in the browser as well
//! as on the desktop, and would add no work factor against an attacker: testing one
//! master-password guess already costs a full Argon2id evaluation.
//!
//! The consequence has to be stated plainly: **the Argon2id parameters are
//! load-bearing for the OPAQUE registration record, not only for the wrapped user
//! key.** Lowering them weakens offline resistance in both places.
//!
//! # What this module does not do
//!
//! It does not establish a transport security context. The OPAQUE session key is
//! exposed so a caller can bind a session to it, but confidentiality of the sync
//! protocol rests on TLS plus the fact that everything the server stores is already
//! encrypted by [`crate::vault`].

use core::fmt;

use opaque_ke::errors::ProtocolError;
use opaque_ke::CipherSuite;

use crate::error::{Error, Result};
use crate::kdf::{
    derive_opaque_input, derive_recovery_auth, hkdf_expand, stretch_master_password, RecoveryKey,
    StretchedKey, INFO_OPAQUE_SESSION,
};
use crate::key_newtype;
use crate::params::{KdfParams, KDF_SALT_LEN};
use crate::secret::SecretKey;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;

/// The OPAQUE ciphersuite used by every CloudPass client and server.
///
/// The two sides must agree on this exactly; changing any of the three associated
/// types is a protocol break that invalidates every registration record, so the
/// choice is centralised here rather than repeated at call sites.
///
/// * `OprfCs = Ristretto255` — the OPRF group.
/// * `KeyExchange = TripleDh<Ristretto255, Sha512>` — the 3DH key exchange.
/// * `Ksf = Identity` — see the module documentation for why.
#[derive(Debug, Clone, Copy)]
pub struct CloudPassOpaque;

impl CipherSuite for CloudPassOpaque {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

key_newtype!(
    #[doc = "Session key agreed by a successful OPAQUE login on both sides."]
    pub SessionKey
);

/// The value OPAQUE treats as the user's password.
///
/// Constructing this is the only supported way to feed credentials into the
/// protocol, and none of the constructors accept a bare master password without
/// deriving through Argon2id first. That is the point: it is not possible to
/// accidentally hand OPAQUE the raw master password and thereby skip the stretching.
pub struct AuthInput(SecretKey);

impl AuthInput {
    /// Derives the OPAQUE input from the master password.
    ///
    /// Prefer [`AuthInput::from_stretched`] during a real login: the client has
    /// already run Argon2id to unwrap its user key, and stretching a second time
    /// would double the cost for no benefit.
    pub fn from_master_password(
        master_password: &[u8],
        kdf_salt: &[u8; KDF_SALT_LEN],
        params: &KdfParams,
    ) -> Result<Self> {
        Self::from_stretched(&stretch_master_password(master_password, kdf_salt, params)?)
    }

    /// Derives the OPAQUE input from an already stretched key.
    pub fn from_stretched(stretched: &StretchedKey) -> Result<Self> {
        Ok(Self(derive_opaque_input(stretched)?))
    }

    /// Derives the OPAQUE input from the Emergency Kit's recovery key.
    ///
    /// The recovery key is already 256 bits from a CSPRNG, so it goes straight to
    /// HKDF with no Argon2id in front of it — see [`crate::kdf::derive_recovery_auth`].
    /// The result is a credential in its own right: it authenticates the account, and
    /// it cannot be turned back into the value that unwraps the user key.
    pub fn from_recovery_key(recovery_key: &RecoveryKey, user_id: &[u8; 16]) -> Result<Self> {
        Ok(Self(derive_recovery_auth(recovery_key, user_id)?))
    }

    /// Wraps an already derived value.
    ///
    /// Exists for protocol tests and for callers that persisted the derived value
    /// themselves. It deliberately takes a [`SecretKey`] rather than a `&[u8]`, so
    /// the caller has to be explicit about handling key material.
    #[must_use]
    pub fn from_secret(secret: SecretKey) -> Self {
        Self(secret)
    }

    /// Borrows the bytes to hand to OPAQUE.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl fmt::Debug for AuthInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthInput(<redacted>)")
    }
}

/// Reduces the raw OPAQUE session key to a 32-byte, zeroizing [`SessionKey`].
///
/// Both sides derive this the same way, so comparing two of them is how a test — or
/// a caller — proves the exchange completed with matching transcripts.
pub(crate) fn derive_session_key(raw: &[u8]) -> Result<SessionKey> {
    Ok(SessionKey::from_secret(hkdf_expand(
        raw,
        b"",
        INFO_OPAQUE_SESSION,
    )?))
}

/// Maps an OPAQUE protocol error onto ours.
///
/// Every failure mode that means "these credentials did not verify" collapses to
/// [`Error::AuthFailed`], including the ones OPAQUE reports as a library error
/// during envelope opening. Everything else is reported as [`Error::Opaque`] tagged
/// with the step, which is useful for diagnosis and reveals nothing: the step is a
/// fixed string, and the caller already knows which request it made.
pub(crate) fn map_protocol_error<T>(stage: &'static str, error: ProtocolError<T>) -> Error {
    match error {
        ProtocolError::InvalidLoginError => Error::AuthFailed,
        _ => Error::Opaque(stage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; KDF_SALT_LEN] = [0x3Cu8; KDF_SALT_LEN];

    fn auth(password: &[u8]) -> AuthInput {
        AuthInput::from_master_password(password, &SALT, &KdfParams::OWASP_MINIMUM).unwrap()
    }

    #[test]
    fn auth_input_is_deterministic() {
        assert_eq!(
            auth(b"same password").expose(),
            auth(b"same password").expose()
        );
    }

    #[test]
    fn auth_input_is_password_and_salt_bound() {
        assert_ne!(
            auth(b"password one").expose(),
            auth(b"password two").expose()
        );

        let mut other_salt = SALT;
        other_salt[0] ^= 0xFF;
        let other = AuthInput::from_master_password(
            b"password one",
            &other_salt,
            &KdfParams::OWASP_MINIMUM,
        )
        .unwrap();
        assert_ne!(auth(b"password one").expose(), other.expose());
    }

    /// The value the server sees must not be the value that unwraps the vault.
    #[test]
    fn auth_input_differs_from_ukek_material() {
        let stretched = stretch_master_password(b"pw", &SALT, &KdfParams::OWASP_MINIMUM).unwrap();
        let input = AuthInput::from_stretched(&stretched).unwrap();
        let ukek = crate::kdf::derive_ukek(&stretched, None, &SALT).unwrap();
        assert_ne!(input.expose(), ukek.expose());
    }

    /// The same rule for recovery: what authenticates must not unwrap.
    #[test]
    fn the_recovery_auth_input_differs_from_the_recovery_ukek() {
        let root = RecoveryKey::from_slice(&[0x7Eu8; 32]).unwrap();
        let user_id = [0x22u8; 16];

        let input = AuthInput::from_recovery_key(&root, &user_id).unwrap();
        let ukek = crate::kdf::derive_recovery_ukek(&root, &user_id).unwrap();

        assert_ne!(input.expose(), ukek.expose());
        assert_eq!(format!("{input:?}"), "AuthInput(<redacted>)");
    }

    #[test]
    fn auth_input_is_redacted_in_debug() {
        let rendered = format!("{:?}", auth(b"pw"));
        assert_eq!(rendered, "AuthInput(<redacted>)");
    }

    #[test]
    fn session_key_derivation_differs_per_transcript() {
        let a = derive_session_key(&[0x01u8; 64]).unwrap();
        let b = derive_session_key(&[0x02u8; 64]).unwrap();
        assert_ne!(a, b);
        assert_eq!(format!("{a:?}"), "SessionKey(<redacted>)");
    }
}
