//! Device identity keys.
//!
//! Every device generates an Ed25519 key pair when it first joins an account. The
//! private half never leaves the device; the public half is registered with the
//! server so that other devices — and the same device later — can verify statements
//! it signed.
//!
//! This is the root of the anti-rollback argument. A head signature made with a
//! device key is something a malicious *server* cannot produce, because it never sees
//! a private key. Losing that property is what lets a server silently serve an old
//! version of a vault, which for a password manager means silently un-deleting a
//! password or restoring one the user already replaced.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::fill_random;

/// Length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// A device's public identity. Public data, safe to log and to publish.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DevicePublicKey([u8; PUBLIC_KEY_LEN]);

impl DevicePublicKey {
    /// Wraps 32 bytes that are already known to be a public key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Copies 32 bytes out of a slice, as received from a request body.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::KeyLength);
        }
        let mut buf = [0u8; PUBLIC_KEY_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public data, so printing it is useful rather than dangerous — a device id
        // alone is not enough to debug a signature mismatch.
        write!(f, "DevicePublicKey({})", hex(&self.0))
    }
}

/// An Ed25519 signature over a head commitment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HeadSignature([u8; SIGNATURE_LEN]);

impl HeadSignature {
    /// Wraps 64 bytes already known to be a signature.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// Copies 64 bytes out of a slice, as received from a request body.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(Error::KeyLength);
        }
        let mut buf = [0u8; SIGNATURE_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// The signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl fmt::Debug for HeadSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeadSignature({})", hex(&self.0))
    }
}

/// A device's private signing key.
///
/// Zeroized on drop, never printed, and never serialized by accident: the only way
/// out is [`DeviceSigningKey::to_seed`], which the caller has to call deliberately
/// in order to persist it in an OS keychain.
pub struct DeviceSigningKey(SigningKey);

impl DeviceSigningKey {
    /// Generates a fresh key pair from the OS CSPRNG.
    ///
    /// The seed is drawn through the crate's single randomness path rather than
    /// through a library helper, so there is one place to audit and one place to wire
    /// up for the browser. The seed buffer is zeroized before the function returns.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_random(&mut seed[..]);
        Self(SigningKey::from_bytes(&seed))
    }

    /// Reconstructs a key from its 32-byte seed.
    ///
    /// Ed25519 signing is deterministic, so a seed is all that is needed to reproduce
    /// the key exactly — there is no second secret half to store.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The seed, for storage in a keychain. Zeroizes when dropped.
    #[must_use]
    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The matching public key, to register with the server.
    #[must_use]
    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey(self.0.verifying_key().to_bytes())
    }

    /// Signs an arbitrary message.
    ///
    /// Callers should pass [`crate::head::HeadCommitment::canonical`] rather than
    /// hand-rolled bytes: a signature over an ambiguous encoding is a signature over
    /// something other than what was intended.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> HeadSignature {
        HeadSignature(self.0.sign(message).to_bytes())
    }
}

impl fmt::Debug for DeviceSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceSigningKey(<redacted>)")
    }
}

/// Verifies a device signature.
///
/// Every failure — a malformed key, a malformed signature, a wrong key, a tampered
/// message — collapses to [`Error::BadSignature`] on purpose. Telling them apart
/// would help an attacker probing what a server would accept.
pub fn verify(
    public_key: &DevicePublicKey,
    message: &[u8],
    signature: &HeadSignature,
) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key.as_bytes()).map_err(|_| Error::BadSignature)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    key.verify(message, &signature)
        .map_err(|_| Error::BadSignature)
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_differ_and_round_trip_through_their_seed() {
        let first = DeviceSigningKey::generate();
        let second = DeviceSigningKey::generate();
        assert_ne!(first.public_key(), second.public_key());

        let seed = first.to_seed();
        let restored = DeviceSigningKey::from_seed(&seed);
        assert_eq!(first.public_key(), restored.public_key());

        // Deterministic signing: the same message gives the same signature.
        assert_eq!(
            first.sign(b"message"),
            restored.sign(b"message"),
            "ed25519 signing must be deterministic"
        );
    }

    #[test]
    fn a_signature_verifies_only_under_the_right_key_and_message() {
        let key = DeviceSigningKey::generate();
        let other = DeviceSigningKey::generate();
        let signature = key.sign(b"the message");

        assert!(verify(&key.public_key(), b"the message", &signature).is_ok());
        assert_eq!(
            verify(&key.public_key(), b"another message", &signature),
            Err(Error::BadSignature)
        );
        assert_eq!(
            verify(&other.public_key(), b"the message", &signature),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn a_bit_flipped_signature_is_rejected() {
        let key = DeviceSigningKey::generate();
        let mut bytes = *key.sign(b"message").as_bytes();
        bytes[0] ^= 0x01;
        assert_eq!(
            verify(
                &key.public_key(),
                b"message",
                &HeadSignature::from_bytes(bytes)
            ),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert_eq!(
            DevicePublicKey::from_slice(&[0u8; 31]),
            Err(Error::KeyLength)
        );
        assert_eq!(HeadSignature::from_slice(&[0u8; 63]), Err(Error::KeyLength));
    }

    #[test]
    fn the_signing_key_never_prints_itself() {
        let key = DeviceSigningKey::generate();
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "DeviceSigningKey(<redacted>)");
    }

    #[test]
    fn public_keys_print_as_hex() {
        let key = DeviceSigningKey::generate();
        let rendered = format!("{:?}", key.public_key());
        assert!(rendered.starts_with("DevicePublicKey("));
        assert_eq!(rendered.len(), "DevicePublicKey(".len() + 64 + 1);
    }
}
