//! Authenticated envelopes: the only container this protocol writes to disk or sends
//! to the server.
//!
//! Byte layout:
//!
//! ```text
//!  0        1        2                       14                      46
//!  +--------+--------+-----------------------+-----------------------+--------------+
//!  | ver(1) | alg(1) | nonce(12)             | aad_digest(32)        | ciphertext   |
//!  +--------+--------+-----------------------+-----------------------+--------------+
//! ```
//!
//! `aad_digest` is the SHA-256 of the canonical associated data. It is redundant with
//! the AEAD's own associated-data binding, and that is deliberate: it lets a client
//! notice that the *server-side metadata column* was edited without needing a key,
//! producing a precise error instead of a generic authentication failure.
//!
//! Only AES-256-GCM is implemented in protocol v1. The XChaCha20-Poly1305 algorithm
//! id is reserved so that adding it later is a data change, not a protocol break.

use core::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use crate::aad::sha256;
use crate::error::{Error, Result};
use crate::secret::{fill_random, SecretKey};

/// Envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// AES-256-GCM.
pub const ALG_AES256_GCM: u8 = 0x01;

/// Reserved: XChaCha20-Poly1305. Not implemented in protocol v1.
pub const ALG_XCHACHA20_POLY1305: u8 = 0x02;

/// Nonce length in bytes (96-bit, the native AES-GCM size).
pub const NONCE_LEN: usize = 12;

/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Length of the stored associated-data digest.
pub const AAD_DIGEST_LEN: usize = 32;

const HEADER_LEN: usize = 2 + NONCE_LEN + AAD_DIGEST_LEN;
const MIN_LEN: usize = HEADER_LEN + TAG_LEN;

/// An authenticated, versioned ciphertext.
///
/// The contents are not secret — they are what the server stores — but the type is
/// still opaque: fields are private and [`fmt::Debug`] prints only lengths, so an
/// accidental log line cannot dump a whole vault.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    version: u8,
    alg: u8,
    nonce: [u8; NONCE_LEN],
    aad_digest: [u8; AAD_DIGEST_LEN],
    ciphertext: Vec<u8>,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("version", &self.version)
            .field("alg", &self.alg)
            .field("payload_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

impl Envelope {
    /// Encrypts `plaintext` under `key`, binding it to `aad`.
    ///
    /// A fresh random nonce is drawn on every call. Because keys are per-item (see
    /// [`crate::vault::item_key`]), each key only ever sees a handful of seals, which
    /// is what makes a random 96-bit nonce safe here.
    pub fn seal(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Self> {
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce);
        Self::seal_with_nonce(key, aad, plaintext, nonce)
    }

    /// Sealing with a caller-supplied nonce.
    ///
    /// Crate-private on purpose: a public API taking a nonce invites reuse, and nonce
    /// reuse under AES-GCM is catastrophic — it leaks the authentication subkey and
    /// enables forgery. It exists solely so deterministic test vectors can be built.
    pub(crate) fn seal_with_nonce(
        key: &SecretKey,
        aad: &[u8],
        plaintext: &[u8],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::KeyLength)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::AuthFailed)?;

        Ok(Self {
            version: ENVELOPE_VERSION,
            alg: ALG_AES256_GCM,
            nonce,
            aad_digest: sha256(aad),
            ciphertext,
        })
    }

    /// Decrypts and authenticates, returning a buffer that zeroizes on drop.
    pub fn open(&self, key: &SecretKey, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.version != ENVELOPE_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        if self.alg != ALG_AES256_GCM {
            return Err(Error::UnsupportedAlgorithm(self.alg));
        }
        // Detect metadata tampering before touching the ciphertext.
        if sha256(aad) != self.aad_digest {
            return Err(Error::AadMismatch);
        }

        let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::KeyLength)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::AuthFailed)?;

        Ok(Zeroizing::new(plaintext))
    }

    /// Wraps another key. The plaintext is exactly 32 bytes, so the ciphertext is
    /// always 48 bytes.
    pub fn seal_key(key: &SecretKey, aad: &[u8], wrapped: &SecretKey) -> Result<Self> {
        let envelope = Self::seal(key, aad, wrapped.expose())?;
        if envelope.ciphertext.len() != 32 + TAG_LEN {
            return Err(Error::Malformed);
        }
        Ok(envelope)
    }

    /// Unwraps a key previously produced by [`Envelope::seal_key`].
    pub fn open_key(&self, key: &SecretKey, aad: &[u8]) -> Result<SecretKey> {
        if self.ciphertext.len() != 32 + TAG_LEN {
            return Err(Error::Malformed);
        }
        SecretKey::from_slice(&self.open(key, aad)?)
    }

    /// Serializes to the wire/storage layout.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.push(self.version);
        out.push(self.alg);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.aad_digest);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses the wire/storage layout, rejecting unknown versions and algorithms.
    ///
    /// An unknown version is never treated as "close enough": downgrading a format is
    /// exactly what an attacker controlling storage would want.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MIN_LEN {
            return Err(Error::Malformed);
        }
        let version = bytes[0];
        if version != ENVELOPE_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let alg = bytes[1];
        if alg != ALG_AES256_GCM {
            return Err(Error::UnsupportedAlgorithm(alg));
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[2..2 + NONCE_LEN]);

        let mut aad_digest = [0u8; AAD_DIGEST_LEN];
        aad_digest.copy_from_slice(&bytes[2 + NONCE_LEN..HEADER_LEN]);

        Ok(Self {
            version,
            alg,
            nonce,
            aad_digest,
            ciphertext: bytes[HEADER_LEN..].to_vec(),
        })
    }

    /// Length of the serialized form, useful for storage sizing.
    #[must_use]
    pub fn serialized_len(&self) -> usize {
        HEADER_LEN + self.ciphertext.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretKey {
        SecretKey::from_array([0x42u8; 32])
    }

    #[test]
    fn roundtrip() {
        let env = Envelope::seal(&key(), b"aad", b"secret payload").unwrap();
        let opened = env.open(&key(), b"aad").unwrap();
        assert_eq!(&opened[..], b"secret payload");
    }

    #[test]
    fn wire_format_roundtrips() {
        let env = Envelope::seal(&key(), b"aad", b"payload").unwrap();
        let parsed = Envelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(env, parsed);
        assert_eq!(parsed.serialized_len(), env.to_bytes().len());
    }

    #[test]
    fn nonce_is_fresh_on_every_seal() {
        let a = Envelope::seal(&key(), b"aad", b"same plaintext").unwrap();
        let b = Envelope::seal(&key(), b"aad", b"same plaintext").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn wrong_key_fails() {
        let env = Envelope::seal(&key(), b"aad", b"payload").unwrap();
        let other = SecretKey::from_array([0x43u8; 32]);
        assert_eq!(env.open(&other, b"aad").unwrap_err(), Error::AuthFailed);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let env = Envelope::seal(&key(), b"aad", b"payload").unwrap();
        let mut bytes = env.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(
            tampered.open(&key(), b"aad").unwrap_err(),
            Error::AuthFailed
        );
    }

    #[test]
    fn tampered_nonce_fails() {
        let env = Envelope::seal(&key(), b"aad", b"payload").unwrap();
        let mut bytes = env.to_bytes();
        bytes[2] ^= 0x01;
        let tampered = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(
            tampered.open(&key(), b"aad").unwrap_err(),
            Error::AuthFailed
        );
    }

    #[test]
    fn swapped_associated_data_fails() {
        let env = Envelope::seal(&key(), b"item-a", b"payload").unwrap();
        assert_eq!(env.open(&key(), b"item-b").unwrap_err(), Error::AadMismatch);
    }

    #[test]
    fn truncated_and_unknown_formats_are_rejected() {
        let env = Envelope::seal(&key(), b"aad", b"payload").unwrap();
        let bytes = env.to_bytes();
        assert_eq!(
            Envelope::from_bytes(&bytes[..10]).unwrap_err(),
            Error::Malformed
        );

        let mut bad_version = bytes.clone();
        bad_version[0] = 0x02;
        assert_eq!(
            Envelope::from_bytes(&bad_version).unwrap_err(),
            Error::UnsupportedVersion(2)
        );

        let mut bad_alg = bytes;
        bad_alg[1] = 0xEF;
        assert_eq!(
            Envelope::from_bytes(&bad_alg).unwrap_err(),
            Error::UnsupportedAlgorithm(0xEF)
        );
    }

    #[test]
    fn key_wrapping_roundtrip_and_size() {
        let kek = key();
        let wrapped = SecretKey::from_array([0x99u8; 32]);
        let env = Envelope::seal_key(&kek, b"userkey-aad", &wrapped).unwrap();
        assert_eq!(env.serialized_len(), HEADER_LEN + 48);

        let unwrapped = env.open_key(&kek, b"userkey-aad").unwrap();
        assert_eq!(unwrapped, wrapped);
    }

    #[test]
    fn key_wrapping_rejects_a_payload_that_is_not_a_key() {
        let kek = key();
        // A non-key payload must not be acceptable to open_key even if authentic.
        let env = Envelope::seal(&kek, b"aad", b"this is not 32 bytes").unwrap();
        assert_eq!(env.open_key(&kek, b"aad").unwrap_err(), Error::Malformed);
    }

    #[test]
    fn debug_does_not_dump_payload() {
        let env = Envelope::seal(&key(), b"aad", b"topsecret").unwrap();
        let rendered = format!("{env:?}");
        assert!(!rendered.contains("topsecret"));
        assert!(rendered.contains("payload_len"));
    }

    /// Freezes the exact wire layout for a fixed key, nonce, AAD and payload.
    ///
    /// Any change to header order, nonce length, AAD handling or the ciphertext
    /// position breaks this test. That is the point: the layout is a storage format,
    /// and changing it silently would make previously stored envelopes unreadable.
    #[test]
    fn envelope_layout_is_frozen() {
        let nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let env = Envelope::seal_with_nonce(&key(), b"cloudpass-aad", b"payload", nonce).unwrap();
        let bytes = env.to_bytes();

        assert_eq!(
            hex::encode(&bytes),
            concat!(
                // header: version(01) alg(01) nonce(12 bytes)
                "01010102030405060708090a0b0c",
                // SHA-256 of the associated data
                "116568bf1916521059b5026871171a8c5ff39d187ef7bdc28ec05ee9f7a87c37",
                // AES-256-GCM of "payload" under the key, tag appended
                "c59b5f2022122db805a6e02ceece19b9b4eec84f488b14"
            )
        );
        // Version, algorithm, nonce, digest, then 7 bytes of payload plus a 16-byte tag.
        assert_eq!(
            bytes.len(),
            2 + NONCE_LEN + AAD_DIGEST_LEN + b"payload".len() + TAG_LEN
        );
        assert_eq!(Envelope::from_bytes(&bytes).unwrap(), env);
    }
}
