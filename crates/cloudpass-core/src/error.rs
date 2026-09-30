use thiserror::Error;

/// Errors produced by the cryptographic core.
///
/// Every variant is safe to log, show to the user and send over the wire: none of
/// them carries key material, plaintext or a distinguishing oracle. In particular
/// [`Error::AuthFailed`] covers *all* AEAD failures — a wrong key, a flipped
/// ciphertext bit, a truncated tag and a mismatched associated data are
/// indistinguishable from the outside.
#[derive(Debug, Error)]
pub enum Error {
    #[error("key material must be exactly 32 bytes")]
    KeyLength,

    #[error("kdf parameters are below the accepted security floor")]
    WeakKdfParams,

    #[error("kdf parameters are outside the algorithm's valid range")]
    InvalidKdfParams,

    #[error("argon2 failed")]
    Kdf,

    #[error("hkdf expand failed")]
    Hkdf,

    /// Any AEAD failure. Deliberately opaque.
    #[error("authentication failed: ciphertext or associated data was modified")]
    AuthFailed,

    /// The stored envelope carries a format version this build does not understand.
    /// Never treated as "try anyway" — an unknown version means downgrade attack.
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),

    #[error("unsupported algorithm id {0}")]
    UnsupportedAlgorithm(u8),

    #[error("envelope is malformed or truncated")]
    Malformed,

    /// The associated-data digest stored next to the ciphertext does not match the
    /// associated data the client reconstructed from server-side metadata. This
    /// means the metadata column was tampered with, and is detected before any
    /// decryption is attempted.
    #[error("associated data does not match the stored digest")]
    AadMismatch,

    /// The head was signed by a device this client does not trust.
    #[error("head signature comes from an unknown device")]
    UnknownSigner,

    /// A signature did not verify. Covers a wrong key, a tampered commitment and a
    /// malformed signature alike: distinguishing them would only help an attacker
    /// probe what a server or client is willing to accept.
    #[error("signature does not verify")]
    BadSignature,

    /// The server offered a head older than one already accepted. The signature may
    /// be perfectly valid, which is exactly what makes this worth detecting.
    #[error("offered head is older than one already accepted")]
    StaleHead,

    /// A failure inside the OPAQUE protocol, tagged with the step that failed.
    ///
    /// The tag is a fixed, non-secret string naming an operation. It carries no
    /// protocol data: a wrong password is reported as [`Error::AuthFailed`], never
    /// through this variant, so this variant cannot be used as a guessing oracle.
    #[error("opaque protocol error during {0}")]
    Opaque(&'static str),

    #[error("serialization failed")]
    Serde(#[from] serde_json::Error),
}

/// Variant-level equality, used by tests that assert on the *kind* of failure.
///
/// Written by hand rather than derived because [`serde_json::Error`] does not
/// implement `PartialEq`. Two `Serde` errors compare equal: the payload is a
/// third-party type we do not inspect, and no test depends on its contents.
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::KeyLength, Error::KeyLength)
            | (Error::WeakKdfParams, Error::WeakKdfParams)
            | (Error::InvalidKdfParams, Error::InvalidKdfParams)
            | (Error::Kdf, Error::Kdf)
            | (Error::Hkdf, Error::Hkdf)
            | (Error::AuthFailed, Error::AuthFailed)
            | (Error::Malformed, Error::Malformed)
            | (Error::AadMismatch, Error::AadMismatch)
            | (Error::UnknownSigner, Error::UnknownSigner)
            | (Error::BadSignature, Error::BadSignature)
            | (Error::StaleHead, Error::StaleHead)
            | (Error::Serde(_), Error::Serde(_)) => true,
            (Error::UnsupportedVersion(a), Error::UnsupportedVersion(b)) => a == b,
            (Error::UnsupportedAlgorithm(a), Error::UnsupportedAlgorithm(b)) => a == b,
            (Error::Opaque(a), Error::Opaque(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Error {}

pub type Result<T> = core::result::Result<T, Error>;
