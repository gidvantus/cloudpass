use thiserror::Error;

/// Errors a client operation can produce.
///
/// Like the core's error type, nothing here carries key material or plaintext. The
/// `Storage` variant wraps a backend message — those come from the operating system,
/// not from the vault, and are safe to show.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Anything the cryptographic core refused.
    #[error(transparent)]
    Crypto(#[from] cloudpass_core::Error),

    /// The requested operation needs an unlocked vault.
    #[error("the vault is locked")]
    Locked,

    /// No account has been set up on this device yet.
    #[error("no account is configured on this device")]
    NoAccount,

    /// An account already exists and cannot be created twice.
    #[error("an account already exists on this device")]
    AccountExists,

    /// The account record does not match the password that was supplied.
    ///
    /// Reported without detail on purpose: distinguishing "wrong password" from
    /// "corrupted stored key" would only help someone attacking the vault.
    #[error("the master password does not match this account")]
    WrongPassword,

    /// No recovery envelope is stored on this device.
    #[error("this account has no recovery envelope on this device")]
    NoRecoveryKit,

    /// The recovery key did not open the envelope.
    ///
    /// Distinct from [`ClientError::WrongPassword`] because the two are typed in
    /// completely different places, and the useful thing to tell someone is which of
    /// them is wrong.
    #[error("the recovery key does not match this account")]
    WrongRecoveryKey,

    #[error("item not found")]
    ItemNotFound,

    /// A draft with no fields worth storing.
    #[error("the item has nothing to store")]
    EmptyItem,

    /// The transport itself failed. The message is the transport's own.
    #[error("network failure: {0}")]
    Transport(String),

    /// The server answered, and refused. The code is its stable error identifier
    /// rather than prose, so callers can branch on it.
    #[error("the server refused the request ({status} {code})")]
    Http { status: u16, code: String },

    /// The server answered with something this client cannot use: a malformed body, a
    /// head it cannot verify, or a state it does not agree with.
    #[error("the server sent something this client cannot use: {0}")]
    Protocol(String),

    /// The storage backend failed. The message is the backend's own.
    #[error("storage failure: {0}")]
    Storage(String),

    /// A stored record could not be decoded.
    #[error("stored data is not readable: {0}")]
    Corrupt(String),

    #[error("serialization failed")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = core::result::Result<T, ClientError>;
