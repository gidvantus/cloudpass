use core::fmt;

use rand::rngs::OsRng;
use rand::RngCore;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// A 32-byte symmetric key.
///
/// Guarantees, in order of importance:
///
/// 1. **Zeroized on drop** via [`Zeroizing`].
/// 2. **Never printed** — [`fmt::Debug`] emits `SecretKey(<redacted>)`, so an
///    accidental `{:?}` in a log, a panic message or a test failure cannot leak a key.
/// 3. **Compared in constant time** via [`ConstantTimeEq`].
///
/// There is intentionally no `Display`, no `Serialize` and no cheap way to copy the
/// bytes into a plain `[u8; 32]` that would leave an un-zeroized remnant behind.
/// Callers borrow through [`SecretKey::expose`] and let this type own the bytes.
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    /// Generates a fresh random key from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    /// Wraps an existing 32-byte array, taking ownership of it.
    #[must_use]
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Takes ownership of an already-zeroizing buffer, without copying it.
    /// Preferred over [`SecretKey::from_array`] inside the crate: it avoids leaving a
    /// transient, un-zeroized copy of the key on the stack.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Copies exactly 32 bytes out of a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::KeyLength);
        }
        let mut buf = Zeroizing::new([0u8; 32]);
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// Borrows the key bytes. The borrow cannot outlive the zeroizing owner.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Borrows the key as a fixed-size array.
    #[must_use]
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expose().ct_eq(other.expose())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(ConstantTimeEq::ct_eq(self, other))
    }
}

impl Eq for SecretKey {}

/// Defines a distinct newtype around [`SecretKey`] for every role a key plays.
///
/// Type confusion between key roles (`UKEK` used where a `UserKey` is expected, an
/// item key used as a vault key, and so on) is a real attack class, so each role gets
/// its own type. The macro generates no `Clone`, no `Serialize` and no `Display`, and
/// its `Debug` prints `<redacted>`.
#[macro_export]
macro_rules! key_newtype {
    ($(#[$meta:meta])* $vis:vis $name:ident) => {
        $(#[$meta])*
        #[derive(PartialEq, Eq)]
        $vis struct $name($crate::secret::SecretKey);

        impl $name {
            /// Generates a fresh random key of this role from the OS CSPRNG.
            #[must_use]
            pub fn generate() -> Self {
                Self($crate::secret::SecretKey::generate())
            }

            /// Takes ownership of an already-zeroizing buffer.
            #[must_use]
            pub fn from_zeroizing(z: ::zeroize::Zeroizing<[u8; 32]>) -> Self {
                Self($crate::secret::SecretKey::from_zeroizing(z))
            }

            /// Wraps an existing secret key, re-labelling it with this role.
            #[must_use]
            pub fn from_secret(k: $crate::secret::SecretKey) -> Self {
                Self(k)
            }

            /// Copies exactly 32 bytes out of a slice.
            pub fn from_slice(b: &[u8]) -> $crate::error::Result<Self> {
                Ok(Self($crate::secret::SecretKey::from_slice(b)?))
            }

            /// Borrows the key bytes.
            #[must_use]
            pub fn expose(&self) -> &[u8] {
                self.0.expose()
            }

            /// Borrows the underlying [`SecretKey`](crate::secret::SecretKey).
            #[must_use]
            pub fn inner(&self) -> &$crate::secret::SecretKey {
                &self.0
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

/// Fills a buffer with cryptographically secure random bytes.
///
/// This is the crate's **only** source of randomness, and it is public so that clients
/// drawing their own values — a KDF salt, a device key seed — go through the same path
/// rather than reaching for a second RNG. In the browser it resolves to
/// `crypto.getRandomValues`; on the desktop, to the operating system.
///
/// # Panics
///
/// Panics if the operating system cannot provide randomness. That is not a recoverable
/// condition for a password manager: continuing with predictable bytes would be worse
/// than stopping.
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_differ() {
        assert_ne!(SecretKey::generate(), SecretKey::generate());
    }

    #[test]
    fn reject_wrong_length() {
        assert_eq!(SecretKey::from_slice(&[0u8; 31]), Err(Error::KeyLength));
        assert_eq!(SecretKey::from_slice(&[0u8; 33]), Err(Error::KeyLength));
        assert!(SecretKey::from_slice(&[0u8; 32]).is_ok());
    }

    #[test]
    fn debug_never_prints_key_bytes() {
        let key = SecretKey::from_array([0xABu8; 32]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "SecretKey(<redacted>)");
        assert!(!rendered.contains("ab"));
        assert!(!rendered.contains("171"));
    }

    #[test]
    fn equality_is_value_based() {
        let a = SecretKey::from_array([7u8; 32]);
        let b = SecretKey::from_array([7u8; 32]);
        let c = SecretKey::from_array([8u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
