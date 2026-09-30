//! Key derivation: Argon2id for the master password, HKDF-SHA256 for subkeys.
//!
//! Every derived value is domain-separated by its own `info` label. Two different
//! roles must never receive the same key, which is why the labels are constants here
//! rather than string literals at call sites, and why a test asserts that all roles
//! produce distinct keys from the same root.

use argon2::{Algorithm, Argon2, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::key_newtype;
use crate::params::{KdfParams, KDF_SALT_LEN};
use crate::secret::SecretKey;

/// Domain-separation label for the key-encryption key that wraps the user key.
pub const INFO_UKEK: &[u8] = b"cloudpass/v1/ukek";

/// Domain-separation label for the OPAQUE password input.
///
/// This is deliberately a *different* value from [`INFO_UKEK`]: the server learns
/// this one, and must not be able to derive anything that decrypts data.
pub const INFO_OPAQUE_INPUT: &[u8] = b"cloudpass/v1/opaque-input";

/// Domain-separation label for the OPAQUE session key.
pub const INFO_OPAQUE_SESSION: &[u8] = b"cloudpass/v1/opaque-session";

/// Domain-separation label for the key that wraps the user key for recovery.
pub const INFO_RECOVERY_UKEK: &[u8] = b"cloudpass/v1/recovery-ukek";

/// Domain-separation label for the recovery key's OPAQUE password input.
///
/// The same 256-bit secret both unwraps the user key and authenticates to the server,
/// and those are two different jobs. Deriving each under its own label is what keeps
/// the server's copy of one from being usable as the other.
pub const INFO_RECOVERY_AUTH: &[u8] = b"cloudpass/v1/recovery-auth";

/// Domain-separation label for per-item keys.
pub const INFO_ITEM: &[u8] = b"cloudpass/v1/item";

/// Domain-separation label for a device-local unlock key.
pub const INFO_DEVICE_UNLOCK: &[u8] = b"cloudpass/v1/device-unlock";

key_newtype!(
    #[doc = "Argon2id output over the master password. Recomputable, never stored."]
    pub StretchedKey
);
key_newtype!(
    #[doc = "Optional second secret (32 random bytes) delivered in the Emergency Kit."]
    pub AccountKey
);
key_newtype!(
    #[doc = "Emergency recovery secret (32 random bytes) delivered in the Emergency Kit."]
    pub RecoveryKey
);
key_newtype!(
    #[doc = "Key-encryption key that wraps the user key. Derived from the master password."]
    pub UserKeyEncryptionKey
);

/// Runs Argon2id over the master password.
///
/// Parameters come from the account record and are validated before use, so a server
/// that hands out weakened parameters causes a hard error rather than a weak key.
pub fn stretch_master_password(
    master_password: &[u8],
    salt: &[u8; KDF_SALT_LEN],
    params: &KdfParams,
) -> Result<StretchedKey> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_argon2()?);
    let mut out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(master_password, salt, &mut out[..])
        .map_err(|_| Error::Kdf)?;
    Ok(StretchedKey::from_zeroizing(out))
}

/// HKDF-SHA256 expand into a 32-byte subkey.
pub(crate) fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<SecretKey> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut okm[..]).map_err(|_| Error::Hkdf)?;
    Ok(SecretKey::from_zeroizing(okm))
}

/// Derives the key-encryption key that protects the user key at rest.
///
/// With an account key enabled the input is `StretchedKey || AccountKey`, so an
/// attacker who steals the database still needs a 256-bit secret that is not in it.
/// Both branches are concatenated into a zeroizing buffer and dropped immediately.
pub fn derive_ukek(
    stretched: &StretchedKey,
    account_key: Option<&AccountKey>,
    kdf_salt: &[u8; KDF_SALT_LEN],
) -> Result<UserKeyEncryptionKey> {
    let ikm = match account_key {
        Some(ak) => {
            let mut buf = Zeroizing::new(Vec::with_capacity(64));
            buf.extend_from_slice(stretched.expose());
            buf.extend_from_slice(ak.expose());
            buf
        }
        None => Zeroizing::new(stretched.expose().to_vec()),
    };
    Ok(UserKeyEncryptionKey::from_secret(hkdf_expand(
        &ikm, kdf_salt, INFO_UKEK,
    )?))
}

/// Derives the value handed to OPAQUE as the "password" input.
///
/// Passing a domain-separated subkey rather than the raw master password means the
/// bytes going into the aPAKE are useless for any other purpose in this protocol.
pub fn derive_opaque_input(stretched: &StretchedKey) -> Result<SecretKey> {
    hkdf_expand(stretched.expose(), b"", INFO_OPAQUE_INPUT)
}

/// Derives the key-encryption key for the recovery envelope.
///
/// # Why there is no Argon2id here
///
/// Everywhere else a password goes through Argon2id, because a password is guessable.
/// A recovery key is 32 bytes from a CSPRNG — 256 bits — so stretching it would add
/// nothing an attacker could not already do faster, while making recovery slower for
/// the one person entitled to it. HKDF is the right primitive for a uniformly random
/// input; Argon2id is the right primitive for a human one, and that distinction is the
/// whole reason this function exists separately from [`derive_ukek`].
///
/// `user_id` is the salt, so a recovery envelope wrapped for one account cannot be
/// replayed into another.
pub fn derive_recovery_ukek(
    recovery_key: &RecoveryKey,
    user_id: &[u8; 16],
) -> Result<UserKeyEncryptionKey> {
    Ok(UserKeyEncryptionKey::from_secret(hkdf_expand(
        recovery_key.expose(),
        user_id,
        INFO_RECOVERY_UKEK,
    )?))
}

/// Derives the value handed to OPAQUE as the recovery key's "password" input.
///
/// # Why recovery needs its own credential
///
/// A recovery key that could only unwrap the local vault would be half a way back in:
/// the vault would open, and the user still could not reach the server, because the
/// master password that authenticates them is exactly the thing they have lost. So the
/// recovery key is a credential in its own right, registered with the server under a
/// distinct OPAQUE record at the same time as the master password.
///
/// No Argon2id here, for the same reason as [`derive_recovery_ukek`]: the input is 32
/// CSPRNG bytes, so there is no guess to make expensive. `user_id` salts the
/// derivation, binding it to one account.
pub fn derive_recovery_auth(recovery_key: &RecoveryKey, user_id: &[u8; 16]) -> Result<SecretKey> {
    hkdf_expand(recovery_key.expose(), user_id, INFO_RECOVERY_AUTH)
}

/// Derives a device-local unlock key, used only to gate the local cache.
pub fn derive_device_unlock(stretched: &StretchedKey, device_id: &[u8]) -> Result<SecretKey> {
    hkdf_expand(stretched.expose(), device_id, INFO_DEVICE_UNLOCK)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; KDF_SALT_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    /// RFC 5869, Appendix A.1, Test Case 1. Guards our HKDF usage and our
    /// understanding of the `salt`/`info` argument order.
    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").expect("valid hex");
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").expect("valid hex");
        let expected_okm = concat!(
            "3cb25f25faacd57a90434f64d0362f2a",
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
            "34007208d5b887185865"
        );

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).expect("expand");
        assert_eq!(hex::encode(okm), expected_okm);

        // A 32-byte expand must be a prefix of the 42-byte expand. This pins the
        // argument order (salt, ikm) and info usage that `hkdf_expand` relies on.
        let mut first32 = [0u8; 32];
        hk.expand(&info, &mut first32).expect("expand");
        assert_eq!(&first32[..], &okm[..32]);
    }

    /// Pins the exact HKDF construction used by `hkdf_expand` to a frozen vector,
    /// so any change in salt/info plumbing breaks a test instead of silently
    /// producing different keys from the same inputs.
    ///
    /// The expected value below is produced by this very implementation and frozen
    /// after review; it is a change-detector, not an external standard vector.
    #[test]
    fn hkdf_expand_is_stable() {
        let key = hkdf_expand(&[0x0bu8; 22], b"cloudpass-salt", INFO_UKEK).unwrap();
        assert_eq!(
            hex::encode(key.expose()),
            "4447b097797035838de1aae582af7d2cd1e73f5a487b86d4d07002944ff4bfc6"
        );
    }

    /// Freezes the Argon2id output for the project's parameter sets.
    ///
    /// This is a change-detector for our own configuration: a dependency upgrade, a
    /// parameter default change or a swapped argument order shows up as a diff
    /// instead of silently making every existing vault undecryptable.
    ///
    /// RFC 9106's official test vectors cannot be reproduced here, because they also
    /// set a `secret` and `associated data`, which the `argon2` crate does not expose
    /// through its public API. Correctness against an independent implementation is
    /// established separately and reproducibly by
    /// `scripts/verify-argon2-reference.mjs`, which recomputes these exact values
    /// using Node's OpenSSL-backed Argon2. Both must agree.
    #[test]
    fn argon2id_output_is_frozen() {
        let sk = stretch_master_password(
            b"correct horse battery staple",
            &SALT,
            &KdfParams::OWASP_MINIMUM,
        )
        .unwrap();
        assert_eq!(
            hex::encode(sk.expose()),
            "818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085"
        );
    }

    /// The RFC 9106 first-recommendation configuration.
    ///
    /// The multi-lane case (p = 4) is worth having separately: it also pins that the
    /// degree of parallelism is threaded through to the algorithm correctly, which a
    /// single-lane vector cannot show.
    #[test]
    fn argon2id_recommended_output_is_frozen() {
        let sk = stretch_master_password(
            b"correct horse battery staple",
            &SALT,
            &KdfParams::RECOMMENDED,
        )
        .unwrap();
        assert_eq!(
            hex::encode(sk.expose()),
            "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e"
        );
    }

    #[test]
    fn argon2id_is_deterministic() {
        let params = KdfParams::OWASP_MINIMUM;
        let a = stretch_master_password(b"correct horse battery staple", &SALT, &params).unwrap();
        let b = stretch_master_password(b"correct horse battery staple", &SALT, &params).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn argon2id_is_salt_and_password_sensitive() {
        let params = KdfParams::OWASP_MINIMUM;
        let base = stretch_master_password(b"pw", &SALT, &params).unwrap();

        let mut other_salt = SALT;
        other_salt[15] ^= 0x01;
        assert_ne!(
            base,
            stretch_master_password(b"pw", &other_salt, &params).unwrap()
        );
        assert_ne!(
            base,
            stretch_master_password(b"pw2", &SALT, &params).unwrap()
        );
    }

    #[test]
    fn argon2id_rejects_downgraded_parameters() {
        let weak = KdfParams {
            m_kib: 1024,
            t: 1,
            p: 1,
            output_len: 32,
        };
        assert_eq!(
            stretch_master_password(b"pw", &SALT, &weak).unwrap_err(),
            Error::WeakKdfParams
        );
    }

    /// The whole point of domain separation: one root, many roles, all distinct.
    #[test]
    fn every_role_gets_a_distinct_key() {
        let params = KdfParams::OWASP_MINIMUM;
        let sk = stretch_master_password(b"pw", &SALT, &params).unwrap();

        let ukek = derive_ukek(&sk, None, &SALT).unwrap();
        let opaque = derive_opaque_input(&sk).unwrap();
        let device = derive_device_unlock(&sk, b"device-1").unwrap();
        let device2 = derive_device_unlock(&sk, b"device-2").unwrap();

        assert_ne!(ukek.expose(), opaque.expose());
        assert_ne!(ukek.expose(), device.expose());
        assert_ne!(opaque.expose(), device.expose());
        assert_ne!(device.expose(), device2.expose());
    }

    #[test]
    fn account_key_changes_the_ukek() {
        let params = KdfParams::OWASP_MINIMUM;
        let sk = stretch_master_password(b"pw", &SALT, &params).unwrap();
        let ak = AccountKey::from_zeroizing(Zeroizing::new([0x42u8; 32]));

        let without = derive_ukek(&sk, None, &SALT).unwrap();
        let with = derive_ukek(&sk, Some(&ak), &SALT).unwrap();
        assert_ne!(without.expose(), with.expose());
    }

    #[test]
    fn key_newtypes_do_not_leak_on_debug() {
        let ak = AccountKey::from_zeroizing(Zeroizing::new([0x11u8; 32]));
        assert_eq!(format!("{ak:?}"), "AccountKey(<redacted>)");
        let ukek = UserKeyEncryptionKey::from_slice(&[0x22u8; 32]).unwrap();
        assert_eq!(format!("{ukek:?}"), "UserKeyEncryptionKey(<redacted>)");
    }

    /// The recovery key does two jobs, and the values it derives must not be
    /// interchangeable: the server holds one of them, and must gain nothing about the
    /// other from holding it.
    #[test]
    fn the_two_recovery_roles_are_independent() {
        let root = RecoveryKey::from_slice(&[0x5Au8; 32]).unwrap();
        let user_id = [0x11u8; 16];

        let ukek = derive_recovery_ukek(&root, &user_id).unwrap();
        let auth = derive_recovery_auth(&root, &user_id).unwrap();
        assert_ne!(ukek.expose(), auth.expose());

        // Both are functions of the same root, so both must move when it does.
        let other = RecoveryKey::from_slice(&[0x5Bu8; 32]).unwrap();
        assert_ne!(
            auth.expose(),
            derive_recovery_auth(&other, &user_id).unwrap().expose()
        );

        // And the salt binds them to the account.
        let mut other_id = user_id;
        other_id[0] ^= 0x01;
        assert_ne!(
            auth.expose(),
            derive_recovery_auth(&root, &other_id).unwrap().expose()
        );
    }
}
