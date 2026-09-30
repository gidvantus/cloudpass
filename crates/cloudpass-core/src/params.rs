use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Length of the per-account KDF salt, in bytes.
pub const KDF_SALT_LEN: usize = 16;

/// Argon2id parameters, stored alongside the account so they can be raised over time.
///
/// The parameters are **not secret**, but they are security-relevant: a malicious
/// server could try to hand a client a weakened parameter set and then crack the
/// resulting envelope cheaply. [`KdfParams::validate`] therefore enforces a floor and
/// is called on every path that accepts parameters from outside this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in kibibytes.
    pub m_kib: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Degree of parallelism (lanes).
    pub p: u32,
    /// Output length in bytes. Fixed at 32 for protocol v1.
    pub output_len: u32,
}

impl KdfParams {
    /// RFC 9106 first recommendation (64 MiB, 3 passes, 4 lanes).
    pub const RECOMMENDED: Self = Self {
        m_kib: 65_536,
        t: 3,
        p: 4,
        output_len: 32,
    };

    /// OWASP minimum configuration (19 MiB, 2 passes, 1 lane).
    pub const OWASP_MINIMUM: Self = Self {
        m_kib: 19_456,
        t: 2,
        p: 1,
        output_len: 32,
    };

    /// Upper bound on the memory cost we are willing to attempt (4 GiB).
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;

    /// Rejects parameters that are structurally impossible or below the security floor.
    ///
    /// The floor is what makes a server-side downgrade attack fail: a client that is
    /// told to use 8 MiB of memory refuses instead of quietly deriving a weak key.
    pub fn validate(&self) -> Result<()> {
        if self.output_len != 32 || self.t == 0 || self.p == 0 || self.p > 64 {
            return Err(Error::InvalidKdfParams);
        }
        if self.m_kib > Self::MAX_M_KIB {
            return Err(Error::InvalidKdfParams);
        }
        // Argon2 requires at least 8 KiB of memory per lane.
        if self.m_kib < 8 * self.p {
            return Err(Error::InvalidKdfParams);
        }
        if self.m_kib < Self::OWASP_MINIMUM.m_kib || self.t < Self::OWASP_MINIMUM.t {
            return Err(Error::WeakKdfParams);
        }
        Ok(())
    }

    /// Validates and converts to the Argon2 crate's parameter type.
    pub fn to_argon2(&self) -> Result<argon2::Params> {
        self.validate()?;
        argon2::Params::new(self.m_kib, self.t, self.p, Some(self.output_len as usize))
            .map_err(|_| Error::InvalidKdfParams)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_and_owasp_minimum_are_valid() {
        assert!(KdfParams::RECOMMENDED.validate().is_ok());
        assert!(KdfParams::OWASP_MINIMUM.validate().is_ok());
    }

    #[test]
    fn downgrade_is_rejected() {
        let weak = KdfParams {
            m_kib: 8_192,
            ..KdfParams::RECOMMENDED
        };
        assert_eq!(weak.validate(), Err(Error::WeakKdfParams));

        let low_iters = KdfParams {
            t: 1,
            ..KdfParams::RECOMMENDED
        };
        assert_eq!(low_iters.validate(), Err(Error::WeakKdfParams));
    }

    #[test]
    fn structurally_invalid_parameters_are_rejected() {
        assert_eq!(
            KdfParams {
                p: 0,
                ..KdfParams::RECOMMENDED
            }
            .validate(),
            Err(Error::InvalidKdfParams)
        );
        assert_eq!(
            KdfParams {
                output_len: 16,
                ..KdfParams::RECOMMENDED
            }
            .validate(),
            Err(Error::InvalidKdfParams)
        );
        assert_eq!(
            KdfParams {
                m_kib: 8,
                p: 8,
                ..KdfParams::RECOMMENDED
            }
            .validate(),
            Err(Error::InvalidKdfParams)
        );
    }
}
