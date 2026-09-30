//! Identifier generation.
//!
//! Identifiers are built here from bytes drawn by [`crate::secret::fill_random`]
//! rather than through a library helper such as `Uuid::new_v4()`. Two reasons:
//!
//! 1. **One entropy path.** The whole core draws randomness from exactly one place,
//!    so there is a single thing to audit and a single thing to wire up for the
//!    browser (`crypto.getRandomValues`).
//! 2. **A smaller dependency surface.** `Uuid::new_v4()` drags in a second,
//!    differently-configured `getrandom`, which is exactly the sort of split
//!    configuration where a wasm build ends up with a silently weak RNG.

use uuid::Uuid;

use crate::secret::fill_random;

/// Generates a random RFC 4122 version 4 UUID.
///
/// Used for user, vault, item and device identifiers. These are not secrets, but
/// they must be unguessable enough that an attacker cannot enumerate object ids,
/// which is why they come from the CSPRNG rather than a counter.
#[must_use]
pub fn random_uuid() -> Uuid {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    // Version 4 in the high nibble of byte 6, RFC 4122 variant in byte 8.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generates_distinct_identifiers() {
        let ids: HashSet<Uuid> = (0..1000).map(|_| random_uuid()).collect();
        assert_eq!(ids.len(), 1000, "identifiers must not collide");
    }

    #[test]
    fn sets_version_and_variant_bits() {
        for _ in 0..100 {
            let bytes = *random_uuid().as_bytes();
            assert_eq!(bytes[6] & 0xf0, 0x40, "version nibble must be 4");
            assert_eq!(bytes[8] & 0xc0, 0x80, "variant bits must be RFC 4122");
        }
    }
}
