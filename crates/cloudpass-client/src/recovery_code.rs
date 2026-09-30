//! Encoding a recovery key so a person can write it down and type it back in.
//!
//! # Why not hex or base64
//!
//! A recovery key is the one secret in this system that is meant to leave the computer
//! and live on paper. That changes what matters: the encoding has to survive being read
//! aloud, copied by hand and typed back months later.
//!
//! Crockford base32 is chosen for exactly that. It drops `I`, `L`, `O` and `U` from the
//! alphabet, so the pairs that ruin hand transcription — `1`/`l`, `0`/`O` — cannot both
//! occur, and the decoder folds the lookalikes to the digit anyone would have meant.
//! Base64 would put upper and lower case in the same string and lose that.
//!
//! # The checksum
//!
//! Two bytes of SHA-256 are appended before encoding. Without it a mistyped key is not
//! an error but a *different key*, and the user gets "this recovery key is wrong" with no
//! way to tell a typo from a lost kit. With it, a transcription mistake is caught and
//! named.

use sha2::{Digest, Sha256};

use cloudpass_core::error::{Error, Result};
use cloudpass_core::kdf::RecoveryKey;

/// Marks the format so a future version can change it without ambiguity.
const PREFIX: &str = "CPRK1";

/// Crockford's alphabet: digits and consonants, minus `I`, `L`, `O` and `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Length of the checksum appended to the key before encoding.
const CHECKSUM_LEN: usize = 2;

/// How many characters go between dashes.
const GROUP: usize = 5;

/// Formats a recovery key for a human to write down.
///
/// The result looks like `CPRK1-3F9KQ-...`, with the body grouped in fives. Grouping is
/// not decoration: it is what lets someone read a key aloud and check it off in blocks.
#[must_use]
pub fn encode(key: &RecoveryKey) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.extend_from_slice(key.expose());
    payload.extend_from_slice(&checksum(key.expose())[..CHECKSUM_LEN]);

    let body = base32_encode(&payload);
    let mut grouped = String::with_capacity(PREFIX.len() + 1 + body.len() + body.len() / GROUP);
    grouped.push_str(PREFIX);

    for chunk in body.as_bytes().chunks(GROUP) {
        grouped.push('-');
        // The alphabet is ASCII, so every chunk is valid UTF-8 by construction.
        grouped.push_str(core::str::from_utf8(chunk).unwrap_or_default());
    }

    grouped
}

/// Reads back a recovery key.
///
/// Accepts what a person would plausibly type: lower case, missing dashes, and the
/// characters Crockford folds (`I` and `L` to `1`, `O` to `0`). The folding covers the
/// prefix too, because someone copying `CPRK1` off paper can perfectly well write
/// `CPRKI`.
pub fn decode(text: &str) -> Result<RecoveryKey> {
    let normalised: String = text
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| fold(character.to_ascii_uppercase()))
        .collect();

    let body = normalised
        .strip_prefix(PREFIX)
        .ok_or(Error::Malformed)?
        .to_owned();

    let payload = base32_decode(&body)?;
    if payload.len() < 32 + CHECKSUM_LEN {
        return Err(Error::Malformed);
    }

    let (key, rest) = payload.split_at(32);
    let expected = checksum(key);
    if rest[..CHECKSUM_LEN] != expected[..CHECKSUM_LEN] {
        // Almost always a transcription slip rather than a wrong key, and saying so is
        // the difference between "check what you wrote" and "you have lost the vault".
        return Err(Error::Malformed);
    }

    RecoveryKey::from_slice(key)
}

/// Folds the characters Crockford leaves out of the alphabet onto their lookalikes.
///
/// The alphabet has no `I`, `L`, `O` or `U`, so none of these can be a genuine
/// character and the mapping is unambiguous.
fn fold(character: char) -> char {
    match character {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    }
}

fn checksum(key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"cloudpass/v1/recovery-key-checksum");
    hasher.update(key);
    hasher.finalize().into()
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }

    out
}

fn base32_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for character in text.chars() {
        // Folding already happened in `decode`, so anything outside the alphabet here is
        // genuinely not a recovery key.
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate as char == character)
            .ok_or(Error::Malformed)? as u32;

        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> RecoveryKey {
        RecoveryKey::from_slice(&[0x5Au8; 32]).expect("32 bytes")
    }

    #[test]
    fn a_key_round_trips() {
        let original = key();
        let text = encode(&original);
        assert!(text.starts_with("CPRK1-"), "{text}");
        assert_eq!(decode(&text).expect("decode"), original);
    }

    #[test]
    fn the_encoding_avoids_characters_people_misread() {
        // A key chosen so the encoding exercises many symbols.
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index * 11) as u8;
        }
        let text = encode(&RecoveryKey::from_slice(&bytes).expect("32 bytes"));

        for forbidden in ['I', 'L', 'O', 'U'] {
            assert!(
                !text.contains(forbidden),
                "{forbidden} is not in the alphabet and must never be produced: {text}"
            );
        }
    }

    #[test]
    fn typing_it_back_sloppily_still_works() {
        let original = key();
        let text = encode(&original);

        // Lower case, no dashes: what someone types when they are reading from paper
        // and not thinking about formatting.
        let sloppy = text.to_lowercase().replace('-', "");
        assert_eq!(decode(&sloppy).expect("decode"), original);

        // And with the lookalike letters Crockford folds.
        let folded = text.replace('0', "O").replace('1', "l");
        assert_eq!(decode(&folded).expect("decode"), original);
    }

    #[test]
    fn a_mistyped_key_is_rejected_rather_than_silently_different() {
        let text = encode(&key());

        // Change one character in the middle of the body. Not the last one: the final
        // five bits are mostly padding, so a change there can land outside the payload
        // and the test would pass for the wrong reason.
        let mut characters: Vec<char> = text.chars().collect();
        let position = characters.len() / 2;
        characters[position] = if characters[position] == '0' {
            '1'
        } else {
            '0'
        };
        let broken: String = characters.into_iter().collect();
        assert_ne!(text, broken);

        assert!(matches!(decode(&broken), Err(Error::Malformed)));
    }

    #[test]
    fn nonsense_is_rejected() {
        assert!(decode("").is_err());
        assert!(decode("not-a-kit").is_err());
        assert!(decode("CPRK1-$$$$$").is_err());
        // The right prefix but nothing usable after it.
        assert!(decode("CPRK1-").is_err());
    }

    #[test]
    fn a_different_key_encodes_differently() {
        let first = RecoveryKey::from_slice(&[1u8; 32]).expect("32 bytes");
        let second = RecoveryKey::from_slice(&[2u8; 32]).expect("32 bytes");
        assert_ne!(encode(&first), encode(&second));
    }
}
