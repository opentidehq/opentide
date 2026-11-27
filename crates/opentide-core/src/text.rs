//! Small text helpers every crate shares (#1957): one copy each, never a
//! second one at a call site.
//!
//! - [`hex`]: bytes as lowercase hex digits;
//! - `sha256_hex` (the opt-in `digest` feature): the SHA-256 of bytes as 64
//!   lowercase hex digits (RustCrypto's `sha2`).

use std::fmt::Write as _;

#[cfg(feature = "digest")]
use sha2::{Digest as _, Sha256};

/// `bytes` as lowercase hex digits, two per byte.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// The SHA-256 of `bytes`: 64 lowercase hex digits.
#[cfg(feature = "digest")]
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn hex_is_two_lowercase_digits_per_byte() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        assert_eq!(hex("é😀".as_bytes()), "c3a9f09f9880");
    }

    #[cfg(feature = "digest")]
    #[test]
    fn the_digest_is_lowercase_hex() {
        use super::sha256_hex;
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex("é".as_bytes()),
            "4a99557e4033c3539de2eb65472017cad5f9557f7a0625a09f1c3f6e2ba69c4c"
        );
    }
}
