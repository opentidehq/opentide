//! The SHA-256 digests the CLI prints: share-ledger content hashes, SARIF and
//! Code Quality fingerprints, and `serve`'s result identifiers.

use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

/// The SHA-256 of `bytes`: 64 lowercase hex digits.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn the_digest_is_lowercase_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
