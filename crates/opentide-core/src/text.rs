//! Small text helpers every crate shares (#1957): one copy each, never a
//! second one at a call site.
//!
//! - [`hex`]: bytes as lowercase hex digits;
//! - [`sha256_hex`]: the SHA-256 of bytes as 64 lowercase hex digits
//!   (RustCrypto's `sha2`);
//! - line endings: [`universal_newlines`] reads `\r\n` and a lone `\r` as
//!   `\n`; [`newline_of`] is the line ending a file writes (CRLF when it has
//!   one) and [`with_newlines_of`] writes a text in it.
//!
//! A caller that reads only `\r\n` as `\n` (a lone `\r` kept) or that
//! keeps CRLF only when every line ends in it says so where it does: those
//! are different rules, not copies of these.

use std::borrow::Cow;
use std::fmt::Write as _;

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
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// `text` with `\r\n` and a lone `\r` read as `\n`, as a text-mode read
/// reads a file (Python's universal newlines). Borrowed when `text` has no
/// `\r`.
#[must_use]
pub fn universal_newlines(text: &str) -> Cow<'_, str> {
    if text.contains('\r') {
        Cow::Owned(text.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Cow::Borrowed(text)
    }
}

/// The line ending a file uses: `"\r\n"` when it has one CRLF, else
/// `"\n"`.
#[must_use]
pub fn newline_of(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

/// `written`, text an editor produced from `original`, in `original`'s line
/// ending: when `original` has a CRLF, every line break of `written` (`\n`
/// or `\r\n`) becomes `\r\n`; otherwise `written` as it is.
#[must_use]
pub fn with_newlines_of(written: String, original: &str) -> String {
    if original.contains("\r\n") {
        written.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        written
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{hex, newline_of, sha256_hex, universal_newlines, with_newlines_of};

    #[test]
    fn universal_newlines_reads_crlf_and_a_lone_cr_as_lf() {
        assert_eq!(universal_newlines("é\r\n😀\rü\n\r\r\nx"), "é\n😀\nü\n\n\nx");
        assert!(matches!(
            universal_newlines("é\n😀"),
            Cow::Borrowed("é\n😀")
        ));
        assert_eq!(universal_newlines(""), "");
    }

    #[test]
    fn one_crlf_makes_a_file_crlf() {
        assert_eq!(newline_of("é\n😀\r\n"), "\r\n");
        assert_eq!(newline_of("é\n😀\r"), "\n");
        assert_eq!(newline_of(""), "\n");
    }

    #[test]
    fn written_text_takes_the_original_line_ending() {
        assert_eq!(
            with_newlines_of("é\r\n😀\nü".to_owned(), "a\r\nb\n"),
            "é\r\n😀\r\nü"
        );
        // An LF original leaves the text alone, a CRLF in it included.
        assert_eq!(
            with_newlines_of("é\r\n😀\n".to_owned(), "a\nb\r"),
            "é\r\n😀\n"
        );
    }

    #[test]
    fn hex_is_two_lowercase_digits_per_byte() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        assert_eq!(hex("é😀".as_bytes()), "c3a9f09f9880");
    }

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
        assert_eq!(
            sha256_hex("é".as_bytes()),
            "4a99557e4033c3539de2eb65472017cad5f9557f7a0625a09f1c3f6e2ba69c4c"
        );
    }
}
