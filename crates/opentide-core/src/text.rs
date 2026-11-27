//! Small text helpers every crate shares (#1957): one copy each, never a
//! second one at a call site.
//!
//! - [`hex`]: bytes as lowercase hex digits;
//! - `sha256_hex` (the opt-in `digest` feature): the SHA-256 of bytes as 64
//!   lowercase hex digits (RustCrypto's `sha2`);
//! - line endings: [`universal_newlines`] reads `\r\n` and a lone `\r` as
//!   `\n`; [`newline_of`] is the line ending a file writes (CRLF when it has
//!   one) and [`with_newlines_of`] writes a text in it;
//! - [`unique`]: each item once, in the order it first came (names, ids),
//!   in linear time;
//! - `shell_word` and `shell_line` (the opt-in `shell` feature): words
//!   quoted for a POSIX shell, as a command line the user may paste.
//!
//! A caller that reads only `\r\n` as `\n` (a lone `\r` kept), that reads
//! every YAML line break as `\n`, or that keeps CRLF only when every line
//! ends in it says so where it does, with a one-line pointer here: those
//! are different rules, not copies of these.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::hash::Hash;

use indexmap::IndexSet;

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

/// `items` each once, in the order each first came.
#[must_use]
pub fn unique<T: Hash + Eq>(items: impl IntoIterator<Item = T>) -> Vec<T> {
    items
        .into_iter()
        .collect::<IndexSet<T>>()
        .into_iter()
        .collect()
}

/// `word` as one POSIX shell word, quoted only when it needs it (the shlex
/// crate's quoting). A word no shell can carry, one with a NUL byte, is
/// written as Rust writes a string (`"a\0b"`): visibly not a word to paste,
/// never a different word or none.
#[cfg(feature = "shell")]
#[must_use]
pub fn shell_word(word: &str) -> Cow<'_, str> {
    shlex::try_quote(word).unwrap_or_else(|_| Cow::Owned(format!("{word:?}")))
}

/// `words` as one command line: each a [`shell_word`], space-separated.
#[cfg(feature = "shell")]
#[must_use]
pub fn shell_line<'a>(words: impl IntoIterator<Item = &'a str>) -> String {
    let mut line = String::new();
    for word in words {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&shell_word(word));
    }
    line
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{hex, newline_of, unique, universal_newlines, with_newlines_of};

    #[test]
    fn unique_keeps_the_first_of_each_in_order() {
        assert_eq!(
            unique(["é", "😀", "e", "é", "É", "😀", "e\u{301}"]),
            ["é", "😀", "e", "É", "e\u{301}"]
        );
        assert_eq!(unique(Vec::<String>::new()), Vec::<String>::new());
    }

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

    #[cfg(feature = "shell")]
    #[test]
    fn a_shell_word_is_quoted_only_when_it_needs_it() {
        use super::{shell_line, shell_word};
        assert_eq!(shell_word("--strict"), "--strict");
        assert_eq!(shell_word("é"), "'é'");
        assert_eq!(shell_word("😀"), "'😀'");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("it's"), "\"it's\"");
        assert_eq!(shell_word(""), "''");
        // No shell carries a NUL: shown, never dropped or passed raw.
        assert_eq!(shell_word("a\0b"), "\"a\\0b\"");
        assert_eq!(
            shell_line(["opentide", "validate", "--file", "é 😀.yaml", "a\0b"]),
            "opentide validate --file 'é 😀.yaml' \"a\\0b\""
        );
        assert_eq!(shell_line([]), "");
        // Without a NUL, the line is shlex's own join.
        let words = ["x", "é", "a b", "", "it's", "$HOME"];
        assert_eq!(
            shell_line(words),
            shlex::try_join(words).unwrap_or_default()
        );
    }
}
