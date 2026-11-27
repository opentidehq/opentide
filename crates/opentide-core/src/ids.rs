//! UUIDs: how every crate reads, writes and recognises one (#1938).
//!
//! One rule, on the [`uuid`] crate:
//!
//! - **Reading** ([`parse`], [`canonical`]) follows Python's
//!   `uuid.UUID(text.strip())`, which wrote the deployment states and the
//!   rule files opentide reads: surrounding white space is dropped, `urn:` and
//!   `uuid:` and enclosing braces are dropped, hyphens are ignored, and the 32
//!   hex digits may be in either case. Every version and variant is a UUID.
//!   It is a strict subset of Python's reading on purpose: the signs (`+`),
//!   underscores, `0x` and inner blanks Python's `int(hex, 16)` also takes
//!   are refused, as `deploy` always refused them.
//! - **Writing** ([`canonical`]) is lower case, hyphenated `8-4-4-4-12`.
//! - **Recognising a value as written** is stricter, where the place asks
//!   for it: [`is_hyphenated`] is the `8-4-4-4-12` form in either case (what
//!   `new` and completion offer), [`is_canonical`] that form in lower case (a
//!   UUID `share` copies into an event as it is written), and [`is_v4`] the
//!   hyphenated form of a version 4 UUID (a Tide object's `metadata.uuid`,
//!   and what the MCP server's `search` reads as an object's id).
//! - **Finding** UUIDs in text ([`PATTERN`], [`finder`]) matches the
//!   hyphenated form in either case.

use std::sync::OnceLock;

use regex::Regex;
pub use uuid::Uuid;

/// The hyphenated form, in either case, unanchored: what highlighting, the
/// outline, inlay hints and the editor's links find in text. Its text is part
/// of the generated TextMate grammars.
pub const PATTERN: &str =
    "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

/// [`PATTERN`], compiled once.
#[expect(
    clippy::expect_used,
    reason = "a literal pattern, compiled once: an invalid one fails every test"
)]
pub fn finder() -> &'static Regex {
    static FINDER: OnceLock<Regex> = OnceLock::new();
    FINDER.get_or_init(|| Regex::new(PATTERN).expect("the UUID pattern compiles"))
}

/// `text` read as a UUID, as Python's `uuid.UUID(text.strip())` reads it
/// (without the signs, underscores and blanks Python's `int()` takes);
/// `None` when it is not one.
pub fn parse(text: &str) -> Option<Uuid> {
    let bare = text.trim().replace("urn:", "").replace("uuid:", "");
    let hex: String = bare
        .trim_matches(['{', '}'])
        .chars()
        .filter(|c| *c != '-')
        .collect();
    // `Uuid::try_parse` takes 32 hex digits as the simple form; anything
    // else of that length (a `+`, a blank) it refuses.
    (hex.len() == 32)
        .then(|| Uuid::try_parse(&hex).ok())
        .flatten()
}

/// `text`'s canonical form ([`parse`]): lower case, hyphenated.
pub fn canonical(text: &str) -> Option<String> {
    parse(text).map(|id| id.hyphenated().to_string())
}

/// Whether `text` is a UUID written `8-4-4-4-12`, hex digits in either case,
/// nothing around it.
pub fn is_hyphenated(text: &str) -> bool {
    hyphenated(text).is_some()
}

/// Whether `text` is a UUID in its canonical form: [`is_hyphenated`], in
/// lower case.
pub fn is_canonical(text: &str) -> bool {
    is_hyphenated(text) && !text.bytes().any(|byte| byte.is_ascii_uppercase())
}

/// Whether `text` is a version 4 UUID written `8-4-4-4-12`, hex digits in
/// either case. The variant is not checked.
pub fn is_v4(text: &str) -> bool {
    hyphenated(text).is_some_and(|id| id.get_version_num() == 4)
}

/// `text` as a UUID when it is written `8-4-4-4-12`.
fn hyphenated(text: &str) -> Option<Uuid> {
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 36
        && bytes.iter().enumerate().all(|(at, byte)| match at {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    shaped.then(|| Uuid::try_parse(text).ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = "0000000a-0000-4000-8003-00000000000b";

    /// Each input, what [`canonical`] makes of it, and which of
    /// [`is_hyphenated`] (`h`), [`is_canonical`] (`c`) and [`is_v4`] (`4`)
    /// hold.
    const CASES: [(&str, Option<&str>, &str); 22] = [
        (V4, Some(V4), "hc4"),
        ("0000000A-0000-4000-8003-00000000000B", Some(V4), "h4"),
        (" 0000000a-0000-4000-8003-00000000000b\n", Some(V4), ""),
        ("0000000a000040008003000000000000b", None, ""),
        ("0000000a00004000800300000000000b", Some(V4), ""),
        ("{0000000a-0000-4000-8003-00000000000b}", Some(V4), ""),
        ("{0000000a00004000800300000000000b}", Some(V4), ""),
        (
            "urn:uuid:0000000a-0000-4000-8003-00000000000b",
            Some(V4),
            "",
        ),
        ("uuid:0000000a-0000-4000-8003-00000000000b", Some(V4), ""),
        ("0000-000a-0000-4000-8003-00000000000b", Some(V4), ""),
        // Other versions are UUIDs; only `is_v4` refuses them.
        (V1, Some(V1), "hc"),
        (NIL, Some(NIL), "hc"),
        // The variant is not checked.
        (V4_NCS, Some(V4_NCS), "hc4"),
        ("0000000a-0000-4000-8003-00000000000", None, ""),
        ("0000000g-0000-4000-8003-00000000000b", None, ""),
        ("0000000a-0000-4000-8003+00000000000b", None, ""),
        ("+000000a-0000-4000-8003-00000000000b", None, ""),
        ("0000000a-0000-4000-8003-00000000000é", None, ""),
        ("😀000000a-0000-4000-8003-00000000000b", None, ""),
        ("not-a-uuid", None, ""),
        ("", None, ""),
        ("{}", None, ""),
    ];
    const V1: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const NIL: &str = "00000000-0000-0000-0000-000000000000";
    const V4_NCS: &str = "00000000-0000-4000-0000-000000000000";

    #[test]
    fn one_rule_for_every_form() {
        for (text, expected, holds) in CASES {
            assert_eq!(canonical(text).as_deref(), expected, "canonical({text:?})");
            assert_eq!(parse(text).is_some(), expected.is_some(), "parse({text:?})");
            assert_eq!(
                is_hyphenated(text),
                holds.contains('h'),
                "is_hyphenated({text:?})"
            );
            assert_eq!(
                is_canonical(text),
                holds.contains('c'),
                "is_canonical({text:?})"
            );
            assert_eq!(is_v4(text), holds.contains('4'), "is_v4({text:?})");
        }
    }

    #[test]
    fn the_finder_finds_the_hyphenated_form_in_either_case() {
        let text = format!("detection_model: {} # é {V4}", V4.to_uppercase());
        let found: Vec<&str> = finder().find_iter(&text).map(|m| m.as_str()).collect();
        assert_eq!(found, [V4.to_uppercase().as_str(), V4]);
    }
}
