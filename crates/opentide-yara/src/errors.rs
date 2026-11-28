//! yara-x-parser's errors as yara-1.0 codes. YARA-X is the language
//! (#1225): every error is an error, with YARA-X's own text, and a hint
//! where YARA-X's text does not name the fix.

use crate::Finding;
use opentide_core::{Severity, codes};
use yara_x_parser::Span;
use yara_x_parser::ast::Error as ParseError;

/// The diagnostic for one yara-x-parser error.
pub fn classify(error: &ParseError, source: &str) -> Finding {
    let (code, message, span) = match error {
        ParseError::SyntaxError { message, span } => {
            let code = if in_hex_string(source, span.start()) {
                codes::YARA_HEX_STRING
            } else {
                codes::YARA_PARSE_ERROR
            };
            // On the wildcard itself, where the error is at the `)` after it.
            if let Some((start, end)) = rule_wildcard_before(source, span.start()) {
                return Finding::new(
                    code,
                    Severity::Error,
                    format!(
                        "YARA syntax error: {message}: a rule wildcard in `of` (`name*`) is not YARA-X; list the rules instead, `any of (rule_a, rule_b)`"
                    ),
                    start,
                    end,
                );
            }
            (code, format!("YARA syntax error: {message}"), span)
        }
        // A jump bound past `u32`.
        ParseError::InvalidInteger { message, span } if in_hex_string(source, span.start()) => (
            codes::YARA_HEX_STRING,
            format!("invalid jump bound: {message}"),
            span,
        ),
        ParseError::InvalidInteger { message, span } => {
            let before = text_before(source, span.start()).trim_end();
            // A bound of `xor(a-b)`: the number follows `xor(` or the `-`
            // of a range whose `xor(` is still open. A `-` elsewhere is a
            // negative number, whatever came earlier in the text.
            let open_xor = before
                .rsplit_once("xor(")
                .is_some_and(|(_, after)| !after.contains(')'));
            let code = if open_xor && (before.ends_with("xor(") || before.ends_with('-')) {
                codes::YARA_STRING_MODIFIER
            } else {
                codes::YARA_NUMBER_OUT_OF_RANGE
            };
            (code, message.clone(), span)
        }
        ParseError::InvalidRegexpModifier { message, span } => {
            (codes::YARA_REGEXP, message.clone(), span)
        }
        ParseError::InvalidFloat { message, span }
        | ParseError::InvalidEscapeSequence { message, span } => {
            (codes::YARA_PARSE_ERROR, message.clone(), span)
        }
        ParseError::InvalidUTF8(span) => (
            codes::YARA_PARSE_ERROR,
            "invalid UTF-8 in the YARA source".to_string(),
            span,
        ),
        ParseError::UnexpectedEscapeSequence(span) => (
            codes::YARA_PARSE_ERROR,
            "escape sequences are not allowed in this string".to_string(),
            span,
        ),
    };
    Finding::new(code, Severity::Error, message, span.start(), span.end())
}

pub fn span(error: &ParseError) -> Span {
    match error {
        ParseError::SyntaxError { span, .. }
        | ParseError::InvalidInteger { span, .. }
        | ParseError::InvalidFloat { span, .. }
        | ParseError::InvalidRegexpModifier { span, .. }
        | ParseError::InvalidEscapeSequence { span, .. }
        | ParseError::InvalidUTF8(span)
        | ParseError::UnexpectedEscapeSequence(span) => span.clone(),
    }
}

/// The span of `name*` when the error at `offset` follows it in an `of`
/// tuple: libyara's rule wildcard, which YARA-X reads as an unfinished
/// product.
fn rule_wildcard_before(source: &str, offset: usize) -> Option<(usize, usize)> {
    let before = text_before(source, offset).trim_end();
    let name = before.strip_suffix('*')?;
    let word = name.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
    let opened = word.trim_end().ends_with('(') || word.trim_end().ends_with(',');
    (word.len() < name.len() && !word.ends_with('$') && opened)
        .then_some((word.len(), before.len()))
}

/// Whether `offset` falls inside a hex string: after `$id = {` on a strings
/// line, before its `}`.
fn in_hex_string(source: &str, offset: usize) -> bool {
    let before = text_before(source, offset);
    let Some((head, inside)) = before.rsplit_once('{') else {
        return false;
    };
    if inside.contains('}') {
        return false;
    }
    let Some(head) = head.trim_end().strip_suffix('=') else {
        return false;
    };
    // The identifier before the `=` is a string's: its sigil is the last
    // character that no name holds.
    head.trim_end()
        .chars()
        .rev()
        .find(|&c| !(c.is_ascii_alphanumeric() || c == '_'))
        == Some('$')
}

/// The text before `offset`, a byte offset yara-x-parser gives: an offset
/// past the end is the end, and one inside a character counts from that
/// character's start.
fn text_before(source: &str, offset: usize) -> &str {
    source
        .get(..source.floor_char_boundary(offset))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_string_offsets() {
        let source = "rule a { strings: $h = { 01 ( 02 | [-] 03 ) } condition: $h }";
        assert!(in_hex_string(source, source.find("[-]").unwrap()));
        assert!(!in_hex_string(source, source.find("condition").unwrap()));
        assert!(!in_hex_string(source, 9));
    }

    #[test]
    fn rule_wildcards_are_named() {
        let source = "rule b { condition: any of (a, base*) }";
        let at = rule_wildcard_before(source, source.find(')').unwrap());
        assert_eq!(at.and_then(|(s, e)| source.get(s..e)), Some("base*"));
        let strings = "rule b { condition: any of ($a*) }";
        assert_eq!(
            rule_wildcard_before(strings, strings.find(')').unwrap()),
            None
        );
        let product = "rule b { condition: 2 * )";
        assert_eq!(
            rule_wildcard_before(product, product.find(')').unwrap()),
            None
        );
    }

    /// yara-x-parser's offsets are bytes: one past the end reads the whole
    /// text, and one inside a character counts from that character's start.
    #[test]
    fn offsets_in_multi_byte_text() {
        let source = "rule é { strings: $h = { 01 [😀-] 02 } condition: $h }";
        let inside = source.find("[😀").unwrap() + 2;
        assert!(in_hex_string(source, inside));
        assert!(in_hex_string(source, inside + 1));
        assert!(!in_hex_string(source, source.len() + 10));
        let unnamed = "rule a { strings: é = { 01";
        assert!(!in_hex_string(unnamed, unnamed.len()));
        assert_eq!(text_before("é😀", 1), "");
        assert_eq!(text_before("é😀", 3), "é");
        assert_eq!(text_before("é😀", 99), "é😀");
        let wildcard = "rule b { condition: any of (é, base*) }";
        let at = rule_wildcard_before(wildcard, wildcard.find(')').unwrap());
        assert_eq!(at.and_then(|(s, e)| wildcard.get(s..e)), Some("base*"));
        assert_eq!(rule_wildcard_before("any of (é😀*)", 13), None);
        assert_eq!(rule_wildcard_before("any of (é😀*)", 15), None);
    }
}
