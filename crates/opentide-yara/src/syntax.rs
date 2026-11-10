//! Parsing a signature with `yara-x-parser` as libyara 4.5 would read it.
//!
//! yara-x-parser refuses three forms libyara accepts, which yara-1.0 reports
//! as `yara_x_incompatible`, not as syntax errors:
//!
//! - a repeated rule modifier (`global global rule a`);
//! - a rule wildcard in `of` (`any of (base*)`), which YARA-X reads as a
//!   product;
//! - an escape in a `base64` alphabet.
//!
//! The libyara grammar (tree-sitter) finds them. Each is blanked to text of
//! the same length that yara-x-parser accepts, so every byte offset stays
//! the source's; the semantic pass knows the wildcards by their spans.

use crate::Finding;
use opentide_core::{LanguageId, Severity, codes};
use tree_sitter::Node;
use yara_x_parser::Span;
use yara_x_parser::ast::Error as ParseError;

pub struct Prepared {
    /// The source with libyara-only forms blanked, byte for byte as long.
    pub text: String,
    /// Each rule wildcard in `of`, as the span of its name (without `*`).
    pub rule_wildcards: Vec<(usize, usize)>,
    pub findings: Vec<Finding>,
}

pub fn prepare(source: &str) -> Prepared {
    let mut bytes = source.as_bytes().to_vec();
    let mut rule_wildcards = Vec::new();
    let mut findings = Vec::new();
    if let Some(tree) = opentide_syntax::parse(LanguageId::Yara, source) {
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "rule_wildcard" => {
                    let (start, end) = (node.start_byte(), node.end_byte());
                    // `base*` -> `base `: a rule reference yara-x-parser takes.
                    bytes[end - 1] = b' ';
                    rule_wildcards.push((start, end - 1));
                    findings.push(Finding::new(
                        codes::YARA_X_INCOMPATIBLE,
                        Severity::Warning,
                        "YARA-X refuses rule wildcards in `of`: it reads `name*` as a product"
                            .into(),
                        start,
                        end,
                    ));
                }
                "rule" => blank_repeated_modifiers(node, source, &mut bytes, &mut findings),
                "hex_jump_bound" => {
                    let (start, end) = (node.start_byte(), node.end_byte());
                    // libyara reads a bound past `u32` modulo 2^32; YARA-X
                    // refuses it. Writing the bound libyara reads, as long
                    // as the original, lets yara-x-parser read the string,
                    // so its atoms and its jumps are checked as libyara's.
                    // libyara's strtoll saturates at i64::MAX before the
                    // 32-bit truncation: 2^63 and above read as -1.
                    let digits = &source[start..end];
                    let value = digits
                        .parse::<u128>()
                        .unwrap_or(u128::MAX)
                        .min(i64::MAX as u128);
                    if digits.bytes().all(|b| b.is_ascii_digit()) && value > u128::from(u32::MAX) {
                        let wrapped = (value % (1u128 << 32)) as u32;
                        let text = format!("{wrapped:0>width$}", width = end - start);
                        if text.len() == end - start {
                            bytes[start..end].copy_from_slice(text.as_bytes());
                            findings.push(Finding::new(
                                codes::YARA_X_INCOMPATIBLE,
                                Severity::Warning,
                                format!("YARA-X refuses a jump bound above {}; libyara reads `{digits}` as {wrapped}", u32::MAX),
                                start,
                                end,
                            ));
                        }
                    }
                }
                "base64_modifier" => {
                    if let Some(alphabet) = node.child_by_field_name("alphabet") {
                        let (start, end) = (alphabet.start_byte(), alphabet.end_byte());
                        if source[start..end].contains('\\') {
                            for b in &mut bytes[start + 1..end - 1] {
                                if *b == b'\\' {
                                    *b = b'_';
                                }
                            }
                            findings.push(Finding::new(
                                codes::YARA_X_INCOMPATIBLE,
                                Severity::Warning,
                                "YARA-X refuses escape sequences in a base64 alphabet".into(),
                                start,
                                end,
                            ));
                        }
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }
    // Only ASCII bytes were replaced with ASCII bytes.
    let text = String::from_utf8(bytes).unwrap_or_else(|_| source.to_string());
    Prepared {
        text,
        rule_wildcards,
        findings,
    }
}

fn blank_repeated_modifiers(rule: Node, source: &str, bytes: &mut [u8], out: &mut Vec<Finding>) {
    let mut seen: Vec<&str> = Vec::new();
    let mut cursor = rule.walk();
    for child in rule.children_by_field_name("modifier", &mut cursor) {
        let word = &source[child.byte_range()];
        if seen.contains(&word) {
            for b in &mut bytes[child.byte_range()] {
                *b = b' ';
            }
            out.push(Finding::new(
                codes::YARA_X_INCOMPATIBLE,
                Severity::Warning,
                format!("YARA-X refuses a repeated rule modifier: `{word}` is already set"),
                child.start_byte(),
                child.end_byte(),
            ));
        } else {
            seen.push(word);
        }
    }
}

/// The diagnostic for one yara-x-parser error.
pub fn classify(error: &ParseError, source: &str) -> Finding {
    let (code, message, span) = match error {
        ParseError::SyntaxError { message, span } => {
            let code = if in_hex_string(source, span.start()) {
                codes::YARA_HEX_STRING
            } else {
                codes::YARA_PARSE_ERROR
            };
            (code, format!("YARA syntax error: {message}"), span)
        }
        // A jump bound past `u32`: libyara reads it, YARA-X refuses it.
        ParseError::InvalidInteger { message, span } if in_hex_string(source, span.start()) => {
            return Finding::new(
                codes::YARA_X_INCOMPATIBLE,
                Severity::Warning,
                format!("YARA-X refuses this jump bound: {message}"),
                span.start(),
                span.end(),
            );
        }
        ParseError::InvalidInteger { message, span } => {
            let before = source[..span.start()].trim_end();
            // A bound of `xor(a-b)`: the number follows `xor(` or the `-`
            // of a range whose `xor(` is still open. A `-` elsewhere is a
            // negative number, whatever came earlier in the text.
            let open_xor = before
                .rfind("xor(")
                .is_some_and(|i| !before[i..].contains(')'));
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

pub fn error_span(error: &ParseError) -> Span {
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

/// Whether `offset` falls inside a hex string: after `$id = {` on a strings
/// line, before its `}`.
fn in_hex_string(source: &str, offset: usize) -> bool {
    let before = &source[..offset.min(source.len())];
    let Some(open) = before.rfind('{') else {
        return false;
    };
    if before[open..].contains('}') {
        return false;
    }
    let head = before[..open].trim_end();
    let Some(head) = head.strip_suffix('=') else {
        return false;
    };
    let head = head.trim_end();
    let ident_start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |i| i);
    head[ident_start..].starts_with('$')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_keep_offsets() {
        let source =
            "global global rule a { condition: true }\nrule b { condition: any of (a*) }\n";
        let p = prepare(source);
        assert_eq!(p.text.len(), source.len());
        assert!(p.text.starts_with("global        rule a"));
        assert!(p.text.contains("any of (a )"));
        assert_eq!(p.rule_wildcards.len(), 1);
        assert_eq!(p.findings.len(), 2);
    }

    #[test]
    fn hex_string_offsets() {
        let source = "rule a { strings: $h = { 01 ( 02 | [-] 03 ) } condition: $h }";
        assert!(in_hex_string(source, source.find("[-]").unwrap()));
        assert!(!in_hex_string(source, source.find("condition").unwrap()));
        assert!(!in_hex_string(source, 9));
    }
}
