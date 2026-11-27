//! `opentide_core::yara::escape_string`, the escape the HarfangLab compiler
//! and the language server write `meta` values with, read back by YARA-X's
//! parser (#1939): every value parses and means the text it was given, and
//! no raw control character reaches the rule.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use opentide_core::yara::escape_string;
use yara_x_parser::Parser;
use yara_x_parser::ast::{AST, MetaValue};

/// The bytes of the one `meta` value of `rule`.
fn meta_value(rule: &str) -> Vec<u8> {
    let ast = AST::from(Parser::new(rule.as_bytes()));
    assert!(ast.errors().is_empty(), "{rule:?}: {:?}", ast.errors());
    let meta = ast.rules().next().unwrap().meta.as_ref().unwrap();
    match &meta[0].value {
        MetaValue::String((text, _)) => text.as_bytes().to_vec(),
        MetaValue::Bytes((bytes, _)) => bytes.to_vec(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_escaped_value_reads_back_as_its_text() {
    for text in [
        "plain",
        "tab\there",
        "a \"quote\" and a \\ backslash",
        "two\nlines",
        "nul\0 bell\u{7} escape\u{1b} delete\u{7f}",
        "é 😀",
        "\\x41 is not an escape here",
    ] {
        let escaped = escape_string(text);
        assert!(
            !escaped.chars().any(|c| c.is_ascii_control()),
            "{escaped:?}"
        );
        let rule = format!(
            "rule r {{\n    meta:\n        d = \"{escaped}\"\n    condition:\n        true\n}}\n"
        );
        assert_eq!(meta_value(&rule), text.as_bytes(), "{text:?}");
    }
}

/// A carriage return is dropped, so CRLF text writes the LF text's rule.
#[test]
fn a_carriage_return_is_dropped() {
    assert_eq!(escape_string("a\r\nb"), escape_string("a\nb"));
}
