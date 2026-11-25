//! Writing a model as YAML: serde-saphyr's serializer, YAML 1.2. A string
//! that would read back as another type (`true`, `null`, `12`, `.inf`) is
//! quoted, so [`super::load`] reads back the same value.

use serde::Serialize;

/// Why a value could not be written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DumpError(String);

/// `value` as one YAML document, fields in declaration order.
pub fn to_yaml<T: Serialize>(value: &T) -> Result<String, DumpError> {
    serde_saphyr::to_string(value).map_err(|error| DumpError(error.to_string()))
}

/// `text` as a YAML double-quoted scalar, which [`super::load`] reads back as
/// `text`: `"` and `\\` escaped, every character YAML does not allow as is
/// (control characters, line separators, the byte-order mark) written as
/// an escape, and everything else as it is, in UTF-8.
pub fn double_quoted(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\0' => out.push_str("\\0"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\u{1b}' => out.push_str("\\e"),
            '\u{85}' => out.push_str("\\N"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => {
                let _ = write!(out, "\\x{:02X}", u32::from(ch));
            }
            '\u{feff}' | '\u{fffe}' | '\u{ffff}' => {
                let _ = write!(out, "\\u{:04X}", u32::from(ch));
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Value, load};

    #[test]
    fn strings_that_look_like_other_types_read_back_as_strings() {
        let texts = [
            "yes",
            "true",
            "True",
            "null",
            "~",
            "",
            "12",
            "0x1f",
            "0o17",
            "1.5",
            ".inf",
            "-.inf",
            ".nan",
            "1e3",
            "2026-01-01",
            "<<",
            "=",
            "a: b",
            "- x",
            "#c",
            " lead",
            "it's",
            "line\nbreak",
        ];
        let yaml = to_yaml(&texts).unwrap();
        let document = load(&yaml).unwrap();
        let Value::Seq(items) = &document.root().unwrap().value else {
            panic!("{yaml}")
        };
        let back: Vec<&str> = items.iter().map(|n| n.value.as_str().unwrap()).collect();
        assert_eq!(back, texts, "{yaml}");
    }

    #[test]
    fn a_double_quoted_scalar_reads_back_as_its_text() {
        let texts = [
            "plain",
            "a: \u{e9} — 😀",
            "quote \" and \\ back",
            "line\nbreak\ttab\r",
            "\u{0}\u{1}\u{7}\u{1b}\u{7f}\u{85}\u{9f}\u{a0}",
            "\u{2028}\u{2029}\u{feff}\u{fffe}",
            "",
        ];
        for text in texts {
            let quoted = double_quoted(text);
            let document = load(&quoted).unwrap();
            assert_eq!(
                document.root().unwrap().value.as_str(),
                Some(text),
                "{quoted}"
            );
        }
        assert_eq!(double_quoted("a: \u{e9}"), "\"a: \u{e9}\"");
        assert_eq!(double_quoted("x\u{7f}\"\n"), "\"x\\x7F\\\"\\n\"");
    }

    #[test]
    fn floats_read_back_equal() {
        let floats = [0.5, 1e16, 1.0, -0.0, f64::INFINITY, f64::NEG_INFINITY, 1e-7];
        let yaml = to_yaml(&floats).unwrap();
        let document = load(&yaml).unwrap();
        let Value::Seq(items) = &document.root().unwrap().value else {
            panic!("{yaml}")
        };
        for (item, float) in items.iter().zip(floats) {
            match item.value {
                Value::Float(back) => assert_eq!(back.to_bits(), float.to_bits(), "{yaml}"),
                ref other => panic!("{other:?} in {yaml}"),
            }
        }
    }
}
