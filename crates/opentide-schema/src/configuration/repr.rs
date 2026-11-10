//! Values quoted in messages as the CLI quotes them (`{name!r}`): a string in
//! single quotes, or double quotes when it holds a single quote and no double
//! one, with backslashes, the quote and characters that do not print escaped;
//! numbers and booleans as written (`True`, `False`); lists and tables
//! bracketed.

use std::sync::LazyLock;

use regex::Regex;

use crate::node::{Node, Value};

/// A string quoted as the CLI's messages quote it.
pub fn quote(text: &str) -> String {
    let delimiter = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(delimiter);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch == delimiter => {
                out.push('\\');
                out.push(ch);
            }
            ch if !prints(ch) => {
                let code = u32::from(ch);
                if code <= 0xff {
                    out.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\U{code:08x}"));
                }
            }
            ch => out.push(ch),
        }
    }
    out.push(delimiter);
    out
}

/// Whether a character prints as itself, as Python's `str.isprintable`
/// decides it: not in a general category of Other (Cc, Cf, Cs, Co, Cn) or
/// Separator (Zs, Zl, Zp), U+0020 excepted. The categories are the `regex`
/// crate's Unicode tables.
fn prints(ch: char) -> bool {
    static NOT_PRINTABLE: LazyLock<Regex> = LazyLock::new(|| {
        #[expect(clippy::expect_used, reason = "a literal class that compiles")]
        Regex::new(r"\A[\p{C}\p{Z}--\x20]\z").expect("the class compiles")
    });
    if ch.is_ascii() {
        return !ch.is_ascii_control();
    }
    let mut buffer = [0; 4];
    !NOT_PRINTABLE.is_match(ch.encode_utf8(&mut buffer))
}

/// A node written as the CLI writes the value it holds.
pub fn node(node: &Node) -> String {
    match &node.value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Int(integer) => integer.to_string(),
        Value::Float(float) => float_text(*float),
        Value::Str(text) | Value::Datetime(text) => quote(text),
        Value::Seq(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|item| self::node(item))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Map(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|entry| format!("{}: {}", self::node(&entry.key), self::node(&entry.value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// A float as the CLI writes one (Python's `repr`): the shortest digits
/// that read back, `1.0`, `1.5`, `inf`, `-inf`, `nan`; past 1e16 or below
/// 1e-4 with an exponent of a sign and at least two digits (`1e+20`,
/// `1.5e-07`).
pub fn float_text(float: f64) -> String {
    if float.is_nan() {
        return "nan".to_owned();
    }
    if float.is_infinite() {
        return if float > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    // Debug writes the same shortest digits, and switches to an exponent at
    // the same bounds; only the exponent's form differs.
    let text = format!("{float:?}");
    let Some((mantissa, exponent)) = text.split_once('e') else {
        return text;
    };
    let (sign, digits) = exponent
        .strip_prefix('-')
        .map_or(('+', exponent), |digits| ('-', digits));
    format!("{mantissa}e{sign}{digits:0>2}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::toml::parse;

    #[test]
    fn strings_are_quoted_as_the_cli_quotes_them() {
        assert_eq!(quote("abc"), "'abc'");
        assert_eq!(quote("it's"), "\"it's\"");
        assert_eq!(quote("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(quote("a\\b\nc\u{1}"), "'a\\\\b\\nc\\x01'");
        assert_eq!(quote("é\u{200b}"), "'é\\u200b'");
    }

    #[test]
    fn characters_that_do_not_print_are_escaped_by_general_category() {
        // Private use (Co), format (Cf), unassigned (Cn), separators (Zs,
        // Zl), a C1 control (Cc); a letter, an emoji and U+0020 print.
        for (ch, escaped) in [
            ('\u{e000}', "\\ue000"),
            ('\u{600}', "\\u0600"),
            ('\u{378}', "\\u0378"),
            ('\u{fff9}', "\\ufff9"),
            ('\u{a0}', "\\xa0"),
            ('\u{3000}', "\\u3000"),
            ('\u{2028}', "\\u2028"),
            ('\u{85}', "\\x85"),
            ('\u{f0000}', "\\U000f0000"),
            ('\u{7f}', "\\x7f"),
        ] {
            assert_eq!(quote(&ch.to_string()), format!("'{escaped}'"), "{ch:?}");
        }
        assert_eq!(quote("a b\u{e9}\u{1f600}"), "'a b\u{e9}\u{1f600}'");
    }

    #[test]
    fn floats_take_the_exponent_form_of_the_cli() {
        for (float, text) in [
            (1e20, "1e+20"),
            (1.5e-7, "1.5e-07"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (-2.5e-300, "-2.5e-300"),
            (f64::MAX, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (-0.0, "-0.0"),
            (123.0, "123.0"),
        ] {
            assert_eq!(float_text(float), text);
        }
    }

    #[test]
    fn values_are_written_as_the_cli_writes_them() {
        let doc = parse("a = [1, 1.5, true, \"x\", {k = false}]\nb = 2.0\n").unwrap();
        assert_eq!(
            node(doc.get("a").unwrap()),
            "[1, 1.5, True, 'x', {'k': False}]"
        );
        assert_eq!(node(doc.get("b").unwrap()), "2.0");
    }
}
