//! Values quoted in messages as the CLI quotes them (`{name!r}`): a string in
//! single quotes, or double quotes when it holds a single quote and no double
//! one, with backslashes, the quote and characters that do not print escaped;
//! numbers and booleans as written (`True`, `False`); lists and tables
//! bracketed.

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

/// Whether a character prints as itself: not a control character, a line or
/// paragraph separator, a format character or a space other than U+0020.
fn prints(ch: char) -> bool {
    !(ch.is_control()
        || matches!(
            ch,
            '\u{a0}'
                | '\u{ad}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200f}'
                | '\u{2028}'..='\u{202f}'
                | '\u{205f}'..='\u{2064}'
                | '\u{3000}'
                | '\u{feff}'
        ))
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

/// A float as the CLI writes one: `1.0`, `1.5`, `inf`, `-inf`, `nan`.
fn float_text(float: f64) -> String {
    if float.is_nan() {
        "nan".to_owned()
    } else if float.is_infinite() {
        if float > 0.0 { "inf" } else { "-inf" }.to_owned()
    } else {
        format!("{float:?}")
    }
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
    fn values_are_written_as_the_cli_writes_them() {
        let doc = parse("a = [1, 1.5, true, \"x\", {k = false}]\nb = 2.0\n").unwrap();
        assert_eq!(
            node(doc.get("a").unwrap()),
            "[1, 1.5, True, 'x', {'k': False}]"
        );
        assert_eq!(node(doc.get("b").unwrap()), "2.0");
    }
}
