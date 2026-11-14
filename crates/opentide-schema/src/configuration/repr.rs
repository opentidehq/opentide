//! Values quoted in messages: a string as [`quote`] quotes it (double
//! quotes, Rust's escapes), any other value as YAML and JSON write it
//! (`null`, `true`, `1.5`), lists and tables bracketed.

use crate::node::{Node, Value};

pub use crate::vocab::quote;

/// A node as a message shows the value it holds: a string quoted, a scalar
/// as YAML writes it, a list `[a, b]` and a table `{k: v}`.
pub fn node(node: &Node) -> String {
    match &node.value {
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
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::toml::parse;

    #[test]
    fn strings_are_quoted_with_rusts_escapes() {
        assert_eq!(quote("abc"), "\"abc\"");
        assert_eq!(quote("it's"), "\"it's\"");
        assert_eq!(quote("a\\b\nc\u{1}"), "\"a\\\\b\\nc\\u{1}\"");
        assert_eq!(quote("é\u{200b}"), "\"é\\u{200b}\"");
    }

    #[test]
    fn values_are_written_as_yaml_writes_them() {
        let doc = parse("a = [1, 1.5, true, \"x\", {k = false}]\nb = 2.0\n").unwrap();
        assert_eq!(
            node(doc.get("a").unwrap()),
            "[1, 1.5, true, \"x\", {\"k\": false}]"
        );
        assert_eq!(node(doc.get("b").unwrap()), "2.0");
    }
}
