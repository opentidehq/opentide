//! Tide YAML as values (#850): opentide-core's node tree (`opentide_core::node`), the one YAML
//! reader of the workspace.
//!
//! [`parse`] reads a document with [`opentide_core::node::load`], as
//! `opentide validate` and the language server's workspace read an object
//! file: YAML 1.2, core schema, one document, unique keys, core tags only.
//! A text the loader refuses has no values here, as it has no object there
//! (`yaml_parse`).
//!
//! [`YamlNode`] reads a node the way the engine read `serde_yaml` values
//! before it: a string is only a string, a number prints as YAML writes it
//! ([`YamlNode::scalar_text`]).

use std::sync::Arc;

use opentide_core::node::{self, Mark, Node, Value};

/// The root of `source`, read as an object file is (a leading byte order
/// mark is dropped); a stream with no document (empty, or only comments) is
/// a `null` root. `None` for a text the loader refuses.
pub(crate) fn parse(source: &str) -> Option<Arc<Node>> {
    let document = node::load(source).ok()?;
    Some(
        document
            .root()
            .cloned()
            .unwrap_or_else(|| Arc::new(Node::null_at(Mark::default()))),
    )
}

/// What the engine reads of a node.
pub(crate) trait YamlNode {
    /// The text of a string; `None` for any other node, a number included.
    fn as_str(&self) -> Option<&str>;
    /// The items of a sequence.
    fn as_sequence(&self) -> Option<&[Arc<Node>]>;
    /// The value of an integer.
    fn as_i64(&self) -> Option<i64>;
    /// Whether the node is `null` (`null`, `~` or nothing).
    fn is_null(&self) -> bool;
    /// Whether the node is a mapping.
    fn is_mapping(&self) -> bool;
    /// A string, number or boolean as text: the string itself, a number as
    /// YAML writes it ([`number_text`]), `true` or `false`. `None` for `null`
    /// and a collection.
    fn scalar_text(&self) -> Option<String>;
}

impl YamlNode for Node {
    fn as_str(&self) -> Option<&str> {
        self.value.as_str()
    }

    fn as_sequence(&self) -> Option<&[Arc<Node>]> {
        match &self.value {
            Value::Seq(items) => Some(items),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self.value {
            Value::Int(integer) => Some(integer),
            _ => None,
        }
    }

    fn is_null(&self) -> bool {
        matches!(self.value, Value::Null)
    }

    fn is_mapping(&self) -> bool {
        matches!(self.value, Value::Map(_))
    }

    fn scalar_text(&self) -> Option<String> {
        match &self.value {
            Value::Str(text) | Value::Datetime(text) => Some(text.clone()),
            // A boolean or a number as written (`True`, `1.50`), as Falco reads it.
            Value::Bool(flag) => Some(
                self.text
                    .as_deref()
                    .map_or_else(|| flag.to_string(), str::to_owned),
            ),
            Value::Int(_) | Value::Float(_) => self
                .text
                .as_deref()
                .map(str::to_owned)
                .or_else(|| number_text(&self.value)),
            Value::Null | Value::Seq(_) | Value::Map(_) => None,
        }
    }
}

/// A number as YAML writes it: an integer in decimal; a float as the
/// shortest text that reads back the same (`ryu`, as `serde_yaml` printed
/// one), `.inf`, `-.inf` or `.nan`.
pub(crate) fn number_text(value: &Value) -> Option<String> {
    match *value {
        Value::Int(integer) => Some(integer.to_string()),
        Value::Float(float) if float.is_nan() => Some(".nan".to_owned()),
        Value::Float(float) if float.is_infinite() => Some(
            if float.is_sign_negative() {
                "-.inf"
            } else {
                ".inf"
            }
            .to_owned(),
        ),
        Value::Float(float) => Some(ryu::Buffer::new().format_finite(float).to_owned()),
        _ => None,
    }
}

/// A scalar's text as written in `source` (the text `node` was read from):
/// a string's value; for a number, boolean or `null`, the plain scalar after
/// any anchor and tag (`0x1F`, `1.50`, `True`), which a field read as text
/// keeps. `None` for a collection.
pub(crate) fn written_text(source: &str, node: &Node) -> Option<String> {
    match &node.value {
        Value::Str(text) | Value::Datetime(text) => Some(text.clone()),
        Value::Seq(_) | Value::Map(_) => None,
        Value::Null | Value::Bool(_) | Value::Int(_) | Value::Float(_) => {
            let written: String = source
                .chars()
                .skip(node.start.index)
                .take(node.end.index.saturating_sub(node.start.index))
                .collect();
            // A number, boolean or null is one word; an anchor and a tag
            // (`&a !!int 12`) come before it. A tagged one may be quoted
            // (`!!int "12"`): the text is what the quotes hold.
            let word = written.split_whitespace().last().unwrap_or_default();
            let quoted = |mark: char| {
                word.strip_prefix(mark)
                    .and_then(|inner| inner.strip_suffix(mark))
            };
            Some(match (quoted('"'), quoted('\'')) {
                (Some(inner), _) => inner.to_owned(),
                (None, Some(inner)) => inner.replace("''", "'"),
                (None, None) => word.to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(text: &str) -> Arc<Node> {
        parse(text).expect("loads")
    }

    #[test]
    fn a_text_the_loader_refuses_has_no_root() {
        assert!(parse("a: 1\na: 2\n").is_none());
        assert!(parse("a: !Ref x\n").is_none());
        assert!(parse("a: [\n").is_none());
        assert!(parse("a: 1\n---\nb: 2\n").is_none());
    }

    #[test]
    fn an_empty_stream_is_a_null_root() {
        assert!(root("").is_null());
        assert!(root("# only a comment\n").is_null());
        assert!(root("\u{feff}").is_null());
    }

    #[test]
    fn scalars_print_as_written() {
        let doc = root(
            "[1, -7, 0x1F, 1.5, 1e3, 1.0, .inf, -.inf, .nan, 0.00005, 1e16, 1e-7, true, x, ~, [], {}]",
        );
        let texts: Vec<Option<String>> = doc
            .as_sequence()
            .unwrap()
            .iter()
            .map(|item| item.scalar_text())
            .collect();
        let want = [
            "1", "-7", "0x1F", "1.5", "1e3", "1.0", ".inf", "-.inf", ".nan", "0.00005", "1e16",
            "1e-7", "true", "x",
        ];
        let mut expected: Vec<Option<String>> =
            want.iter().map(|text| Some((*text).to_owned())).collect();
        expected.extend([None, None, None]);
        assert_eq!(texts, expected);
    }

    #[test]
    fn a_field_read_as_text_keeps_the_scalar_as_written() {
        let source = "a: 0x1F\nb: &x !!float 1.50\nc: True\nd: 'q'\ne: [1]\nf: ~\ng: !!int \"12\"\nh: !!bool 'true'\n";
        let doc = root(source);
        let text = |key: &str| written_text(source, doc.get(key).unwrap());
        assert_eq!(text("a").as_deref(), Some("0x1F"));
        assert_eq!(text("b").as_deref(), Some("1.50"));
        assert_eq!(text("c").as_deref(), Some("True"));
        assert_eq!(text("d").as_deref(), Some("q"));
        assert_eq!(text("e"), None);
        assert_eq!(text("f").as_deref(), Some("~"));
        assert_eq!(text("g").as_deref(), Some("12"));
        assert_eq!(text("h").as_deref(), Some("true"));
    }

    #[test]
    fn only_a_string_reads_as_str() {
        let doc = root("a: '1'\nb: 1\nc: ~\nd: [x]\ne: {x: 1}\n");
        assert_eq!(doc.get("a").unwrap().as_str(), Some("1"));
        assert_eq!(doc.get("b").unwrap().as_str(), None);
        assert_eq!(doc.get("b").unwrap().as_i64(), Some(1));
        assert!(doc.get("c").unwrap().is_null());
        assert!(doc.get("d").unwrap().as_sequence().is_some());
        assert!(doc.get("e").unwrap().is_mapping());
    }
}
