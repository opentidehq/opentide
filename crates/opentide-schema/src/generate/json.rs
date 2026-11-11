//! JSON documents as the oracle writes them: keys in insertion order, and
//! `json.dumps(document, indent=4)` + `"\n"`'s bytes (Python's default
//! `ensure_ascii`, so every character past ASCII is a `\uXXXX` escape).
//!
//! The workspace's `serde_json` keeps object keys sorted (`preserve_order`
//! is off: ADR 0001), so a generated document is a [`Json`], whose objects
//! are `IndexMap`s, written through `serde_json`'s pretty printer with a
//! formatter that escapes as Python does.

use std::io;

use indexmap::IndexMap;
use serde::Serialize;
use serde_json::ser::{CharEscape, Formatter, PrettyFormatter};

/// An object: keys in insertion order.
pub type Object = IndexMap<String, Json>;

/// A JSON value whose objects keep their keys in insertion order.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as `serde_json` writes it.
    Number(serde_json::Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object.
    Object(Object),
}

impl Json {
    /// An empty object.
    pub fn object() -> Self {
        Self::Object(Object::new())
    }

    /// The object, if this is one.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    /// The object, mutably, if this is one.
    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// The array, if this is one.
    pub fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The value at `key`, if this is an object that holds it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object().and_then(|map| map.get(key))
    }

    /// The document as the oracle writes it: four-space indentation, `": "`
    /// and `","` separators, non-ASCII escaped, and a final newline.
    pub fn to_python_text(&self) -> String {
        let mut out = Vec::new();
        let mut serializer =
            serde_json::Serializer::with_formatter(&mut out, PythonFormatter::default());
        // Writing into a Vec cannot fail, and a Json holds no map with
        // non-string keys.
        if self.serialize(&mut serializer).is_err() {
            return String::new();
        }
        out.push(b'\n');
        // The formatter writes ASCII only.
        String::from_utf8(out).unwrap_or_default()
    }
}

impl From<&str> for Json {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for Json {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<bool> for Json {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<Vec<Json>> for Json {
    fn from(value: Vec<Json>) -> Self {
        Self::Array(value)
    }
}

impl From<Object> for Json {
    fn from(value: Object) -> Self {
        Self::Object(value)
    }
}

impl From<&serde_json::Value> for Json {
    /// A `serde_json` value, its object keys in the order it holds them
    /// (sorted, in this workspace).
    fn from(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(flag) => Self::Bool(*flag),
            serde_json::Value::Number(number) => Self::Number(number.clone()),
            serde_json::Value::String(text) => Self::String(text.clone()),
            serde_json::Value::Array(items) => Self::Array(items.iter().map(Self::from).collect()),
            serde_json::Value::Object(map) => Self::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), Self::from(value)))
                    .collect(),
            ),
        }
    }
}

/// `serde_json`'s pretty printer with four spaces, escaping strings as
/// Python's `json` module does with `ensure_ascii`.
struct PythonFormatter {
    pretty: PrettyFormatter<'static>,
}

impl Default for PythonFormatter {
    fn default() -> Self {
        Self {
            pretty: PrettyFormatter::with_indent(b"    "),
        }
    }
}

impl Formatter for PythonFormatter {
    fn begin_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_array(writer)
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array(writer)
    }

    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_array_value(writer, first)
    }

    fn end_array_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_array_value(writer)
    }

    fn begin_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object(writer)
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object(writer)
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.pretty.begin_object_key(writer, first)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.begin_object_value(writer)
    }

    fn end_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.pretty.end_object_value(writer)
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        // ASCII runs are written whole: a schema is megabytes of them, and
        // a write per character was most of the time spent writing it.
        let mut units = [0_u16; 2];
        let mut run = 0;
        for (at, character) in fragment.char_indices() {
            if character.is_ascii() {
                continue;
            }
            writer.write_all(&fragment.as_bytes()[run..at])?;
            for unit in character.encode_utf16(&mut units) {
                write!(writer, "\\u{unit:04x}")?;
            }
            run = at + character.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[run..])
    }

    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        escape: CharEscape,
    ) -> io::Result<()> {
        // Python writes the same short escapes, and other control
        // characters as lower-case `\u00XX`, as serde_json does.
        self.pretty.write_char_escape(writer, escape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(entries: &[(&str, Json)]) -> Json {
        Json::Object(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    #[test]
    fn keys_keep_their_insertion_order() {
        let document = object(&[("b", Json::from("1")), ("a", Json::from(true))]);
        assert_eq!(
            document.to_python_text(),
            "{\n    \"b\": \"1\",\n    \"a\": true\n}\n"
        );
    }

    #[test]
    fn nesting_indents_four_spaces_and_empty_containers_stay_inline() {
        let document = object(&[
            (
                "list",
                Json::Array(vec![Json::from("x"), Json::Array(Vec::new())]),
            ),
            ("empty", Json::object()),
            ("null", Json::Null),
            ("number", Json::Number(3.into())),
        ]);
        assert_eq!(
            document.to_python_text(),
            "{\n    \"list\": [\n        \"x\",\n        []\n    ],\n    \"empty\": {},\n    \"null\": null,\n    \"number\": 3\n}\n"
        );
    }

    #[test]
    fn non_ascii_is_escaped_as_python_does() {
        // json.dumps("é — 😀\n\"\\\u{1}") in Python.
        let text = Json::from("é — 😀\n\"\\\u{1}\u{7f}").to_python_text();
        assert_eq!(
            text,
            "\"\\u00e9 \\u2014 \\ud83d\\ude00\\n\\\"\\\\\\u0001\u{7f}\"\n"
        );
    }
}
