//! JSON as the exports write it, UTF-8 throughout: serde_json's pretty
//! printer at an indent of `n` spaces, serde_json's compact line, or one
//! line with a space after each `,` and `:` for a value that becomes text
//! (the explorer's search content, where the space keeps words apart).

use std::io;

use serde::Serialize;
use serde_json::ser::{Formatter, PrettyFormatter};

use crate::json::{Json, Object};

/// serde_json's [`CompactFormatter`] with a space after each separator.
struct Spaced;

impl Formatter for Spaced {
    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }
    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.begin_array_value(writer, first)
    }
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(b": ")
    }
}

/// `value` as a file: laid out at `indent` spaces, with a final newline.
pub fn pretty(value: &Json, indent: usize) -> String {
    let spaces = " ".repeat(indent);
    let mut bytes = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(
        &mut bytes,
        PrettyFormatter::with_indent(spaces.as_bytes()),
    );
    // Writing to a Vec cannot fail; a float JSON cannot carry is written `null`.
    if value.serialize(&mut serializer).is_err() {
        bytes.clear();
    }
    let mut text = String::from_utf8(bytes).unwrap_or_default();
    text.push('\n');
    text
}

/// `value` as text on one line, `, ` and `: ` between items, without a final
/// newline.
pub fn line(value: &Json) -> String {
    let mut bytes = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, Spaced);
    // Writing to a Vec cannot fail; a float JSON cannot carry is written `null`.
    if value.serialize(&mut serializer).is_err() {
        bytes.clear();
    }
    String::from_utf8(bytes).unwrap_or_default()
}

/// `value` with every object's keys sorted, by code point (UTF-8 byte
/// order), so an export is the same whatever order its objects were read in.
pub fn sorted(value: Json) -> Json {
    match value {
        Json::Object(object) => {
            let mut entries: Vec<(String, Json)> = object
                .into_iter()
                .map(|(key, value)| (key, sorted(value)))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Json::Object(entries.into_iter().collect::<Object>())
        }
        Json::Array(items) => Json::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laid_out_at_an_indent() {
        let mut object = Object::new();
        object.insert("b".into(), Json::Array(vec![]));
        object.insert("a".into(), Json::Object(Object::new()));
        object.insert("c".into(), Json::Array(vec![Json::Int(1), Json::Null]));
        assert_eq!(
            pretty(&Json::Object(object.clone()), 2),
            "{\n  \"b\": [],\n  \"a\": {},\n  \"c\": [\n    1,\n    null\n  ]\n}\n"
        );
        assert_eq!(
            pretty(&sorted(Json::Object(object)), 4),
            "{\n    \"a\": {},\n    \"b\": [],\n    \"c\": [\n        1,\n        null\n    ]\n}\n"
        );
    }

    #[test]
    fn one_line_with_a_space_after_each_separator() {
        let mut object = Object::new();
        object.insert("a".into(), Json::Array(vec![Json::Int(1), Json::Null]));
        object.insert("b".into(), Json::Object(Object::new()));
        object.insert("é".into(), Json::Array(vec![]));
        let mut inner = Object::new();
        inner.insert("x".into(), Json::Bool(true));
        inner.insert("y".into(), Json::Float(1.5));
        object.insert("c".into(), Json::Object(inner));
        assert_eq!(
            line(&Json::Object(object)),
            "{\"a\": [1, null], \"b\": {}, \"\u{e9}\": [], \"c\": {\"x\": true, \"y\": 1.5}}"
        );
    }

    #[test]
    fn non_ascii_stays_utf8() {
        assert_eq!(
            pretty(&Json::Str("\u{e9}\u{7f}\u{1f600}\"\n".into()), 2),
            "\"\u{e9}\u{7f}\u{1f600}\\\"\\n\"\n"
        );
    }
}
