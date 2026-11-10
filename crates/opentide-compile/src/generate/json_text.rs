//! JSON files as the exports write them: serde_json's pretty printer at an
//! indent of `n` spaces (`json.dumps(..., indent=n)` lays a document out the
//! same way), every character outside printable ASCII escaped as `\uXXXX`
//! (`ensure_ascii`), so a committed export keeps its bytes.

use std::io;

use serde::Serialize;
use serde_json::ser::{Formatter, PrettyFormatter};

use crate::json::{Json, Object};

/// serde_json's [`PrettyFormatter`] with string contents escaped to ASCII.
struct AsciiPretty<'a>(PrettyFormatter<'a>);

impl Formatter for AsciiPretty<'_> {
    fn begin_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_array(writer)
    }
    fn end_array<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_array(writer)
    }
    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_array_value(writer, first)
    }
    fn end_array_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_array_value(writer)
    }
    fn begin_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_object(writer)
    }
    fn end_object<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_object(writer)
    }
    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_object_key(writer, first)
    }
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.begin_object_value(writer)
    }
    fn end_object_value<W: ?Sized + io::Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.0.end_object_value(writer)
    }
    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (at, ch) in fragment.char_indices() {
            if (' '..='~').contains(&ch) {
                continue;
            }
            writer.write_all(&fragment.as_bytes()[start..at])?;
            let mut units = [0u16; 2];
            for unit in ch.encode_utf16(&mut units) {
                write!(writer, "\\u{unit:04x}")?;
            }
            start = at + ch.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

/// `value` as a file: laid out at `indent` spaces, ASCII only, with a final newline.
pub fn pretty(value: &Json, indent: usize) -> String {
    let spaces = " ".repeat(indent);
    let mut bytes = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(
        &mut bytes,
        AsciiPretty(PrettyFormatter::with_indent(spaces.as_bytes())),
    );
    // Writing to a Vec cannot fail; a float JSON cannot carry is written `null`.
    if value.serialize(&mut serializer).is_err() {
        bytes.clear();
    }
    let mut text = String::from_utf8(bytes).unwrap_or_default();
    text.push('\n');
    text
}

/// `value` with every object's keys sorted (`sort_keys=True`): by code
/// point, which is UTF-8 byte order.
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
    fn laid_out_as_json_dumps_with_an_indent() {
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
    fn non_ascii_is_escaped() {
        assert_eq!(
            pretty(&Json::Str("é\u{7f}\u{1f600}\"\n".into()), 2),
            "\"\\u00e9\\u007f\\ud83d\\ude00\\\"\\n\"\n"
        );
    }
}
