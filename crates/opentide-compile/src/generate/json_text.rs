//! JSON as the exports write it, UTF-8 throughout: serde_json's pretty
//! printer at an indent of `n` spaces for a file. A value on one line (the
//! explorer's bundle and search content, the inflight change metadata) is
//! serde_json's compact text, [`Json::to_compact`].

use serde::Serialize;
use serde_json::ser::PrettyFormatter;

use crate::json::{Json, Object};

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
    fn one_line_is_compact_utf8_in_key_order() {
        let mut object = Object::new();
        object.insert("a".into(), Json::Array(vec![Json::Int(1), Json::Null]));
        object.insert("b".into(), Json::Object(Object::new()));
        object.insert("é".into(), Json::Array(vec![]));
        let mut inner = Object::new();
        inner.insert("x".into(), Json::Bool(true));
        inner.insert("y".into(), Json::Float(1.5));
        object.insert("c".into(), Json::Object(inner));
        assert_eq!(
            Json::Object(object).to_compact(),
            "{\"a\":[1,null],\"b\":{},\"\u{e9}\":[],\"c\":{\"x\":true,\"y\":1.5}}"
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
