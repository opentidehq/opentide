//! JSON whose objects keep their key order, and the document text the CLI prints.
//!
//! The envelope's key order is part of the contract (`docs/cli/json-output.md`):
//! a reader may compare documents as text. serde_json's `Value` sorts object
//! keys unless its `preserve_order` feature is on, and that feature would change
//! the map type of every crate built with this one (`opentide-compare` relies on
//! the default), so the CLI keeps its own small tree. It is (de)serialised with
//! serde and written with serde_json's formatters.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::fmt;

/// A JSON value; an object is its members in order.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// A whole number that fits `i64`.
    Int(i64),
    /// A whole number above `i64::MAX`.
    UInt(u64),
    /// Any other number.
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, its members in order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// An object from `(key, value)` pairs.
    pub fn object<K: Into<String>>(members: impl IntoIterator<Item = (K, Json)>) -> Json {
        Json::Object(members.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// A string value.
    pub fn str(text: impl Into<String>) -> Json {
        Json::Str(text.into())
    }

    /// `text` as a string value, or `null`.
    pub fn opt_str(text: Option<impl Into<String>>) -> Json {
        text.map_or(Json::Null, |text| Json::Str(text.into()))
    }

    /// The text of a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text),
            _ => None,
        }
    }

    /// The value of `key` in an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Parses JSON text, keeping key order.
    pub fn parse(text: &str) -> Result<Json, serde_json::Error> {
        serde_json::from_str(text)
    }
}

impl From<usize> for Json {
    fn from(count: usize) -> Json {
        i64::try_from(count).map_or(Json::UInt(count as u64), Json::Int)
    }
}

impl From<bool> for Json {
    fn from(value: bool) -> Json {
        Json::Bool(value)
    }
}

impl Serialize for Json {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Json::Null => serializer.serialize_unit(),
            Json::Bool(value) => serializer.serialize_bool(*value),
            Json::Int(value) => serializer.serialize_i64(*value),
            Json::UInt(value) => serializer.serialize_u64(*value),
            Json::Float(value) => serializer.serialize_f64(*value),
            Json::Str(value) => serializer.serialize_str(value),
            Json::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Json::Object(members) => {
                let mut map = serializer.serialize_map(Some(members.len()))?;
                for (key, value) in members {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Json, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Int(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Json, E> {
        Ok(i64::try_from(value).map_or(Json::UInt(value), Json::Int))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Json, E> {
        Ok(Json::Float(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Json, E> {
        Ok(Json::Str(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Json, E> {
        Ok(Json::Str(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut members = Vec::new();
        while let Some((key, value)) = map.next_entry::<String, Json>()? {
            members.push((key, value));
        }
        Ok(Json::Object(members))
    }
}

/// `document` as the CLI prints it: indented by two spaces when `indent`,
/// otherwise one compact line; either way ending in exactly one newline.
pub fn document_text(document: &Json, indent: bool) -> String {
    let mut bytes = Vec::new();
    let written = if indent {
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, formatter);
        document.serialize(&mut serializer)
    } else {
        document.serialize(&mut serde_json::Serializer::new(&mut bytes))
    };
    // Serialising this tree into memory cannot fail: every key is a string and
    // every float is finite or written as null by serde_json.
    if written.is_err() {
        bytes.clear();
        bytes.extend_from_slice(b"null");
    }
    let mut text = String::from_utf8(bytes).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_keep_their_key_order_through_a_round_trip() {
        let text = r#"{"z":1,"a":[true,null,{"y":"x","b":2.5}],"m":18446744073709551615}"#;
        let json = Json::parse(text).unwrap();
        assert_eq!(document_text(&json, false), format!("{text}\n"));
    }

    #[test]
    fn indented_documents_use_two_spaces_and_one_trailing_newline() {
        let json = Json::object([
            ("a", Json::Int(1)),
            ("b", Json::Array(vec![])),
            ("c", Json::object::<String>([])),
        ]);
        assert_eq!(
            document_text(&json, true),
            "{\n  \"a\": 1,\n  \"b\": [],\n  \"c\": {}\n}\n"
        );
    }

    #[test]
    fn floats_print_as_python_prints_them() {
        assert_eq!(document_text(&Json::Float(120.0), false), "120.0\n");
    }

    #[test]
    fn non_ascii_stays_as_is_and_control_characters_are_escaped() {
        assert_eq!(
            document_text(&Json::str("✓ \u{1b}"), false),
            "\"✓ \\u001b\"\n"
        );
    }

    #[test]
    fn get_reads_a_member() {
        let json = Json::object([("a", Json::Int(1))]);
        assert_eq!(json.get("a"), Some(&Json::Int(1)));
        assert_eq!(json.get("b"), None);
        assert_eq!(Json::Null.get("a"), None);
        assert_eq!(Json::opt_str(None::<String>), Json::Null);
    }
}
