//! Generated JSON documents: keys in the order they are built in (a schema
//! reads in that order), written by `serde_json`'s pretty printer at four
//! spaces with a final newline, every character as UTF-8.
//!
//! The workspace's `serde_json` keeps object keys sorted (`preserve_order`
//! is off: ADR 0001), so a generated document is a [`Json`], whose objects
//! are `IndexMap`s.

use indexmap::IndexMap;
use serde::Serialize;
use serde_json::ser::PrettyFormatter;

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

    /// The document as a file: four-space indentation and a final newline.
    pub fn to_text(&self) -> String {
        let mut out = Vec::new();
        let mut serializer =
            serde_json::Serializer::with_formatter(&mut out, PrettyFormatter::with_indent(b"    "));
        // Writing into a Vec cannot fail, and a Json holds no map with
        // non-string keys.
        if self.serialize(&mut serializer).is_err() {
            return String::new();
        }
        out.push(b'\n');
        // serde_json writes UTF-8.
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
            document.to_text(),
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
            document.to_text(),
            "{\n    \"list\": [\n        \"x\",\n        []\n    ],\n    \"empty\": {},\n    \"null\": null,\n    \"number\": 3\n}\n"
        );
    }

    #[test]
    fn non_ascii_stays_utf8() {
        let text = Json::from("é — 😀\n\"\\\u{1}").to_text();
        assert_eq!(text, "\"é — 😀\\n\\\"\\\\\\u0001\"\n");
    }
}
