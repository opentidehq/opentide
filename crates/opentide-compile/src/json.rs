//! A JSON value that keeps the order its keys are inserted in: a request
//! body is built key by key, as the oracle builds its dicts, and is sent and
//! printed in that order. `serde_json::Value` sorts its keys unless the
//! workspace turns on `preserve_order` for every crate at once.

use std::fmt::Write as _;

use indexmap::IndexMap;
use opentide_schema::configuration::repr::float_text;
use opentide_schema::node::{Node, Value};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

/// An object: keys in insertion order.
pub type Object = IndexMap<String, Json>;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A float.
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object.
    Object(Object),
}

impl Json {
    /// The value of a YAML node, keys in the document's order. A key that is
    /// not a string is written as JSON writes a dict key of that type.
    pub fn from_node(node: &Node) -> Self {
        match &node.value {
            Value::Null => Self::Null,
            Value::Bool(flag) => Self::Bool(*flag),
            Value::Int(integer) => Self::Int(*integer),
            Value::Float(float) => Self::Float(*float),
            Value::Str(text) | Value::Datetime(text) => Self::Str(text.clone()),
            Value::Seq(items) => {
                Self::Array(items.iter().map(|item| Self::from_node(item)).collect())
            }
            Value::Map(entries) => Self::Object(
                entries
                    .iter()
                    .map(|entry| (key_text(&entry.key), Self::from_node(&entry.value)))
                    .collect(),
            ),
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }

    /// The object, if this is one.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }

    /// The value at `key`, if this is an object that has it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object()?.get(key)
    }

    /// Whether the value is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Python's truthiness: `null`, `false`, `0`, `0.0`, `""`, `[]` and `{}`
    /// are false.
    pub fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(flag) => *flag,
            Self::Int(integer) => *integer != 0,
            Self::Float(float) => *float != 0.0,
            Self::Str(text) => !text.is_empty(),
            Self::Array(items) => !items.is_empty(),
            Self::Object(object) => !object.is_empty(),
        }
    }

    /// The compact JSON text (`separators=(",", ":")`, UTF-8 as is).
    pub fn to_compact(&self) -> String {
        // Writing to a String cannot fail, and every value is serialisable:
        // a float that JSON cannot carry (NaN, infinity) is written `null`.
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A mapping key as JSON writes a dict key: a string as is, a number or a
/// boolean as its text.
fn key_text(node: &Node) -> String {
    match &node.value {
        Value::Str(text) | Value::Datetime(text) => text.clone(),
        Value::Int(integer) => integer.to_string(),
        Value::Float(float) => python_float(*float),
        Value::Bool(flag) => if *flag { "true" } else { "false" }.to_owned(),
        Value::Null => "null".to_owned(),
        // A collection cannot key a Python dict; the oracle could not load it.
        Value::Seq(_) | Value::Map(_) => {
            let mut text = String::new();
            let _ = write!(text, "{}", Json::from_node(node).to_compact());
            text
        }
    }
}

/// A float as `json.dumps` writes a dict key: `NaN`, `Infinity` and
/// `-Infinity` for what JSON has no number for, otherwise Python's `repr`.
fn python_float(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value.is_infinite() {
        if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned()
    } else {
        float_text(value)
    }
}

impl Serialize for Json {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(flag) => serializer.serialize_bool(*flag),
            Self::Int(integer) => serializer.serialize_i64(*integer),
            Self::Float(float) => serializer.serialize_f64(*float),
            Self::Str(text) => serializer.serialize_str(text),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Object(object) => {
                let mut map = serializer.serialize_map(Some(object.len()))?;
                for (key, value) in object {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl From<&str> for Json {
    fn from(text: &str) -> Self {
        Self::Str(text.to_owned())
    }
}

impl From<String> for Json {
    fn from(text: String) -> Self {
        Self::Str(text)
    }
}

impl From<bool> for Json {
    fn from(flag: bool) -> Self {
        Self::Bool(flag)
    }
}

impl From<i64> for Json {
    fn from(integer: i64) -> Self {
        Self::Int(integer)
    }
}

impl From<Vec<Json>> for Json {
    fn from(items: Vec<Json>) -> Self {
        Self::Array(items)
    }
}

impl From<Object> for Json {
    fn from(object: Object) -> Self {
        Self::Object(object)
    }
}

impl From<Vec<String>> for Json {
    fn from(items: Vec<String>) -> Self {
        Self::Array(items.into_iter().map(Self::Str).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_keep_their_order() {
        let mut object = Object::new();
        object.insert("z".into(), Json::Int(1));
        object.insert("a".into(), Json::Null);
        assert_eq!(Json::Object(object).to_compact(), r#"{"z":1,"a":null}"#);
    }

    #[test]
    fn a_node_becomes_its_json() {
        let document = opentide_schema::node::load("b: 1\na: [x, 2.5, true, ~]\n1: k\n").unwrap();
        let json = Json::from_node(document.root().unwrap());
        assert_eq!(
            json.to_compact(),
            r#"{"b":1,"a":["x",2.5,true,null],"1":"k"}"#
        );
    }

    #[test]
    fn truthiness_is_pythons() {
        assert!(!Json::Str(String::new()).truthy());
        assert!(!Json::Array(vec![]).truthy());
        assert!(!Json::Int(0).truthy());
        assert!(Json::Str("x".into()).truthy());
    }

    #[test]
    fn float_keys_are_written_as_python_writes_them() {
        assert_eq!(python_float(1.0), "1.0");
        assert_eq!(python_float(2.5), "2.5");
        assert_eq!(python_float(1e16), "1e+16");
        assert_eq!(python_float(1e-5), "1e-05");
        assert_eq!(python_float(f64::NAN), "NaN");
        assert_eq!(python_float(f64::NEG_INFINITY), "-Infinity");
    }
}
