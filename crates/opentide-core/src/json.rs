//! A JSON value whose objects keep their keys in insertion order.
//!
//! What opentide writes (envelopes, request bodies, generated schemas) is built
//! key by key, and the order is part of what a reader sees. `serde_json::Value`
//! sorts its keys unless serde_json's `preserve_order` feature is on, and that
//! feature is unified across a build: it would change the map of every crate,
//! `opentide-compare` and the goldens included. So the workspace keeps it off
//! and builds ordered documents with this [`Json`], whose objects are
//! [`IndexMap`]s. It is read and written with serde, so serde_json's parser and
//! formatters do the text.
//!
//! An object holds a key once: a key inserted again keeps its first position
//! and takes the new value, which is also what parsing a document with a
//! repeated key gives.

use std::fmt;
use std::ops::{Deref, DerefMut};

use indexmap::IndexMap;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::ser::PrettyFormatter;

use crate::node::{Node, Value as NodeValue};

/// An object: its members in insertion order.
///
/// An [`IndexMap`] behind a pointer. A [`Json`] is as large as its largest
/// variant, and an `IndexMap` held inline is 72 bytes: every number, string and
/// `null` of a document would take that, 2.5 times the 32 bytes the other
/// variants need (`info catalog`'s peak memory grew by 10 MiB with it). The map's
/// own methods are the object's, through `Deref`.
#[derive(Clone, Default, PartialEq)]
pub struct Object(Box<IndexMap<String, Json>>);

impl Object {
    /// An empty object.
    pub fn new() -> Object {
        Object::default()
    }

    /// An empty object with room for `capacity` members.
    pub fn with_capacity(capacity: usize) -> Object {
        Object(Box::new(IndexMap::with_capacity(capacity)))
    }

    /// The members as the map that holds them.
    pub fn into_map(self) -> IndexMap<String, Json> {
        *self.0
    }
}

impl Deref for Object {
    type Target = IndexMap<String, Json>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Object {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<IndexMap<String, Json>> for Object {
    fn from(map: IndexMap<String, Json>) -> Object {
        Object(Box::new(map))
    }
}

impl<const N: usize> From<[(String, Json); N]> for Object {
    fn from(members: [(String, Json); N]) -> Object {
        members.into_iter().collect()
    }
}

impl FromIterator<(String, Json)> for Object {
    fn from_iter<I: IntoIterator<Item = (String, Json)>>(members: I) -> Object {
        Object(Box::new(members.into_iter().collect()))
    }
}

impl Extend<(String, Json)> for Object {
    fn extend<I: IntoIterator<Item = (String, Json)>>(&mut self, members: I) {
        self.0.extend(members);
    }
}

impl IntoIterator for Object {
    type Item = (String, Json);
    type IntoIter = indexmap::map::IntoIter<String, Json>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_map().into_iter()
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a String, &'a Json);
    type IntoIter = indexmap::map::Iter<'a, String, Json>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut Object {
    type Item = (&'a String, &'a mut Json);
    type IntoIter = indexmap::map::IterMut<'a, String, Json>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

/// A JSON value.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Json {
    /// `null`.
    #[default]
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A whole number that fits `i64`.
    Int(i64),
    /// A whole number above `i64::MAX`.
    UInt(u64),
    /// Any other number. NaN and the infinities, which JSON has no number
    /// for, are written `null`, as serde_json writes them.
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, its members in insertion order.
    Object(Object),
}

impl Json {
    /// An object from `(key, value)` members, in their order.
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

    /// Whether the value is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    /// The value of a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// A whole number that fits `i64`.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(value) => Some(*value),
            _ => None,
        }
    }

    /// A whole number that is not negative.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(value) => u64::try_from(*value).ok(),
            Json::UInt(value) => Some(*value),
            _ => None,
        }
    }

    /// The text of a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text),
            _ => None,
        }
    }

    /// The items of an array.
    pub fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The members of an object.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Json::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The members of an object, mutably.
    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Json::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The value of `key`, if this is an object that has it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object()?.get(key)
    }

    /// The value of `key`, mutably, if this is an object that has it.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        self.as_object_mut()?.get_mut(key)
    }

    /// Parses JSON text, keeping key order.
    ///
    /// # Errors
    ///
    /// serde_json's error when `text` is not one JSON document.
    pub fn parse(text: &str) -> Result<Json, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// `value` serialised with serde: a struct's fields in declaration order.
    ///
    /// # Errors
    ///
    /// serde_json's error when `value` cannot be written as JSON (a map with
    /// keys that are not strings, or a failing `Serialize`).
    pub fn from_serialize<T: Serialize + ?Sized>(value: &T) -> Result<Json, serde_json::Error> {
        serde_json::from_str(&serde_json::to_string(value)?)
    }

    /// The value of a YAML node, keys in the document's order. A key that is
    /// not a string is written as JSON writes a dict key of that type.
    pub fn from_node(node: &Node) -> Json {
        match &node.value {
            NodeValue::Null => Json::Null,
            NodeValue::Bool(flag) => Json::Bool(*flag),
            NodeValue::Int(integer) => Json::Int(*integer),
            NodeValue::Float(float) => Json::Float(*float),
            NodeValue::Str(text) | NodeValue::Datetime(text) => Json::Str(text.clone()),
            NodeValue::Seq(items) => {
                Json::Array(items.iter().map(|item| Json::from_node(item)).collect())
            }
            NodeValue::Map(entries) => Json::Object(
                entries
                    .iter()
                    .map(|entry| (key_text(&entry.key), Json::from_node(&entry.value)))
                    .collect(),
            ),
        }
    }

    /// Whether the value is `true`.
    pub fn is_true(&self) -> bool {
        matches!(self, Json::Bool(true))
    }

    /// Whether the value holds something: it is not `null` and not an empty
    /// string, array or object. A boolean or a number is a value, `false`
    /// and `0` included.
    pub fn is_filled(&self) -> bool {
        match self {
            Json::Null => false,
            Json::Str(text) => !text.is_empty(),
            Json::Array(items) => !items.is_empty(),
            Json::Object(object) => !object.is_empty(),
            Json::Bool(_) | Json::Int(_) | Json::UInt(_) | Json::Float(_) => true,
        }
    }

    /// Whether the value names something (a UUID, a reference, a
    /// relation): a non-empty string or a number. `null`, a boolean, an
    /// array and an object name nothing.
    pub fn is_name(&self) -> bool {
        match self {
            Json::Str(text) => !text.is_empty(),
            Json::Int(_) | Json::UInt(_) | Json::Float(_) => true,
            Json::Null | Json::Bool(_) | Json::Array(_) | Json::Object(_) => false,
        }
    }

    /// The value as serde_json writes it on one line, UTF-8 as is.
    pub fn to_compact(&self) -> String {
        // Writing into memory cannot fail: every key is a string, and a float
        // JSON cannot carry is written `null`.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The value as serde_json's pretty printer writes it, each level
    /// indented by `indent` spaces, UTF-8 as is, without a final newline.
    pub fn to_pretty(&self, indent: usize) -> String {
        let indent = " ".repeat(indent);
        let mut bytes = Vec::new();
        let formatter = PrettyFormatter::with_indent(indent.as_bytes());
        let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, formatter);
        // As in `to_compact`, writing into memory cannot fail.
        if self.serialize(&mut serializer).is_err() {
            return String::new();
        }
        // serde_json writes UTF-8.
        String::from_utf8(bytes).unwrap_or_default()
    }
}

/// A mapping key as JSON writes a dict key: a string as is, a number or a
/// boolean as its text.
fn key_text(node: &Node) -> String {
    match &node.value {
        NodeValue::Str(text) | NodeValue::Datetime(text) => text.clone(),
        NodeValue::Int(integer) => integer.to_string(),
        NodeValue::Float(float) => float_key(*float),
        NodeValue::Bool(flag) => if *flag { "true" } else { "false" }.to_owned(),
        NodeValue::Null => "null".to_owned(),
        // A collection cannot key a Python dict; the oracle could not load it.
        NodeValue::Seq(_) | NodeValue::Map(_) => Json::from_node(node).to_compact(),
    }
}

/// A float key as JSON writes the number (`1.0`, `1e+16`), and NaN and the
/// infinities, which JSON has no number for, as Rust prints them.
fn float_key(value: f64) -> String {
    serde_json::Number::from_f64(value)
        .map_or_else(|| value.to_string(), |number| number.to_string())
}

impl From<bool> for Json {
    fn from(value: bool) -> Json {
        Json::Bool(value)
    }
}

impl From<i64> for Json {
    fn from(value: i64) -> Json {
        Json::Int(value)
    }
}

impl From<u64> for Json {
    fn from(value: u64) -> Json {
        i64::try_from(value).map_or(Json::UInt(value), Json::Int)
    }
}

impl From<usize> for Json {
    fn from(value: usize) -> Json {
        // usize is at most 64 bits on every target Rust supports.
        Json::from(u64::try_from(value).unwrap_or(u64::MAX))
    }
}

impl From<f64> for Json {
    fn from(value: f64) -> Json {
        Json::Float(value)
    }
}

impl From<&str> for Json {
    fn from(text: &str) -> Json {
        Json::Str(text.to_owned())
    }
}

impl From<String> for Json {
    fn from(text: String) -> Json {
        Json::Str(text)
    }
}

impl From<Vec<Json>> for Json {
    fn from(items: Vec<Json>) -> Json {
        Json::Array(items)
    }
}

impl From<Vec<String>> for Json {
    fn from(items: Vec<String>) -> Json {
        Json::Array(items.into_iter().map(Json::Str).collect())
    }
}

impl From<Object> for Json {
    fn from(members: Object) -> Json {
        Json::Object(members)
    }
}

impl From<&serde_json::Value> for Json {
    /// A `serde_json` value, its object keys in the order it holds them
    /// (sorted, since the workspace keeps `preserve_order` off).
    fn from(value: &serde_json::Value) -> Json {
        match value {
            serde_json::Value::Null => Json::Null,
            serde_json::Value::Bool(flag) => Json::Bool(*flag),
            serde_json::Value::Number(number) => Json::from(number),
            serde_json::Value::String(text) => Json::Str(text.clone()),
            serde_json::Value::Array(items) => Json::Array(items.iter().map(Json::from).collect()),
            serde_json::Value::Object(map) => Json::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), Json::from(value)))
                    .collect(),
            ),
        }
    }
}

impl From<&serde_json::Number> for Json {
    fn from(number: &serde_json::Number) -> Json {
        if let Some(value) = number.as_i64() {
            Json::Int(value)
        } else if let Some(value) = number.as_u64() {
            Json::UInt(value)
        } else {
            // A number that is neither i64 nor u64 is an f64 in serde_json.
            Json::Float(number.as_f64().unwrap_or(f64::NAN))
        }
    }
}

impl Serialize for Object {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in self {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Object, D::Error> {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Object;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Object, A::Error> {
                let mut members = Object::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((key, value)) = map.next_entry::<String, Json>()? {
                    members.insert(key, value);
                }
                Ok(members)
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
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
            Json::Str(text) => serializer.serialize_str(text),
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

/// Reads any serde value, keys in the order they come.
impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Json, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_none<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Json, D::Error> {
        Json::deserialize(deserializer)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Int(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Json, E> {
        Ok(Json::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Json, E> {
        Ok(Json::Float(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Json, E> {
        Ok(Json::Str(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Json, E> {
        Ok(Json::Str(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut members = Object::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((key, value)) = map.next_entry::<String, Json>()? {
            members.insert(key, value);
        }
        Ok(Json::Object(members))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document holds a `Json` per value: an object must not make every
    /// number and string as large as an `IndexMap`.
    #[test]
    fn a_value_is_as_large_as_a_string() {
        assert_eq!(size_of::<Json>(), size_of::<String>() + size_of::<usize>());
    }

    #[test]
    fn an_object_is_built_and_read_like_its_map() {
        let mut object = Object::from([("b".to_owned(), Json::Int(1))]);
        object.insert("a".to_owned(), Json::Int(2));
        object.extend([("c".to_owned(), Json::Int(3))]);
        let keys: Vec<&str> = (&object).into_iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["b", "a", "c"]);
        let owned: Vec<String> = object.clone().into_iter().map(|(key, _)| key).collect();
        assert_eq!(owned, ["b", "a", "c"]);
        assert_eq!(object.into_map().len(), 3);
    }

    #[test]
    fn objects_keep_their_key_order_through_a_round_trip() {
        let text = r#"{"z":1,"a":[true,null,{"y":"x","b":2.5}],"m":18446744073709551615,"n":-3}"#;
        let json = Json::parse(text).unwrap();
        assert_eq!(json.to_compact(), text);
        assert_eq!(json.get("m"), Some(&Json::UInt(u64::MAX)));
        assert_eq!(json.get("n").and_then(Json::as_i64), Some(-3));
    }

    #[test]
    fn writes_the_bytes_serde_json_writes_for_the_same_document() {
        // With keys already sorted, serde_json's own Value is the reference:
        // the same numbers, escapes and layout, byte for byte.
        let text = r#"{"a":[1,-2,2.5,1e300,120.0,18446744073709551615],"b":"é — 😀\n\"\\\u0001","c":{},"d":[],"e":null,"f":false}"#;
        let ours = Json::parse(text).unwrap();
        let reference: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            ours.to_compact(),
            serde_json::to_string(&reference).unwrap()
        );
        assert_eq!(
            ours.to_pretty(2),
            serde_json::to_string_pretty(&reference).unwrap()
        );
        assert_eq!(Json::from(&reference), ours);
    }

    #[test]
    fn pretty_indents_by_the_given_width_and_keeps_empty_containers_inline() {
        let json = Json::object([
            ("b", Json::Array(vec![Json::from("x"), Json::Array(vec![])])),
            ("a", Json::Object(Object::new())),
        ]);
        assert_eq!(
            json.to_pretty(4),
            "{\n    \"b\": [\n        \"x\",\n        []\n    ],\n    \"a\": {}\n}"
        );
        assert_eq!(
            json.to_pretty(2),
            "{\n  \"b\": [\n    \"x\",\n    []\n  ],\n  \"a\": {}\n}"
        );
    }

    #[test]
    fn floats_keep_their_point_and_non_finite_ones_are_null() {
        assert_eq!(Json::Float(120.0).to_compact(), "120.0");
        assert_eq!(Json::Float(1e16).to_compact(), "1e+16");
        assert_eq!(Json::Float(f64::NAN).to_compact(), "null");
        assert_eq!(Json::Float(f64::INFINITY).to_compact(), "null");
    }

    #[test]
    fn a_repeated_key_keeps_its_first_place_and_its_last_value() {
        let json = Json::parse(r#"{"a":1,"b":2,"a":3}"#).unwrap();
        assert_eq!(json.to_compact(), r#"{"a":3,"b":2}"#);
        let mut members = Object::new();
        members.insert("x".into(), Json::Int(1));
        members.insert("y".into(), Json::Int(2));
        members.insert("x".into(), Json::Int(3));
        assert_eq!(Json::Object(members).to_compact(), r#"{"x":3,"y":2}"#);
    }

    #[test]
    fn a_serialised_value_keeps_its_field_order() {
        #[derive(serde::Serialize)]
        struct Model {
            zeta: u8,
            alpha: Option<&'static str>,
            nested: Vec<f64>,
            big: u64,
        }
        let json = Json::from_serialize(&Model {
            zeta: 1,
            alpha: None,
            nested: vec![0.5],
            big: u64::MAX,
        })
        .unwrap();
        assert_eq!(
            json.to_compact(),
            r#"{"zeta":1,"alpha":null,"nested":[0.5],"big":18446744073709551615}"#
        );
    }

    #[test]
    fn numbers_take_the_narrowest_variant() {
        assert_eq!(Json::from(5_u64), Json::Int(5));
        assert_eq!(Json::from(u64::MAX), Json::UInt(u64::MAX));
        assert_eq!(Json::from(7_usize), Json::Int(7));
        assert_eq!(
            Json::from(&serde_json::Number::from_f64(2.5).unwrap()),
            Json::Float(2.5)
        );
        assert_eq!(Json::Int(-1).as_u64(), None);
        assert_eq!(Json::UInt(u64::MAX).as_u64(), Some(u64::MAX));
    }

    #[test]
    fn accessors_read_their_variant_only() {
        let mut json = Json::object([("a", Json::str("x")), ("b", Json::from(true))]);
        assert_eq!(json.get("a").and_then(Json::as_str), Some("x"));
        assert_eq!(json.get("b").and_then(Json::as_bool), Some(true));
        assert_eq!(json.get("c"), None);
        assert_eq!(Json::Null.get("a"), None);
        assert!(Json::opt_str(None::<String>).is_null());
        assert_eq!(Json::opt_str(Some("y")), Json::str("y"));
        if let Some(value) = json.get_mut("a") {
            *value = Json::from(vec!["p".to_owned()]);
        }
        assert_eq!(json.to_compact(), r#"{"a":["p"],"b":true}"#);
        assert_eq!(json.as_array(), None);
        assert_eq!(Json::default(), Json::Null);
    }

    /// A node becomes its JSON, keys in the document's order, a non-string
    /// key as JSON writes it.
    #[test]
    fn a_node_becomes_its_json() {
        let document = crate::node::load("b: 1\na: [x, 2.5, true, ~]\n1: k\n").unwrap();
        let json = Json::from_node(document.root().unwrap());
        assert_eq!(
            json.to_compact(),
            r#"{"b":1,"a":["x",2.5,true,null],"1":"k"}"#
        );
    }

    /// A value is read by its type: `false` and `0` are values, not empty
    /// ones; only `true` is true; a name is text or a number.
    #[test]
    fn values_are_read_by_their_type() {
        assert!(!Json::Null.is_filled());
        assert!(!Json::Str(String::new()).is_filled());
        assert!(!Json::Array(vec![]).is_filled());
        assert!(!Json::Object(Object::new()).is_filled());
        for value in [
            Json::Bool(false),
            Json::Int(0),
            Json::Float(0.0),
            Json::UInt(u64::MAX),
            Json::Str("x".into()),
        ] {
            assert!(value.is_filled(), "{value:?}");
        }
        assert!(Json::Bool(true).is_true());
        for value in [Json::Bool(false), Json::Int(1), Json::Str("true".into())] {
            assert!(!value.is_true(), "{value:?}");
        }
        assert!(Json::Int(0).is_name());
        assert!(Json::UInt(u64::MAX).is_name());
        assert!(Json::Str("u-1".into()).is_name());
        for value in [
            Json::Null,
            Json::Bool(true),
            Json::Str(String::new()),
            Json::Array(vec![Json::Int(1)]),
        ] {
            assert!(!value.is_name(), "{value:?}");
        }
    }

    #[test]
    fn float_keys_are_written_as_json_writes_the_number() {
        assert_eq!(float_key(1.0), "1.0");
        assert_eq!(float_key(2.5), "2.5");
        assert_eq!(float_key(1e16), "1e+16");
        assert_eq!(float_key(1e-5), "0.00001");
        assert_eq!(float_key(f64::NAN), "NaN");
        assert_eq!(float_key(f64::NEG_INFINITY), "-inf");
    }

    /// An object is read and written alone, its keys in order.
    #[test]
    fn an_object_alone_round_trips_in_order() {
        let object: Object = serde_json::from_str(r#"{"z":1,"a":[true]}"#).unwrap();
        assert_eq!(
            serde_json::to_string(&object).unwrap(),
            r#"{"z":1,"a":[true]}"#
        );
        let refused = serde_json::from_str::<Object>("[1]")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("a JSON object"), "{refused}");
    }
}
