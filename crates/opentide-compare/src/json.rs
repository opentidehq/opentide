//! A JSON tree that keeps the order of an object's keys, and what the
//! comparator does with it: structural differences, key order, JSON pointers,
//! and the two layouts the CLI prints a document in.
//!
//! The tree is built through `serde_json`'s parser without its
//! `preserve_order` feature, which would change the map type of every crate
//! in a build that unifies features.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;

/// A parsed JSON value. Objects keep their keys in document order, duplicates
/// included; derived equality is therefore order-sensitive.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as `serde_json` reads it: `1` and `1.0` differ.
    Number(serde_json::Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, its members in document order.
    Object(Vec<(String, Json)>),
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
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
        Ok(Json::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Json, E> {
        serde_json::Number::from_f64(value)
            .map(Json::Number)
            .ok_or_else(|| E::custom("a number JSON cannot hold"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Json, E> {
        Ok(Json::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Json, E> {
        Ok(Json::String(value))
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

/// `bytes` as one JSON document (surrounding whitespace allowed), or `None`.
pub fn parse(bytes: &[u8]) -> Option<Json> {
    serde_json::from_slice(bytes).ok()
}

/// `text` as one JSON document, or `None`.
pub fn parse_str(text: &str) -> Option<Json> {
    serde_json::from_str(text).ok()
}

impl Json {
    /// Whether `self` and `other` hold the same data, whatever the order of
    /// their objects' keys.
    pub fn same(&self, other: &Json) -> bool {
        match (self, other) {
            (Json::Array(left), Json::Array(right)) => {
                left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a.same(b))
            }
            (Json::Object(left), Json::Object(right)) => {
                if left.len() != right.len() {
                    return false;
                }
                let mut left: Vec<_> = left.iter().collect();
                let mut right: Vec<_> = right.iter().collect();
                left.sort_by(|a, b| a.0.cmp(&b.0));
                right.sort_by(|a, b| a.0.cmp(&b.0));
                left.iter()
                    .zip(&right)
                    .all(|(a, b)| a.0 == b.0 && a.1.same(&b.1))
            }
            (left, right) => left == right,
        }
    }

    /// The value at `pointer` (parsed with [`parse_pointer`]), if there is one.
    pub fn get(&self, pointer: &[String]) -> Option<&Json> {
        let mut current = self;
        for token in pointer {
            current = match current {
                Json::Object(members) => &members.iter().find(|(key, _)| key == token)?.1,
                Json::Array(items) => items.get(array_index(token)?)?,
                _ => return None,
            };
        }
        Some(current)
    }

    /// Where the member or item at `pointer` sits in its parent: its index.
    pub fn position(&self, pointer: &[String]) -> Option<usize> {
        let (last, parent) = pointer.split_last()?;
        match self.get(parent)? {
            Json::Object(members) => members.iter().position(|(key, _)| key == last),
            Json::Array(items) => array_index(last).filter(|index| *index < items.len()),
            _ => None,
        }
    }

    /// Sets the value at `pointer` to `value`, or removes it when `value` is
    /// `None`. A new object member is inserted at `index` (clamped), so that
    /// key order can still be compared. Returns whether anything changed.
    pub fn set(&mut self, pointer: &[String], value: Option<Json>, index: Option<usize>) -> bool {
        let Some((last, parent)) = pointer.split_last() else {
            return match value {
                Some(value) => {
                    *self = value;
                    true
                }
                None => false,
            };
        };
        let Some(parent) = self.get_mut(parent) else {
            return false;
        };
        match parent {
            Json::Object(members) => {
                let existing = members.iter().position(|(key, _)| key == last);
                match (existing, value) {
                    (Some(at), Some(value)) => members[at].1 = value,
                    (Some(at), None) => {
                        members.remove(at);
                    }
                    (None, Some(value)) => {
                        let at = index.unwrap_or(members.len()).min(members.len());
                        members.insert(at, (last.clone(), value));
                    }
                    (None, None) => return false,
                }
                true
            }
            Json::Array(items) => {
                let Some(at) = array_index(last) else {
                    return false;
                };
                match value {
                    Some(value) if at < items.len() => items[at] = value,
                    Some(value) if at == items.len() => items.push(value),
                    None if at < items.len() => {
                        items.remove(at);
                    }
                    _ => return false,
                }
                true
            }
            _ => false,
        }
    }

    fn get_mut(&mut self, pointer: &[String]) -> Option<&mut Json> {
        let mut current = self;
        for token in pointer {
            current = match current {
                Json::Object(members) => &mut members.iter_mut().find(|(key, _)| key == token)?.1,
                Json::Array(items) => items.get_mut(array_index(token)?)?,
                _ => return None,
            };
        }
        Some(current)
    }
}

/// An array index token: decimal, without a leading zero (RFC 6901).
fn array_index(token: &str) -> Option<usize> {
    if token.is_empty()
        || (token.len() > 1 && token.starts_with('0'))
        || !token.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    token.parse().ok()
}

/// The tokens of a JSON pointer (RFC 6901): `""` is the whole document,
/// otherwise it starts with `/`, and `~` is only ever `~0` or `~1`.
pub fn parse_pointer(pointer: &str) -> Option<Vec<String>> {
    if pointer.is_empty() {
        return Some(Vec::new());
    }
    let rest = pointer.strip_prefix('/')?;
    rest.split('/')
        .map(|token| {
            let mut out = String::with_capacity(token.len());
            let mut chars = token.chars();
            while let Some(c) = chars.next() {
                if c == '~' {
                    match chars.next() {
                        Some('0') => out.push('~'),
                        Some('1') => out.push('/'),
                        _ => return None,
                    }
                } else {
                    out.push(c);
                }
            }
            Some(out)
        })
        .collect()
}

/// The JSON pointer of `tokens`.
pub fn format_pointer(tokens: &[String]) -> String {
    tokens.iter().fold(String::new(), |mut out, token| {
        out.push('/');
        out.push_str(&token.replace('~', "~0").replace('/', "~1"));
        out
    })
}

/// One way the data of two documents differs, at a pointer.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonDifference {
    /// The values differ; `None` on the side that has no value there.
    Value {
        /// Where.
        pointer: Vec<String>,
        /// The oracle's value.
        oracle: Option<Json>,
        /// The candidate's value.
        candidate: Option<Json>,
    },
    /// The same keys, in another order.
    KeyOrder {
        /// The object.
        pointer: Vec<String>,
        /// Its keys in the oracle.
        oracle: Vec<String>,
        /// Its keys in the candidate.
        candidate: Vec<String>,
    },
}

/// Where the data of `oracle` and `candidate` differs, key order aside.
pub fn value_differences(oracle: &Json, candidate: &Json) -> Vec<JsonDifference> {
    let mut out = Vec::new();
    values(oracle, candidate, &mut Vec::new(), &mut out);
    out
}

fn values(oracle: &Json, candidate: &Json, at: &mut Vec<String>, out: &mut Vec<JsonDifference>) {
    match (oracle, candidate) {
        (Json::Object(left), Json::Object(right)) => {
            let before = out.len();
            for (key, value) in left {
                at.push(key.clone());
                match right.iter().find(|(other, _)| other == key) {
                    Some((_, other)) => values(value, other, at, out),
                    None => out.push(JsonDifference::Value {
                        pointer: at.clone(),
                        oracle: Some(value.clone()),
                        candidate: None,
                    }),
                }
                at.pop();
            }
            for (key, value) in right {
                if !left.iter().any(|(other, _)| other == key) {
                    at.push(key.clone());
                    out.push(JsonDifference::Value {
                        pointer: at.clone(),
                        oracle: None,
                        candidate: Some(value.clone()),
                    });
                    at.pop();
                }
            }
            // Duplicate keys: the lookups above pair the first of each, so a
            // second copy that differs is reported as the whole object.
            if out.len() == before && !oracle.same(candidate) {
                out.push(JsonDifference::Value {
                    pointer: at.clone(),
                    oracle: Some(oracle.clone()),
                    candidate: Some(candidate.clone()),
                });
            }
        }
        (Json::Array(left), Json::Array(right)) => {
            for index in 0..left.len().max(right.len()) {
                at.push(index.to_string());
                match (left.get(index), right.get(index)) {
                    (Some(a), Some(b)) => values(a, b, at, out),
                    (a, b) => out.push(JsonDifference::Value {
                        pointer: at.clone(),
                        oracle: a.cloned(),
                        candidate: b.cloned(),
                    }),
                }
                at.pop();
            }
        }
        (left, right) => {
            if left != right {
                out.push(JsonDifference::Value {
                    pointer: at.clone(),
                    oracle: Some(left.clone()),
                    candidate: Some(right.clone()),
                });
            }
        }
    }
}

/// The objects whose keys come in another order, for two documents whose
/// data is the same ([`Json::same`]).
pub fn key_order_differences(oracle: &Json, candidate: &Json) -> Vec<JsonDifference> {
    let mut out = Vec::new();
    key_order(oracle, candidate, &mut Vec::new(), &mut out);
    out
}

fn key_order(oracle: &Json, candidate: &Json, at: &mut Vec<String>, out: &mut Vec<JsonDifference>) {
    match (oracle, candidate) {
        (Json::Object(left), Json::Object(right)) => {
            let left_keys: Vec<String> = left.iter().map(|(key, _)| key.clone()).collect();
            let right_keys: Vec<String> = right.iter().map(|(key, _)| key.clone()).collect();
            if left_keys != right_keys {
                out.push(JsonDifference::KeyOrder {
                    pointer: at.clone(),
                    oracle: left_keys,
                    candidate: right_keys,
                });
            }
            for (key, value) in left {
                if let Some((_, other)) = right.iter().find(|(other, _)| other == key) {
                    at.push(key.clone());
                    key_order(value, other, at, out);
                    at.pop();
                }
            }
        }
        (Json::Array(left), Json::Array(right)) => {
            for (index, (a, b)) in left.iter().zip(right).enumerate() {
                at.push(index.to_string());
                key_order(a, b, at, out);
                at.pop();
            }
        }
        _ => {}
    }
}

/// How the CLI lays a document out: orjson's compact line or its two-space
/// indentation, each with or without a final newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `{"a":1}`.
    Compact,
    /// `{\n  "a": 1\n}`.
    Indented,
}

/// The layouts the comparator knows, each with and without a final newline.
pub const LAYOUTS: [(Layout, bool); 4] = [
    (Layout::Compact, true),
    (Layout::Indented, true),
    (Layout::Compact, false),
    (Layout::Indented, false),
];

/// `value` written in `layout`, ending in a newline when `newline` is set.
pub fn write(value: &Json, layout: Layout, newline: bool) -> Vec<u8> {
    let mut out = String::new();
    write_value(value, layout, 0, &mut out);
    if newline {
        out.push('\n');
    }
    out.into_bytes()
}

/// `value` on one line, for a report.
pub fn compact(value: &Json) -> String {
    let mut out = String::new();
    write_value(value, Layout::Compact, 0, &mut out);
    out
}

fn write_value(value: &Json, layout: Layout, depth: usize, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Json::Number(number) => out.push_str(&number.to_string()),
        Json::String(text) => write_string(text, out),
        Json::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                indent(layout, depth + 1, out);
                write_value(item, layout, depth + 1, out);
            }
            indent(layout, depth, out);
            out.push(']');
        }
        Json::Object(members) => {
            if members.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (index, (key, item)) in members.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                indent(layout, depth + 1, out);
                write_string(key, out);
                out.push(':');
                if layout == Layout::Indented {
                    out.push(' ');
                }
                write_value(item, layout, depth + 1, out);
            }
            indent(layout, depth, out);
            out.push('}');
        }
    }
}

fn indent(layout: Layout, depth: usize, out: &mut String) {
    if layout == Layout::Indented {
        out.push('\n');
        for _ in 0..depth {
            out.push_str("  ");
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    // serde_json escapes as orjson does: `"`, `\`, and control characters,
    // with the short forms for \b \f \n \r \t; everything else is literal.
    match serde_json::to_string(text) {
        Ok(quoted) => out.push_str(&quoted),
        // A str always serialises; keep the output a JSON string regardless.
        Err(_) => out.push_str("\"\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        parse_str(text).expect("valid JSON")
    }

    fn ptr(text: &str) -> Vec<String> {
        parse_pointer(text).expect("valid pointer")
    }

    #[test]
    fn objects_keep_their_key_order() {
        let value = json(r#"{"b":1,"a":2}"#);
        let Json::Object(members) = &value else {
            panic!("an object")
        };
        assert_eq!(members[0].0, "b");
        assert_ne!(value, json(r#"{"a":2,"b":1}"#));
        assert!(value.same(&json(r#"{"a":2,"b":1}"#)));
    }

    #[test]
    fn integers_and_floats_differ() {
        assert!(!json("1").same(&json("1.0")));
    }

    #[test]
    fn pointers_round_trip_with_escapes() {
        let tokens = ptr("/a~1b/c~0d/0");
        assert_eq!(tokens, vec!["a/b", "c~d", "0"]);
        assert_eq!(format_pointer(&tokens), "/a~1b/c~0d/0");
        assert_eq!(parse_pointer(""), Some(vec![]));
        assert_eq!(parse_pointer("a"), None);
        assert_eq!(parse_pointer("/a~2"), None);
    }

    #[test]
    fn get_reads_objects_and_canonical_indexes() {
        let value = json(r#"{"a":[10,20]}"#);
        assert_eq!(value.get(&ptr("/a/1")), Some(&json("20")));
        assert_eq!(value.get(&ptr("/a/01")), None);
        assert_eq!(value.get(&ptr("/b")), None);
        assert_eq!(value.position(&ptr("/a")), Some(0));
    }

    #[test]
    fn set_inserts_at_the_given_index_and_removes() {
        let mut value = json(r#"{"a":1,"c":3}"#);
        assert!(value.set(&ptr("/b"), Some(json("2")), Some(1)));
        assert_eq!(value, json(r#"{"a":1,"b":2,"c":3}"#));
        assert!(value.set(&ptr("/a"), None, None));
        assert_eq!(value, json(r#"{"b":2,"c":3}"#));
        assert!(!value.set(&ptr("/x/y"), Some(json("1")), None));
        let mut list = json("[1,2]");
        assert!(list.set(&ptr("/2"), Some(json("3")), None));
        assert!(list.set(&ptr("/0"), None, None));
        assert_eq!(list, json("[2,3]"));
    }

    #[test]
    fn value_differences_name_each_pointer() {
        let found = value_differences(
            &json(r#"{"a":1,"b":[1,2]}"#),
            &json(r#"{"a":2,"b":[1],"c":0}"#),
        );
        assert_eq!(
            found,
            vec![
                JsonDifference::Value {
                    pointer: ptr("/a"),
                    oracle: Some(json("1")),
                    candidate: Some(json("2"))
                },
                JsonDifference::Value {
                    pointer: ptr("/b/1"),
                    oracle: Some(json("2")),
                    candidate: None
                },
                JsonDifference::Value {
                    pointer: ptr("/c"),
                    oracle: None,
                    candidate: Some(json("0"))
                },
            ]
        );
    }

    #[test]
    fn a_duplicate_key_is_a_difference() {
        let oracle = json(r#"{"a":1}"#);
        let candidate = json(r#"{"a":1,"a":1}"#);
        assert!(!oracle.same(&candidate));
        assert_eq!(value_differences(&oracle, &candidate).len(), 1);
    }

    #[test]
    fn key_order_differences_name_the_object() {
        let found = key_order_differences(
            &json(r#"{"x":{"a":1,"b":2}}"#),
            &json(r#"{"x":{"b":2,"a":1}}"#),
        );
        assert_eq!(
            found,
            vec![JsonDifference::KeyOrder {
                pointer: ptr("/x"),
                oracle: vec!["a".into(), "b".into()],
                candidate: vec!["b".into(), "a".into()],
            }]
        );
    }

    #[test]
    fn layouts_match_orjson() {
        let value = json(r#"{"a":[1,{"b":null}],"c":{},"d":[],"e":"é\n\"","f":1.5}"#);
        assert_eq!(
            String::from_utf8(write(&value, Layout::Compact, true)).unwrap(),
            "{\"a\":[1,{\"b\":null}],\"c\":{},\"d\":[],\"e\":\"é\\n\\\"\",\"f\":1.5}\n"
        );
        assert_eq!(
            String::from_utf8(write(&value, Layout::Indented, false)).unwrap(),
            "{\n  \"a\": [\n    1,\n    {\n      \"b\": null\n    }\n  ],\n  \"c\": {},\n  \"d\": [],\n  \"e\": \"é\\n\\\"\",\n  \"f\": 1.5\n}"
        );
    }
}
