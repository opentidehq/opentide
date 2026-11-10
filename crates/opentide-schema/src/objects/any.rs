//! A value of any shape, kept as the node the document holds: Pydantic's
//! `Any` (`DetectionRule.platforms`), and the platform blocks until their
//! models arrive (UC-1.4, #810).

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use crate::from_node::{Context, FromNode};
use crate::node::{Entry, Mark, Node, Value};

/// Any YAML value, unchecked. Two values are equal when their trees are,
/// wherever they sit in their documents.
#[derive(Debug, Clone)]
pub struct Any(pub Arc<Node>);

impl Any {
    /// The node.
    pub fn node(&self) -> &Node {
        &self.0
    }
}

impl PartialEq for Any {
    fn eq(&self, other: &Self) -> bool {
        same(&self.0, &other.0)
    }
}

/// Structural equality, without the positions. The tree is at most
/// [`crate::node::MAX_DEPTH`] deep, so the recursion is bounded.
fn same(a: &Node, b: &Node) -> bool {
    match (&a.value, &b.value) {
        (Value::Seq(left), Value::Seq(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| same(l, r))
        }
        (Value::Map(left), Value::Map(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(l, r)| same(&l.key, &r.key) && same(&l.value, &r.value))
        }
        (left, right) => left == right,
    }
}

impl FromNode for Any {
    fn from_node(node: &Node, _cx: &mut Context) -> Option<Self> {
        Some(Self(Arc::new(node.clone())))
    }
}

impl JsonSchema for Any {
    fn schema_name() -> Cow<'static, str> {
        "Any".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!(true)
    }
}

/// One node as serde data: the same shape the document has.
struct AsData<'a>(&'a Node);

impl Serialize for AsData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0.value {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(flag) => serializer.serialize_bool(*flag),
            Value::Int(integer) => serializer.serialize_i64(*integer),
            Value::Float(float) => serializer.serialize_f64(*float),
            Value::Str(text) => serializer.serialize_str(text),
            Value::Seq(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(&AsData(item))?;
                }
                seq.end()
            }
            Value::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for entry in entries {
                    map.serialize_entry(&AsData(&entry.key), &AsData(&entry.value))?;
                }
                map.end()
            }
        }
    }
}

impl Serialize for Any {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        AsData(&self.0).serialize(serializer)
    }
}

fn node(value: Value) -> Arc<Node> {
    Arc::new(Node {
        value,
        start: Mark::default(),
        end: Mark::default(),
    })
}

struct AnyVisitor;

impl<'de> Visitor<'de> for AnyVisitor {
    type Value = Arc<Node>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(node(Value::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(node(Value::Null))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_bool<E: de::Error>(self, flag: bool) -> Result<Self::Value, E> {
        Ok(node(Value::Bool(flag)))
    }

    fn visit_i64<E: de::Error>(self, integer: i64) -> Result<Self::Value, E> {
        Ok(node(Value::Int(integer)))
    }

    fn visit_u64<E: de::Error>(self, integer: u64) -> Result<Self::Value, E> {
        i64::try_from(integer)
            .map(|integer| node(Value::Int(integer)))
            .map_err(|_| E::custom("an integer beyond 64 bits"))
    }

    fn visit_f64<E: de::Error>(self, float: f64) -> Result<Self::Value, E> {
        Ok(node(Value::Float(float)))
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
        Ok(node(Value::Str(text.to_owned())))
    }

    fn visit_string<E: de::Error>(self, text: String) -> Result<Self::Value, E> {
        Ok(node(Value::Str(text)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Seed)? {
            items.push(item);
        }
        Ok(node(Value::Seq(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries: Vec<Entry> = Vec::new();
        while let Some(key) = map.next_key_seed(Seed)? {
            let value = map.next_value_seed(Seed)?;
            entries.push(Entry { key, value });
        }
        Ok(node(Value::Map(entries)))
    }
}

struct Seed;

impl<'de> de::DeserializeSeed<'de> for Seed {
    type Value = Arc<Node>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(AnyVisitor)
    }
}

impl<'de> Deserialize<'de> for Any {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(AnyVisitor).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::load;

    #[test]
    fn equal_trees_at_different_places_are_equal() {
        let a = load("x: [1, {b: c}]\n").unwrap();
        let b = load("\n\nx:\n  - 1\n  - b: c\n").unwrap();
        let a = Any(Arc::clone(a.root().unwrap()));
        let b = Any(Arc::clone(b.root().unwrap()));
        assert_eq!(a, b);
        let c = load("x: [1, {b: d}]\n").unwrap();
        assert_ne!(a, Any(Arc::clone(c.root().unwrap())));
    }

    #[test]
    fn written_and_read_back_through_serde() {
        let document = load("a: 1\nb: [true, null, 1.5, text]\nc: {d: e}\n").unwrap();
        let any = Any(Arc::clone(document.root().unwrap()));
        let json = serde_json::to_value(&any).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"a": 1, "b": [true, null, 1.5, "text"], "c": {"d": "e"}})
        );
        let back: Any = serde_json::from_value(json).unwrap();
        assert_eq!(back, any);
    }
}
