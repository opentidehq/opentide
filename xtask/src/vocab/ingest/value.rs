//! The values the ingest reads and writes, with the semantics of the Python
//! objects the old ingest (`opentide.vocabulary`, removed in UC-6.2) held them
//! in: a table keeps its keys in insertion order (a Python `dict`), equality is
//! Python's `==`, truthiness is Python's, and [`Value::py_str`] is `str()`.
//!
//! STIX and MISP JSON is read straight into [`Value`] (its own `Deserialize`,
//! so an object keeps its key order without serde_json's `preserve_order`,
//! which would change every JSON document the workspace writes), and a
//! vocabulary TOML file through `toml_edit` ([`parse_toml`]).

use std::fmt;

use anyhow::{Result, bail};
use indexmap::IndexMap;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

/// A table: keys in insertion order. `insert` on a present key keeps its
/// place, as assigning to a Python `dict` key does; remove with
/// `shift_remove`, which keeps the others' order as `dict.pop` does.
pub type Table = IndexMap<String, Value>;

/// A JSON or TOML value.
#[derive(Debug, Clone)]
pub enum Value {
    /// JSON `null` (Python `None`): never written, TOML has no null.
    None,
    /// A boolean.
    Bool(bool),
    /// An integer (TOML's are 64-bit; JSON's can be larger).
    Int(i128),
    /// A float.
    Float(f64),
    /// A string.
    Str(String),
    /// A list.
    Array(Vec<Value>),
    /// A table or JSON object.
    Table(Table),
}

impl Value {
    /// A string value.
    pub fn str(text: impl Into<String>) -> Self {
        Self::Str(text.into())
    }

    /// The value as a string, when it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }

    /// The value as a table, when it is one.
    pub fn as_table(&self) -> Option<&Table> {
        match self {
            Self::Table(table) => Some(table),
            _ => None,
        }
    }

    /// The value as a list, when it is one.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// `obj.get(key)` on a table; `None` for a missing key or a value that is
    /// not a table.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_table()?.get(key)
    }

    /// Python's `bool(value)`.
    pub fn truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(value) => *value,
            Self::Int(value) => *value != 0,
            Self::Float(value) => *value != 0.0,
            Self::Str(text) => !text.is_empty(),
            Self::Array(items) => !items.is_empty(),
            Self::Table(table) => !table.is_empty(),
        }
    }

    /// Python's `str(value)` for a scalar. A list or table is refused: the
    /// old ingest only ever took `str()` of identifiers, names and versions.
    pub fn py_str(&self) -> Result<String> {
        Ok(match self {
            Self::None => "None".to_owned(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Int(value) => value.to_string(),
            Self::Float(value) => py_float(*value),
            Self::Str(text) => text.clone(),
            Self::Array(_) | Self::Table(_) => {
                bail!("str() of a list or table is not supported here: {self:?}")
            }
        })
    }

    /// Python's `==`: tables compare without regard to key order, lists item
    /// by item, and `True == 1 == 1.0`.
    pub fn py_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (Self::Str(a), Self::Str(b)) => a == b,
            (Self::Array(a), Self::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.py_eq(b))
            }
            (Self::Table(a), Self::Table(b)) => tables_eq(a, b),
            (a, b) => match (a.number(), b.number()) {
                (Some(Number::Int(a)), Some(Number::Int(b))) => a == b,
                (Some(a), Some(b)) => a.as_f64() == b.as_f64(),
                _ => false,
            },
        }
    }

    fn number(&self) -> Option<Number> {
        match self {
            Self::Bool(value) => Some(Number::Int(i128::from(*value))),
            Self::Int(value) => Some(Number::Int(*value)),
            Self::Float(value) => Some(Number::Float(*value)),
            _ => None,
        }
    }
}

enum Number {
    Int(i128),
    Float(f64),
}

impl Number {
    #[expect(
        clippy::cast_precision_loss,
        reason = "Python compares an int with a float by value"
    )]
    fn as_f64(&self) -> f64 {
        match self {
            Self::Int(value) => *value as f64,
            Self::Float(value) => *value,
        }
    }
}

/// Python's `==` on two dicts.
pub fn tables_eq(a: &Table, b: &Table) -> bool {
    a.len() == b.len()
        && a.iter()
            .all(|(key, value)| b.get(key).is_some_and(|other| value.py_eq(other)))
}

/// Python's `str(float)` (its `repr`): the shortest digits that read back,
/// in positional notation for exponents from -4 to 15, else scientific with
/// a signed, at least two-digit exponent.
pub fn py_float(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    // `{:e}` writes the shortest round-trip digits: `1.5e-7`, `-1e16`, `0e0`.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", mantissa),
    };
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    if (-4..16).contains(&exponent) {
        let point = exponent + 1; // digits before the decimal point
        let body = if point <= 0 {
            let zeros = "0".repeat(usize::try_from(-point).unwrap_or(0));
            format!("0.{zeros}{digits}")
        } else {
            let point = usize::try_from(point).unwrap_or(0);
            if digits.len() <= point {
                format!("{digits}{}.0", "0".repeat(point - digits.len()))
            } else {
                format!("{}.{}", &digits[..point], &digits[point..])
            }
        };
        format!("{sign}{body}")
    } else {
        let mantissa = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits
        };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        format!("{sign}{mantissa}e{exponent_sign}{:02}", exponent.abs())
    }
}

/// Whether Python's `str.isspace()` holds for `c`: Unicode white space and
/// the four ASCII separators (`\x1c`-`\x1f`) Python counts too.
pub fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python's `str.strip()`.
pub fn py_strip(text: &str) -> &str {
    text.trim_matches(py_space)
}

/// Python's `str.title()`: each letter after a letter lowercased, every other
/// letter uppercased.
pub fn py_title(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut previous_cased = false;
    for c in text.chars() {
        let cased = c.is_lowercase() || c.is_uppercase();
        if previous_cased {
            out.extend(c.to_lowercase());
        } else {
            out.extend(c.to_uppercase());
        }
        previous_cased = cased;
    }
    out
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::None)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::None)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Int(i128::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Int(i128::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(Value::Float(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::Str(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::Str(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut table = Table::new();
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            // A repeated key keeps its first place and takes the last value,
            // as a Python dict built from JSON does.
            table.insert(key, value);
        }
        Ok(Value::Table(table))
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::None => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Int(value) => serializer.serialize_i128(*value),
            Self::Float(value) => serializer.serialize_f64(*value),
            Self::Str(text) => serializer.serialize_str(text),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Table(table) => {
                let mut map = serializer.serialize_map(Some(table.len()))?;
                for (key, value) in table {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

/// Parses JSON bytes (a STIX bundle, a MISP galaxy, a GitHub release).
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Parses a TOML document as Python's `tomllib.loads(path.read_text())` does:
/// line endings read as `\n` first (universal newlines), keys in document
/// order. A date or time value is refused: the old ingest wrote it back with
/// Python's `str()`, which this port does not reproduce, and no vocabulary
/// holds one.
pub fn parse_toml(text: &str) -> Result<Table> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let document: toml_edit::DocumentMut = text.parse()?;
    table_of(document.as_table())
}

fn table_of(table: &toml_edit::Table) -> Result<Table> {
    let mut out = Table::new();
    for (key, item) in table {
        out.insert(key.to_owned(), item_of(item)?);
    }
    Ok(out)
}

fn item_of(item: &toml_edit::Item) -> Result<Value> {
    Ok(match item {
        toml_edit::Item::None => Value::None,
        toml_edit::Item::Value(value) => value_of(value)?,
        toml_edit::Item::Table(table) => Value::Table(table_of(table)?),
        toml_edit::Item::ArrayOfTables(tables) => Value::Array(
            tables
                .iter()
                .map(|table| table_of(table).map(Value::Table))
                .collect::<Result<_>>()?,
        ),
    })
}

fn value_of(value: &toml_edit::Value) -> Result<Value> {
    Ok(match value {
        toml_edit::Value::String(text) => Value::Str(text.value().clone()),
        toml_edit::Value::Integer(number) => Value::Int(i128::from(*number.value())),
        toml_edit::Value::Float(number) => Value::Float(*number.value()),
        toml_edit::Value::Boolean(flag) => Value::Bool(*flag.value()),
        toml_edit::Value::Datetime(datetime) => {
            bail!(
                "a vocabulary holds a date or time ({}), which the ingest does not write",
                datetime.value()
            )
        }
        toml_edit::Value::Array(items) => {
            Value::Array(items.iter().map(value_of).collect::<Result<_>>()?)
        }
        toml_edit::Value::InlineTable(table) => {
            let mut out = Table::new();
            for (key, value) in table {
                out.insert(key.to_owned(), value_of(value)?);
            }
            Value::Table(out)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_print_as_python_prints_them() {
        for (value, python) in [
            (1.0, "1.0"),
            (0.1, "0.1"),
            (-2.5, "-2.5"),
            (0.0, "0.0"),
            (1e16, "1e+16"),
            (1.5e-7, "1.5e-07"),
            (0.0001, "0.0001"),
            (123_456_789.125, "123456789.125"),
            (1e15, "1000000000000000.0"),
            (f64::INFINITY, "inf"),
            (f64::NAN, "nan"),
        ] {
            assert_eq!(py_float(value), python, "{value}");
        }
    }

    #[test]
    fn title_and_strip_are_pythons() {
        assert_eq!(py_title("command and-control 3d"), "Command And-Control 3D");
        assert_eq!(py_title("eVASION"), "Evasion");
        assert_eq!(py_strip("\u{1c} a b \n"), "a b");
    }

    #[test]
    fn json_objects_keep_their_key_order_and_the_last_repeated_value() {
        let value = parse_json(br#"{"b": 1, "a": [true, null, 2.5], "b": "x"}"#).unwrap();
        let table = value.as_table().unwrap();
        assert_eq!(table.keys().collect::<Vec<_>>(), ["b", "a"]);
        assert_eq!(table["b"].as_str(), Some("x"));
        assert!(!table["a"].as_array().unwrap()[1].truthy());
    }

    #[test]
    fn equality_is_pythons() {
        let a = parse_json(br#"{"x": 1, "y": [1, "a"]}"#).unwrap();
        let b = parse_json(br#"{"y": [1.0, "a"], "x": true}"#).unwrap();
        assert!(a.py_eq(&b));
        let c = parse_json(br#"{"y": ["a", 1], "x": 1}"#).unwrap();
        assert!(!a.py_eq(&c));
    }

    #[test]
    fn toml_keeps_document_order_and_reads_universal_newlines() {
        let table = parse_toml("z = 1\r\na = \"\"\"x\r\ny\"\"\"\n[[keys]]\nid = \"T1\"\n").unwrap();
        assert_eq!(table.keys().collect::<Vec<_>>(), ["z", "a", "keys"]);
        assert_eq!(table["a"].as_str(), Some("x\ny"));
        assert!(parse_toml("when = 2026-01-01\n").is_err());
    }
}
