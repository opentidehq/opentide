//! The values the ingest reads and writes: [`serde_json::Value`]. STIX and
//! MISP JSON is read with `serde_json`, a vocabulary with the `toml` crate
//! ([`parse_toml`]) and written back with it ([`to_toml`]).
//!
//! The order of a list is data (a vocabulary's `[[keys]]` follow the merge
//! order) and a `Vec` keeps it. The order of keys in a table is not: the
//! workspace builds `serde_json` and `toml` without `preserve_order`, so a
//! table is a sorted map and the files come out the same on every run.
//!
//! What is left of the old Python ingest's semantics decides data, not
//! layout: truthiness for its `x or default` and merge rules ([`truthy`]),
//! `str()` of an identifier or version ([`text`]), `str.strip()` on
//! identities ([`strip`]) and `str.title()` on tactic names ([`title`]).

use anyhow::{Context, Result, bail};
pub use serde_json::Value;

/// A table or JSON object.
pub type Table = serde_json::Map<String, Value>;

/// Whether a value counts as set, as Python's `bool(value)` decides it: the
/// ingest's `x or default` and `removed`/`version` rules hang on it.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(table) => !table.is_empty(),
    }
}

/// The text of a scalar: an identifier, a name or a version. A string as it
/// is, a number or boolean as JSON writes it; null, a list or a table is
/// refused.
pub fn text(value: &Value) -> Result<String> {
    Ok(match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null | Value::Array(_) | Value::Object(_) => {
            bail!("expected a string, found {value}")
        }
    })
}

/// Python's `str.strip()`: Unicode white space and the four ASCII
/// separators (`\x1c`-`\x1f`) Python counts too. It decides an identity.
pub fn strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Python's `str.title()`, which names a tactic without a display name: each
/// letter after a letter lowercased, every other letter uppercased.
pub fn title(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut previous_cased = false;
    for c in text.chars() {
        if previous_cased {
            out.extend(c.to_lowercase());
        } else {
            out.extend(c.to_uppercase());
        }
        previous_cased = c.is_lowercase() || c.is_uppercase();
    }
    out
}

/// Parses JSON bytes (a STIX bundle, a MISP galaxy, a GitHub release).
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Parses a TOML document, line endings read as `\n` first (the old ingest
/// read with universal newlines, so a multi-line string holds `\n`). A date
/// or time is refused: no vocabulary holds one, and JSON has none to carry
/// it to the writer.
pub fn parse_toml(text: &str) -> Result<Table> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let document: toml::Table = toml::from_str(&text)?;
    table_of(document)
}

fn table_of(table: toml::Table) -> Result<Table> {
    table
        .into_iter()
        .map(|(key, value)| Ok((key, json_of(value)?)))
        .collect()
}

fn json_of(value: toml::Value) -> Result<Value> {
    Ok(match value {
        toml::Value::String(text) => Value::String(text),
        toml::Value::Integer(number) => Value::from(number),
        toml::Value::Float(number) => serde_json::Number::from_f64(number)
            .map(Value::Number)
            .with_context(|| {
                format!("a vocabulary holds {number}, which the ingest does not write")
            })?,
        toml::Value::Boolean(flag) => Value::Bool(flag),
        toml::Value::Datetime(datetime) => {
            bail!("a vocabulary holds a date or time ({datetime}), which the ingest does not write")
        }
        toml::Value::Array(items) => {
            Value::Array(items.into_iter().map(json_of).collect::<Result<_>>()?)
        }
        toml::Value::Table(table) => Value::Object(table_of(table)?),
    })
}

/// The TOML text of a vocabulary document, laid out by the `toml` crate
/// (`[[keys]]` tables, one array item per line). A null is refused: TOML has
/// none.
pub fn to_toml(document: &Table) -> Result<String> {
    Ok(toml::to_string_pretty(document)?)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn truthiness_is_pythons() {
        for value in [
            json!(null),
            json!(false),
            json!(0),
            json!(0.0),
            json!(""),
            json!([]),
            json!({}),
        ] {
            assert!(!truthy(&value), "{value}");
        }
        for value in [
            json!(true),
            json!(-1),
            json!(0.5),
            json!(" "),
            json!([0]),
            json!({"a": null}),
        ] {
            assert!(truthy(&value), "{value}");
        }
    }

    #[test]
    fn scalars_have_text_and_containers_none() {
        assert_eq!(text(&json!("T1")).unwrap(), "T1");
        assert_eq!(text(&json!(3)).unwrap(), "3");
        assert_eq!(text(&json!(1.5)).unwrap(), "1.5");
        assert_eq!(text(&json!(true)).unwrap(), "true");
        assert!(text(&json!(null)).is_err());
        assert!(text(&json!(["a"])).is_err());
    }

    #[test]
    fn title_and_strip_are_pythons() {
        assert_eq!(title("command and-control 3d"), "Command And-Control 3D");
        assert_eq!(title("eVASION"), "Evasion");
        assert_eq!(strip("\u{1c} a b \n"), "a b");
    }

    #[test]
    fn toml_reads_universal_newlines_and_refuses_dates() {
        let table = parse_toml(
            "z = 1\r\na = \"\"\"x\r\ny\"\"\"\nf = 0.5\nb = true\nt = { s = [\"u\"] }\n\
             [[keys]]\nid = \"T1\"\n",
        )
        .unwrap();
        assert_eq!(
            Value::Object(table),
            json!({"z": 1, "a": "x\ny", "f": 0.5, "b": true, "t": {"s": ["u"]},
                   "keys": [{"id": "T1"}]})
        );
        assert!(parse_toml("when = 2026-01-01\n").is_err());
        assert!(parse_toml("x = nan\n").is_err());
        assert!(parse_toml("x = [\n").is_err());
    }

    #[test]
    fn a_document_reads_back_as_the_data_it_was_written_from() {
        let document = json!({
            "name": "N", "field": "f", "key": "id",
            "stages": [{"id": "misp", "name": "MISP"}],
            "keys": [
                {"id": "T2", "alias": ["a", "b"], "tide.vocab.stages": "misp", "version": "1.0",
                 "description": "line one\nline \"two\"\u{1}"},
                {"id": "T1", "version": "1.1", "description": "ends in a quote\n\"q\"",
                 "link": "'''\r\t\\"},
            ],
        });
        let Value::Object(table) = &document else {
            unreachable!()
        };
        let written = to_toml(table).unwrap();
        assert!(written.contains("[[keys]]"), "{written}");
        assert_eq!(Value::Object(parse_toml(&written).unwrap()), document);
        // The keys keep their order: it is the merge's.
        let read: toml::Table = toml::from_str(&written).unwrap();
        let ids: Vec<_> = read["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["T2", "T1"]);
    }

    #[test]
    fn null_is_not_written() {
        let Value::Object(document) = json!({"field": "f", "keys": [{"id": null}]}) else {
            unreachable!()
        };
        assert!(to_toml(&document).is_err());
    }
}
