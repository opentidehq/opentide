//! The values the ingest reads and writes: [`serde_json::Value`]. STIX and
//! MISP JSON is read with `serde_json`, a vocabulary with the `toml` crate
//! ([`parse_toml`]) and written back with it ([`to_toml`]).
//!
//! The order of a list is data (a vocabulary's `[[keys]]` follow the merge
//! order) and a `Vec` keeps it. The order of keys in a table is not: the
//! workspace builds `serde_json` and `toml` without `preserve_order`, so a
//! table is a sorted map and the files come out the same on every run.
//!
//! A value is read by its type: a text or list field is set when it holds
//! something ([`filled`]), an identifier, a version or a removal when it
//! names one ([`named`]); `str()` of an identifier or version ([`text`]) and
//! `str.title()` on tactic names ([`title`]) remain.

use anyhow::{Context, Result, bail};
pub use serde_json::Value;

/// A table or JSON object.
pub type Table = serde_json::Map<String, Value>;

/// Whether a value holds something: it is not null and not an empty
/// string, list or table. A boolean or a number is a value.
pub fn filled(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(table) => !table.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

/// Whether a value names something (an identifier, a version, the version
/// a key was removed in): a non-empty string or a number. `false`, null, a
/// list and a table name nothing.
pub fn named(value: &Value) -> bool {
    match value {
        Value::String(text) => !text.is_empty(),
        Value::Number(_) => true,
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => false,
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

/// Title case, which names a tactic without a display name: each character
/// after a cased one lowercased, every other one uppercased.
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

/// The TOML text of a vocabulary document, in the form the bundled loader
/// reads: the document's own keys first (a table's keys sorted), then each
/// array of tables as `[[name]]` blocks (`[[keys]]` keep their order), and
/// every value on one line, a string a basic `"..."` with its newlines
/// escaped. A null is refused: TOML has none.
///
/// Not the `toml` crate's writer: it lays a string with a newline out as a
/// `"""` block, and the bundled loader takes an entry's description as the
/// single line that starts `description = ` (`opentide_schema::vocab::split`).
pub fn to_toml(document: &Table) -> Result<String> {
    let mut out = String::new();
    for (key, value) in document {
        if !is_array_of_tables(value) {
            out.push_str(&format!("{} = {}\n", key_text(key), inline(value)?));
        }
    }
    for (key, value) in document {
        let Value::Array(items) = value else { continue };
        if !is_array_of_tables(value) {
            continue;
        }
        for item in items {
            let Value::Object(entry) = item else { continue };
            out.push_str(&format!("\n[[{}]]\n", key_text(key)));
            for (name, value) in entry {
                out.push_str(&format!("{} = {}\n", key_text(name), inline(value)?));
            }
        }
    }
    Ok(out)
}

/// A non-empty array of objects: what TOML writes as `[[name]]` blocks.
fn is_array_of_tables(value: &Value) -> bool {
    matches!(value, Value::Array(items) if !items.is_empty() && items.iter().all(Value::is_object))
}

/// A key, quoted unless it is bare (`A-Za-z0-9_-`).
fn key_text(key: &str) -> String {
    if !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        key.to_owned()
    } else {
        string_text(key)
    }
}

/// A basic TOML string on one line.
fn string_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A value on one line.
fn inline(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Null => bail!("a vocabulary holds a null, which TOML cannot write"),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => string_text(text),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(inline)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
        Value::Object(table) => format!(
            "{{ {} }}",
            table
                .iter()
                .map(|(key, value)| Ok(format!("{} = {}", key_text(key), inline(value)?)))
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn values_are_read_by_their_type() {
        for value in [json!(null), json!(""), json!([]), json!({})] {
            assert!(!filled(&value), "{value}");
        }
        for value in [
            json!(false),
            json!(0),
            json!(" "),
            json!([0]),
            json!({"a": null}),
        ] {
            assert!(filled(&value), "{value}");
        }
        for value in [
            json!(null),
            json!(false),
            json!(true),
            json!(""),
            json!(["1.0"]),
        ] {
            assert!(!named(&value), "{value}");
        }
        for value in [json!("2.0"), json!(0), json!(1.5)] {
            assert!(named(&value), "{value}");
        }
    }

    #[test]
    fn a_description_with_newlines_is_one_line() {
        let document =
            parse_json(br#"{"keys":[{"id":"T1","description":"a\nb\n\nc","version":"1.0"}]}"#)
                .unwrap();
        let Value::Object(document) = document else {
            unreachable!("the literal is an object")
        };
        let text = to_toml(&document).unwrap();
        assert!(!text.contains("\"\"\""), "{text}");
        let line = text
            .lines()
            .find(|line| line.starts_with("description = "))
            .unwrap_or_else(|| panic!("no description line in {text}"));
        assert_eq!(line, r#"description = "a\nb\n\nc""#);
        assert_eq!(parse_toml(&text).unwrap().get("keys"), document.get("keys"));
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
    fn title_is_pythons() {
        assert_eq!(title("command and-control 3d"), "Command And-Control 3D");
        assert_eq!(title("eVASION"), "Evasion");
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
