//! The vocabulary TOML layout the old ingest wrote: `tomli_w` 1.2.0's
//! `dumps` (four-space indents, one array item per line, basic strings, no
//! multi-line strings, an array of tables inline only when each table fits on
//! a 100-character line) for the header, then each `keys` (or `entries`)
//! table as `[[keys]]` with its keys one by one (`dump_vocab_document`).
//!
//! Byte for byte what Python wrote: `cargo xtask vocab ingest` is held to it
//! (the proof in `scripts/vocabulary/README.md`), and the tests below are the
//! cases `tomli_w` decides on.

use anyhow::{Result, bail};

use super::value::{Table, Value, py_float, py_space};

/// tomli_w's `MAX_LINE_LENGTH`: the longest inline table of an array of
/// tables, its indent and comma included.
const MAX_LINE_LENGTH: usize = 100;
/// tomli_w's default indent.
const INDENT: &str = "    ";
/// The document keys written as `[[section]]` tables after the header.
const AOT_ARRAY_FIELDS: [&str; 2] = ["entries", "keys"];

/// The text of a vocabulary document (`dump_vocab_document`).
pub fn dump_vocab_document(document: &Table) -> Result<String> {
    let mut payload = document.clone();
    if !payload.contains_key("keys") {
        payload.insert("keys".to_owned(), Value::Array(Vec::new()));
    }
    let mut header = Table::new();
    let mut sections: Vec<(&str, Vec<&Table>)> = Vec::new();
    for (key, value) in &payload {
        match value {
            Value::Array(items) if AOT_ARRAY_FIELDS.contains(&key.as_str()) => {
                sections.push((key, items.iter().filter_map(Value::as_table).collect()));
            }
            _ => {
                header.insert(key.clone(), value.clone());
            }
        }
    }
    let mut parts = vec![dumps(&header)?.trim_end_matches(py_space).to_owned()];
    for (section, items) in sections {
        for item in items {
            let mut lines = vec![format!("[[{section}]]")];
            for (key, value) in item {
                let mut one = Table::new();
                one.insert(key.clone(), value.clone());
                lines.push(dumps(&one)?.trim_matches(py_space).to_owned());
            }
            parts.push(lines.join("\n"));
        }
    }
    Ok(parts.join("\n") + "\n")
}

/// `tomli_w.dumps(table)`.
pub fn dumps(table: &Table) -> Result<String> {
    let mut out = String::new();
    table_chunks(table, "", false, &mut out)?;
    Ok(out)
}

fn is_aot(value: &Value) -> Option<&[Value]> {
    match value {
        Value::Array(items)
            if !items.is_empty() && items.iter().all(|v| v.as_table().is_some()) =>
        {
            Some(items)
        }
        _ => None,
    }
}

fn is_suitable_inline_table(table: &Table) -> Result<bool> {
    let rendered = format!("{INDENT}{},", inline_table(table)?);
    Ok(rendered.chars().count() <= MAX_LINE_LENGTH && !rendered.contains('\n'))
}

fn table_chunks(table: &Table, name: &str, inside_aot: bool, out: &mut String) -> Result<()> {
    let mut literals: Vec<(&str, &Value)> = Vec::new();
    let mut tables: Vec<(&str, &Table, bool)> = Vec::new();
    for (key, value) in table {
        if let Value::Table(inner) = value {
            tables.push((key, inner, false));
            continue;
        }
        if let Some(items) = is_aot(value) {
            let mut all_inline = true;
            for item in items {
                if let Value::Table(inner) = item
                    && !is_suitable_inline_table(inner)?
                {
                    all_inline = false;
                    break;
                }
            }
            if !all_inline {
                tables.extend(
                    items
                        .iter()
                        .filter_map(Value::as_table)
                        .map(|inner| (key.as_str(), inner, true)),
                );
                continue;
            }
        }
        literals.push((key, value));
    }

    let mut yielded = false;
    if inside_aot || (!name.is_empty() && (!literals.is_empty() || tables.is_empty())) {
        yielded = true;
        if inside_aot {
            out.push_str(&format!("[[{name}]]\n"));
        } else {
            out.push_str(&format!("[{name}]\n"));
        }
    }
    if !literals.is_empty() {
        yielded = true;
        for (key, value) in literals {
            out.push_str(&format!("{} = {}\n", key_part(key), literal(value, 0)?));
        }
    }
    for (key, inner, in_aot) in tables {
        if yielded {
            out.push('\n');
        } else {
            yielded = true;
        }
        let key = key_part(key);
        let display = if name.is_empty() {
            key
        } else {
            format!("{name}.{key}")
        };
        table_chunks(inner, &display, in_aot, out)?;
    }
    Ok(())
}

fn literal(value: &Value, nest_level: usize) -> Result<String> {
    Ok(match value {
        Value::Bool(flag) => if *flag { "true" } else { "false" }.to_owned(),
        Value::Int(number) => number.to_string(),
        Value::Float(number) => py_float(*number),
        Value::Str(text) => basic_string(text),
        Value::Array(items) => inline_array(items, nest_level)?,
        Value::Table(table) => inline_table(table)?,
        Value::None => bail!("Object of type 'NoneType' is not TOML serializable"),
    })
}

fn inline_table(table: &Table) -> Result<String> {
    if table.is_empty() {
        return Ok("{}".to_owned());
    }
    let pairs = table
        .iter()
        .map(|(key, value)| Ok(format!("{} = {}", key_part(key), literal(value, 0)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("{{ {} }}", pairs.join(", ")))
}

fn inline_array(items: &[Value], nest_level: usize) -> Result<String> {
    if items.is_empty() {
        return Ok("[]".to_owned());
    }
    let item_indent = INDENT.repeat(nest_level + 1);
    let closing = INDENT.repeat(nest_level);
    let lines = items
        .iter()
        .map(|item| Ok(format!("{item_indent}{}", literal(item, nest_level + 1)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("[\n{},\n{closing}]", lines.join(",\n")))
}

fn key_part(key: &str) -> String {
    if !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        key.to_owned()
    } else {
        basic_string(key)
    }
}

/// A TOML basic string: `\b \n \f \r " \` compact, every other ASCII control
/// character but the tab as `\u00xx`, everything else as is.
fn basic_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\u{8}' => out.push_str("\\b"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push('\t'),
            c if c.is_ascii_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::super::value::parse_json;
    use super::*;

    fn table(json: &str) -> Table {
        parse_json(json.as_bytes())
            .unwrap()
            .as_table()
            .unwrap()
            .clone()
    }

    #[test]
    fn strings_escape_as_tomli_w_escapes_them() {
        assert_eq!(
            basic_string("a\"b\\c\nd\te\u{1}f\u{7f}é\u{8}\u{c}\r"),
            "\"a\\\"b\\\\c\\nd\te\\u0001f\\u007fé\\b\\f\\r\""
        );
        assert_eq!(key_part("tide.vocab.stages"), "\"tide.vocab.stages\"");
        assert_eq!(key_part("source_misp-url9"), "source_misp-url9");
        assert_eq!(key_part(""), "\"\"");
    }

    #[test]
    fn a_header_puts_literals_first_and_tables_after_a_blank_line() {
        let header = table(
            r#"{"name": "N", "stages": [{"id": "misp", "name": "MISP"}],
                "nested": {"a": [1, [2]], "b": {}}, "list": ["x"], "empty": [], "flag": false,
                "f": 0.5}"#,
        );
        assert_eq!(
            dumps(&header).unwrap(),
            "name = \"N\"\nstages = [\n    { id = \"misp\", name = \"MISP\" },\n]\n\
             list = [\n    \"x\",\n]\nempty = []\nflag = false\nf = 0.5\n\n\
             [nested]\na = [\n    1,\n    [\n        2,\n    ],\n]\n\n[nested.b]\n"
        );
    }

    #[test]
    fn an_array_of_tables_goes_inline_only_when_every_table_fits_a_line() {
        let long = "x".repeat(80);
        let header = table(&format!(
            r#"{{"stages": [{{"id": "a"}}, {{"id": "b", "description": "{long}"}}]}}"#
        ));
        assert_eq!(
            dumps(&header).unwrap(),
            format!("[[stages]]\nid = \"a\"\n\n[[stages]]\nid = \"b\"\ndescription = \"{long}\"\n")
        );
    }

    #[test]
    fn a_document_writes_its_header_then_one_section_per_key() {
        let document = table(
            r#"{"name": "N", "field": "f", "keys": [{"id": "T1", "alias": ["a", "b"],
                "tide.vocab.stages": "misp", "version": "1.0"}, "skipped"], "key": "id"}"#,
        );
        assert_eq!(
            dump_vocab_document(&document).unwrap(),
            "name = \"N\"\nfield = \"f\"\nkey = \"id\"\n[[keys]]\nid = \"T1\"\n\
             alias = [\n    \"a\",\n    \"b\",\n]\n\"tide.vocab.stages\" = \"misp\"\nversion = \"1.0\"\n"
        );
        let empty = table(r#"{"name": "N", "field": "f"}"#);
        assert_eq!(
            dump_vocab_document(&empty).unwrap(),
            "name = \"N\"\nfield = \"f\"\n",
            "an empty `keys` writes no section"
        );
    }

    #[test]
    fn null_is_not_written() {
        let document = table(r#"{"field": "f", "keys": [{"id": null}]}"#);
        assert!(dump_vocab_document(&document).is_err());
    }
}
