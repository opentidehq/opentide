//! A Sentinel or Defender query with its exclusions (`platforms/kql.py`
//! `compile_kql_query`): the `let` statements of every exclusion that applies
//! to the tenant before the query, their filters after it.

use indexmap::IndexMap;

use crate::json::Json;

/// `value` as a double-quoted KQL string literal (`kql_string`).
pub fn kql_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A float as a KQL `real` literal: the shortest digits that read back, with
/// a decimal point or an exponent so that KQL reads a real and not a long
/// (`1.0`, `1.5e-7`), and `real(nan)`, `real(+inf)`, `real(-inf)` for the
/// values no digits write.
fn kql_real(float: f64) -> String {
    if float.is_nan() {
        "real(nan)".to_owned()
    } else if float.is_infinite() {
        if float > 0.0 {
            "real(+inf)"
        } else {
            "real(-inf)"
        }
        .to_owned()
    } else {
        format!("{float:?}")
    }
}

/// A `let` value as KQL writes it, or `None` for a type KQL has no literal for
/// (the oracle skips it with a warning).
fn let_literal(value: &Json) -> Option<String> {
    match value {
        Json::Bool(flag) => Some(if *flag { "true" } else { "false" }.to_owned()),
        Json::Int(integer) => Some(integer.to_string()),
        Json::Float(float) => Some(kql_real(*float)),
        Json::Str(text) => Some(kql_string(text)),
        Json::Null | Json::Array(_) | Json::Object(_) => None,
    }
}

/// The query `base` with the exclusions (`[{query, tenant, let}]`, as the
/// block holds them) that name `tenant` or no tenant.
pub fn compile_query(base: &str, exclusions: Option<&Json>, tenant: &str) -> String {
    let mut lets: IndexMap<String, String> = IndexMap::new();
    let mut filters: Vec<String> = Vec::new();
    if let Some(Json::Array(exclusions)) = exclusions {
        for exclusion in exclusions {
            let applies = match exclusion.get("tenant") {
                Some(Json::Str(name)) => name == tenant || name.is_empty(),
                Some(value) => !value.truthy(),
                None => true,
            };
            if !applies {
                continue;
            }
            if let Some(query) = exclusion.get("query").and_then(Json::as_str) {
                filters.push(query.to_owned());
            }
            if let Some(Json::Object(variables)) = exclusion.get("let") {
                for (name, value) in variables {
                    if let Some(literal) = let_literal(value) {
                        // The last definition wins, in the place of the first.
                        lets.insert(name.clone(), literal);
                    }
                }
            }
        }
    }
    let mut query = base.to_owned();
    if !lets.is_empty() {
        let statements: Vec<String> = lets
            .iter()
            .map(|(name, value)| format!("let {name} = {value};"))
            .collect();
        query = format!("{}\n{query}", statements.join("\n"));
    }
    if !filters.is_empty() {
        query = format!("{query}\n{}", filters.join("\n"));
    }
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exclusions(yaml: &str) -> Json {
        let document = opentide_schema::node::load(yaml).unwrap();
        Json::from_node(document.root().unwrap())
    }

    #[test]
    fn exclusions_for_the_tenant_or_none_apply() {
        let list = exclusions(
            "- {query: '| where A', tenant: one, let: {x: 1, y: \"a\\\\b\"}}\n\
             - {query: '| where B', tenant: two}\n\
             - {query: '| where C', let: {x: true, z: 1.5, w: [1]}}\n",
        );
        assert_eq!(
            compile_query("T", Some(&list), "one"),
            "let x = true;\nlet y = \"a\\\\b\";\nlet z = 1.5;\nT\n| where A\n| where C"
        );
        assert_eq!(
            compile_query("T", Some(&list), "two"),
            "let x = true;\nlet z = 1.5;\nT\n| where B\n| where C"
        );
        assert_eq!(compile_query("T", None, "two"), "T");
    }

    #[test]
    fn float_lets_are_written_as_python_writes_them() {
        // Past 1e16 and below 1e-4 Python's str takes an exponent.
        let list =
            exclusions("- {let: {big: 1.0e+16, small: 1.0e-5, whole: 1.0e+15, half: 0.5}}\n");
        assert_eq!(
            compile_query("T", Some(&list), "one"),
            "let big = 1e+16;\nlet small = 1e-05;\nlet whole = 1000000000000000.0;\n\
             let half = 0.5;\nT"
        );
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(
            kql_string("C:\\Temp\\\t\"x\""),
            "\"C:\\\\Temp\\\\\\t\\\"x\\\"\""
        );
    }
}
