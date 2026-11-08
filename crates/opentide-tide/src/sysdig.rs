//! The Sysdig block's constraint codes (sysdig-1.0, "Constraints"), reported
//! natively so the editor and `opentide validate` agree.
//!
//! The codes, their conditions, and the order they are judged in follow
//! opentide's `SysdigConfig` validator and `platforms/sysdig/expansion.py`: a
//! block without `status` reports only the missing field, as there; exception
//! shapes follow Falco's `validate_exception_info`; definition order is
//! Falco's: a macro sees only earlier block macros (and every block list); a
//! list naming a later list still expands, because `resolve_list` runs over the
//! condition for every list in order; a list naming itself keeps the name as a
//! literal (`sysdig_list_self_reference`, a warning). Each code is reported on
//! the field path it is about.

use opentide_core::{Diagnostic, codes};
use opentide_falco::Context;
use serde_yaml::Value;

const BLOCK: [&str; 2] = ["configurations", "sysdig"];
/// Keys a tuning inherits from the rule it tunes (`sysdig_tuning_keys`).
const TUNING_FORBIDDEN: [&str; 5] = ["output", "priority", "policies", "source", "name"];
const PRIORITIES: [&str; 9] = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "info",
    "debug",
];
const LIST_COMPS: [&str; 3] = ["in", "pmatch", "intersects"];
const MODIFIABLE: [&str; 12] = [
    "=",
    "==",
    "!=",
    "contains",
    "icontains",
    "bcontains",
    "startswith",
    "bstartswith",
    "endswith",
    "glob",
    "iglob",
    "regex",
];
const OTHER_OPERATORS: [&str; 8] = ["exists", "<", "<=", ">", ">=", "in", "intersects", "pmatch"];
const MODIFIERS: [&str; 3] = ["oneof", "anyof", "allof"];
const RESERVED: [&str; 6] = ["and", "or", "not", "in", "exists", "val"];

fn non_blank(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

fn set(v: Option<&Value>) -> bool {
    !matches!(v, None | Some(Value::Null)) && v.and_then(Value::as_str) != Some("")
}

/// Falco's `normalize_comp`.
fn normalize(comp: &str) -> &str {
    comp.trim_matches([' ', '\t', '\r', '\n'])
}

/// Falco's `is_str_operator_with_modifier`: split at the first space.
fn modified(op: &str) -> bool {
    op.split_once(' ')
        .is_some_and(|(head, m)| MODIFIABLE.contains(&head) && MODIFIERS.contains(&m))
}

fn exception_operator(op: &str) -> bool {
    MODIFIABLE.contains(&op) || OTHER_OPERATORS.contains(&op) || modified(op)
}

fn list_comparison(op: &str) -> bool {
    LIST_COMPS.contains(&op) || modified(op)
}

fn scalar(v: &Value) -> bool {
    !matches!(v, Value::Sequence(_) | Value::Mapping(_))
}

fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "None".into(),
        _ => String::new(),
    }
}

/// One exception, by Falco's `validate_exception_info` and
/// `build_rule_exception_infos` shape checks.
fn exception_ok(entry: &Value) -> bool {
    let Some(map) = entry.as_mapping() else {
        return false;
    };
    if !non_blank(map.get("name")) {
        return false;
    }
    let fields = map.get("fields");
    let comps = map.get("comps").filter(|c| !c.is_null());
    let values = map.get("values").filter(|v| !v.is_null());
    if values.is_some_and(|v| !v.is_sequence()) {
        return false;
    }
    let rows = values
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    if let Some(field) = fields.and_then(Value::as_str) {
        if field.trim().is_empty() {
            return false;
        }
        if let Some(comp) = comps {
            let Some(comp) = comp.as_str() else {
                return false; // "Fields and comps must both be strings"
            };
            let comp = normalize(comp);
            if !LIST_COMPS.contains(&comp) && !modified(comp) {
                return false;
            }
        }
        return rows.iter().all(scalar);
    }
    let Some(fields) = fields.and_then(Value::as_sequence) else {
        return false;
    };
    if fields.is_empty() || !fields.iter().all(|f| non_blank(Some(f))) {
        return false;
    }
    if let Some(comps) = comps {
        let Some(comps) = comps.as_sequence() else {
            return false;
        };
        if comps.len() != fields.len() {
            return false; // "Fields and comps lists must have equal length"
        }
        if !comps
            .iter()
            .all(|c| c.as_str().is_some_and(|c| exception_operator(normalize(c))))
        {
            return false;
        }
    }
    for row in &rows {
        let Some(row) = row.as_sequence() else {
            return false;
        };
        if row.len() != fields.len() {
            return false; // "Fields and values lists must have equal length"
        }
        for item in row {
            match item {
                Value::Mapping(_) => return false,
                Value::Sequence(vs) if !vs.iter().all(scalar) => return false,
                _ => {}
            }
        }
    }
    true
}

fn err(source: &str, code: &'static str, message: String, path: &[&str]) -> Diagnostic {
    let mut full: Vec<&str> = BLOCK.to_vec();
    full.extend_from_slice(path);
    Diagnostic::error(code, message, crate::elastic::path_range(source, &full))
        .with_field_path(full.iter().map(|p| p.to_string()).collect())
}

struct Definitions {
    macros: Vec<(usize, String, String)>,
    lists: Vec<(usize, String, Vec<String>)>,
}

/// The block's macros and lists in order, with `sysdig_definition_name` and
/// `sysdig_definition_duplicate` findings.
fn definitions(source: &str, block: &Value, out: &mut Vec<Diagnostic>) -> Definitions {
    let mut defs = Definitions {
        macros: Vec::new(),
        lists: Vec::new(),
    };
    let mut seen: Vec<String> = Vec::new();
    for key in ["macros", "lists"] {
        let Some(entries) = block.get(key).and_then(Value::as_sequence) else {
            continue;
        };
        for (index, entry) in entries.iter().enumerate() {
            let Some(name) = entry.get("name").and_then(Value::as_str) else {
                continue;
            };
            let at = index.to_string();
            let valid = name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !RESERVED.contains(&name)
                && !exception_operator(name);
            if !valid {
                out.push(err(
                    source,
                    codes::SYSDIG_DEFINITION_NAME,
                    format!(
                        "`{name}` is not a macro or list name: [A-Za-z_][A-Za-z0-9_]*, and not a Falco operator or keyword"
                    ),
                    &[key, &at, "name"],
                ));
            }
            if seen.iter().any(|s| s == name) {
                out.push(err(
                    source,
                    codes::SYSDIG_DEFINITION_DUPLICATE,
                    format!(
                        "`{name}` is defined more than once across the block's macros and lists"
                    ),
                    &[key, &at, "name"],
                ));
            }
            seen.push(name.to_string());
            if key == "macros" {
                if let Some(condition) = entry.get("condition").and_then(Value::as_str) {
                    defs.macros
                        .push((index, name.to_string(), condition.to_string()));
                }
            } else if let Some(items) = entry.get("items").and_then(Value::as_sequence) {
                defs.lists
                    .push((index, name.to_string(), items.iter().map(text_of).collect()));
            }
        }
    }
    defs
}

/// `sysdig_definition_order` for macros (Falco refuses a macro naming itself or
/// a later block macro: `Undefined macro`), and `sysdig_list_self_reference`
/// for a list naming itself (Falco keeps the name as a literal item, which on
/// Sysdig resolves against a tenant list of that name). A list naming a later
/// list is fine: Falco's `resolve_list` runs over the condition for every list
/// in order, so the later list still expands.
fn order(source: &str, defs: &Definitions, out: &mut Vec<Diagnostic>) -> bool {
    for (index, name, items) in &defs.lists {
        for (item_index, item) in items.iter().enumerate() {
            if item == name {
                out.push(
                    Diagnostic::warning(
                        codes::SYSDIG_LIST_SELF_REFERENCE,
                        format!(
                            "list `{name}` names itself: Falco keeps `{name}` as a literal item, which on Sysdig resolves against a tenant list of that name, not this one"
                        ),
                        crate::elastic::path_range(
                            source,
                            &[
                                BLOCK[0],
                                BLOCK[1],
                                "lists",
                                &index.to_string(),
                                "items",
                                &item_index.to_string(),
                            ],
                        ),
                    )
                    .with_field_path(
                        [
                            BLOCK[0],
                            BLOCK[1],
                            "lists",
                            &index.to_string(),
                            "items",
                            &item_index.to_string(),
                        ]
                        .iter()
                        .map(|p| p.to_string())
                        .collect(),
                    ),
                );
            }
        }
    }
    let ctx = Context {
        lists: defs
            .lists
            .iter()
            .map(|(_, n, items)| (n.clone(), items.clone()))
            .collect(),
        list_order: defs.lists.iter().map(|(_, n, _)| n.clone()).collect(),
        ..Context::default()
    };
    let macro_names: Vec<&str> = defs.macros.iter().map(|(_, n, _)| n.as_str()).collect();
    for (pos, (index, name, condition)) in defs.macros.iter().enumerate() {
        let joined = condition.split_whitespace().collect::<Vec<_>>().join(" ");
        let Some(used) = opentide_falco::check_position_names(&joined, &ctx) else {
            continue;
        };
        let later: Vec<&String> = used
            .iter()
            .filter(|u| macro_names[pos..].contains(&u.as_str()))
            .collect();
        if let Some(first) = later.first() {
            out.push(err(
                source,
                codes::SYSDIG_DEFINITION_ORDER,
                format!(
                    "macro `{name}` uses `{first}`, which is not defined before it in the block: a macro sees only earlier block macros (and every block list)"
                ),
                &["macros", &index.to_string(), "condition"],
            ));
            return true;
        }
    }
    false
}

/// `sysdig_list_in_value`: a block list name in an exception value where
/// Falco's expansion would not produce a value list.
fn list_in_value(source: &str, block: &Value, defs: &Definitions, out: &mut Vec<Diagnostic>) {
    let names: Vec<&str> = defs.lists.iter().map(|(_, n, _)| n.as_str()).collect();
    if names.is_empty() {
        return;
    }
    let inside = |text: &str| {
        names
            .iter()
            .find(|n| opentide_falco::occurs_delimited(text, n))
            .copied()
    };
    let Some(entries) = block.get("exceptions").and_then(Value::as_sequence) else {
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let name = entry.get("name").map(text_of).unwrap_or_default();
        let at = index.to_string();
        let report = |list: &str, out: &mut Vec<Diagnostic>| {
            out.push(err(
                source,
                codes::SYSDIG_LIST_IN_VALUE,
                format!(
                    "exception `{name}`: the block list `{list}` appears in a value where Falco's expansion would not produce a value list"
                ),
                &["exceptions", &at, "values"],
            ));
        };
        let members = |values: &[Value], out: &mut Vec<Diagnostic>| -> bool {
            for v in values {
                let text = text_of(v);
                if scalar(v) && names.contains(&text.as_str()) {
                    continue;
                }
                if let Some(list) = inside(&text) {
                    report(list, out);
                    return true;
                }
            }
            false
        };
        let values = entry
            .get("values")
            .and_then(Value::as_sequence)
            .cloned()
            .unwrap_or_default();
        if entry.get("fields").is_some_and(Value::is_string) {
            if members(&values, out) {
                return;
            }
            continue;
        }
        let width = entry
            .get("fields")
            .and_then(Value::as_sequence)
            .map_or(0, Vec::len);
        let comps: Vec<String> = match entry.get("comps").and_then(Value::as_sequence) {
            Some(cs) => cs
                .iter()
                .map(|c| normalize(&text_of(c)).to_string())
                .collect(),
            None => vec!["=".into(); width],
        };
        for row in values.iter().filter_map(Value::as_sequence) {
            for (comp, item) in comps.iter().zip(row) {
                if let Some(vs) = item.as_sequence() {
                    if members(vs, out) {
                        return;
                    }
                    continue;
                }
                let text = text_of(item);
                if names.contains(&text.as_str()) {
                    if !list_comparison(comp) {
                        report(&text, out);
                        return;
                    }
                    continue;
                }
                if let Some(list) = inside(&text) {
                    report(list, out);
                    return;
                }
            }
        }
    }
}

/// Every constraint code of the block, as opentide reports them.
pub(crate) fn constraint_diagnostics(source: &str, block: &Value) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if !set(block.get("status")) {
        return out;
    }
    let tuning = block.get("append_to_rule").filter(|v| !v.is_null());
    let condition = block.get("condition").filter(|v| !v.is_null());
    match tuning {
        None => {
            if !non_blank(condition) {
                out.push(err(
                    source,
                    codes::SYSDIG_RULE_SHAPE,
                    "a new rule needs a non-blank `condition` (or set `append_to_rule` to tune an existing rule)".into(),
                    if condition.is_some() { &["condition"] } else { &[] },
                ));
            }
        }
        Some(t) => {
            let has_condition = non_blank(condition);
            let has_exceptions = block
                .get("exceptions")
                .and_then(Value::as_sequence)
                .is_some_and(|e| !e.is_empty());
            if !non_blank(Some(t))
                || (condition.is_some() && !has_condition)
                || !(has_condition || has_exceptions)
            {
                out.push(err(
                    source,
                    codes::SYSDIG_RULE_SHAPE,
                    "a tuning names the rule it tunes and appends a non-blank `condition`, `exceptions`, or both".into(),
                    &["append_to_rule"],
                ));
            }
            for key in TUNING_FORBIDDEN {
                if set(block.get(key)) {
                    out.push(err(
                        source,
                        codes::SYSDIG_TUNING_KEYS,
                        format!(
                            "a tuning (`append_to_rule`) inherits `{key}` from the rule it tunes: remove it"
                        ),
                        &[key],
                    ));
                }
            }
        }
    }
    if let Some(p) = block.get("priority").filter(|v| !v.is_null()) {
        let ok = p
            .as_str()
            .is_some_and(|s| PRIORITIES.contains(&s.trim().to_ascii_lowercase().as_str()));
        if !ok {
            out.push(err(
                source,
                codes::SYSDIG_PRIORITY,
                format!(
                    "`{}` is not a Falco priority: EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL (or INFO), DEBUG",
                    text_of(p)
                ),
                &["priority"],
            ));
        }
    }
    if let Some(s) = block.get("source").filter(|v| !v.is_null()) {
        let ok = s.as_str().is_some_and(|s| {
            s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        });
        if !ok {
            out.push(err(
                source,
                codes::SYSDIG_SOURCE,
                format!(
                    "`{}` is not a Falco event source name: [a-z][a-z0-9_]*",
                    text_of(s)
                ),
                &["source"],
            ));
        }
    }
    let mut shaped = true;
    match block.get("exceptions").filter(|v| !v.is_null()) {
        Some(Value::Sequence(entries)) => {
            for (index, entry) in entries.iter().enumerate() {
                if !exception_ok(entry) {
                    shaped = false;
                    out.push(err(
                        source,
                        codes::SYSDIG_EXCEPTION_SHAPE,
                        "the exception's fields, comps, and values do not have a shape Falco accepts (validate_exception_info)".into(),
                        &["exceptions", &index.to_string()],
                    ));
                }
            }
        }
        Some(_) => {
            shaped = false;
            out.push(err(
                source,
                codes::SYSDIG_EXCEPTION_SHAPE,
                "`exceptions` is a list of exceptions".into(),
                &["exceptions"],
            ));
        }
        None => {}
    }
    let before = out.len();
    let defs = definitions(source, block, &mut out);
    let named = out[before..].iter().any(|d| {
        d.code == codes::SYSDIG_DEFINITION_NAME || d.code == codes::SYSDIG_DEFINITION_DUPLICATE
    });
    if !named && !order(source, &defs, &mut out) && shaped {
        list_in_value(source, block, &defs, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes_for(block: &str) -> Vec<(String, Vec<String>)> {
        let source = format!("configurations:\n  sysdig:\n{block}");
        let object: Value = serde_yaml::from_str(&source).unwrap();
        let block = &object["configurations"]["sysdig"];
        constraint_diagnostics(&source, block)
            .into_iter()
            .map(|d| (d.code, d.field_path.unwrap_or_default()))
            .collect()
    }

    fn only_codes(block: &str) -> Vec<String> {
        codes_for(block).into_iter().map(|(c, _)| c).collect()
    }

    #[test]
    fn the_editor_reports_what_opentide_reports_on_a_broken_tuning() {
        let found = codes_for(
            "    status: STAGING
    append_to_rule: Terminal shell in container
    output: replaced
    priority: ERROR
    condition: and not proc.pname in (ci_runners)
    exceptions:
    - name: misaligned
      fields: [proc.pname, k8s.ns.name]
      comps: ['=']
    lists:
    - name: ci_runners
      items: [gitlab-runner, ci_runners]
",
        );
        let codes: Vec<&str> = found.iter().map(|(c, _)| c.as_str()).collect();
        assert_eq!(
            codes,
            [
                "sysdig_tuning_keys",
                "sysdig_tuning_keys",
                "sysdig_exception_shape",
                "sysdig_list_self_reference"
            ]
        );
        assert_eq!(found[0].1.last().map(String::as_str), Some("output"));
        assert_eq!(found[2].1.join("."), "configurations.sysdig.exceptions.0");
        assert_eq!(
            found[3].1.join("."),
            "configurations.sysdig.lists.0.items.1"
        );
    }

    #[test]
    fn no_status_reports_nothing_here() {
        assert!(only_codes("    condition: ''\n").is_empty());
    }

    #[test]
    fn rule_shape_priority_and_source() {
        assert_eq!(
            only_codes("    status: STAGING\n    condition: '  '\n"),
            ["sysdig_rule_shape"]
        );
        assert_eq!(
            only_codes("    status: STAGING\n    append_to_rule: X\n"),
            ["sysdig_rule_shape"]
        );
        assert_eq!(
            only_codes(
                "    status: STAGING\n    condition: a\n    priority: HIGH\n    source: k8s-audit\n"
            ),
            ["sysdig_priority", "sysdig_source"]
        );
        assert!(
            only_codes("    status: STAGING\n    condition: a\n    priority: info\n").is_empty()
        );
    }

    #[test]
    fn exceptions_follow_falcos_rule_loader() {
        let ok = "    status: STAGING
    condition: a
    exceptions:
    - name: a
      fields: proc.name
      comps: startswith oneof
      values: [ba, zs]
    - name: b
      fields: [proc.name, fd.name]
      comps: ['==', ' glob anyof ']
      values: [[sh, [/tmp/*]]]
    - name: b
      fields: [proc.pname]
      comps: [in]
      values: [[shell_binaries]]
";
        assert!(only_codes(ok).is_empty(), "{:?}", only_codes(ok));
        let bad = "    status: STAGING
    condition: a
    exceptions:
    - name: x
      fields: proc.name
      comps: '='
";
        assert_eq!(only_codes(bad), ["sysdig_exception_shape"]);
    }

    #[test]
    fn definitions_are_named_unique_and_ordered() {
        assert_eq!(
            only_codes(
                "    status: STAGING\n    condition: a\n    macros:\n    - name: in\n      condition: b\n"
            ),
            ["sysdig_definition_name"]
        );
        assert_eq!(
            only_codes(
                "    status: STAGING\n    condition: a\n    macros:\n    - name: s\n      condition: b\n    lists:\n    - name: s\n      items: [c]\n"
            ),
            ["sysdig_definition_duplicate"]
        );
        // A macro sees only earlier macros, but every block list.
        assert_eq!(
            only_codes(
                "    status: STAGING\n    condition: m1\n    macros:\n    - name: m1\n      condition: m2\n    - name: m2\n      condition: proc.name in (l1)\n    lists:\n    - name: l1\n      items: [bash]\n"
            ),
            ["sysdig_definition_order"]
        );
        assert!(only_codes("    status: STAGING\n    condition: m1\n    macros:\n    - name: m1\n      condition: proc.name in (l1)\n    lists:\n    - name: l1\n      items: [bash]\n").is_empty());
    }

    #[test]
    fn lists_follow_falcos_load_order() {
        // A later list still expands (resolve_list runs for every list in order).
        assert!(only_codes("    status: STAGING\n    condition: a\n    lists:\n    - name: l1\n      items: [l2, zsh]\n    - name: l2\n      items: [bash]\n").is_empty());
        // A list naming itself keeps the name: a warning, not an error.
        let found = codes_for(
            "    status: STAGING\n    condition: a\n    lists:\n    - name: l1\n      items: [l1, zsh]\n",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "sysdig_list_self_reference");
        assert_eq!(
            found[0].1.join("."),
            "configurations.sysdig.lists.0.items.0"
        );
    }

    #[test]
    fn a_block_list_in_a_value_must_expand_to_a_value_list() {
        let block = |values: &str, comps: &str| {
            format!(
                "    status: STAGING\n    condition: a\n    exceptions:\n    - name: e\n      fields: [proc.pname]\n      comps: [{comps}]\n      values: {values}\n    lists:\n    - name: ci\n      items: [gitlab-runner]\n"
            )
        };
        assert!(only_codes(&block("[[ci]]", "in")).is_empty());
        assert_eq!(
            only_codes(&block("[[ci]]", "'='")),
            ["sysdig_list_in_value"]
        );
        assert_eq!(
            only_codes(&block("[['x ci']]", "in")),
            ["sysdig_list_in_value"]
        );
    }
}
