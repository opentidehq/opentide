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
//!
//! Falco's terms (operators, modifiers, priorities, keywords, the name rule)
//! are `opentide_core::falco`'s, the one copy opentide-schema's
//! `sysdig_rule_shape` (the CLI's model) uses too; this module walks
//! the block's YAML nodes and places each finding.
//! `the_editor_and_the_model_agree_on_the_sysdig_cases` runs both on the
//! model's oracle cases and compares the codes.

use opentide_core::falco::{
    TUNING_FORBIDDEN, definition_name_ok, flatten_lists, is_blank, is_exception_operator,
    is_list_comparison, list_inside, normalize_comp, priority_ok, source_ok, value_passes,
};
use opentide_core::node::{Node, Value};
use opentide_core::{Diagnostic, codes};
use opentide_falco::Context;
use std::sync::Arc;

use crate::yaml::YamlNode;

const BLOCK: [&str; 2] = ["configurations", "sysdig"];

fn non_blank(v: Option<&Arc<Node>>) -> bool {
    v.and_then(|v| v.as_str()).is_some_and(|s| !is_blank(s))
}

fn set(v: Option<&Arc<Node>>) -> bool {
    v.is_some_and(|v| !v.is_null()) && v.and_then(|v| v.as_str()) != Some("")
}

fn scalar(v: &Node) -> bool {
    v.is_scalar()
}

fn text_of(v: &Node) -> String {
    if v.is_null() {
        return "None".into();
    }
    v.scalar_text().unwrap_or_default()
}

/// One exception, by Falco's `validate_exception_info` and
/// `build_rule_exception_infos` shape checks.
fn exception_ok(entry: &Node) -> bool {
    if !entry.is_mapping() {
        return false;
    }
    let map = entry;
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
        .and_then(|v| v.as_sequence())
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    if let Some(field) = fields.and_then(|f| f.as_str()) {
        if is_blank(field) {
            return false;
        }
        if let Some(comp) = comps {
            let Some(comp) = comp.as_str() else {
                return false; // "Fields and comps must both be strings"
            };
            if !is_list_comparison(normalize_comp(comp)) {
                return false;
            }
        }
        return rows.iter().all(|row| scalar(row));
    }
    let Some(fields) = fields.and_then(|f| f.as_sequence()) else {
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
        if !comps.iter().all(|c| {
            c.as_str()
                .is_some_and(|c| is_exception_operator(normalize_comp(c)))
        }) {
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
            match &item.value {
                Value::Map(_) => return false,
                Value::Seq(vs) if !vs.iter().all(|v| scalar(v)) => return false,
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
fn definitions(source: &str, block: &Node, out: &mut Vec<Diagnostic>) -> Definitions {
    let mut defs = Definitions {
        macros: Vec::new(),
        lists: Vec::new(),
    };
    let mut seen: Vec<String> = Vec::new();
    for key in ["macros", "lists"] {
        let Some(entries) = block.get(key).and_then(|e| e.as_sequence()) else {
            continue;
        };
        for (index, entry) in entries.iter().enumerate() {
            let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let at = index.to_string();
            if !definition_name_ok(name) {
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
                if let Some(condition) = entry.get("condition").and_then(|c| c.as_str()) {
                    defs.macros
                        .push((index, name.to_string(), condition.to_string()));
                }
            } else if let Some(items) = entry.get("items").and_then(|i| i.as_sequence()) {
                defs.lists.push((
                    index,
                    name.to_string(),
                    items.iter().map(|i| text_of(i)).collect(),
                ));
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
fn list_in_value(source: &str, block: &Node, defs: &Definitions, out: &mut Vec<Diagnostic>) {
    if defs.lists.is_empty() {
        return;
    }
    // Falco's `compile_list_infos`, then the oracle's `_passes` and
    // `_list_in` (`opentide_core::falco`, as the model judges them).
    let flat = flatten_lists(
        &defs
            .lists
            .iter()
            .map(|(_, n, items)| (n.clone(), items.clone()))
            .collect::<Vec<_>>(),
    );
    let names: Vec<&str> = flat.iter().map(|(n, _)| n.as_str()).collect();
    let inside = |text: &str| list_inside(&flat, text);
    let Some(entries) = block.get("exceptions").and_then(|e| e.as_sequence()) else {
        return;
    };
    for (index, entry) in entries.iter().enumerate() {
        let name = entry.get("name").map(|n| text_of(n)).unwrap_or_default();
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
        // A value list: each member through the passes (a member naming a
        // block list becomes its items), then no block list inside one.
        let members = |values: &[Arc<Node>], out: &mut Vec<Diagnostic>| -> bool {
            let passed = value_passes(
                &flat,
                values
                    .iter()
                    .map(|v| scalar(v).then(|| text_of(v)))
                    .collect(),
            );
            for text in passed.iter().flatten() {
                if let Some(list) = inside(text) {
                    report(list, out);
                    return true;
                }
            }
            false
        };
        let values = entry
            .get("values")
            .and_then(|v| v.as_sequence())
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        if entry.get("fields").is_some_and(|f| f.is_string()) {
            if members(&values, out) {
                return;
            }
            continue;
        }
        let width = entry
            .get("fields")
            .and_then(|f| f.as_sequence())
            .map_or(0, <[_]>::len);
        let comps: Vec<String> = match entry.get("comps").and_then(|c| c.as_sequence()) {
            Some(cs) => cs
                .iter()
                .map(|c| normalize_comp(&text_of(c)).to_string())
                .collect(),
            None => vec!["=".into(); width],
        };
        for row in values.iter().filter_map(|v| v.as_sequence()) {
            for (comp, item) in comps.iter().zip(row) {
                if let Some(vs) = item.as_sequence() {
                    if members(vs, out) {
                        return;
                    }
                    continue;
                }
                let text = text_of(item);
                if names.contains(&text.as_str()) {
                    if !is_list_comparison(comp) {
                        report(&text, out);
                        return;
                    }
                    // Falco wraps it in parentheses: one value list, then the passes.
                    if members(std::slice::from_ref(item), out) {
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
pub(crate) fn constraint_diagnostics(source: &str, block: &Node) -> Vec<Diagnostic> {
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
                .and_then(|e| e.as_sequence())
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
        let ok = p.as_str().is_some_and(priority_ok);
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
        let ok = s.as_str().is_some_and(source_ok);
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
    match block
        .get("exceptions")
        .filter(|v| !v.is_null())
        .map(|v| (v, v.as_sequence()))
    {
        Some((_, Some(entries))) => {
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
        let object = crate::yaml::parse(&source).unwrap();
        let block = object.get("configurations").unwrap().get("sysdig").unwrap();
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

    /// A value naming a block list is that list's items (the oracle's
    /// `_passes`, after Falco's `compile_list_infos` flattened the lists):
    /// an item holding another list's name inside it is `sysdig_list_in_value`,
    /// as `opentide validate` reports it (`platform-sysdig-list-pass` and
    /// `platform-sysdig-list-flattened` in opentide-schema's oracle cases).
    #[test]
    fn a_value_list_is_judged_after_the_lists_expand() {
        let lists = "    lists:
    - {name: l0, items: [a]}
    - {name: l1, items: ['x l0']}
    - {name: l2, items: [l1, y]}
";
        for value in ["l1", "l2"] {
            let block = format!(
                "    status: STAGING
    condition: spawned_process
{lists}    exceptions:
    - {{name: e, fields: proc.name, comps: in, values: [{value}]}}
"
            );
            assert_eq!(only_codes(&block), ["sysdig_list_in_value"], "{value}");
        }
        let block = format!(
            "    status: STAGING
    condition: spawned_process
{lists}    exceptions:
    - {{name: e, fields: [proc.name], comps: [in], values: [[l2]]}}
"
        );
        assert_eq!(only_codes(&block), ["sysdig_list_in_value"]);
    }
}
