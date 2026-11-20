//! A SARIF report held without its rules' help text, shared by the CLI
//! snapshots (`snapshot.rs`) and the renderers' snapshots (`render.rs`).

/// A SARIF report's rule catalogue lists every diagnostic code with its short
/// and full description and its help (text and Markdown), generated from the
/// explain pages, and the results point into it by `ruleIndex`: an edit of a
/// page, or a new code, would rewrite every snapshot that holds a report, and
/// the catalogue is most of the file. The report is held without the help
/// text and without the catalogue's position: each result's `ruleIndex` is
/// checked against its `ruleId` (a mismatch fails the case) and dropped, and
/// the catalogue is cut to the rules the results name, each as one line,
/// `id | level | name | helpUri` (`| retired` for a retired code). The explain
/// pages are held once, by the explain cases, and a rule's full shape by
/// `tests/render.rs`, which asserts it on the whole catalogue before cutting it. The results, with
/// their locations, and the rest of the document stay as they are.
pub fn stable_sarif(value: &mut serde_json::Value) {
    use serde_json::Value;
    let Some(runs) = value.get_mut("runs").and_then(Value::as_array_mut) else {
        return;
    };
    for run in runs {
        let Some(rules) = run
            .pointer("/tool/driver/rules")
            .and_then(Value::as_array)
            .cloned()
        else {
            continue;
        };
        let mut named = std::collections::BTreeSet::new();
        if let Some(results) = run.get_mut("results").and_then(Value::as_array_mut) {
            for result in results {
                let Some(id) = result
                    .get("ruleId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                else {
                    continue;
                };
                if let Some(index) = result.get("ruleIndex").and_then(Value::as_u64) {
                    let listed = usize::try_from(index)
                        .ok()
                        .and_then(|index| rules.get(index))
                        .and_then(|rule| rule.get("id"))
                        .and_then(Value::as_str);
                    assert_eq!(
                        listed,
                        Some(id.as_str()),
                        "a SARIF result's ruleIndex {index} does not point at its rule {id}"
                    );
                    result
                        .as_object_mut()
                        .map(|result| result.remove("ruleIndex"));
                }
                named.insert(id);
            }
        }
        let lines: Vec<Value> = rules
            .iter()
            .filter_map(|rule| {
                let id = rule.get("id").and_then(Value::as_str)?;
                if !named.contains(id) {
                    return None;
                }
                let text = |pointer: &str| {
                    rule.pointer(pointer)
                        .and_then(Value::as_str)
                        .unwrap_or("-")
                        .to_owned()
                };
                let retired = rule
                    .pointer("/properties/tags")
                    .and_then(Value::as_array)
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "retired"));
                Some(Value::String(format!(
                    "{id} | {} | {} | {}{}",
                    text("/defaultConfiguration/level"),
                    text("/name"),
                    text("/helpUri"),
                    if retired { " | retired" } else { "" }
                )))
            })
            .collect();
        if let Some(slot) = run.pointer_mut("/tool/driver/rules") {
            *slot = Value::Array(lines);
        }
    }
}
