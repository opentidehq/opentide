//! The one Sysdig check the engine owns: a block list that names itself
//! (`sysdig_list_self_reference`, a warning `opentide lint` reports).
//!
//! The block's constraints (`sysdig_rule_shape`, `sysdig_priority`,
//! `sysdig_source`, `sysdig_exception_shape`, the definition and list codes)
//! are opentide-schema's `SysdigConfig` model, which `opentide validate`
//! runs and the language server publishes: this crate walked them a second
//! time until UC-1.4/UC-2.6 ([#810](https://github.com/opentidehq/opentide/issues/810),
//! [#821](https://github.com/opentidehq/opentide/issues/821)), which showed
//! one fault twice in the editor. The walk and the test that held the two
//! engines together (`xtask/tests/sysdig_engines.rs`) went with it.
//!
//! Falco keeps a self-naming list's own name as a literal item, which on
//! Sysdig resolves against a tenant list of that name, not this one: the
//! rule loads, so it is an advisory, reported on the item.

use opentide_core::node::Node;
use opentide_core::{Diagnostic, codes};

use crate::yaml::YamlNode;

const BLOCK: [&str; 2] = ["configurations", "sysdig"];

fn text_of(v: &Node) -> String {
    if v.is_null() {
        return "None".into();
    }
    v.scalar_text().unwrap_or_default()
}

/// `sysdig_list_self_reference` for every item of a block list that is the
/// list's own name. A list naming a *later* list is fine: Falco's
/// `resolve_list` runs over the condition for every list in order, so the
/// later list still expands.
pub(crate) fn list_self_references(source: &str, block: &Node) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let Some(entries) = block.get("lists").and_then(|l| l.as_sequence()) else {
        return out;
    };
    for (index, entry) in entries.iter().enumerate() {
        let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(items) = entry.get("items").and_then(|i| i.as_sequence()) else {
            continue;
        };
        for (item_index, item) in items.iter().enumerate() {
            if text_of(item) != name {
                continue;
            }
            let path = [
                BLOCK[0],
                BLOCK[1],
                "lists",
                &index.to_string(),
                "items",
                &item_index.to_string(),
            ];
            out.push(
                Diagnostic::warning(
                    codes::SYSDIG_LIST_SELF_REFERENCE,
                    format!(
                        "list `{name}` names itself: Falco keeps `{name}` as a literal item, which on Sysdig resolves against a tenant list of that name, not this one"
                    ),
                    crate::elastic::path_range(source, &path),
                )
                .with_field_path(path.iter().map(|p| p.to_string()).collect()),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(block: &str) -> Vec<(String, String)> {
        let source = format!("configurations:\n  sysdig:\n{block}");
        let object = crate::yaml::parse(&source).unwrap();
        let block = object.get("configurations").unwrap().get("sysdig").unwrap();
        list_self_references(&source, block)
            .into_iter()
            .map(|d| (d.code, d.field_path.unwrap_or_default().join(".")))
            .collect()
    }

    #[test]
    fn a_list_naming_itself_is_reported_on_the_item() {
        assert_eq!(
            found(
                "    status: STAGING
    lists:
    - name: ci_runners
      items: [gitlab-runner, ci_runners]
"
            ),
            [(
                codes::SYSDIG_LIST_SELF_REFERENCE.to_owned(),
                "configurations.sysdig.lists.0.items.1".to_owned()
            )]
        );
    }

    #[test]
    fn a_list_naming_another_list_is_not_reported() {
        assert!(
            found(
                "    lists:
    - name: l1
      items: [l2]
    - name: l2
      items: [execve]
"
            )
            .is_empty()
        );
    }

    /// The block's constraints are the model's (`opentide validate`): a
    /// priority Falco does not know is not reported here (#810, #821).
    #[test]
    fn the_blocks_constraints_are_left_to_the_model() {
        assert!(
            found(
                "    status: STAGING
    priority: LOUD
    source: not a source!
    condition: ''
"
            )
            .is_empty()
        );
    }
}
