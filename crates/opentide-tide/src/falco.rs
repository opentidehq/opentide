//! The Sysdig Secure block (`configurations.sysdig`, sysdig-1.0): what its
//! Falco condition, macro conditions, and output are checked against.
//!
//! A condition is checked with the block's own `macros` and `lists` in scope
//! (deploy expands them), against the fields of the block's `source`. A
//! tuning's condition (`append_to_rule`) is a fragment that starts with `and`
//! or `or`; a new rule's and a macro's are whole conditions.

use opentide_core::{Diagnostic, codes};
use opentide_falco::exceptions::{Exception, Item, Strs};
use opentide_falco::{Catalog, Context};

/// The Falco context of the value at `field_path` in the object `source`.
pub fn falco_context(source: &str, field_path: &[String]) -> Context {
    let object = serde_yaml::from_str::<serde_yaml::Value>(opentide_core::strip_bom(source)).ok();
    let block = object
        .as_ref()
        .and_then(|o| o.get("configurations"))
        .and_then(|c| c.get("sysdig"));
    context_for(block, field_path)
}

pub(crate) fn context_for(block: Option<&serde_yaml::Value>, field_path: &[String]) -> Context {
    let Some(block) = block else {
        return Context::default();
    };
    let text = |v: Option<&serde_yaml::Value>| v.and_then(|v| v.as_str()).map(str::to_string);
    let mut ctx = Context {
        source: text(block.get("source")).filter(|s| !s.trim().is_empty()),
        ..Context::default()
    };
    if let Some(macros) = block.get("macros").and_then(|m| m.as_sequence()) {
        for m in macros {
            if let (Some(name), Some(condition)) = (text(m.get("name")), text(m.get("condition"))) {
                ctx.macros.insert(name, condition);
            }
        }
    }
    if let Some(lists) = block.get("lists").and_then(|l| l.as_sequence()) {
        for l in lists {
            let Some(name) = text(l.get("name")) else {
                continue;
            };
            let items = l
                .get("items")
                .and_then(|i| i.as_sequence())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|i| match i {
                            serde_yaml::Value::String(s) => Some(s.clone()),
                            serde_yaml::Value::Number(n) => Some(n.to_string()),
                            serde_yaml::Value::Bool(b) => Some(b.to_string()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            ctx.lists.insert(name, items);
        }
    }
    let tuning = text(block.get("append_to_rule")).is_some_and(|s| !s.trim().is_empty());
    ctx.append = match field_path {
        [_, _, last] if last == "condition" => Some(tuning),
        [.., last] if last == "output" => None,
        _ => Some(false),
    };
    ctx.macro_condition = matches!(field_path, [_, _, m, _, _] if m == "macros");
    ctx
}

/// `falco_unknown_source` on the block's `source` when no Falco plugin the
/// engine knows defines it: its fields are then not checked.
pub(crate) fn source_diagnostics(source: &str, block: &serde_yaml::Value) -> Vec<Diagnostic> {
    let Some(name) = block.get("source").and_then(|s| s.as_str()) else {
        return Vec::new();
    };
    if Catalog::cached().source(name).is_some() {
        return Vec::new();
    }
    let path = ["configurations", "sysdig", "source"];
    let known: Vec<String> = Catalog::cached()
        .sources
        .iter()
        .map(|s| format!("`{}`", s.name))
        .collect();
    vec![
        Diagnostic::warning(
            codes::FALCO_UNKNOWN_SOURCE,
            format!(
                "`{name}` is not an event source the engine knows ({}); its fields are not checked",
                known.join(", ")
            ),
            crate::elastic::path_range(source, &path),
        )
        .with_field_path(path.iter().map(|p| p.to_string()).collect()),
    ]
}

fn scalar(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn strs(v: Option<&serde_yaml::Value>) -> Option<Strs> {
    match v? {
        serde_yaml::Value::Sequence(items) => {
            Some(Strs::Many(items.iter().filter_map(scalar).collect()))
        }
        other => scalar(other).map(Strs::One),
    }
}

fn item(v: &serde_yaml::Value) -> Item {
    match v {
        serde_yaml::Value::Sequence(items) => Item::List(items.iter().map(item).collect()),
        other => Item::Scalar(scalar(other).unwrap_or_default()),
    }
}

/// Falco's checks on the block's `exceptions` (opentide_falco::exceptions):
/// operators, field and value counts, and the values compiled as Falco writes
/// them into the condition.
pub(crate) fn exception_diagnostics(source: &str, block: &serde_yaml::Value) -> Vec<Diagnostic> {
    let Some(list) = block.get("exceptions").and_then(|e| e.as_sequence()) else {
        return Vec::new();
    };
    let exceptions: Vec<Exception> = list
        .iter()
        .map(|e| Exception {
            name: e.get("name").and_then(scalar).unwrap_or_default(),
            fields: strs(e.get("fields")),
            comps: strs(e.get("comps")),
            values: e
                .get("values")
                .and_then(|v| v.as_sequence())
                .map(|vs| vs.iter().map(item).collect())
                .unwrap_or_default(),
        })
        .collect();
    let ctx = context_for(
        Some(block),
        &["configurations".into(), "sysdig".into(), "condition".into()],
    );
    opentide_falco::exceptions::check(&exceptions, &ctx)
        .into_iter()
        .map(|f| {
            let index = f.index.to_string();
            let path = [
                "configurations",
                "sysdig",
                "exceptions",
                index.as_str(),
                f.key,
            ];
            let range = crate::elastic::path_range(source, &path);
            let d = match f.level {
                opentide_falco::compile::Level::Error => {
                    Diagnostic::error(f.code, f.message, range)
                }
                opentide_falco::compile::Level::Warning => {
                    Diagnostic::warning(f.code, f.message, range)
                }
            };
            d.with_field_path(path.iter().map(|p| p.to_string()).collect())
        })
        .collect()
}
