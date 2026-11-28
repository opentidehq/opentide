//! The Sysdig Secure block (`configurations.sysdig`, sysdig-1.0): what its
//! Falco condition, macro conditions, and output are checked against.
//!
//! A condition is checked with the block's own `macros` and `lists` in scope
//! (deploy expands them), against the fields of the block's `source`. A
//! tuning's condition (`append_to_rule`) is a fragment that starts with `and`
//! or `or`; a new rule's and a macro's are whole conditions.

use opentide_core::node::{Node, Value};
use opentide_core::{Diagnostic, codes};
use opentide_falco::exceptions::{Exception, Item, Strs};
use opentide_falco::{Catalog, Context};
use std::sync::Arc;

use crate::yaml::YamlNode;

/// The Falco context of the value at `field_path` in the object `source`.
pub fn falco_context(source: &str, field_path: &[String]) -> Context {
    let object = crate::yaml::parse(opentide_core::strip_bom(source));
    let block = object
        .as_ref()
        .and_then(|o| o.get("configurations"))
        .and_then(|c| c.get("sysdig"));
    context_for(block.map(Arc::as_ref), field_path)
}

pub(crate) fn context_for(block: Option<&Node>, field_path: &[String]) -> Context {
    let Some(block) = block else {
        return Context::default();
    };
    let text = |v: Option<&Arc<Node>>| v.and_then(|v| v.as_str()).map(str::to_string);
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
                .map(|items| items.iter().filter_map(|i| i.scalar_text()).collect())
                .unwrap_or_default();
            ctx.list_order.push(name.clone());
            ctx.lists.insert(name, items);
        }
    }
    let tuned = text(block.get("append_to_rule")).filter(|s| !s.trim().is_empty());
    let tuning = tuned.is_some();
    ctx.tuned_rule = tuned;
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
pub(crate) fn source_diagnostics(source: &str, block: &Node) -> Vec<Diagnostic> {
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

/// `falco_unknown_rule` on `append_to_rule` when the Falco default rules have
/// no rule by that name. Falco OSS refuses the append; on a Sysdig tenant it may
/// tune a rule Sysdig manages, so it is a warning.
pub(crate) fn tuning_diagnostics(source: &str, block: &Node) -> Vec<Diagnostic> {
    let Some(name) = block.get("append_to_rule").and_then(|s| s.as_str()) else {
        return Vec::new();
    };
    if name.trim().is_empty() || Catalog::cached().rules.contains_key(name) {
        return Vec::new();
    }
    let path = ["configurations", "sysdig", "append_to_rule"];
    let mut d = Diagnostic::warning(
        codes::FALCO_UNKNOWN_RULE,
        format!(
            "`{name}` is not a rule of the Falco default rules: Falco refuses to append to it, and on Sysdig it must be a rule the tenant has"
        ),
        crate::elastic::path_range(source, &path),
    )
    .with_field_path(path.iter().map(|p| p.to_string()).collect());
    if let Some(near) =
        opentide_falco::near_miss(name, Catalog::cached().rules.keys().map(String::as_str))
    {
        d = d.with_suggestion(near);
    }
    vec![d]
}

fn strs(v: Option<&Arc<Node>>) -> Option<Strs> {
    let v = v?;
    match &v.value {
        Value::Seq(items) => Some(Strs::Many(
            items.iter().filter_map(|i| i.scalar_text()).collect(),
        )),
        _ => v.scalar_text().map(Strs::One),
    }
}

fn item(v: &Node) -> Item {
    match &v.value {
        Value::Seq(items) => Item::List(items.iter().map(|i| item(i)).collect()),
        _ => Item::Scalar(v.scalar_text().unwrap_or_default()),
    }
}

/// Falco's checks on the block's `exceptions` (opentide_falco::exceptions):
/// operators, field and value counts, and the values compiled as Falco writes
/// them into the condition.
pub(crate) fn exception_diagnostics(source: &str, block: &Node) -> Vec<Diagnostic> {
    let Some(list) = block.get("exceptions").and_then(|e| e.as_sequence()) else {
        return Vec::new();
    };
    let exceptions: Vec<Exception> = list
        .iter()
        .map(|e| Exception {
            name: e
                .get("name")
                .and_then(|n| n.scalar_text())
                .unwrap_or_default(),
            fields: strs(e.get("fields")),
            comps: strs(e.get("comps")),
            values: e
                .get("values")
                .and_then(|v| v.as_sequence())
                .map(|vs| vs.iter().map(|v| item(v)).collect())
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
