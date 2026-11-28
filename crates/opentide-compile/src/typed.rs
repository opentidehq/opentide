//! A platform block read by the model `opentide validate` checks it with
//! (#1951): the typed `*Config` of `opentide-schema`, through the same
//! conversion (`FromNode`), so a refusal reads as `validate`'s `schema`
//! finding does.

use std::sync::Arc;

use opentide_schema::from_node::Context;
use opentide_schema::node::{Entry, Mark, Node, Value};
use opentide_schema::{ErrorKind, FromNode, SchemaError};
use serde::de::DeserializeOwned;

use crate::json::Json;
use crate::rule::CompileError;

/// What to do about a block the model refuses.
pub(crate) const REFUSED_HINT: &str =
    "run `opentide validate` and fix what its schema check reports on this block";

/// `block`, the rule's `configurations.<platform>`, read by the model `T`.
///
/// A refusal names the field path the rule wrote and the model's reason
/// (`configurations.sentinel.alert: Field required`) for every fault of the
/// block's shape, at the first one's field, as `compile_failed` for
/// `display`.
///
/// Only the block's shape is refused (a missing field, an unknown key, a
/// wrong type, a value outside a closed set). A block whose only faults are
/// values a field's or the block's own check refuses ([`is_field_check`]: a
/// duration, an ATT&CK id, a named check's constraint) is read with serde,
/// which runs no check, and the compile deals with those values as it always
/// has; `validate` reports them. Serde reads the block's text, not
/// `serde_json::Value`, so an `IndexMap` keeps its keys' order. When serde
/// cannot read it either, the block is refused with the model's findings.
///
/// A named check that refuses the block stops the model's conversion of its
/// fields, so a fault of their shape would hide behind the check's finding.
/// The fields are converted again without the model's checks
/// ([`Context::without_model_checks`]), and the refusal names every shape
/// fault that conversion finds, not the check's.
///
/// The block is the one the deploy sends (`modifiers::rule_for_tenant` may
/// have changed it), so it is read from the rule's JSON, not its node.
pub(crate) fn read_block<T>(block: &Json, platform: &str, display: &str) -> Result<T, CompileError>
where
    T: FromNode + DeserializeOwned,
{
    let node = json_node(block);
    let (config, errors) = convert::<T>(&node, platform, Context::new());
    if let (Some(config), true) = (config, errors.is_empty()) {
        return Ok(config);
    }
    let (_, unchecked) = convert::<T>(&node, platform, Context::without_model_checks());
    let mut shape: Vec<&SchemaError> = unchecked
        .iter()
        .filter(|error| !is_field_check(error))
        .collect();
    for error in errors.iter().filter(|error| !is_field_check(error)) {
        if !shape
            .iter()
            .any(|known| known.to_string() == error.to_string())
        {
            shape.push(error);
        }
    }
    if shape.is_empty()
        && let Ok(config) = serde_json::from_str(&block.to_compact())
    {
        return Ok(config);
    }
    // The model's findings name the fields, as `validate` does: the shape
    // faults, or, when serde cannot read a block that has none, every one.
    let errors: Vec<&SchemaError> = if shape.is_empty() {
        errors.iter().collect()
    } else {
        shape
    };
    let field = errors
        .first()
        .map(|error| error.field_path())
        .unwrap_or_default();
    let field: Vec<&str> = field.iter().map(String::as_str).collect();
    let reasons: Vec<String> = errors.iter().map(ToString::to_string).collect();
    let mut error = CompileError::failed(display, &reasons.join("; "));
    error.hint = Some(REFUSED_HINT.to_owned());
    Err(error.at(&field))
}

/// `node`, the block at `configurations.<platform>`, converted by the model
/// `T` in `cx`, with the errors the conversion found.
fn convert<T: FromNode>(
    node: &Node,
    platform: &str,
    mut cx: Context,
) -> (Option<T>, Vec<SchemaError>) {
    let config = cx.at_key("configurations", |cx| {
        cx.at_key(platform, |cx| T::from_node(node, cx))
    });
    (config, cx.into_errors())
}

/// Whether the model refused a value a field's or the block's own check
/// reads (a duration, an ATT&CK id, a named check's constraint), not the
/// block's shape: a missing or unknown key, a type, a value outside a closed
/// set.
pub(crate) fn is_field_check(error: &SchemaError) -> bool {
    match error.kind {
        ErrorKind::InvalidValue(kind) => kind != "literal_error" && kind != "enum",
        ErrorKind::Constraint(_) => true,
        _ => false,
    }
}

/// A JSON value as a node without positions, for the model's conversion. A
/// rule's JSON comes from its YAML, whose loader refuses an integer past
/// `i64`, so a `UInt` does not occur; it would read as a float.
pub(crate) fn json_node(value: &Json) -> Node {
    let value = match value {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Int(integer) => Value::Int(*integer),
        #[expect(
            clippy::cast_precision_loss,
            reason = "a rule read from YAML holds no integer past i64; a node has no wider integer"
        )]
        Json::UInt(integer) => Value::Float(*integer as f64),
        Json::Float(float) => Value::Float(*float),
        Json::Str(text) => Value::Str(text.as_str().into()),
        Json::Array(items) => {
            Value::Seq(items.iter().map(|item| Arc::new(json_node(item))).collect())
        }
        Json::Object(members) => Value::Map(
            members
                .iter()
                .map(|(key, item)| Entry {
                    key: Arc::new(json_node(&Json::Str(key.clone()))),
                    value: Arc::new(json_node(item)),
                })
                .collect(),
        ),
    };
    Node {
        value,
        start: Mark::default(),
        end: Mark::default(),
        text: None,
    }
}
