//! A model's errors as configuration findings (`models/configuration/loading.py`
//! `model_errors` and `describe_error`).
//!
//! The conversion reports every error a union's members raise, each under the
//! member's tag ([`crate::from_node::union_value`]). A tag is not a key of the
//! file: a path segment that does not name a key or an index of the input is
//! dropped, and the error is one branch of a union. Of the branches on one
//! key, the one that reaches deepest into the input is kept, then the one
//! that says what was wrong before the one that says what was expected
//! (`_branch_rank`).

use crate::error::{PathSegment, SchemaError};
use crate::node::{Node, Value};

/// One error, placed in the input: the key path (indexes as decimal strings),
/// Pydantic's error type and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError {
    /// The key path.
    pub path: Vec<String>,
    /// Pydantic's error type (`missing`, `extra_forbidden`, `string_type`, ...).
    pub kind: &'static str,
    /// Pydantic's message.
    pub message: String,
}

/// The part of `loc` that names keys and indexes of `data`, and whether a
/// segment was dropped (a union member's tag).
fn input_path(data: &Node, loc: &[PathSegment], kind: &str) -> (Vec<String>, bool) {
    let mut path = Vec::new();
    let mut node = Some(data);
    let mut branch = false;
    for (position, part) in loc.iter().enumerate() {
        let child = node.and_then(|node| match (&node.value, part) {
            (Value::Map(_), PathSegment::Key(key)) => node.get(key).map(AsRef::as_ref),
            (Value::Seq(items), PathSegment::Index(index)) => items.get(*index).map(AsRef::as_ref),
            _ => None,
        });
        if let Some(child) = child {
            node = Some(child);
            path.push(part.to_string());
        } else if kind == "missing"
            && position == loc.len() - 1
            && node.is_some_and(|node| matches!(node.value, Value::Map(_)))
        {
            path.push(part.to_string());
        } else {
            branch = true;
        }
    }
    (path, branch)
}

/// The error types that only say "not this member's type".
const TYPE_MISMATCH: [&str; 3] = ["_type", "is_instance_of", "model_attributes_type"];

fn branch_rank(kind: &str, branch: bool) -> u8 {
    if !branch {
        0
    } else if TYPE_MISMATCH.iter().any(|suffix| kind.ends_with(suffix)) {
        2
    } else {
        1
    }
}

/// `(key path, error type, message)` per error of `errors`, raised on `data`.
pub fn model_errors(errors: &[SchemaError], data: &Node) -> Vec<ModelError> {
    struct Located {
        path: Vec<String>,
        kind: &'static str,
        message: String,
        branch: bool,
    }
    let located: Vec<Located> = errors
        .iter()
        .map(|error| {
            let kind = error.kind.pydantic_type().unwrap_or("");
            let (path, branch) = input_path(data, &error.path, kind);
            Located {
                path,
                kind,
                message: error.message.clone(),
                branch,
            }
        })
        .collect();
    let mut ranked: Vec<&Located> = located.iter().collect();
    ranked.sort_by_key(|item| branch_rank(item.kind, item.branch));
    let mut kept: Vec<&Located> = Vec::new();
    let mut seen: Vec<&[String]> = Vec::new();
    for item in ranked {
        if item.branch {
            let deeper = located.iter().any(|other| {
                other.branch
                    && other.path.len() > item.path.len()
                    && other.path[..item.path.len()] == item.path[..]
            });
            if deeper || seen.contains(&item.path.as_slice()) {
                continue;
            }
        }
        seen.push(&item.path);
        kept.push(item);
    }
    // The oracle orders by the last position each path has in the errors.
    let order = |path: &[String]| {
        located
            .iter()
            .rposition(|item| item.path == path)
            .unwrap_or(0)
    };
    kept.sort_by_key(|item| order(&item.path));
    kept.into_iter()
        .map(|item| ModelError {
            path: item.path.clone(),
            kind: item.kind,
            message: item.message.clone(),
        })
        .collect()
}

/// The message a configuration error shows: plain words for a key,
/// Pydantic's otherwise.
pub fn describe_error(kind: &str, message: &str) -> String {
    match kind {
        "extra_forbidden" => "unknown key".to_owned(),
        "missing" => "required key is missing".to_owned(),
        _ if message.is_empty() => "invalid value".to_owned(),
        _ => message.to_owned(),
    }
}

/// The finding code of an error type: `missing_field`, `unknown_key`, or
/// `schema_validation`.
pub fn code_of(kind: &str) -> &'static str {
    match kind {
        "missing" => super::codes::MISSING_FIELD,
        "extra_forbidden" => super::codes::UNKNOWN_KEY,
        _ => super::codes::SCHEMA_VALIDATION,
    }
}
