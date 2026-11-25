//! What the object models say about their fields, read from their JSON
//! Schemas: the fields that play a catalogue role (`core/object_fields.py`
//! `_role_paths`) and a field's own `tide.*` keys (`cli/services/info.py`
//! `_field_is_scoped`). The schemas are generated once, on first use.

use std::sync::OnceLock;

use serde_json::Value;

use crate::objects::role::{FieldRole, fields_with_roles};
use crate::objects::{ObjectiveV1_0, RuleV1_0, RuleV1_1, ThreatVectorV1_0};

/// The object revisions with a model, by identifier, each with its schema.
fn models() -> &'static [(&'static str, Value)] {
    static MODELS: OnceLock<Vec<(&'static str, Value)>> = OnceLock::new();
    MODELS.get_or_init(|| {
        vec![
            ("rule::1.0", schemars::schema_for!(RuleV1_0).to_value()),
            ("rule::1.1", schemars::schema_for!(RuleV1_1).to_value()),
            (
                "threat::1.0",
                schemars::schema_for!(ThreatVectorV1_0).to_value(),
            ),
            (
                "objective::1.0",
                schemars::schema_for!(ObjectiveV1_0).to_value(),
            ),
        ]
    })
}

/// The JSON Schema of the object revision `identifier` (`rule::1.1`), when
/// it has a model.
pub fn model_schema(identifier: &str) -> Option<&'static Value> {
    models()
        .iter()
        .find(|(id, _)| *id == identifier)
        .map(|(_, schema)| schema)
}

/// The schema of the newest object revision of `family` that has a model
/// (`latest_model_for_family`).
pub fn newest_model_schema(family: &str) -> Option<&'static Value> {
    models()
        .iter()
        .filter(|(id, _)| id.split_once("::").is_some_and(|(f, _)| f == family))
        .max_by_key(|(id, _)| {
            id.rsplit_once("::")
                .and_then(|(_, version)| version.split_once('.'))
                .map(|(major, minor)| {
                    (
                        major.parse::<u32>().unwrap_or_default(),
                        minor.parse::<u32>().unwrap_or_default(),
                    )
                })
        })
        .map(|(_, schema)| schema)
}

/// The paths of the fields that play `role` in the revision `identifier`,
/// in lexicographic order. A revision without a model (or `None`)
/// takes the union of every model's paths, as the oracle does for a body
/// whose `metadata.schema` it cannot resolve. Computed once, on first use.
pub fn role_paths(identifier: Option<&str>, role: FieldRole) -> &'static [Vec<String>] {
    type Table = Vec<(Option<&'static str>, FieldRole, Vec<Vec<String>>)>;
    static TABLE: OnceLock<Table> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        type Found = Vec<(&'static str, Vec<(Vec<String>, FieldRole)>)>;
        let found: Found = models()
            .iter()
            .map(|(id, schema)| (*id, fields_with_roles(schema)))
            .collect();
        let mut table: Table = Vec::new();
        for role in FieldRole::ALL {
            let mut union: Vec<Vec<String>> = Vec::new();
            for (id, paths) in &found {
                let mut own: Vec<Vec<String>> = paths
                    .iter()
                    .filter(|(_, found)| *found == role)
                    .map(|(path, _)| path.clone())
                    .collect();
                own.sort();
                own.dedup();
                union.extend(own.iter().cloned());
                table.push((Some(*id), role, own));
            }
            union.sort();
            union.dedup();
            table.push((None, role, union));
        }
        table
    });
    let wanted = identifier.filter(|id| model_schema(id).is_some());
    table
        .iter()
        .find(|(id, found, _)| *id == wanted && *found == role)
        .map_or(&[], |(_, _, paths)| paths.as_slice())
}

/// The schema of the property at `path` (field names as files write them)
/// in `schema`: each step goes through `$ref`, `anyOf`, `oneOf` and `items`
/// to the model that holds the next field. `None` when a step names no field.
pub fn property<'s>(schema: &'s Value, path: &[&str]) -> Option<&'s Value> {
    let mut current = schema;
    for (position, part) in path.iter().enumerate() {
        let found = find_property(schema, current, part, 0)?;
        if position + 1 == path.len() {
            return Some(found);
        }
        current = found;
    }
    None
}

fn find_property<'s>(
    root: &'s Value,
    schema: &'s Value,
    name: &str,
    depth: usize,
) -> Option<&'s Value> {
    if depth > 16 {
        return None;
    }
    if let Some(found) = schema
        .get("properties")
        .and_then(|properties| properties.get(name))
    {
        return Some(found);
    }
    if let Some(target) = schema.get("$ref").and_then(Value::as_str) {
        let definition = target
            .strip_prefix("#/$defs/")
            .and_then(|name| root.get("$defs")?.get(name))?;
        return find_property(root, definition, name, depth + 1);
    }
    for branch in ["anyOf", "oneOf"] {
        if let Some(options) = schema.get(branch).and_then(Value::as_array) {
            for option in options {
                if let Some(found) = find_property(root, option, name, depth + 1) {
                    return Some(found);
                }
            }
        }
    }
    schema
        .get("items")
        .and_then(|items| find_property(root, items, name, depth + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(paths: &[Vec<String>]) -> Vec<String> {
        paths.iter().map(|path| path.join(".")).collect()
    }

    /// The oracle's `_role_paths` for each revision and for none.
    #[test]
    fn role_paths_are_the_oracles() {
        assert_eq!(
            joined(role_paths(None, FieldRole::Techniques)),
            [
                "objective.mitre_attack",
                "techniques",
                "threat.mitre_attack"
            ]
        );
        assert_eq!(
            joined(role_paths(Some("rule::1.0"), FieldRole::Techniques)),
            ["techniques"]
        );
        assert_eq!(
            joined(role_paths(Some("threat::1.0"), FieldRole::Actors)),
            ["threat.actors"]
        );
        assert!(role_paths(Some("rule::1.1"), FieldRole::Actors).is_empty());
        assert_eq!(
            joined(role_paths(Some("rule::1.1"), FieldRole::Configurations)),
            ["configurations", "platforms"]
        );
        // An unknown revision reads every model's paths.
        assert_eq!(
            joined(role_paths(Some("rule::9.9"), FieldRole::Actors)),
            ["threat.actors"]
        );
    }

    #[test]
    fn properties_through_refs_lists_and_options() {
        let threat = model_schema("threat::1.0").unwrap();
        let surface = property(threat, &["threat", "surface"]).unwrap();
        assert_eq!(surface.get("tide.vocab.scoped"), Some(&Value::Bool(true)));
        assert!(property(threat, &["threat", "actors", "name"]).is_some());
        assert!(property(threat, &["threat", "nothing"]).is_none());
        assert!(newest_model_schema("objective").is_some());
        assert_eq!(
            newest_model_schema("rule"),
            model_schema("rule::1.1"),
            "the newest rule revision"
        );
        assert!(newest_model_schema("lunch").is_none());
    }
}
