//! Field roles (`models/base.py` `FieldRole`): the role a field plays for
//! cross-object field extraction, declared under `tide.field.role` in the
//! field's schema, so extraction derives from the model, not a key list.

use std::fmt;
use std::str::FromStr;

use serde_json::Value;

use crate::keys;

/// The catalogue role a model field plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FieldRole {
    /// ATT&CK technique ids (`techniques`, `mitre_attack`).
    Techniques,
    /// Threat actors (`threat.actors`).
    Actors,
    /// Platform configuration blocks (`configurations`, `platforms`).
    Configurations,
}

impl FieldRole {
    /// Every role, in `FieldRole`'s order.
    pub const ALL: [Self; 3] = [Self::Techniques, Self::Actors, Self::Configurations];

    /// The value under `tide.field.role`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Techniques => "techniques",
            Self::Actors => "actors",
            Self::Configurations => "configurations",
        }
    }
}

impl fmt::Display for FieldRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `tide.field.role` value no role has (`field_role` returns `None` for
/// it, as the oracle's does).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no field role `{0}`")]
pub struct UnknownRole(pub String);

impl FromStr for FieldRole {
    type Err = UnknownRole;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == text)
            .ok_or_else(|| UnknownRole(text.to_owned()))
    }
}

/// The role a field's schema declares (`field_role`), if any.
pub fn field_role(field_schema: &Value) -> Option<FieldRole> {
    field_schema.get(keys::FIELD_ROLE)?.as_str()?.parse().ok()
}

/// Every field of a model's schema (`schemars::schema_for!(T)`) that
/// declares a role, with its path of property names from the root, in the
/// schema's order. Sub-models are followed through `$ref`, arrays through
/// `items` and optional fields through `anyOf`.
pub fn fields_with_roles(schema: &Value) -> Vec<(Vec<String>, FieldRole)> {
    let mut found = Vec::new();
    walk(schema, schema, &mut Vec::new(), &mut found, 0);
    found
}

fn walk(
    root: &Value,
    schema: &Value,
    path: &mut Vec<String>,
    found: &mut Vec<(Vec<String>, FieldRole)>,
    depth: usize,
) {
    // The object models nest a few levels; the bound guards a recursive model.
    if depth > 32 {
        return;
    }
    if let Some(target) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(name) = target.strip_prefix("#/$defs/")
            && let Some(definition) = root.get("$defs").and_then(|defs| defs.get(name))
        {
            walk(root, definition, path, found, depth + 1);
        }
        return;
    }
    for branch in ["anyOf", "oneOf"] {
        if let Some(options) = schema.get(branch).and_then(Value::as_array) {
            for option in options {
                walk(root, option, path, found, depth + 1);
            }
        }
    }
    if let Some(items) = schema.get("items") {
        walk(root, items, path, found, depth + 1);
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            path.push(name.clone());
            if let Some(role) = field_role(property) {
                found.push((path.clone(), role));
            }
            walk(root, property, path, found, depth + 1);
            path.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_read_and_print_as_the_oracles() {
        for role in FieldRole::ALL {
            assert_eq!(role.as_str().parse::<FieldRole>(), Ok(role));
        }
        assert_eq!(
            "actor".parse::<FieldRole>(),
            Err(UnknownRole("actor".into()))
        );
        assert_eq!(
            field_role(&serde_json::json!({"tide.field.role": "unknown"})),
            None
        );
    }
}
