//! Reading an object's fields by the role its model gives them
//! (`core/object_fields.py`): ATT&CK techniques, threat actors and platform
//! blocks live at different places in each family, and the places come from
//! the models (`opentide_schema::objects::fields::role_paths`), never from a
//! key list.

use std::collections::BTreeSet;

use opentide_schema::node::{Node, Value};
use opentide_schema::objects::FieldRole;
use opentide_schema::objects::fields::role_paths;

/// `_text`: `None` for a missing, `null` or empty value, else its text.
pub fn text(node: Option<&Node>) -> Option<String> {
    let node = node?;
    match &node.value {
        Value::Null => None,
        Value::Str(text) if text.is_empty() => None,
        _ => Some(node.value.to_string()),
    }
}

/// `_string`: the value when it is a string that is not blank.
pub fn string(node: Option<&Node>) -> Option<String> {
    match node.map(|node| &node.value) {
        Some(Value::Str(text)) if !text.trim().is_empty() => Some(text.clone()),
        _ => None,
    }
}

/// The value of `key` when `node` is a mapping.
pub fn get<'n>(node: &'n Node, key: &str) -> Option<&'n Node> {
    node.get(key).map(AsRef::as_ref)
}

/// The mapping under `key`, when it is one.
pub fn mapping<'n>(node: &'n Node, key: &str) -> Option<&'n Node> {
    get(node, key).filter(|child| matches!(child.value, Value::Map(_)))
}

/// The string under `key`, when it is one.
pub fn str_at<'n>(node: &'n Node, key: &str) -> Option<&'n str> {
    get(node, key).and_then(|child| match &child.value {
        Value::Str(text) => Some(text.as_str()),
        _ => None,
    })
}

/// `as_list`: a field that holds a list, read as one; a lone string that is
/// not blank is a list of itself.
pub fn as_list(node: Option<&Node>) -> Vec<&Node> {
    match node.map(|node| (node, &node.value)) {
        Some((node, Value::Str(text))) if !text.trim().is_empty() => vec![node],
        Some((_, Value::Seq(items))) => items.iter().map(AsRef::as_ref).collect(),
        _ => Vec::new(),
    }
}

/// `metadata.schema`, trimmed, when it is a string that is not blank.
pub fn schema_id(root: &Node) -> Option<String> {
    mapping(root, "metadata")
        .and_then(|metadata| str_at(metadata, "schema"))
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
}

fn resolve<'n>(node: &'n Node, path: &[String], out: &mut Vec<&'n Node>) {
    let Some((head, rest)) = path.split_first() else {
        return;
    };
    let Some(value) = get(node, head) else {
        return;
    };
    if rest.is_empty() {
        if !matches!(value.value, Value::Null) {
            out.push(value);
        }
        return;
    }
    match &value.value {
        Value::Map(_) => resolve(value, rest, out),
        Value::Seq(items) => {
            for item in items {
                if matches!(item.value, Value::Map(_)) {
                    resolve(item, rest, out);
                }
            }
        }
        _ => {}
    }
}

fn names(node: &Node, out: &mut Vec<String>) {
    match &node.value {
        Value::Str(text) => {
            let text = text.trim();
            if !text.is_empty() {
                out.push(text.to_owned());
            }
        }
        Value::Map(_) => {
            for key in ["name", "id", "value"] {
                if let Some(Value::Str(candidate)) = get(node, key).map(|n| &n.value)
                    && !candidate.trim().is_empty()
                {
                    out.push(candidate.trim().to_owned());
                    break;
                }
            }
        }
        Value::Seq(items) => {
            for item in items {
                names(item, out);
            }
        }
        _ => {}
    }
}

/// `object_role_values`: `(dotted field path, value)` for each value the
/// object's model tags with `role`, in authored order, each once.
pub fn role_values(root: &Node, role: FieldRole) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    for path in role_paths(schema_id(root).as_deref(), role) {
        let mut values = Vec::new();
        resolve(root, path, &mut values);
        for value in values {
            let mut out = Vec::new();
            names(value, &mut out);
            for name in out {
                if seen.insert(name.clone()) {
                    found.push((path.join("."), name));
                }
            }
        }
    }
    found
}

/// `object_platforms`: the lowercased keys of the object's platform blocks.
pub fn platforms(root: &Node) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for path in role_paths(schema_id(root).as_deref(), FieldRole::Configurations) {
        let mut values = Vec::new();
        resolve(root, path, &mut values);
        for value in values {
            if let Value::Map(entries) = &value.value {
                out.extend(
                    entries
                        .iter()
                        .map(|entry| entry.key.value.to_string().to_lowercase()),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_schema::node;

    fn root(text: &str) -> Node {
        node::load(text).unwrap().root().unwrap().as_ref().clone()
    }

    #[test]
    fn values_come_from_the_models_fields() {
        let threat = root(
            "metadata: {schema: threat::1.0}\nthreat:\n  mitre_attack: [T1059, ' T1003 ', T1059]\n  actors:\n    - {name: APT1}\n    - {id: G0006}\n    - {}\n",
        );
        assert_eq!(
            role_values(&threat, FieldRole::Techniques),
            [
                ("threat.mitre_attack".to_owned(), "T1059".to_owned()),
                ("threat.mitre_attack".to_owned(), "T1003".to_owned()),
            ]
        );
        assert_eq!(
            role_values(&threat, FieldRole::Actors)
                .into_iter()
                .map(|(_, value)| value)
                .collect::<Vec<_>>(),
            ["APT1", "G0006"]
        );
        // Without a schema, every model's paths apply.
        let rule = root("techniques: T1059\nconfigurations: {Sentinel: {}, splunk: 1}\n");
        assert_eq!(role_values(&rule, FieldRole::Techniques)[0].1, "T1059");
        assert_eq!(
            platforms(&rule).into_iter().collect::<Vec<_>>(),
            ["sentinel", "splunk"]
        );
    }

    #[test]
    fn scalars_print_as_yaml_writes_them() {
        let node = root("a: true\nb: ~\nc: 1.5\nd: ''\ne: x\n");
        assert_eq!(text(get(&node, "a")).as_deref(), Some("true"));
        assert_eq!(text(get(&node, "b")), None);
        assert_eq!(text(get(&node, "c")).as_deref(), Some("1.5"));
        assert_eq!(text(get(&node, "d")), None);
        assert_eq!(string(get(&node, "e")).as_deref(), Some("x"));
        assert_eq!(string(get(&node, "a")), None);
        assert_eq!(as_list(get(&node, "e")).len(), 1);
        assert!(as_list(get(&node, "d")).is_empty());
    }
}
