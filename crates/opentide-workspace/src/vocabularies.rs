//! The vocabularies a workspace's own objects make, for the editor schemas
//! (`build_object_vocabularies`; UC-1.8b, #900): one per family, keyed by
//! UUID, each entry with the object's name, TLP, level and description, and
//! an objective's signals after it (`<objective>::<signal>`), so a rule's
//! `detection_model` offers both.

use opentide_schema::node::{Node, Value};
use opentide_schema::vocab::{OBJECT_TYPES, Vocabulary};

use crate::index::Index;

fn scalar(node: &Node) -> Option<toml::Value> {
    Some(match &node.value {
        Value::Null => return None,
        Value::Bool(flag) => toml::Value::Boolean(*flag),
        Value::Int(number) => toml::Value::Integer(*number),
        Value::Float(number) => toml::Value::Float(*number),
        Value::Str(text) | Value::Datetime(text) => toml::Value::String(text.replace("\n ", " ")),
        Value::Seq(items) => toml::Value::Array(items.iter().filter_map(|i| scalar(i)).collect()),
        Value::Map(_) => toml::Value::String(node.value.to_string()),
    })
}

fn put(entry: &mut toml::Table, key: &str, node: Option<&Node>) {
    if let Some(value) = node.and_then(scalar) {
        entry.insert(key.to_owned(), value);
    }
}

fn text(node: Option<&Node>) -> Option<String> {
    match node.map(|node| &node.value) {
        Some(Value::Null) | None => None,
        Some(value) => Some(value.to_string()),
    }
}

/// The vocabulary of each family's objects in `index`, in [`OBJECT_TYPES`]'
/// order, named as the resolved configuration's `[documentation.object_names]`
/// names the family (`config`); a family with no objects has an empty one. An object
/// without a name or a `metadata` mapping is left out, as the oracle leaves
/// it out.
pub fn object_vocabularies(index: &Index, config: &Node) -> Vec<Vocabulary> {
    let mut out = Vec::new();
    for family in OBJECT_TYPES {
        let mut keys = Vec::new();
        for object in index
            .objects
            .get(family)
            .into_iter()
            .flat_map(|objects| objects.values())
        {
            let Some(root) = object.root() else {
                continue;
            };
            let Some(name) = text(root.get("name").map(AsRef::as_ref))
                .filter(|name| !name.is_empty() && name != "false")
            else {
                continue;
            };
            let Some(metadata) = root
                .get("metadata")
                .filter(|metadata| matches!(metadata.value, Value::Map(_)))
            else {
                continue;
            };
            let mut entry = toml::Table::new();
            entry.insert("id".to_owned(), toml::Value::String(object.uuid.clone()));
            entry.insert(
                "name".to_owned(),
                toml::Value::String(name.replace("\n ", " ")),
            );
            put(&mut entry, "tlp", metadata.get("tlp").map(AsRef::as_ref));
            put(
                &mut entry,
                "criticality",
                root.get("criticality").map(AsRef::as_ref),
            );
            if let Some(actor) = root.get("actor") {
                put(
                    &mut entry,
                    "aliases",
                    actor.get("aliases").map(AsRef::as_ref),
                );
            }
            let body = match family {
                "threat" => root.get("threat"),
                "objective" => root.get("objective"),
                _ => None,
            };
            let description = match family {
                "rule" => root.get("description"),
                _ => body.and_then(|body| body.get("description")),
            };
            if family == "objective" {
                put(
                    &mut entry,
                    "priority",
                    body.and_then(|b| b.get("priority")).map(AsRef::as_ref),
                );
            }
            put(&mut entry, "description", description.map(AsRef::as_ref));
            keys.push(toml::Value::Table(entry));
            if family != "objective" {
                continue;
            }
            let signals = match body.and_then(|body| body.get("signals")).map(|n| &n.value) {
                Some(Value::Seq(signals)) => signals.clone(),
                _ => Vec::new(),
            };
            for signal in signals {
                let uuid = text(signal.get("uuid").map(AsRef::as_ref)).filter(|u| !u.is_empty());
                let signal_name =
                    text(signal.get("name").map(AsRef::as_ref)).filter(|n| !n.is_empty());
                let (Some(uuid), Some(signal_name)) = (uuid, signal_name) else {
                    continue;
                };
                let mut entry = toml::Table::new();
                entry.insert("id".to_owned(), toml::Value::String(uuid));
                entry.insert(
                    "name".to_owned(),
                    toml::Value::String(format!("{name}::{signal_name}").replace("\n ", " ")),
                );
                entry.insert(
                    opentide_schema::keys::OBJECT_PARENT.to_owned(),
                    toml::Value::String(object.uuid.clone()),
                );
                put(&mut entry, "tlp", metadata.get("tlp").map(AsRef::as_ref));
                put(
                    &mut entry,
                    "severity",
                    signal.get("severity").map(AsRef::as_ref),
                );
                put(
                    &mut entry,
                    "description",
                    signal.get("description").map(AsRef::as_ref),
                );
                keys.push(toml::Value::Table(entry));
            }
        }
        let mut table = toml::Table::new();
        let display = config
            .get("documentation")
            .and_then(|documentation| documentation.get("object_names"))
            .and_then(|names| names.get(family))
            .and_then(|name| name.value.as_str())
            .unwrap_or(family);
        table.insert("name".to_owned(), toml::Value::String(display.to_owned()));
        table.insert("field".to_owned(), toml::Value::String(family.to_owned()));
        table.insert("key".to_owned(), toml::Value::String("id".to_owned()));
        table.insert("keys".to_owned(), toml::Value::Array(keys));
        if let Ok(vocabulary) = Vocabulary::from_table(table, family) {
            out.push(vocabulary);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Object;
    use indexmap::IndexMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn object(family: &str, uuid: &str, text: &str) -> Object {
        Object {
            uuid: uuid.to_owned(),
            family: family.to_owned(),
            path: PathBuf::from(format!("{uuid}.yaml")),
            document: Arc::new(opentide_schema::node::load(text).unwrap()),
        }
    }

    #[test]
    fn objects_and_signals_become_entries_by_uuid() {
        let mut index = Index::default();
        let mut objectives = IndexMap::new();
        objectives.insert(
            "o1".to_owned(),
            object(
                "objective",
                "o1",
                "name: Credential access\nmetadata:\n  tlp: amber\nobjective:\n  description: Finds it.\n  priority: High\n  signals:\n    - uuid: s1\n      name: Logon\n      severity: Low\n    - name: no uuid\n",
            ),
        );
        objectives.insert(
            "o2".to_owned(),
            object("objective", "o2", "name: No metadata\n"),
        );
        index.objects.insert("objective".to_owned(), objectives);
        let config = opentide_schema::configuration::toml::parse(
            "[documentation.object_names]\nobjective = \"Detection Objectives\"\n",
        )
        .unwrap();
        let vocabularies = object_vocabularies(&index, &config);
        let fields: Vec<&str> = vocabularies.iter().map(Vocabulary::field).collect();
        assert_eq!(fields, ["threat", "objective", "rule"]);
        let objective = &vocabularies[1];
        assert_eq!(objective.metadata.name, "Detection Objectives");
        assert_eq!(vocabularies[0].metadata.name, "threat");
        let keys: Vec<&String> = objective.entries.keys().collect();
        assert_eq!(keys, ["o1", "s1"]);
        assert_eq!(objective.entries["o1"].name, "Credential access");
        assert_eq!(objective.entries["o1"].description, "Finds it.");
        assert_eq!(
            objective.entries["o1"]
                .extra
                .get("priority")
                .and_then(toml::Value::as_str),
            Some("High")
        );
        let signal = &objective.entries["s1"];
        assert_eq!(signal.name, "Credential access::Logon");
        assert_eq!(
            signal
                .extra
                .get(opentide_schema::keys::OBJECT_PARENT)
                .and_then(toml::Value::as_str),
            Some("o1")
        );
        assert!(vocabularies[2].entries.is_empty());
    }
}
