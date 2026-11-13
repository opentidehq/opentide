//! An object's parents and children (`generation/framework.py` `get_type`,
//! `parents`, `childs` and its reverse relation index).
//!
//! | Parent | Children | Read from the child |
//! |--------|----------|---------------------|
//! | threat | objectives | `detection.vectors`, `detection.threats`, `objective.vectors`, `objective.threats` |
//! | objective | signals, then rules | `detection_model`, `owner` (a signal's objective) |
//! | signal | rules | `detection_model` |
//!
//! Children are listed in index order, a child once per reference that names
//! the parent.

use std::collections::HashMap;

use opentide_schema::node::{Node, Value};
use opentide_workspace::Index;

use super::Cause;

/// An object of the flat index: its body, and its objective when it is a signal.
#[derive(Clone, Copy)]
pub struct Body<'i> {
    /// The document's root, or the signal's mapping.
    pub node: &'i Node,
    /// The objective a signal is indexed under (`owner`).
    pub owner: Option<&'i str>,
}

impl<'i> Body<'i> {
    /// The value of `key`; a signal's `owner` is its objective.
    pub fn get(&self, key: &str) -> Option<&'i Node> {
        self.node.get(key).map(AsRef::as_ref)
    }
}

/// The relations of every object of an index, inverted once.
pub struct Relations<'i> {
    index: &'i Index,
    /// `parent type → parent uuid → children`.
    children: HashMap<&'static str, HashMap<String, Vec<String>>>,
}

/// The parent types, the child types each has, the sections a reference sits
/// in (none: at the top) and the references.
/// A parent type, its child types, the sections and the references.
type ChildRelation = (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
);

const CHILD_RELATIONS: [ChildRelation; 3] = [
    (
        "threat",
        &["objective"],
        &["detection", "objective"],
        &["vectors", "threats"],
    ),
    (
        "objective",
        &["signal", "rule"],
        &[],
        &["detection_model", "owner"],
    ),
    ("signal", &["rule"], &[], &["detection_model"]),
];

/// The UUIDs a reference names: a string, or the strings of a list.
fn referenced(node: Option<&Node>) -> Vec<String> {
    match node.map(|node| &node.value) {
        Some(Value::Str(text)) => vec![text.clone()],
        Some(Value::Seq(items)) => items
            .iter()
            .filter_map(|item| item.value.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

impl<'i> Relations<'i> {
    /// The relations of `index`.
    pub fn new(index: &'i Index) -> Self {
        let mut children: HashMap<&'static str, HashMap<String, Vec<String>>> = HashMap::new();
        for (parent_type, child_types, sections, references) in CHILD_RELATIONS {
            let per_type = children.entry(parent_type).or_default();
            for child_type in child_types {
                for (uuid, body) in Self::family(index, child_type) {
                    let mut parents: Vec<String> = Vec::new();
                    if sections.is_empty() {
                        for reference in references {
                            match body.owner {
                                Some(owner) if *reference == "owner" => {
                                    parents.push(owner.to_owned());
                                }
                                _ => parents.extend(referenced(body.get(reference))),
                            }
                        }
                    } else {
                        for section in sections {
                            let section = body
                                .get(section)
                                .filter(|node| matches!(node.value, Value::Map(_)));
                            for reference in references {
                                parents.extend(referenced(section.and_then(|section| {
                                    section.get(reference).map(AsRef::as_ref)
                                })));
                            }
                        }
                    }
                    for parent in parents {
                        per_type.entry(parent).or_default().push(uuid.to_owned());
                    }
                }
            }
        }
        Self { index, children }
    }

    /// The objects of `family` (or the signals), in index order.
    fn family(index: &'i Index, family: &str) -> Vec<(&'i str, Body<'i>)> {
        if family == "signal" {
            return index
                .signals
                .values()
                .map(|signal| {
                    (
                        signal.uuid.as_str(),
                        Body {
                            node: signal.node.as_ref(),
                            owner: Some(signal.owner.as_str()),
                        },
                    )
                })
                .collect();
        }
        index
            .objects
            .get(family)
            .into_iter()
            .flat_map(|members| members.values())
            .filter_map(|object| {
                object
                    .root()
                    .map(|node| (object.uuid.as_str(), Body { node, owner: None }))
            })
            .collect()
    }

    /// The index these relations are of.
    pub fn index(&self) -> &'i Index {
        self.index
    }

    /// The body `uuid` names in the flat index (objects of every family, then
    /// signals).
    pub fn body(&self, uuid: &str) -> Option<Body<'i>> {
        for members in self.index.objects.values() {
            if let Some(object) = members.get(uuid) {
                return object.root().map(|node| Body { node, owner: None });
            }
        }
        self.index.signals.get(uuid).map(|signal| Body {
            node: signal.node.as_ref(),
            owner: Some(signal.owner.as_str()),
        })
    }

    /// The type of `uuid` (`get_type`): its schema's family, else `signal` for
    /// a signal or `rule` for a body with `configurations`.
    ///
    /// # Errors
    ///
    /// The object is not in the index, or has no schema and is neither.
    pub fn kind(&self, uuid: &str) -> Result<String, Cause> {
        let body = self
            .body(uuid)
            .filter(|body| opentide_workspace::index::truthy(body.node))
            .ok_or_else(|| Cause::Other(format!("UUID {uuid} does not exist in the catalogue")))?;
        let schema = body
            .get("metadata")
            .and_then(|metadata| metadata.get("schema"))
            .map(AsRef::as_ref)
            .filter(|schema| opentide_workspace::index::truthy(schema));
        if let Some(schema) = schema {
            let text = node_text(schema);
            return Ok(text.split("::").next().unwrap_or_default().to_owned());
        }
        if self.index.signals.contains_key(uuid) {
            return Ok("signal".to_owned());
        }
        if body
            .get("configurations")
            .is_some_and(opentide_workspace::index::truthy)
        {
            return Ok("rule".to_owned());
        }
        let name = body
            .get("name")
            .map_or_else(|| "NAME NOT FOUND".to_owned(), node_text);
        Err(Cause::Other(format!(
            "Object {name} is missing a schema identifier"
        )))
    }

    /// The direct children of `uuid` (`childs`).
    ///
    /// # Errors
    ///
    /// [`Self::kind`]'s.
    pub fn children(&self, uuid: &str) -> Result<Vec<String>, Cause> {
        let kind = self.kind(uuid)?;
        Ok(self
            .children
            .get(kind.as_str())
            .and_then(|per_type| per_type.get(uuid))
            .cloned()
            .unwrap_or_default())
    }

    /// The parents of `uuid` (`parents`): an objective's threats, a signal's
    /// objective, a rule's detection model.
    ///
    /// # Errors
    ///
    /// [`Self::kind`]'s; an objective without `objective`; a rule whose
    /// detection model the index does not hold.
    pub fn parents(&self, uuid: &str) -> Result<Vec<String>, Cause> {
        let kind = self.kind(uuid)?;
        let Some(body) = self.body(uuid) else {
            return Ok(Vec::new());
        };
        let parents: Vec<String> = match kind.as_str() {
            "objective" => {
                let objective = body
                    .get("objective")
                    .ok_or_else(|| Cause::MissingKey("objective".to_owned()))?;
                let threats = objective
                    .get("threats")
                    .map(AsRef::as_ref)
                    .filter(|node| opentide_workspace::index::truthy(node));
                listed(threats)
            }
            "signal" => body.owner.map(str::to_owned).into_iter().collect(),
            "rule" => listed(
                body.get("detection_model")
                    .filter(|node| opentide_workspace::index::truthy(node)),
            ),
            _ => return Ok(Vec::new()),
        };
        if kind == "rule" {
            let missing: Vec<&str> = parents
                .iter()
                .map(String::as_str)
                .filter(|parent| !parent.is_empty() && self.body(parent).is_none())
                .collect();
            if !missing.is_empty() {
                return Err(Cause::Other(format!(
                    "detection_model {} does not exist in the catalogue",
                    missing.join(", ")
                )));
            }
        }
        Ok(parents)
    }
}

/// A reference field as a list: a string alone, or a list's items as text.
fn listed(node: Option<&Node>) -> Vec<String> {
    match node.map(|node| &node.value) {
        None => Vec::new(),
        Some(Value::Seq(items)) => items.iter().map(|item| node_text(item)).collect(),
        Some(_) => node.map(node_text).into_iter().collect(),
    }
}

/// A value as text: a string as it is, anything else as its JSON (`1`,
/// `null`, `true`, `["x",1]`).
pub fn node_text(node: &Node) -> String {
    match &node.value {
        Value::Str(text) | Value::Datetime(text) => text.clone(),
        _ => crate::json::Json::from_node(node).to_compact(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_as_text() {
        let document =
            opentide_schema::node::load("a: x\nb: 1\nc: ~\nd: true\ne: 1.5\nf: [x, 1]\n").unwrap();
        let root = document.root().unwrap();
        let text = |key: &str| node_text(root.get(key).unwrap());
        assert_eq!(text("a"), "x");
        assert_eq!(text("b"), "1");
        assert_eq!(text("c"), "null");
        assert_eq!(text("d"), "true");
        assert_eq!(text("e"), "1.5");
        assert_eq!(text("f"), r#"["x",1]"#);
    }

    fn index_of(objects: &[(&str, &str, &str)]) -> Index {
        let mut index = Index::default();
        for (family, uuid, text) in objects {
            index
                .objects
                .entry((*family).to_owned())
                .or_default()
                .insert(
                    (*uuid).to_owned(),
                    opentide_workspace::Object {
                        uuid: (*uuid).to_owned(),
                        family: (*family).to_owned(),
                        path: std::path::PathBuf::from(format!("{uuid}.yaml")),
                        document: std::sync::Arc::new(opentide_schema::node::load(text).unwrap()),
                    },
                );
        }
        index
    }

    #[test]
    fn a_rule_whose_detection_model_is_not_indexed_fails() {
        let index = index_of(&[
            (
                "objective",
                "o1",
                "name: O\nmetadata: {schema: 'objective::1.0'}\nobjective: {}\n",
            ),
            (
                "rule",
                "r1",
                "name: R\nmetadata: {schema: 'rule::1.0'}\ndetection_model: o1\n",
            ),
            (
                "rule",
                "r2",
                "name: R2\nmetadata: {schema: 'rule::1.0'}\ndetection_model: [o1, gone, lost]\n",
            ),
        ]);
        let relations = Relations::new(&index);
        assert_eq!(relations.parents("r1").unwrap(), ["o1"]);
        assert_eq!(
            relations.parents("r2").unwrap_err(),
            Cause::Other("detection_model gone, lost does not exist in the catalogue".into())
        );
        assert_eq!(relations.children("o1").unwrap(), ["r1", "r2"]);
    }

    #[test]
    fn an_objects_kind_is_its_schema_else_what_it_holds() {
        let mut index = index_of(&[
            (
                "threat",
                "t1",
                "name: T\nmetadata: {schema: 'threat::1.0'}\n",
            ),
            (
                "rule",
                "r1",
                "name: R\nmetadata: {}\nconfigurations: {sentinel: {}}\n",
            ),
            ("rule", "x1", "name: Lost\nmetadata: {schema: ''}\n"),
            ("rule", "x2", "metadata: {}\n"),
            ("rule", "empty", "{}\n"),
        ]);
        index.signals.insert(
            "s1".into(),
            opentide_workspace::index::Signal {
                uuid: "s1".into(),
                owner: "o1".into(),
                node: opentide_schema::node::load("name: S\n")
                    .unwrap()
                    .root()
                    .unwrap()
                    .clone(),
            },
        );
        let relations = Relations::new(&index);
        assert_eq!(relations.kind("t1").unwrap(), "threat");
        assert_eq!(relations.kind("s1").unwrap(), "signal");
        assert_eq!(relations.kind("r1").unwrap(), "rule");
        assert_eq!(
            relations.kind("x1").unwrap_err(),
            Cause::Other("Object Lost is missing a schema identifier".into())
        );
        assert_eq!(
            relations.kind("x2").unwrap_err(),
            Cause::Other("Object NAME NOT FOUND is missing a schema identifier".into())
        );
        for unknown in ["empty", "nowhere"] {
            assert_eq!(
                relations.kind(unknown).unwrap_err(),
                Cause::Other(format!("UUID {unknown} does not exist in the catalogue"))
            );
        }
    }

    #[test]
    fn references_are_strings_or_lists_of_strings() {
        let document = opentide_schema::node::load("a: x\nb: [x, 1, y]\nc: 3\n").unwrap();
        let root = document.root().unwrap();
        assert_eq!(referenced(root.get("a").map(AsRef::as_ref)), ["x"]);
        assert_eq!(referenced(root.get("b").map(AsRef::as_ref)), ["x", "y"]);
        assert!(referenced(root.get("c").map(AsRef::as_ref)).is_empty());
        assert!(referenced(None).is_empty());
    }
}
