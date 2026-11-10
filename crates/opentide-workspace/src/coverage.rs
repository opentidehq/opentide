//! Which ATT&CK techniques each rule covers: those it lists, and those it
//! inherits from its objective or that objective's threats
//! (`core/technique_coverage.py`). `info catalog` and `info coverage` read
//! coverage from here, so they cannot disagree.

use indexmap::IndexMap;
use opentide_schema::node::{Node, Value};
use opentide_schema::objects::FieldRole;
use serde::Serialize;

use crate::fields::{as_list, get, mapping, role_values};
use crate::index::Index;

/// The objects of `family` in the index, by UUID.
pub fn bucket<'i>(index: &'i Index, family: &str) -> Vec<(&'i str, &'i Node)> {
    index
        .objects
        .get(family)
        .map(|objects| {
            objects
                .iter()
                .filter_map(|(uuid, object)| Some((uuid.as_str(), object.root()?)))
                .collect()
        })
        .unwrap_or_default()
}

fn lookup<'i>(index: &'i Index, family: &str, uuid: &str) -> Option<&'i Node> {
    index.objects.get(family)?.get(uuid)?.root()
}

/// The techniques an object lists itself, in authored order.
pub fn own_techniques(root: &Node) -> Vec<String> {
    role_values(root, FieldRole::Techniques)
        .into_iter()
        .map(|(_, technique)| technique)
        .collect()
}

/// An objective's techniques: its own, else those of each threat it covers
/// that exists, each once.
fn objective_techniques(objective: &Node, index: &Index) -> Vec<String> {
    let own = own_techniques(objective);
    if !own.is_empty() {
        return own;
    }
    let mut found: Vec<String> = Vec::new();
    let covered = mapping(objective, "objective").map(|section| get(section, "threats"));
    for threat in as_list(covered.flatten()) {
        if let Value::Str(uuid) = &threat.value
            && let Some(parent) = lookup(index, "threat", uuid)
        {
            for technique in own_techniques(parent) {
                if !found.contains(&technique) {
                    found.push(technique);
                }
            }
        }
    }
    found
}

/// The objective a rule implements: its `detection_model`, or the owner of
/// the signal it names.
pub fn rule_objective<'i>(rule: &Node, index: &'i Index) -> Option<&'i Node> {
    let Some(Value::Str(target)) = get(rule, "detection_model").map(|n| &n.value) else {
        return None;
    };
    let owner = index
        .signals
        .get(target)
        .map_or(target.as_str(), |signal| signal.owner.as_str());
    lookup(index, "objective", owner)
}

/// What an object gets from its parents: a rule its objective's
/// techniques, an objective its threats'. May repeat the object's own.
pub fn inherited_techniques(family: &str, root: &Node, index: &Index) -> Vec<String> {
    match family {
        "objective" => objective_techniques(root, index),
        "rule" => rule_objective(root, index)
            .map(|objective| objective_techniques(objective, index))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The techniques one rule covers, kept apart by where they come from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleTechniques {
    /// Listed by the rule, in authored order.
    pub own: Vec<String>,
    /// From its objective or that objective's threats, without its own.
    pub inherited: Vec<String>,
}

/// Every rule's techniques, in index order.
pub fn rule_technique_index(index: &Index) -> IndexMap<String, RuleTechniques> {
    bucket(index, "rule")
        .into_iter()
        .map(|(uuid, rule)| {
            let own = own_techniques(rule);
            let mut inherited: Vec<String> = Vec::new();
            for technique in inherited_techniques("rule", rule, index) {
                if !own.contains(&technique) && !inherited.contains(&technique) {
                    inherited.push(technique);
                }
            }
            (uuid.to_owned(), RuleTechniques { own, inherited })
        })
        .collect()
}

/// Whether `candidate` answers a query for `requested`: case-insensitive,
/// and a parent technique covers its sub-techniques.
pub fn technique_covers(requested: &str, candidate: &str) -> bool {
    let needle = requested.trim().to_lowercase();
    let value = candidate.trim().to_lowercase();
    !needle.is_empty() && (value == needle || value.starts_with(&format!("{needle}.")))
}

/// The rules that cover one technique (`info coverage`'s document).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TechniqueMatch {
    /// The technique asked for, trimmed.
    pub technique: String,
    /// Every covering rule: those that list it first.
    pub rules: Vec<String>,
    /// How many.
    pub count: usize,
    /// Rules whose own list covers it.
    pub own: Vec<String>,
    /// Rules that cover it only through their objective or its threats.
    pub inherited: Vec<String>,
    /// The technique ids that matched, sorted.
    pub matched_techniques: Vec<String>,
}

/// The rules of `index` that cover `technique`.
pub fn match_technique(
    technique: &str,
    index: &IndexMap<String, RuleTechniques>,
) -> TechniqueMatch {
    let needle = technique.trim();
    let mut own = Vec::new();
    let mut inherited = Vec::new();
    let mut matched = std::collections::BTreeSet::new();
    for (uuid, techniques) in index {
        let own_hits: Vec<&String> = techniques
            .own
            .iter()
            .filter(|t| technique_covers(needle, t))
            .collect();
        let inherited_hits: Vec<&String> = techniques
            .inherited
            .iter()
            .filter(|t| technique_covers(needle, t))
            .collect();
        matched.extend(own_hits.iter().map(|t| (*t).clone()));
        matched.extend(inherited_hits.iter().map(|t| (*t).clone()));
        if !own_hits.is_empty() {
            own.push(uuid.clone());
        } else if !inherited_hits.is_empty() {
            inherited.push(uuid.clone());
        }
    }
    let rules: Vec<String> = own.iter().chain(&inherited).cloned().collect();
    TechniqueMatch {
        technique: needle.to_owned(),
        count: rules.len(),
        rules,
        own,
        inherited,
        matched_techniques: matched.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parent_covers_its_subtechniques_only() {
        assert!(technique_covers("T1059", "t1059.001"));
        assert!(technique_covers(" t1059 ", "T1059"));
        assert!(!technique_covers("T1059.001", "T1059"));
        assert!(!technique_covers("T105", "T1059"));
        assert!(!technique_covers(" ", "T1059"));
    }

    #[test]
    fn own_rules_come_first_and_matches_are_sorted() {
        let mut index = IndexMap::new();
        index.insert(
            "b".to_owned(),
            RuleTechniques {
                own: Vec::new(),
                inherited: vec!["T1059.003".into()],
            },
        );
        index.insert(
            "a".to_owned(),
            RuleTechniques {
                own: vec!["T1059.001".into()],
                inherited: vec!["T1059".into()],
            },
        );
        index.insert("c".to_owned(), RuleTechniques::default());
        let found = match_technique("T1059 ", &index);
        assert_eq!(found.technique, "T1059");
        assert_eq!(found.rules, ["a", "b"]);
        assert_eq!(found.own, ["a"]);
        assert_eq!(found.inherited, ["b"]);
        assert_eq!(found.count, 2);
        assert_eq!(
            found.matched_techniques,
            ["T1059", "T1059.001", "T1059.003"]
        );
    }
}
