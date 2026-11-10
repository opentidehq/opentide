//! MITRE ATT&CK for the compilers: the techniques a rule inherits through its
//! detection model (`generation/framework.py` `techniques_resolver`), and the
//! `att&ck` vocabulary's names, links and stages (`get_vocab_entry`).

use opentide_schema::node::{Node, Value};
use opentide_schema::vocab::{Entry, Vocabularies, Vocabulary};
use opentide_workspace::Index;

/// The vocabulary field of ATT&CK techniques.
pub const ATTACK: &str = "att&ck";

/// Why the resolver could not finish: an object it walked lacks a key the
/// oracle indexes without a default (`threat.mitre_attack`), which the oracle
/// raises as a `KeyError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingKey(pub String);

/// The family the index files `uuid` under (`get_type`): an object family, or
/// `signal`.
fn family_of<'i>(index: &'i Index, uuid: &str) -> Option<(&'i str, &'i Node)> {
    for (family, objects) in &index.objects {
        if let Some(object) = objects.get(uuid) {
            return object.root().map(|root| (family.as_str(), root));
        }
    }
    index
        .signals
        .get(uuid)
        .map(|signal| ("signal", signal.node.as_ref()))
}

/// The strings of a sequence node; anything else is no strings.
fn strings(node: Option<&Node>) -> Vec<String> {
    match node.map(|node| &node.value) {
        Some(Value::Seq(items)) => items
            .iter()
            .filter_map(|item| match &item.value {
                Value::Str(text) => Some(text.clone()),
                Value::Int(integer) => Some(integer.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether a node is set as Python reads `if value:`.
fn truthy(node: Option<&Node>) -> bool {
    node.is_some_and(opentide_workspace::index::truthy)
}

/// The techniques `uuid` resolves to: a rule's through its detection model, a
/// signal's through its objective, an objective's own `mitre_attack` or else
/// its threats', a threat's `mitre_attack`; each list de-duplicated in order.
/// An object the index does not hold resolves to none.
pub fn techniques(index: &Index, uuid: &str) -> Result<Vec<String>, MissingKey> {
    resolve(index, uuid, 0)
}

/// Objects link at most this deep before the walk stops: the oracle recursed
/// without a bound, a cycle being a `RecursionError`.
const MAX_DEPTH: usize = 64;

fn resolve(index: &Index, uuid: &str, depth: usize) -> Result<Vec<String>, MissingKey> {
    if depth > MAX_DEPTH {
        return Ok(Vec::new());
    }
    let Some((family, body)) = family_of(index, uuid) else {
        return Ok(Vec::new());
    };
    let mut found: Vec<String> = Vec::new();
    match family {
        "rule" => {
            let Some(parent) = body
                .get("detection_model")
                .filter(|node| truthy(Some(node)))
            else {
                return Ok(Vec::new());
            };
            if let Some(parent) = parent.value.as_str() {
                found.extend(resolve(index, parent, depth + 1)?);
            }
        }
        "objective" => {
            let objective = body
                .get("objective")
                .ok_or_else(|| MissingKey("objective".to_owned()))?;
            let attack = objective.get("mitre_attack").map(AsRef::as_ref);
            if truthy(attack) {
                found = strings(attack);
            } else if let Some(Value::Seq(threats)) = objective.get("threats").map(|n| &n.value) {
                for threat in threats {
                    if let Some(threat) = threat.value.as_str() {
                        found.extend(resolve(index, threat, depth + 1)?);
                    }
                }
            }
        }
        "signal" => {
            let Some(owner) = index.signals.get(uuid).map(|signal| signal.owner.as_str()) else {
                return Ok(Vec::new());
            };
            found.extend(resolve(index, owner, depth + 1)?);
        }
        "threat" => {
            let threat = body
                .get("threat")
                .ok_or_else(|| MissingKey("threat".to_owned()))?;
            let attack = threat
                .get("mitre_attack")
                .ok_or_else(|| MissingKey("mitre_attack".to_owned()))?;
            found = strings(Some(attack));
        }
        _ => {}
    }
    let mut unique: Vec<String> = Vec::with_capacity(found.len());
    for technique in found {
        if !unique.contains(&technique) {
            unique.push(technique);
        }
    }
    Ok(unique)
}

/// The vocabulary entries the compilers read.
pub struct Attack {
    vocabulary: Option<std::sync::Arc<Vocabulary>>,
    vocabularies: Vocabularies,
}

impl Attack {
    /// The `att&ck` vocabulary of `vocabularies`.
    pub fn new(vocabularies: &Vocabularies) -> Self {
        Self {
            vocabulary: vocabularies.get(ATTACK),
            vocabularies: vocabularies.clone(),
        }
    }

    /// The entry `id` names (`get_vocab_entry`): by key after the stage prefix
    /// is resolved, else the entry whose `legacy` is `id`.
    pub fn entry(&self, id: &str) -> Option<&Entry> {
        let vocabulary = self.vocabulary.as_deref()?;
        let key = self.vocabularies.identifier(ATTACK, id);
        if let Some(entry) = vocabulary.entries.get(key) {
            return Some(entry);
        }
        vocabulary.entries.values().find(|entry| {
            entry
                .extra
                .get("legacy")
                .and_then(|value| value.as_str())
                .is_some_and(|legacy| legacy == key)
        })
    }

    /// The entry's name.
    pub fn name(&self, id: &str) -> Option<&str> {
        self.entry(id).map(|entry| entry.name.as_str())
    }

    /// The entry's link, if it has one.
    pub fn link(&self, id: &str) -> Option<&str> {
        self.entry(id)
            .map(|entry| entry.link.as_str())
            .filter(|link| !link.is_empty())
    }

    /// The entry's stages (`tide.vocab.stages`).
    pub fn stages(&self, id: &str) -> Vec<String> {
        self.entry(id)
            .map(|entry| entry.stages.clone())
            .unwrap_or_default()
    }
}

/// The Enterprise ATT&CK tactics, in matrix order, with their ids.
pub const TACTIC_ORDER: [(&str, &str); 15] = [
    ("Reconnaissance", "TA0043"),
    ("Resource Development", "TA0042"),
    ("Initial Access", "TA0001"),
    ("Execution", "TA0002"),
    ("Persistence", "TA0003"),
    ("Privilege Escalation", "TA0004"),
    ("Stealth", "TA0005"),
    ("Defense Impairment", "TA0112"),
    ("Credential Access", "TA0006"),
    ("Discovery", "TA0007"),
    ("Lateral Movement", "TA0008"),
    ("Collection", "TA0009"),
    ("Command and Control", "TA0011"),
    ("Exfiltration", "TA0010"),
    ("Impact", "TA0040"),
];

/// The tactic a vocabulary stage maps to (`TACTIC_MAP`): its name in any case,
/// the misspelt `priviledge escalation`, and `defense evasion` as `Stealth`.
pub fn tactic(stage: &str) -> Option<(&'static str, &'static str)> {
    let key = stage.trim().to_lowercase();
    match key.as_str() {
        "priviledge escalation" => Some(("Privilege Escalation", "TA0004")),
        "defense evasion" => Some(("Stealth", "TA0005")),
        _ => TACTIC_ORDER
            .iter()
            .find(|(name, _)| name.to_lowercase() == key)
            .copied(),
    }
}

/// Name prefixes of the matrices other than Enterprise.
pub const NON_ENTERPRISE_PREFIXES: [&str; 2] = ["Mobile : ", "Industrial : "];

/// Whether a technique's name places it outside Enterprise ATT&CK.
pub fn non_enterprise(name: &str) -> bool {
    NON_ENTERPRISE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_map_to_tactics() {
        assert_eq!(tactic("execution"), Some(("Execution", "TA0002")));
        assert_eq!(tactic(" Defense Evasion "), Some(("Stealth", "TA0005")));
        assert_eq!(
            tactic("Priviledge Escalation"),
            Some(("Privilege Escalation", "TA0004"))
        );
        assert_eq!(tactic("Inhibit Response Function"), None);
    }

    #[test]
    fn bundled_entries_have_names_and_stages() {
        let attack = Attack::new(&Vocabularies::bundled());
        assert_eq!(
            attack.name("T1059"),
            Some("Command and Scripting Interpreter")
        );
        assert!(
            attack
                .stages("T1059")
                .iter()
                .any(|stage| stage == "Execution")
        );
        assert!(attack.entry("T0000000").is_none());
    }
}
