//! The ATT&CK Enterprise matrix `info catalog` shows: tactics in order, each
//! with its techniques, and every technique with its name, parent and
//! sub-techniques, from the `att&ck` vocabulary at the newest revision an
//! object schema pins.

use std::collections::BTreeMap;

use indexmap::IndexMap;
use serde::Serialize;

use super::{Entry, Version, Vocabulary};

/// The Enterprise tactics in matrix order, with their ATT&CK ids. ATT&CK v19
/// renamed Defense Evasion (TA0005) to Stealth and split Defense Impairment
/// (TA0112) out of it.
pub const TACTICS: [(&str, &str); 15] = [
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

/// Name prefixes of the techniques of the Mobile and ICS matrices.
pub const NON_ENTERPRISE: [&str; 2] = ["Mobile : ", "Industrial : "];

/// The tactic a stage name stands for, with its id: case and surrounding
/// whitespace ignored, the historical spelling `Priviledge Escalation`, and
/// `Defense Evasion`, whose id (TA0005) is now Stealth's. `None` for a stage
/// that is no Enterprise tactic.
pub fn tactic(stage: &str) -> Option<(&'static str, &'static str)> {
    let wanted = stage.trim().to_lowercase();
    match wanted.as_str() {
        "priviledge escalation" => Some(("Privilege Escalation", "TA0004")),
        "defense evasion" => Some(("Stealth", "TA0005")),
        _ => TACTICS
            .iter()
            .find(|(name, _)| name.to_lowercase() == wanted)
            .copied(),
    }
}

/// A tactic's short name: `Command and Control` → `command-and-control`.
pub fn shortname(tactic: &str) -> String {
    tactic.trim().to_lowercase().replace(' ', "-")
}

/// One tactic column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tactic {
    /// The ATT&CK id, when the stage is an Enterprise tactic.
    pub id: Option<&'static str>,
    /// The short name.
    pub shortname: String,
    /// The name.
    pub name: String,
    /// Its top-level techniques, by name.
    pub techniques: Vec<String>,
}

/// One technique or sub-technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Technique {
    /// The name; a sub-technique's without its parent's (`LSASS Memory`).
    pub name: String,
    /// A sub-technique's parent, when the matrix holds it.
    pub parent: Option<String>,
    /// The sub-techniques, by id.
    pub subtechniques: Vec<String>,
}

/// The matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Matrix {
    /// The tactics, in order.
    pub tactics: Vec<Tactic>,
    /// Every technique, by id.
    pub techniques: BTreeMap<String, Technique>,
}

/// The Enterprise entries of `vocabulary` active at `pin` (every entry
/// without a pin), by id.
pub fn enterprise(vocabulary: &Vocabulary, pin: Option<Version>) -> IndexMap<&str, &Entry> {
    vocabulary
        .entries
        .iter()
        .filter(|(_, entry)| {
            !NON_ENTERPRISE
                .iter()
                .any(|prefix| entry.name.starts_with(prefix))
                && pin.is_none_or(|pin| entry.active_at(pin))
        })
        .map(|(key, entry)| (key.as_str(), entry))
        .collect()
}

/// Each technique id to the short names of its tactics, in order, once each.
pub fn technique_tactics<'a>(
    entries: &IndexMap<&'a str, &'a Entry>,
) -> BTreeMap<&'a str, Vec<String>> {
    entries
        .iter()
        .map(|(key, entry)| {
            let mut names: Vec<String> = Vec::new();
            for stage in &entry.stages {
                let name = shortname(tactic(stage).map_or(stage.as_str(), |(name, _)| name));
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            (*key, names)
        })
        .collect()
}

/// The matrix of `entries` (from [`enterprise`]), with the tactic columns of
/// `vocabulary`'s stages ([`TACTICS`] when it has none).
pub fn matrix(vocabulary: Option<&Vocabulary>, entries: &IndexMap<&str, &Entry>) -> Matrix {
    let mut techniques: BTreeMap<String, Technique> = entries
        .keys()
        .map(|key| {
            let parent = key.split_once('.').map(|(parent, _)| parent.to_owned());
            (
                (*key).to_owned(),
                Technique {
                    name: String::new(),
                    parent,
                    subtechniques: Vec::new(),
                },
            )
        })
        .collect();
    let keys: Vec<String> = techniques.keys().cloned().collect();
    for key in &keys {
        let full = entries[key.as_str()].name.as_str();
        let mut name = full;
        let parent = techniques[key].parent.clone();
        if let Some(parent) = parent {
            let parent_name = entries.get(parent.as_str()).map(|e| e.name.as_str());
            if let Some(stripped) = parent_name
                .filter(|p| !p.is_empty())
                .and_then(|p| full.strip_prefix(&format!("{p}: ")))
            {
                name = stripped;
            }
            match techniques.get_mut(&parent) {
                Some(row) => row.subtechniques.push(key.clone()),
                None => {
                    if let Some(row) = techniques.get_mut(key) {
                        row.parent = None;
                    }
                }
            }
        }
        if let Some(row) = techniques.get_mut(key) {
            name.clone_into(&mut row.name);
        }
    }

    let mut stages: Vec<String> = vocabulary
        .map(|v| {
            v.metadata
                .stages
                .iter()
                .filter_map(|stage| stage.name.clone().or_else(|| stage.id.clone()))
                .filter(|name| !name.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if stages.is_empty() {
        stages = TACTICS.iter().map(|(name, _)| (*name).to_owned()).collect();
    }
    let mut tactics: Vec<Tactic> = Vec::new();
    for stage in &stages {
        let (name, id) = tactic(stage).map_or((stage.clone(), None), |(name, id)| {
            (name.to_owned(), Some(id))
        });
        if tactics.iter().any(|t| t.name == name) {
            continue;
        }
        tactics.push(Tactic {
            id,
            shortname: shortname(&name),
            name,
            techniques: Vec::new(),
        });
    }
    let mut by_name: Vec<&String> = techniques.keys().collect();
    by_name.sort_by_key(|key| techniques[*key].name.to_lowercase());
    for key in by_name {
        if techniques[key].parent.is_some() {
            continue;
        }
        for stage in &entries[key.as_str()].stages {
            let name = tactic(stage).map_or(stage.as_str(), |(name, _)| name);
            if let Some(column) = tactics.iter_mut().find(|t| t.name == name) {
                if !column.techniques.contains(key) {
                    column.techniques.push(key.clone());
                }
            }
        }
    }
    Matrix {
        tactics,
        techniques,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK: &str = r#"
name = "MITRE ATT&CK"
field = "att&ck"
key = "id"
stages = ["Credential Access", "Defense Evasion", "Execution"]
[[keys]]
id = "T1003"
name = "OS Credential Dumping"
"tide.vocab.stages" = ["Credential Access"]
[[keys]]
id = "T1003.001"
name = "OS Credential Dumping: LSASS Memory"
"tide.vocab.stages" = ["Credential Access"]
[[keys]]
id = "T1562.001"
name = "Impair Defenses: Disable or Modify Tools"
"tide.vocab.stages" = ["Defense Evasion"]
[[keys]]
id = "T1059"
name = "Command and Scripting Interpreter"
version = "1.3"
"tide.vocab.stages" = ["execution", "Execution"]
[[keys]]
id = "T0800"
name = "Industrial : Activate Firmware Update Mode"
"tide.vocab.stages" = ["Execution"]
"#;

    fn vocabulary() -> Vocabulary {
        Vocabulary::parse(ATTACK, "att&ck").unwrap()
    }

    #[test]
    fn tactics_map_names_and_legacy_spellings() {
        assert_eq!(tactic(" execution "), Some(("Execution", "TA0002")));
        assert_eq!(tactic("Defense Evasion"), Some(("Stealth", "TA0005")));
        assert_eq!(
            tactic("Priviledge Escalation"),
            Some(("Privilege Escalation", "TA0004"))
        );
        assert_eq!(tactic("Lunch"), None);
        assert_eq!(shortname("Command and Control"), "command-and-control");
    }

    #[test]
    fn enterprise_entries_at_the_pin() {
        let attack = vocabulary();
        let entries = enterprise(&attack, Some(Version::new(1, 2)));
        assert_eq!(
            entries.keys().copied().collect::<Vec<_>>(),
            ["T1003", "T1003.001", "T1562.001"]
        );
        assert_eq!(enterprise(&attack, None).len(), 4);
        let tactics = technique_tactics(&enterprise(&attack, None));
        assert_eq!(tactics["T1059"], ["execution"]);
        assert_eq!(tactics["T1562.001"], ["stealth"]);
    }

    #[test]
    fn the_matrix() {
        let attack = vocabulary();
        let entries = enterprise(&attack, None);
        let matrix = matrix(Some(&attack), &entries);
        let names: Vec<(&str, Option<&str>)> = matrix
            .tactics
            .iter()
            .map(|t| (t.name.as_str(), t.id))
            .collect();
        assert_eq!(
            names,
            [
                ("Credential Access", Some("TA0006")),
                ("Stealth", Some("TA0005")),
                ("Execution", Some("TA0002")),
            ]
        );
        assert_eq!(matrix.tactics[0].techniques, ["T1003"]);
        assert_eq!(matrix.tactics[2].techniques, ["T1059"]);
        // The sub-technique sits under its parent, named without the parent's name.
        assert_eq!(matrix.techniques["T1003.001"].name, "LSASS Memory");
        assert_eq!(matrix.techniques["T1003"].subtechniques, ["T1003.001"]);
        // A sub-technique whose parent is absent stands alone, with its full
        // name, and is listed under its tactic as a top-level technique is.
        let orphan = &matrix.techniques["T1562.001"];
        assert_eq!(orphan.parent, None);
        assert_eq!(orphan.name, "Impair Defenses: Disable or Modify Tools");
        assert_eq!(matrix.tactics[1].techniques, ["T1562.001"]);
        assert_eq!(
            matrix.techniques["T1003.001"].parent.as_deref(),
            Some("T1003")
        );
        // Without a vocabulary the columns are the Enterprise tactics.
        assert_eq!(super::matrix(None, &IndexMap::new()).tactics.len(), 15);
    }

    /// Two stages that name one tactic (`Defense Evasion` is Stealth's old
    /// name) make one column, and a column lists its techniques by name, not
    /// by id.
    #[test]
    fn one_column_per_tactic_and_techniques_by_name() {
        let text = r#"
name = "MITRE ATT&CK"
field = "att&ck"
key = "id"
stages = ["Defense Evasion", "Stealth", "stealth", "Execution"]
[[keys]]
id = "T1001"
name = "zeta"
"tide.vocab.stages" = ["Stealth"]
[[keys]]
id = "T1002"
name = "Alpha"
"tide.vocab.stages" = ["Defense Evasion"]
[[keys]]
id = "T1003"
name = "Mu"
"tide.vocab.stages" = ["Stealth"]
"#;
        let attack = Vocabulary::parse(text, "att&ck").unwrap();
        let entries = enterprise(&attack, None);
        let matrix = matrix(Some(&attack), &entries);
        let names: Vec<&str> = matrix.tactics.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Stealth", "Execution"]);
        // Alpha, Mu, zeta: by name without case, whatever the ids say.
        assert_eq!(matrix.tactics[0].techniques, ["T1002", "T1003", "T1001"]);
    }
}
