//! The ATT&CK ids Microsoft Sentinel accepts in
//! `configurations.sentinel.alert.techniques`.
//!
//! Sentinel is aligned to ATT&CK v18, while the `att&ck` vocabulary follows
//! the current release, so the Sentinel field has a list of its own
//! (`src/opentide/data/sentinel/attack-v18.json`, which
//! `cargo xtask vocab sentinel-attack` generates from MITRE's STIX bundles):
//! every technique and sub-technique of ATT&CK 18.1's Enterprise, Mobile and
//! ICS matrices that is neither revoked nor deprecated. The file also lists
//! the ids of the vocabulary's newer release that v18 lacks, with the v18 ids
//! they replaced, and the ids ATT&CK retired before v18, with the v18 ids that
//! replaced them, so a rejected id comes with what to write instead.

use std::sync::OnceLock;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The ATT&CK major version Sentinel is aligned to.
pub const VERSION: &str = "18";

/// The bundled list's text.
pub fn document() -> &'static str {
    opentide_dataset::text!("src/opentide/data/sentinel/attack-v18.json")
}

/// The list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentinelAttack {
    /// The ATT&CK release (`18.1`).
    pub attack: String,
    /// The matrices it covers.
    pub domains: Vec<String>,
    /// Where the bundles come from, `{domain}` standing for each matrix.
    pub source: String,
    /// What wrote the file.
    pub generator: String,
    /// Every id Sentinel accepts, sorted, with its name (a sub-technique's
    /// prefixed with its parent's).
    pub techniques: IndexMap<String, String>,
    /// The ids retired before v18, each with what replaced it.
    pub retired: IndexMap<String, Retired>,
    /// The ids of the vocabulary's newer release that v18 does not have.
    pub later: Later,
}

/// An id ATT&CK revoked or deprecated before v18.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retired {
    /// Its name.
    pub name: String,
    /// The v18 ids that replaced it, if any.
    pub replaced_by: Vec<String>,
}

/// The ids of a newer release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Later {
    /// The release (the `att&ck` vocabulary's `source_version`).
    pub attack: String,
    /// Its ids that v18 lacks.
    pub techniques: IndexMap<String, Newer>,
}

/// An id newer than v18.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Newer {
    /// Its name.
    pub name: String,
    /// The v18 ids it replaced, if any.
    pub replaces: Vec<String>,
}

impl SentinelAttack {
    /// The bundled list.
    #[expect(
        clippy::expect_used,
        reason = "the document is compiled in and read by a test (`the_bundled_list_reads`)"
    )]
    pub fn bundled() -> &'static Self {
        static LIST: OnceLock<SentinelAttack> = OnceLock::new();
        LIST.get_or_init(|| {
            serde_json::from_str(document()).expect("attack-v18.json is a Sentinel ATT&CK list")
        })
    }

    /// `Ok` when Sentinel accepts `value`, else the error message, with what
    /// to write instead when the list knows.
    pub fn check(&self, value: &str) -> Result<(), String> {
        if self.techniques.contains_key(value) {
            return Ok(());
        }
        Err(format!(
            "{} is not an ATT&CK v{VERSION} technique or sub-technique id, which is what \
             Sentinel is aligned to{}",
            super::quote(value),
            self.hint(value)
        ))
    }

    /// What to write instead of `value`, as a clause starting `; `, or empty.
    ///
    /// The value is read as an id is meant: without surrounding whitespace,
    /// in upper case (` t1059.001` names `T1059.001`, `t1086` the retired
    /// `T1086`).
    pub fn hint(&self, value: &str) -> String {
        let wanted = value.trim().to_uppercase();
        let value = wanted.as_str();
        if let Some(name) = self.techniques.get(value) {
            return format!("; did you mean {value} ({name})?");
        }
        if let Some(newer) = self.later.techniques.get(value) {
            let lead = format!("; {value} ({}) is newer than ATT&CK v{VERSION}", newer.name);
            let mut hint = if newer.replaces.is_empty() {
                format!("{lead} and has no v{VERSION} equivalent")
            } else {
                format!(
                    "{lead}: use {}, which it replaced",
                    newer.replaces.join(" or ")
                )
            };
            // A newer parent: where each of its sub-techniques goes, as
            // deploy says it when it sends them.
            if let Some(subs) = self.sub_technique_map(value) {
                hint.push_str(". ");
                hint.push_str(&subs);
            }
            return hint;
        }
        if let Some(retired) = self.retired.get(value) {
            let lead = format!(
                "; ATT&CK retired {value} ({}) before v{VERSION}",
                retired.name
            );
            return if retired.replaced_by.is_empty() {
                format!("{lead} without a replacement")
            } else {
                format!(
                    "{lead}: use {}, which replaced it",
                    retired.replaced_by.join(" or ")
                )
            };
        }
        // An id is a few digits: one edit away, not a third of its length.
        opentide_core::suggest::closest_within(value, self.techniques.keys().map(String::as_str), 1)
            .map(|id| format!("; did you mean {id} ({})?", self.techniques[id]))
            .unwrap_or_default()
    }

    /// What v18 holds in place of `id`, an id it does not know, and why: the v18
    /// ids that replace it (none when it has no equivalent), and the reason.
    ///
    /// - an id newer than v18 becomes the v18 id(s) it replaced; with none, its
    ///   v18 parent when it is a sub-technique (`T1027.018` sends `T1027`), or the
    ///   v18 parents its newer parent replaced (`T1685.007` sends `T1562`);
    /// - a retired id becomes the id(s) that replaced it;
    /// - an id the list does not know at all has none.
    pub fn v18_replacement(&self, id: &str) -> (Vec<&String>, String) {
        let attack = self;
        let known = |id: &&String| attack.techniques.contains_key(*id);
        if let Some(newer) = attack.later.techniques.get(id) {
            let replaced: Vec<&String> = newer.replaces.iter().filter(known).collect();
            let instead = if replaced.is_empty() {
                // A sub-technique with no replacement stands for its parent: the
                // parent when v18 has it, else the parent's own v18 parents (the
                // dot-free ids it replaced).
                id.split_once('.')
                    .map(|(parent, _)| {
                        attack.techniques.get_key_value(parent).map_or_else(
                            || {
                                attack
                                    .later
                                    .techniques
                                    .get(parent)
                                    .map(|newer| {
                                        newer
                                            .replaces
                                            .iter()
                                            .filter(|old| !old.contains('.'))
                                            .filter(known)
                                            .collect()
                                    })
                                    .unwrap_or_default()
                            },
                            |(parent, _)| vec![parent],
                        )
                    })
                    .unwrap_or_default()
            } else {
                replaced
            };
            (instead, format!("newer than ATT&CK v{VERSION}"))
        } else if let Some(retired) = attack.retired.get(id) {
            (
                retired.replaced_by.iter().filter(known).collect(),
                format!("retired before ATT&CK v{VERSION}"),
            )
        } else {
            (
                Vec::new(),
                format!("not an ATT&CK v{VERSION} id Sentinel knows"),
            )
        }
    }

    /// For a parent technique newer than ATT&CK v18, where its sub-technique ids
    /// go, as deploy sends them and as `validate`'s hint names them: `Its sub-techniques map to ATT&CK v18 as
    /// T1685.002 → T1562.008, ...` (`none` for one with no v18 equivalent). `None`
    /// for a sub-technique or an id the list does not hold as newer.
    pub fn sub_technique_map(&self, id: &str) -> Option<String> {
        let attack = self;
        if id.contains('.') || !attack.later.techniques.contains_key(id) {
            return None;
        }
        let prefix = format!("{id}.");
        let mappings: Vec<String> = attack
            .later
            .techniques
            .keys()
            .filter(|sub| sub.starts_with(&prefix))
            .map(|sub| {
                let (instead, _) = attack.v18_replacement(sub);
                if instead.is_empty() {
                    format!("{sub} → none")
                } else {
                    let names: Vec<&str> = instead.iter().map(|id| id.as_str()).collect();
                    format!("{sub} → {}", names.join(" and "))
                }
            })
            .collect();
        if mappings.is_empty() {
            return None;
        }
        Some(format!(
            "Its sub-techniques map to ATT&CK v{VERSION} as {}",
            mappings.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_parents_hint_names_where_its_sub_techniques_go() {
        // OT-1: T1685's hint listed only the ids T1685 itself replaced.
        let list = SentinelAttack::bundled();
        let hint = list.hint("T1685");
        assert_eq!(
            hint,
            "; T1685 (Disable or Modify Tools) is newer than ATT&CK v18: use T1562 or T1562.001 \
             or T1562.006, which it replaced. Its sub-techniques map to ATT&CK v18 as \
             T1685.001 → T1562.002, T1685.002 → T1562.008, T1685.003 → T1562.011, \
             T1685.004 → T1562.012, T1685.005 → T1070.001, T1685.006 → T1070.002, \
             T1685.007 → T1562"
        );
        // The same sentence deploy appends to its warning.
        assert!(hint.ends_with(&list.sub_technique_map("T1685").unwrap()));
        // A sub-technique, or an id v18 has, gets no such sentence.
        assert_eq!(list.sub_technique_map("T1685.002"), None);
        assert_eq!(list.sub_technique_map("T1059"), None);
    }

    #[test]
    fn the_bundled_list_reads() {
        let list = SentinelAttack::bundled();
        assert_eq!(list.attack, "18.1");
        assert!(list.techniques.len() > 600);
        assert!(list.techniques.keys().is_sorted());
        assert!(list.check("T1059.001").is_ok());
    }

    #[test]
    fn rejected_ids_say_what_to_write() {
        let list = SentinelAttack::bundled();
        let message = list.check("T1086").unwrap_err();
        assert!(
            message.starts_with("\"T1086\" is not an ATT&CK v18 technique"),
            "{message}"
        );
        assert!(message.contains("ATT&CK retired T1086 (PowerShell) before v18: use T1059.001"));
        let typo = list.check("t1059.01").unwrap_err();
        assert!(
            typo.ends_with(
                "; did you mean T1059.001 (Command and Scripting Interpreter: PowerShell)?"
            ),
            "{typo}"
        );
        // An exact id in another case or with whitespace around it names
        // that id, never a sibling one edit away (T1059.010).
        for written in ["t1059.001", " T1059.001", "T1059.001 ", "\tt1059.001\n"] {
            let message = list.check(written).unwrap_err();
            assert!(
                message.ends_with(
                    "; did you mean T1059.001 (Command and Scripting Interpreter: PowerShell)?"
                ),
                "{written:?}: {message}"
            );
        }
        // A retired or newer id is recognised the same way.
        let retired = list.check("t1086").unwrap_err();
        assert!(
            retired.contains("ATT&CK retired T1086 (PowerShell) before v18: use T1059.001"),
            "{retired}"
        );
        assert!(
            list.check(" T1086 ")
                .unwrap_err()
                .contains("ATT&CK retired T1086")
        );
        assert!(
            list.check("T9999.999")
                .unwrap_err()
                .ends_with("Sentinel is aligned to")
        );
        if let Some((id, newer)) = list
            .later
            .techniques
            .iter()
            .find(|(_, n)| !n.replaces.is_empty())
        {
            let message = list.check(id).unwrap_err();
            assert!(
                message.contains("is newer than ATT&CK v18: use"),
                "{message}"
            );
            assert!(message.contains(&newer.replaces[0]));
            let lower = list.check(&id.to_lowercase()).unwrap_err();
            assert!(lower.contains(&format!("; {id} (")), "{lower}");
            assert!(lower.contains("is newer than ATT&CK v18: use"), "{lower}");
        }
    }
}
