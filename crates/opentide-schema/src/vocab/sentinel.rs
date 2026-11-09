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
pub const DOCUMENT: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/sentinel/attack-v18.json"
));

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
            serde_json::from_str(DOCUMENT).expect("attack-v18.json is a Sentinel ATT&CK list")
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
            return if newer.replaces.is_empty() {
                format!("{lead} and has no v{VERSION} equivalent")
            } else {
                format!(
                    "{lead}: use {}, which it replaced",
                    newer.replaces.join(" or ")
                )
            };
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
            message.starts_with("'T1086' is not an ATT&CK v18 technique"),
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
