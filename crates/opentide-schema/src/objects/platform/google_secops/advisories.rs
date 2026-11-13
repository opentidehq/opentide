//! What Google accepts but the author most likely did not mean
//! (google-secops-1.0, Advisories), and the workspace check
//! `google_secops_name_duplicate`: `advisories.py` and
//! `validation/google_secops.py`.
//!
//! An advisory never rejects a rule: `opentide validate` reports it as a
//! warning, and so does `opentide lint` with its `queries` check. Each is
//! placed at a path from the rule's root.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::node::{Node, Value};

use super::assemble::rule_name;
use super::yaral::{code_lines, event_variables};

/// `outcome` assigns no `$risk_score`.
pub const RISK_SCORE_MISSING: &str = "google_secops_risk_score_missing";
/// `events` or `condition` compares `detection.detection.rule_id` with a
/// literal `ru_` id.
pub const RULE_ID_LITERAL: &str = "google_secops_rule_id_literal";
/// `run_frequency: LIVE` on a rule of two or more event variables.
pub const LIVE_FREQUENCY_UNAVAILABLE: &str = "google_secops_live_frequency_unavailable";
/// Every advisory code (`ADVISORY_CODES`).
pub const ADVISORY_CODES: [&str; 3] = [
    RISK_SCORE_MISSING,
    RULE_ID_LITERAL,
    LIVE_FREQUENCY_UNAVAILABLE,
];
/// Two enabled blocks resolve to one YARA-L rule name.
pub const NAME_DUPLICATE: &str = "google_secops_name_duplicate";

const BLOCK: [&str; 2] = ["configurations", "google_secops"];

/// One advisory, at its path from the rule's root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// One of [`ADVISORY_CODES`].
    pub code: &'static str,
    /// Where, from the rule's root.
    pub field_path: Vec<String>,
    /// What the rule then does.
    pub message: String,
}

fn at(last: &[&str]) -> Vec<String> {
    BLOCK
        .iter()
        .chain(last)
        .map(|part| (*part).to_owned())
        .collect()
}

fn text(node: Option<&Node>) -> Option<&str> {
    match &node?.value {
        Value::Str(text) => Some(text),
        _ => None,
    }
}

fn block_of(rule: &Node) -> Option<&Node> {
    let configurations = rule.get("configurations")?;
    let block = configurations.get("google_secops")?;
    matches!(block.value, Value::Map(_)).then_some(block.as_ref())
}

#[expect(
    clippy::expect_used,
    reason = "regex literals, exercised by every advisory test"
)]
fn patterns() -> &'static (Regex, Regex, Regex) {
    static PATTERNS: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        (
            Regex::new(r"(?m)^\s*\$risk_score\s*=").expect("a valid pattern"),
            Regex::new(r"\bdetection\.detection\.rule_id\b").expect("a valid pattern"),
            Regex::new(r#"["`/]ru_[0-9a-fA-F]{8}-"#).expect("a valid pattern"),
        )
    })
}

/// Every advisory a rule's `google_secops` block, as authored, earns
/// (`google_secops_advisories`).
pub fn advisories(rule: &Node) -> Vec<Advisory> {
    let Some(block) = block_of(rule) else {
        return Vec::new();
    };
    let (risk_score, rule_id_field, rule_id_literal) = patterns();
    let mut found = Vec::new();
    let outcome = block.get("outcome").map(AsRef::as_ref);
    let scored = text(outcome)
        .is_some_and(|outcome| risk_score.is_match(&code_lines(outcome, true).join("\n")));
    if !scored {
        found.push(Advisory {
            code: RISK_SCORE_MISSING,
            field_path: if outcome.is_some() {
                at(&["outcome"])
            } else {
                at(&[])
            },
            message: "outcome assigns no $risk_score, so Google gives every detection of the rule \
                      the instance's default score (40 for an alert and 15 otherwise, unless the \
                      instance's settings change them), whatever it detects; add $risk_score = \
                      <0-100>"
                .to_owned(),
        });
    }
    for key in ["events", "condition"] {
        let Some(section) = text(block.get(key).map(AsRef::as_ref)) else {
            continue;
        };
        if code_lines(section, false)
            .iter()
            .any(|line| rule_id_field.is_match(line) && rule_id_literal.is_match(line))
        {
            found.push(Advisory {
                code: RULE_ID_LITERAL,
                field_path: at(&[key]),
                message: format!(
                    "{key} compares detection.detection.rule_id with a literal ru_ id, which \
                     differs per instance and changes when the rule is recreated; match the \
                     producer with detection.detection.rule_name"
                ),
            });
        }
    }
    let events = text(block.get("events").map(AsRef::as_ref)).unwrap_or_default();
    if text(block.get("run_frequency").map(AsRef::as_ref)) == Some("LIVE")
        && event_variables(events).len() >= 2
    {
        found.push(Advisory {
            code: LIVE_FREQUENCY_UNAVAILABLE,
            field_path: at(&["run_frequency"]),
            message: "run_frequency LIVE on a rule with two or more event variables: Google \
                      allows LIVE for single-event rules only, so deploy refuses the rule \
                      (google_secops_run_frequency_not_allowed); write LIVE_CUSTOMIZABLE"
                .to_owned(),
        });
    }
    found
}

/// A section key of the block is a YAML alias (`yaral_section_alias`).
pub const SECTION_ALIAS: &str = "yaral_section_alias";

/// `yaral_section_alias` on one section key of a rule's block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionAlias {
    /// The section key.
    pub key: &'static str,
    /// The 0-based line of the node the alias names, where its anchor is
    /// (`attach_yaml_lines` places the issue there).
    pub yaml_line: usize,
}

impl SectionAlias {
    /// Where, from the rule's root.
    pub fn field_path(&self) -> Vec<String> {
        at(&[self.key])
    }

    /// The issue's message.
    pub fn message(&self) -> String {
        format!(
            "configurations.google_secops.{} is a YAML alias; a YARA-L section is written in the \
             block, so what the rule deploys is readable there",
            self.key
        )
    }

    /// The issue's suggestion.
    pub fn suggestion(&self) -> String {
        format!(
            "Write the {key} text under configurations.google_secops.{key}",
            key = self.key
        )
    }
}

/// The section keys of a rule's `google_secops` block whose value is a YAML
/// alias, in the block's order (`aliased_sections`). The loaded tree cannot
/// tell an alias from text written in place, but its marks can: an alias
/// resolves to the node its anchor names, which starts before the key that
/// refers to it ends.
pub fn aliased_sections(rule: &Node) -> Vec<SectionAlias> {
    let Some(Value::Map(entries)) = block_of(rule).map(|block| &block.value) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|entry| entry.value.start.index < entry.key.end.index)
        .filter_map(|entry| {
            let Value::Str(key) = &entry.key.value else {
                return None;
            };
            super::yaral::SECTION_KEYS
                .iter()
                .find(|section| **section == key)
                .map(|key| SectionAlias {
                    key,
                    yaml_line: entry.value.start.line.saturating_sub(1),
                })
        })
        .collect()
}

/// The YARA-L rule name of an enabled `google_secops` block, as deploy
/// writes it (`_rule_name`); `None` for a rule without one.
pub fn enabled_rule_name(rule: &Node) -> Option<String> {
    let block = block_of(rule)?;
    if !matches!(
        block.get("enabled").map(|node| &node.value),
        Some(Value::Bool(true))
    ) {
        return None;
    }
    let title = text(rule.get("name").map(AsRef::as_ref))?;
    let block_name = match block.get("name").map(AsRef::as_ref) {
        None => None,
        Some(node) if matches!(node.value, Value::Null) => None,
        Some(node) => Some(text(Some(node))?),
    };
    let uuid = rule
        .get("metadata")
        .and_then(|metadata| metadata.get("uuid"))
        .map(|uuid| match &uuid.value {
            Value::Str(uuid) => uuid.clone(),
            _ => String::new(),
        })
        .unwrap_or_default();
    Some(rule_name(title, block_name, &uuid)).filter(|name| !name.is_empty())
}

/// A rule whose YARA-L rule name another enabled block resolves to too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameDuplicate {
    /// The rule's uuid.
    pub uuid: String,
    /// Its YARA-L rule name.
    pub name: String,
    /// The other rules' uuids, sorted.
    pub others: Vec<String>,
}

impl NameDuplicate {
    /// The issue's message.
    pub fn message(&self) -> String {
        format!(
            "Google SecOps rule name {} is also the rule name of rule(s) {} (compared \
             case-insensitively); a composite rule matching it by \
             detection.detection.rule_name would match both",
            crate::configuration::repr::quote(&self.name),
            self.others.join(", ")
        )
    }

    /// The issue's suggestion.
    pub const SUGGESTION: &'static str =
        "Set a distinct configurations.google_secops.name on one of the rules";

    /// Where the issue is, from the rule's root.
    pub fn field_path() -> Vec<String> {
        at(&[])
    }
}

/// `google_secops_name_duplicate` for each rule of `in_scope` that shares
/// its rule name, compared case-insensitively, with another of `rules`
/// (`google_secops_name_issues`).
pub fn name_duplicates<'a>(
    rules: impl IntoIterator<Item = (&'a str, &'a Node)>,
    in_scope: impl IntoIterator<Item = &'a str>,
) -> Vec<NameDuplicate> {
    let mut names: BTreeMap<&str, String> = BTreeMap::new();
    let mut by_name: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (uuid, rule) in rules {
        if let Some(name) = enabled_rule_name(rule) {
            by_name.entry(name.to_lowercase()).or_default().push(uuid);
            names.insert(uuid, name);
        }
    }
    let mut found = Vec::new();
    for uuid in in_scope {
        let Some(name) = names.get(uuid) else {
            continue;
        };
        let mut others: Vec<String> = by_name
            .get(&name.to_lowercase())
            .into_iter()
            .flatten()
            .filter(|other| **other != uuid)
            .map(|other| (*other).to_owned())
            .collect();
        if others.is_empty() {
            continue;
        }
        others.sort();
        found.push(NameDuplicate {
            uuid: uuid.to_owned(),
            name: name.clone(),
            others,
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(yaml: &str) -> Node {
        let document = crate::node::load(yaml).unwrap_or_else(|error| panic!("{error:?}"));
        document
            .root()
            .map(|root| (**root).clone())
            .unwrap_or_else(|| panic!("empty"))
    }

    fn codes(found: &[Advisory]) -> Vec<&'static str> {
        found.iter().map(|advisory| advisory.code).collect()
    }

    #[test]
    fn a_rule_without_a_risk_score_is_advised_at_its_outcome_or_block() {
        let none = advisories(&rule(
            "configurations:\n  google_secops:\n    events: $e.metadata.event_type = \"X\"\n",
        ));
        assert_eq!(codes(&none), [RISK_SCORE_MISSING]);
        assert_eq!(none[0].field_path, ["configurations", "google_secops"]);
        let commented = advisories(&rule(
            "configurations:\n  google_secops:\n    outcome: |\n      // $risk_score = 40\n      \
             $host = $e.principal.hostname\n",
        ));
        assert_eq!(
            commented[0].field_path,
            ["configurations", "google_secops", "outcome"]
        );
        assert!(
            advisories(&rule(
                "configurations:\n  google_secops:\n    outcome: |\n      $risk_score = 40\n"
            ))
            .is_empty()
        );
    }

    #[test]
    fn a_literal_rule_id_and_live_on_many_events_are_advised() {
        let found = advisories(&rule(
            "configurations:\n  google_secops:\n    run_frequency: LIVE\n    outcome: \
             \"$risk_score = 1\"\n    events: |\n      $a.metadata.event_type = \"X\"\n      \
             $b.metadata.event_type = \"Y\"\n    condition: |\n      $d and \
             $d.detection.detection.rule_id = \"ru_0123abcd-0000\"\n",
        ));
        assert_eq!(codes(&found), [RULE_ID_LITERAL, LIVE_FREQUENCY_UNAVAILABLE]);
        assert_eq!(found[0].field_path[2], "condition");
        assert!(found[0].message.starts_with("condition compares"));
        // A commented-out comparison is not one.
        let commented = advisories(&rule(
            "configurations:\n  google_secops:\n    outcome: \"$risk_score = 1\"\n    events: \
             \"// $d.detection.detection.rule_id = \\\"ru_0123abcd-0\\\"\"\n",
        ));
        assert!(commented.is_empty(), "{commented:?}");
        assert!(advisories(&rule("configurations: {}\n")).is_empty());
    }

    #[test]
    fn a_section_written_as_an_alias_is_reported() {
        let found = aliased_sections(&rule(
            "x: &text \"$e\"\nconfigurations:\n  google_secops:\n    events: &own |\n      \
             $e.metadata.event_type = \"X\"\n    condition: *text\n    outcome: *own\n    \
             name: *text\n",
        ));
        assert_eq!(
            found,
            [
                SectionAlias {
                    key: "condition",
                    yaml_line: 0
                },
                SectionAlias {
                    key: "outcome",
                    yaml_line: 3
                }
            ]
        );
        assert_eq!(
            found[0].field_path(),
            ["configurations", "google_secops", "condition"]
        );
        assert!(found[0].message().starts_with(
            "configurations.google_secops.condition is a YAML alias; a YARA-L section"
        ));
        assert_eq!(
            found[0].suggestion(),
            "Write the condition text under configurations.google_secops.condition"
        );
        assert!(
            aliased_sections(&rule(
                "configurations:\n  google_secops:\n    events: &own |\n      $e\n"
            ))
            .is_empty()
        );
    }

    #[test]
    fn enabled_rules_sharing_a_name_case_insensitively_are_duplicates() {
        let a = rule(
            "name: Encoded PowerShell\nmetadata:\n  uuid: a\nconfigurations:\n  \
             google_secops:\n    enabled: true\n",
        );
        let b = rule(
            "name: other\nmetadata:\n  uuid: b\nconfigurations:\n  google_secops:\n    \
             enabled: true\n    name: ENCODED_powershell\n",
        );
        let disabled = rule(
            "name: Encoded PowerShell\nmetadata:\n  uuid: c\nconfigurations:\n  \
             google_secops:\n    enabled: false\n",
        );
        let rules = [("a", &a), ("b", &b), ("c", &disabled)];
        let found = name_duplicates(rules, ["a", "c"]);
        assert_eq!(
            found,
            [NameDuplicate {
                uuid: "a".into(),
                name: "encoded_powershell".into(),
                others: vec!["b".into()],
            }]
        );
        assert!(found[0].message().starts_with(
            "Google SecOps rule name 'encoded_powershell' is also the rule name of rule(s) b"
        ));
        assert!(name_duplicates([("a", &a)], ["a"]).is_empty());
    }
}
