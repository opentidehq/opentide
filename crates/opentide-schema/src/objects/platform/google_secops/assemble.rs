//! The YARA-L rule deploy sends for a `configurations.google_secops` block
//! (google-secops-1.0, Assembled rule), ported from 0.28.0's
//! `platforms/google_secops/compile.py` (`assemble`, `AssembledRule`,
//! `SectionPlace`, `Location`).
//!
//! The author writes the rule's sections; the rest is derived from the
//! opentide rule: the rule name, the `meta` section (author, description,
//! severity, priority, ATT&CK techniques, the opentide uuid and version, then
//! the block's own meta). [`assemble`] writes the text and records the line of
//! each section label, so a position Google reports in the assembled text is
//! put back on its key in the YAML ([`AssembledRule::locate`]). This is the
//! one copy: deploy (`opentide-compile`), the live check's error mapping
//! (`opentide-connectors`) and the editor's section injection read it.

use crate::node::{Node, Value};

use super::yaral::{self, SECTION_KEYS, render_match, render_options, section_lines};

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "google_secops";

/// The indentation of a section's content.
pub const INDENT: &str = "    ";

/// The meta `severity` of a rule with no block `severity` and no (or an
/// unknown) `response.alert_severity`.
pub const DEFAULT_SEVERITY: &str = "Medium";

/// `response.alert_severity` → meta `severity` (google-secops-1.0, Severity).
pub fn alert_severity(severity: &str) -> Option<&'static str> {
    Some(match severity {
        "informational" => "Info",
        "low" => "Low",
        "medium" => "Medium",
        "high" => "High",
        "critical" => "Critical",
        _ => return None,
    })
}

/// The YARA-L rule name (google-secops-1.0, Rule name): the block's `name`,
/// else the rule's title in lower snake case (`r_` before a leading digit or
/// a keyword), else `opentide_<uuid>`.
pub fn rule_name(rule_title: &str, block_name: Option<&str>, uuid: &str) -> String {
    if let Some(name) = block_name.filter(|name| !name.is_empty()) {
        return name.to_owned();
    }
    let mut name = String::new();
    let mut gap = false;
    for ch in rule_title.to_lowercase().chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            if gap && !name.is_empty() {
                name.push('_');
            }
            gap = false;
            name.push(ch);
        } else {
            gap = true;
        }
    }
    if name.is_empty() {
        return format!("opentide_{}", uuid.replace('-', "_"));
    }
    if name.starts_with(|ch: char| ch.is_ascii_digit()) || yaral::KEYWORDS.contains(&name.as_str())
    {
        format!("r_{name}")
    } else {
        name
    }
}

/// `text` as a YARA-L double-quoted string: `\` and `"` escaped, control
/// characters as spaces.
pub fn meta_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0}'..='\u{1f}' | '\u{7f}' => out.push(' '),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// What the derived `meta` reads from the opentide rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleFacts {
    /// `name` (the rule's title).
    pub title: String,
    /// `metadata.uuid`, as Python's `UUID` writes it.
    pub uuid: String,
    /// `metadata.version`, as Python's `str()` writes it.
    pub version: String,
    /// `metadata.author`.
    pub author: Option<String>,
    /// `description`.
    pub description: String,
    /// `response.alert_severity`, when the rule sets it.
    pub alert_severity: Option<String>,
    /// The rule's techniques and those it inherits, sorted, each once.
    pub techniques: Vec<String>,
}

fn block_str<'n>(block: &'n Node, key: &str) -> Option<&'n str> {
    block.get(key).and_then(|node| node.value.as_str())
}

/// The meta `severity`: the block's, else `response.alert_severity` mapped,
/// else `Medium`.
pub fn severity(facts: &RuleFacts, block: &Node) -> String {
    if let Some(level) = block_str(block, "severity").filter(|level| !level.is_empty()) {
        return level.to_owned();
    }
    facts
        .alert_severity
        .as_deref()
        .and_then(|severity| {
            alert_severity(&crate::objects::platform::python_strip(severity).to_lowercase())
        })
        .unwrap_or(DEFAULT_SEVERITY)
        .to_owned()
}

/// The `meta` section, in order (google-secops-1.0, Meta).
pub fn meta_entries(facts: &RuleFacts, block: &Node) -> Vec<(String, String)> {
    let mut authors: Vec<String> = Vec::new();
    let contributors: Vec<String> = match block.get("contributors").map(|node| &node.value) {
        Some(Value::Seq(items)) => items
            .iter()
            .filter_map(|item| item.value.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    for author in facts.author.iter().chain(contributors.iter()) {
        if !author.is_empty() && !authors.contains(author) {
            authors.push(author.clone());
        }
    }
    let level = severity(facts, block);
    let priority = block_str(block, "priority")
        .filter(|priority| !priority.is_empty())
        .map_or_else(|| level.clone(), str::to_owned);
    let mut entries = vec![
        ("author".to_owned(), authors.join(", ")),
        (
            "description".to_owned(),
            python_split(&facts.description).join(" "),
        ),
        ("severity".to_owned(), level),
        ("priority".to_owned(), priority),
    ];
    // `technique` only: Google's coverage matrix reads it as a comma-separated
    // list and places each technique under its tactics.
    if !facts.techniques.is_empty() {
        entries.push(("technique".to_owned(), facts.techniques.join(",")));
    }
    entries.push(("opentide_uuid".to_owned(), facts.uuid.clone()));
    entries.push(("opentide_version".to_owned(), facts.version.clone()));
    if let Some(Value::Map(meta)) = block.get("meta").map(|node| &node.value) {
        for entry in meta {
            entries.push((yaral::key_text(&entry.key), yaral::key_text(&entry.value)));
        }
    }
    entries
}

/// Python's `str.split()`: words between runs of whitespace.
fn python_split(text: &str) -> Vec<&str> {
    text.split(crate::objects::platform::is_python_space)
        .filter(|word| !word.is_empty())
        .collect()
}

/// Where a section's content starts in the assembled text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionPlace {
    /// The section key.
    pub key: &'static str,
    /// 1-based line of the section's label (`  events:`).
    pub label_line: usize,
    /// Lines of content written under the label.
    pub lines: usize,
    /// Leading blank lines of the section's text that were not written.
    pub dropped: usize,
}

/// A position in the assembled text, put back on the block's YAML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// `None`: the generated header or meta, or no position at all.
    pub key: Option<&'static str>,
    /// 1-based line inside the section's text; `None` for `match` and
    /// `options`.
    pub line: Option<usize>,
    /// 1-based column inside the section's text.
    pub column: Option<usize>,
}

impl Location {
    /// The finding's path in the rule: the section key, else the block.
    pub fn field_path(&self) -> Vec<&'static str> {
        let mut path = vec!["configurations", PLATFORM];
        path.extend(self.key);
        path
    }

    /// `configurations.google_secops.events line 3, column 5`.
    pub fn describe(&self) -> String {
        let mut text = self.field_path().join(".");
        if let Some(line) = self.line {
            text.push_str(&format!(" line {line}"));
            if let Some(column) = self.column {
                text.push_str(&format!(", column {column}"));
            }
        }
        text
    }
}

/// The YARA-L text deploy sends for one block, and where each section went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledRule {
    /// The rule name.
    pub name: String,
    /// The text, ending in a newline.
    pub text: String,
    /// The sections written, in order.
    pub sections: Vec<SectionPlace>,
}

impl AssembledRule {
    /// The label line of section `key`, when it was written.
    pub fn label_line(&self, key: &str) -> Option<usize> {
        self.sections
            .iter()
            .find(|place| place.key == key)
            .map(|place| place.label_line)
    }

    /// The section key and its own line and column of a 1-based position in
    /// [`Self::text`].
    pub fn locate(&self, line: Option<usize>, column: Option<usize>) -> Location {
        let nowhere = Location {
            key: None,
            line: None,
            column: None,
        };
        let Some(line) = line else {
            return nowhere;
        };
        for place in &self.sections {
            if place.label_line < line && line <= place.label_line + place.lines {
                if matches!(place.key, "match" | "options") {
                    return Location {
                        key: Some(place.key),
                        line: None,
                        column: None,
                    };
                }
                return Location {
                    key: Some(place.key),
                    line: Some(line - place.label_line + place.dropped),
                    column: column.map(|column| column.saturating_sub(INDENT.len()).max(1)),
                };
            }
        }
        nowhere
    }
}

/// Why a block cannot be assembled: it has no `events` or no `condition`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "rule {}: configurations.google_secops has no {}",
    crate::configuration::repr::quote(rule),
    missing.join(" and no ")
)]
pub struct AssembleError {
    /// The rule's title.
    pub rule: String,
    /// The sections missing, in order.
    pub missing: Vec<&'static str>,
}

/// A section's content lines and the leading lines it dropped.
fn content_lines(block: &Node, key: &str) -> (Vec<String>, usize) {
    let Some(node) = block
        .get(key)
        .filter(|node| !matches!(node.value, Value::Null))
    else {
        return (Vec::new(), 0);
    };
    match key {
        "match" => (render_match(node).into_iter().collect(), 0),
        "options" => (render_options(node), 0),
        _ => node
            .value
            .as_str()
            .map_or_else(|| (Vec::new(), 0), section_lines),
    }
}

/// The YARA-L rule deploy sends for a block (google-secops-1.0, Assembled
/// rule).
///
/// # Errors
///
/// [`AssembleError`] when `events` or `condition` is missing or blank.
pub fn assemble(facts: &RuleFacts, block: &Node) -> Result<AssembledRule, AssembleError> {
    let missing: Vec<&'static str> = ["events", "condition"]
        .into_iter()
        .filter(|key| {
            block_str(block, key)
                .is_none_or(|text| crate::objects::platform::python_strip(text).is_empty())
        })
        .collect();
    if !missing.is_empty() {
        return Err(AssembleError {
            rule: facts.title.clone(),
            missing,
        });
    }
    Ok(assemble_present(facts, block))
}

/// The rule [`assemble`] writes, from the sections `block` has, whichever
/// are missing: what the YARA-L engine checks in an editor and `validate`,
/// where a block without `condition` is still checked (the block's own
/// checks report `yaral_section_missing`).
pub fn assemble_present(facts: &RuleFacts, block: &Node) -> AssembledRule {
    let name = rule_name(&facts.title, block_str(block, "name"), &facts.uuid);
    let mut lines = vec![format!("rule {name} {{"), "  meta:".to_owned()];
    lines.extend(
        meta_entries(facts, block)
            .into_iter()
            .map(|(key, value)| format!("{INDENT}{key} = {}", meta_value(&value))),
    );
    let mut sections = Vec::new();
    for key in SECTION_KEYS {
        let (content, dropped) = content_lines(block, key);
        if content.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(format!("  {key}:"));
        sections.push(SectionPlace {
            key,
            label_line: lines.len(),
            lines: content.len(),
            dropped,
        });
        lines.extend(content.into_iter().map(|line| {
            if crate::objects::platform::python_strip(&line).is_empty() {
                String::new()
            } else {
                format!("{INDENT}{line}")
            }
        }));
    }
    lines.push("}".to_owned());
    AssembledRule {
        name,
        text: lines.join("\n") + "\n",
        sections,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names() {
        assert_eq!(rule_name("x", Some("given"), "u"), "given");
        assert_eq!(
            rule_name("Password spraying -- then Success!", None, "u"),
            "password_spraying_then_success"
        );
        assert_eq!(rule_name("3 failures", Some(""), "u"), "r_3_failures");
        assert_eq!(rule_name("Any", None, "u"), "r_any");
        assert_eq!(rule_name("été", None, "a-b"), "t");
        assert_eq!(rule_name("—", None, "a-b"), "opentide_a_b");
    }

    #[test]
    fn meta_values_are_escaped() {
        assert_eq!(
            meta_value("a \"b\" \\ c\td\u{7f}"),
            "\"a \\\"b\\\" \\\\ c d \""
        );
    }

    #[test]
    fn locate_maps_lines_to_sections() {
        let rule = AssembledRule {
            name: "r".to_owned(),
            text: String::new(),
            sections: vec![
                SectionPlace {
                    key: "events",
                    label_line: 10,
                    lines: 3,
                    dropped: 1,
                },
                SectionPlace {
                    key: "match",
                    label_line: 15,
                    lines: 1,
                    dropped: 0,
                },
            ],
        };
        let at = rule.locate(Some(12), Some(9));
        assert_eq!(
            (at.key, at.line, at.column),
            (Some("events"), Some(3), Some(5))
        );
        assert_eq!(
            at.describe(),
            "configurations.google_secops.events line 3, column 5"
        );
        assert_eq!(rule.locate(Some(12), Some(2)).column, Some(1));
        assert_eq!(rule.locate(Some(16), Some(3)).key, Some("match"));
        assert_eq!(
            rule.locate(Some(16), None).describe(),
            "configurations.google_secops.match"
        );
        assert_eq!(rule.locate(Some(10), None).key, None);
        assert_eq!(
            rule.locate(None, None).describe(),
            "configurations.google_secops"
        );
        assert_eq!(rule.label_line("match"), Some(15));
        assert_eq!(rule.label_line("outcome"), None);
    }
}
