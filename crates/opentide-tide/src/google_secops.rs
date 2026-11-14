//! A Google SecOps block's YARA-L sections, checked as the one rule deploy
//! assembles (google-secops-1.0 "Assembled rule"; `docs/engine/YARAL.md`
//! "In Tide objects").
//!
//! The block's `setup`, `events`, `outcome`, `condition` and `export` texts
//! are each an injection, but the YARA-L engine checks them together: the
//! block is assembled with opentide-schema's [`assemble`] (the same text
//! deploy sends), checked under the `rule` profile
//! ([`opentide_yaral::Context::SECTIONS`]), and each finding is mapped back:
//!
//! - one in a section's text lands on its own line and column in that
//!   section ([`Assembled::section`]);
//! - one in the rendered `match` or `options` lands on the YAML value it
//!   came from (a `match.group_by` item when the finding names it), else on
//!   the key; one on a section label lands on the section's key
//!   ([`Assembled::block`]);
//! - one in the generated header or meta is a platform constraint, which the
//!   block's own checks report, and is dropped; a syntax error there moves to
//!   the first section the author wrote.
//!
//! The engine of opentide 0.28.1 checks a block the same way, and these
//! rules follow it:
//!
//! - a section written as a YAML alias is left out of the rule (the block's
//!   checks report `yaral_section_alias`);
//! - a block with no `events` text, or a section text that holds a label, a
//!   `rule` header or a lone brace, is not checked at all: it has no rule to
//!   check, and its sections are not queries ([`checked`]);
//! - a block without `condition` is still checked; what the block's own
//!   checks report on the YAML (`yaral_section_*`, `yaral_match_shape`, and
//!   `yaral_match_window` or `yaral_option` on a rendered `match` or
//!   `options`) is dropped, and so is `yaral_multi_event_match` when the
//!   block has a `match` key, whose shape the block's checks report when it
//!   does not render.

use std::sync::Arc;

use opentide_core::node::{Entry, Node, Value};
use opentide_core::{Diagnostic, Position, Range, codes};
use opentide_schema::objects::platform::google_secops::assemble::{
    AssembledRule, RuleFacts, assemble_present,
};
use opentide_schema::objects::platform::google_secops::yaral::section_header_line;

use crate::yaml::YamlNode;

/// The block's key.
pub(crate) const PLATFORM: &str = "google_secops";

/// The section keys whose text is YARA-L, in the order deploy writes them.
pub(crate) const TEXT_SECTIONS: [&str; 5] = ["setup", "events", "outcome", "condition", "export"];

/// The findings of one block's assembled rule, sorted by where they land.
#[derive(Debug, Default)]
pub(crate) struct Assembled {
    /// Per section key: findings in the section text's own coordinates
    /// (0-based line, and column in characters), for the injection to remap.
    sections: Vec<(&'static str, Diagnostic)>,
    /// Findings on the block's YAML (a `match` or `options` value, a section
    /// key), in the source's coordinates.
    block: Vec<Diagnostic>,
}

impl Assembled {
    /// The findings in section `key`'s text, in that text's coordinates.
    pub(crate) fn section(&self, key: &str) -> Vec<Diagnostic> {
        self.sections
            .iter()
            .filter(|(section, _)| *section == key)
            .map(|(_, diagnostic)| diagnostic.clone())
            .collect()
    }

    /// The findings that land on the block's YAML, already in the source's
    /// coordinates.
    pub(crate) fn block(&self) -> &[Diagnostic] {
        &self.block
    }
}

fn path(rest: &[&str]) -> Vec<String> {
    ["configurations", PLATFORM]
        .iter()
        .chain(rest)
        .map(|part| (*part).to_owned())
        .collect()
}

/// The facts the generated header and meta are written from. The engine
/// checks the body: deploy writes a valid header and meta, and the block's
/// own checks report a `name` or a `meta` key it could not.
fn facts() -> RuleFacts {
    RuleFacts {
        title: "opentide rule".to_owned(),
        uuid: "00000000-0000-4000-8000-000000000000".to_owned(),
        version: Some("1".to_owned()),
        author: None,
        description: String::new(),
        alert_severity: None,
        techniques: Vec::new(),
    }
}

/// The text of the assembled rule's 1-based `line`.
fn line_text(rule: &AssembledRule, line: usize) -> &str {
    rule.text.lines().nth(line.saturating_sub(1)).unwrap_or("")
}

/// The word a finding's range covers on its line of the assembled rule
/// (`$user` of a rendered `match`).
fn covered(rule: &AssembledRule, range: Range) -> String {
    let text = line_text(rule, range.start.line as usize + 1);
    let start = range.start.character as usize;
    let end = if range.end.line == range.start.line {
        range.end.character as usize
    } else {
        text.chars().count()
    };
    text.chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

/// The `match.group_by` item that `word` names, if any.
fn group_by_item(block: &Node, word: &str) -> Option<usize> {
    let word = word.trim();
    if word.is_empty() {
        return None;
    }
    block
        .get("match")?
        .get("group_by")?
        .as_sequence()?
        .iter()
        .position(|item| item.as_str().is_some_and(|text| text.trim() == word))
}

/// A section-local position of an assembled-rule position.
fn local(rule: &AssembledRule, position: Position) -> Option<(&'static str, Position)> {
    let at = rule.locate(
        Some(position.line as usize + 1),
        Some(position.character as usize + 1),
    );
    let (key, line, column) = (at.key?, at.line?, at.column?);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a section's line and column fit the position's u32"
    )]
    Some((key, Position::new((line - 1) as u32, (column - 1) as u32)))
}

/// Codes the block's own checks report on the YAML: an engine finding with
/// one of them is dropped.
const BLOCK_CODES: [&str; 5] = [
    codes::YARAL_SECTION_MISSING,
    codes::YARAL_SECTION_EMPTY,
    codes::YARAL_SECTION_HEADER,
    codes::YARAL_SECTION_ALIAS,
    codes::YARAL_MATCH_SHAPE,
];

/// Whether `entry`'s value is a YAML alias: an alias resolves to the node its
/// anchor names, which starts before the entry's own key ends.
fn is_alias(entry: &Entry) -> bool {
    entry.value.start.index < entry.key.end.index
}

/// The block as the engine reads it: its text sections that are YAML
/// aliases left out. `None` when it is not a mapping, has no `events` text,
/// or a section text holds a label, a `rule` header or a lone brace.
fn checked_block(block: &Node) -> Option<Node> {
    let Value::Map(entries) = &block.value else {
        return None;
    };
    let mut kept = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = entry.key.as_str().unwrap_or_default();
        if TEXT_SECTIONS.contains(&key) {
            if is_alias(entry) {
                continue;
            }
            if entry
                .value
                .as_str()
                .is_some_and(|text| section_header_line(text).is_some())
            {
                return None;
            }
        }
        kept.push(entry.clone());
    }
    let block = Node {
        value: Value::Map(kept),
        start: block.start,
        end: block.end,
        text: None,
    };
    let events = block.get("events").and_then(|events| events.as_str());
    events
        .is_some_and(|text| !text.trim().is_empty())
        .then_some(block)
}

/// Whether the source's Google SecOps block is checked as a rule, so that its
/// sections are queries: see [`checked_block`].
pub(crate) fn checked(source: &str) -> bool {
    crate::yaml::parse(source)
        .and_then(|root| {
            let block = root.get("configurations")?.get(PLATFORM)?.clone();
            checked_block(&block)
        })
        .is_some()
}

/// The source range of a node, from its marks.
fn node_range(node: &Node) -> Range {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a line and a column fit the position's u32"
    )]
    let position = |mark: opentide_core::node::Mark| {
        Position::new(
            mark.line.saturating_sub(1) as u32,
            mark.column.saturating_sub(1) as u32,
        )
    };
    Range::new(position(node.start), position(node.end))
}

/// The findings of `configurations`' Google SecOps block, assembled and
/// checked as one rule; `None` when there is no block or it is not checked
/// ([`checked_block`]).
pub(crate) fn assembled(source: &str, configurations: Option<&Arc<Node>>) -> Option<Assembled> {
    let written = configurations?.get(PLATFORM)?;
    let block = &checked_block(written)?;
    let rule = assemble_present(&facts(), block);
    let has_match = block.get("match").is_some();
    let mut out = Assembled::default();
    for mut finding in opentide_yaral::diagnostics(&rule.text, &opentide_yaral::Context::SECTIONS) {
        if BLOCK_CODES.contains(&finding.code.as_str())
            || (has_match && finding.code == codes::YARAL_MULTI_EVENT_MATCH)
        {
            continue;
        }
        if let Some((key, start)) = local(&rule, finding.range.start) {
            let end = match local(&rule, finding.range.end) {
                Some((end_key, end)) if end_key == key => end,
                _ => Position::new(start.line, start.character + 1),
            };
            finding.range = Range::new(start, end);
            finding.field_path = Some(path(&[key]));
            out.sections.push((key, finding));
            continue;
        }
        let line = finding.range.start.line as usize + 1;
        let at = rule.locate(Some(line), None);
        let target = match at.key {
            // A rendered `match` or `options` line: the value it came from.
            Some(key @ ("match" | "options")) => {
                // The block's checks report a window or an option on the YAML.
                if matches!(
                    finding.code.as_str(),
                    codes::YARAL_MATCH_WINDOW | codes::YARAL_OPTION
                ) {
                    continue;
                }
                let word = covered(&rule, finding.range);
                if key == "match"
                    && let Some(item) = group_by_item(block, &word)
                    && let Some(node) = block
                        .get("match")
                        .and_then(|m| m.get("group_by"))
                        .and_then(|g| g.as_sequence())
                        .and_then(|items| items.get(item))
                {
                    // The item as written: the finding is on its text.
                    finding.range = node_range(node);
                    finding.field_path = Some(path(&["match", "group_by", &item.to_string()]));
                    out.block.push(finding);
                    continue;
                }
                path(&[key])
            }
            _ => match rule.sections.iter().find(|place| place.label_line == line) {
                // A section label: the section's key.
                Some(place) => path(&[place.key]),
                // The generated header or meta: the block reports what it
                // could not write; a syntax error moves to the first
                // section the author wrote.
                None if finding.code == codes::YARAL_PARSE_ERROR => match rule.sections.first() {
                    Some(place) => path(&[place.key]),
                    None => continue,
                },
                None => continue,
            },
        };
        let parts: Vec<&str> = target.iter().map(String::as_str).collect();
        finding.range = crate::elastic::path_range(source, &parts);
        finding.field_path = Some(target);
        out.block.push(finding);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(text: &str) -> (String, Assembled) {
        let source = format!("configurations:\n  google_secops:\n{text}");
        let root = crate::yaml::parse(&source).expect("YAML");
        let found = assembled(&source, root.get("configurations")).expect("assembled");
        (source, found)
    }

    #[test]
    fn a_clean_block_has_no_findings() {
        let (_, found) = block(
            "    events: |\n      $e.metadata.event_type = \"PROCESS_LAUNCH\"\n    outcome: |\n      \
             $risk_score = 40\n    condition: |\n      $e\n",
        );
        assert!(found.sections.is_empty(), "{:?}", found.sections);
        assert!(found.block.is_empty(), "{:?}", found.block);
    }

    #[test]
    fn a_finding_in_a_section_lands_on_its_own_line_and_column() {
        let (_, found) = block(
            "    events: |\n      $e.metadata.event_type = \"PROCESS_LAUNCH\"\n      \
             $e.principal.hostnam = \"h\"\n    condition: |\n      $e\n",
        );
        let events = found.section("events");
        assert!(!events.is_empty(), "{:?}", found.sections);
        let first = &events[0];
        assert_eq!(first.range.start.line, 1, "{first:?}");
        assert!(first.range.start.character < 30, "{first:?}");
        assert_eq!(first.field_path.as_deref(), Some(&path(&["events"])[..]));
        assert!(found.section("condition").is_empty());
    }

    #[test]
    fn two_event_variables_without_match_are_reported_on_the_sections() {
        let (_, found) = block(
            "    events: |\n      $a.metadata.event_type = \"USER_LOGIN\"\n      \
             $b.metadata.event_type = \"USER_LOGIN\"\n    condition: |\n      $a and $b\n",
        );
        let all: Vec<&str> = found
            .sections
            .iter()
            .map(|(_, d)| d.code.as_str())
            .chain(found.block.iter().map(|d| d.code.as_str()))
            .collect();
        assert!(all.contains(&"yaral_multi_event_match"), "{all:?}");
    }

    #[test]
    fn a_match_name_lands_on_its_group_by_item() {
        let (source, found) = block(
            "    events: |\n      $e.metadata.event_type = \"USER_LOGIN\"\n      \
             $e.target.user.userid = $user\n    match:\n      group_by: [$user, $nobody]\n      \
             window: 30m\n    outcome: |\n      $risk_score = 40\n    condition: |\n      $e\n",
        );
        let on_match: Vec<&Diagnostic> = found
            .block
            .iter()
            .filter(|d| d.code == "yaral_match_variable")
            .collect();
        assert_eq!(on_match.len(), 1, "{:?}", found.block);
        assert_eq!(
            on_match[0].field_path.as_deref(),
            Some(&path(&["match", "group_by", "1"])[..])
        );
        // The range is the item's own text.
        let line = source.lines().position(|l| l.contains("group_by")).unwrap();
        let column = source.lines().nth(line).unwrap().find("$nobody").unwrap();
        assert_eq!(on_match[0].range.start.line as usize, line);
        assert_eq!(on_match[0].range.start.character as usize, column);
        assert_eq!(
            on_match[0].range.end.character as usize,
            column + "$nobody".len()
        );
    }

    #[test]
    fn a_block_without_events_or_with_a_header_is_not_checked() {
        let source = "configurations:\n  google_secops:\n    condition: |\n      $e\n";
        let root = crate::yaml::parse(source).unwrap();
        assert!(assembled(source, root.get("configurations")).is_none());
        assert!(!checked(source));
        assert!(assembled(source, None).is_none());
        let header = "configurations:\n  google_secops:\n    events: |\n      \
                      $e.metadata.event_type = \"USER_LOGIN\"\n      condition:\n      $e\n";
        let root = crate::yaml::parse(header).unwrap();
        assert!(assembled(header, root.get("configurations")).is_none());
        assert!(!checked(header));
    }

    #[test]
    fn a_block_without_condition_is_still_checked() {
        let (_, found) = block(
            "    events: |\n      $e.metadata.event_type = \"USER_LOGIN\"\n      \
             $e.principal.hostnam = \"h\"\n",
        );
        let events = found.section("events");
        let codes: Vec<&str> = events.iter().map(|d| d.code.as_str()).collect();
        assert!(codes.contains(&"yaral_unknown_udm_field"), "{codes:?}");
        // The block's checks report the missing section.
        assert!(
            found
                .block
                .iter()
                .all(|d| d.code != "yaral_section_missing")
        );
    }

    #[test]
    fn what_the_block_checks_report_is_dropped() {
        // A window out of bounds on the rendered `match`: the block's
        // `yaral_match_window`.
        let (_, found) = block(
            "    events: |\n      $e.metadata.event_type = \"USER_LOGIN\"\n      \
             $e.target.user.userid = $u\n    match:\n      group_by: [$u]\n      window: 15d\n    \
             outcome: |\n      $risk_score = max(1)\n    condition: |\n      $e\n    options:\n      \
             allow_nulls: true\n",
        );
        assert!(found.block.is_empty(), "{:?}", found.block);
        // Two event variables and a `match` that does not render (no window).
        let (_, found) = block(
            "    events: |\n      $a.metadata.event_type = \"USER_LOGIN\"\n      \
             $b.metadata.event_type = \"USER_LOGIN\"\n    match:\n      group_by: [$u]\n    \
             condition: |\n      $a and $b\n",
        );
        let all: Vec<&str> = found
            .sections
            .iter()
            .map(|(_, d)| d.code.as_str())
            .chain(found.block.iter().map(|d| d.code.as_str()))
            .collect();
        assert!(!all.contains(&"yaral_multi_event_match"), "{all:?}");
    }

    #[test]
    fn an_aliased_section_is_left_out() {
        let source = "configurations:\n  google_secops:\n    meta:\n      note: &c \"$nowhere\"\n    \
                      events: |\n      $e.metadata.event_type = \"USER_LOGIN\"\n    condition: *c\n";
        let root = crate::yaml::parse(source).unwrap();
        let found = assembled(source, root.get("configurations")).unwrap();
        assert!(found.sections.is_empty(), "{:?}", found.sections);
        assert!(found.block.is_empty(), "{:?}", found.block);
    }
}
