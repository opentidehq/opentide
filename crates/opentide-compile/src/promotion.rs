//! Status promotion (`mutation/promotion.py`, UC-4.6c, #979): a RELEASE
//! deploy on a push in CI moves the platform blocks of the rule files the push
//! changed to the promotion target (`[promotion]` in `deployment.toml`),
//! before it plans.
//!
//! The text is edited in place: each `configurations.<platform>.status` the
//! promotion moves is replaced over the characters it occupies, located
//! through the node tree, never by line, so comments, quoting, key order and
//! line endings survive. The result is read back and must differ from the
//! original by exactly those values. A status written as an anchor, an alias
//! or under a merge key is not rewritten ([`Error::Refused`]); a rewrite
//! that cannot be checked ([`Error::Unreadable`], [`Error::NonStringKey`])
//! fails the run.
//!
//! This module reads no file: the host reads the rule files, logs, and
//! writes what [`promote_block_statuses`] returns.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use opentide_schema::configuration::merge::to_json;
use opentide_schema::node::{self, Document, Node, Value};
use regex::Regex;

use crate::Json;
use crate::strategy::{StatusStrategy, Statuses};

/// The advice of a rule a promotion leaves as it is (`rule_not_promoted`).
pub const NOT_PROMOTED_ADVICE: &str =
    "Write each platform block's status as a plain value, then deploy again";

/// `[promotion]` of `deployment.toml`, with the statuses it is checked against.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// `enabled`: on only when it is the boolean `true`.
    pub enabled: bool,
    /// `promotion_target`, when it is a string.
    pub target: Option<String>,
    /// `promotion_target` as the oracle's log writes it, whatever its type:
    /// `None` when it is not set (`invalid_promotion_target`).
    pub target_value: Json,
    /// Every configured status name, in order (`VALID_STATUSES`).
    pub valid: Vec<String>,
    /// The statuses a promotion never moves: those whose strategy is
    /// RELEASE, DELETION or DISABLEMENT (`NON_PROMOTABLE_STATUSES`).
    pub non_promotable: Vec<String>,
}

impl Settings {
    /// The settings of the resolved configuration `config` (its
    /// `deployment.promotion`) and its `statuses`.
    pub fn new(config: &Json, statuses: &Statuses) -> Self {
        let promotion = config.get("deployment").and_then(|d| d.get("promotion"));
        Self {
            enabled: promotion
                .and_then(|p| p.get("enabled"))
                .is_some_and(Json::is_true),
            target: promotion
                .and_then(|p| p.get("promotion_target"))
                .and_then(Json::as_str)
                .map(str::to_owned),
            target_value: promotion
                .and_then(|p| p.get("promotion_target"))
                .cloned()
                .unwrap_or(Json::Null),
            valid: statuses.0.iter().map(|(name, _)| name.clone()).collect(),
            non_promotable: statuses
                .0
                .iter()
                .filter(|(_, strategy)| {
                    matches!(
                        strategy,
                        StatusStrategy::Release
                            | StatusStrategy::Deletion
                            | StatusStrategy::Disablement
                    )
                })
                .map(|(name, _)| name.clone())
                .collect(),
        }
    }

    /// The target, when it names a configured status.
    pub fn valid_target(&self) -> Option<&str> {
        self.target
            .as_deref()
            .filter(|target| self.valid.iter().any(|name| name == target))
    }
}

/// Why a rule file was not promoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The promotion cannot rewrite it without changing what else it says
    /// (`PromotionRefused`): the file is left as it is, with a warning.
    Refused(String),
    /// The target, or the promoted text, does not read as YAML: the run
    /// fails, with the loader's words and where.
    Unreadable(String),
    /// A promoted platform block's key is not a string (`1:`, `null:`, or a
    /// plain `yes:` YAML 1.1 reads as a boolean): the promotion cannot check
    /// the block it rewrote, and the run fails. This holds the key as written.
    NonStringKey(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(detail) | Self::Unreadable(detail) => f.write_str(detail),
            Self::NonStringKey(key) => write!(
                f,
                "configurations.{key} is not a string key (quote the platform name)"
            ),
        }
    }
}

/// Whether a rule file read as `root` is a mapping with a `name`, the error
/// saying what it is instead.
pub fn name_error(root: Option<&Node>) -> Result<(), String> {
    match root.map(|root| (root, &root.value)) {
        None => Err("rule file is empty, not a mapping with a name".to_owned()),
        Some((root, Value::Map(_))) if root.get("name").is_some() => Ok(()),
        Some((_, Value::Map(_))) => Err("rule has no name".to_owned()),
        Some((_, other)) => {
            let kind = other.type_name();
            let article = if kind.starts_with(['a', 'e', 'i', 'o', 'u']) {
                "an"
            } else {
                "a"
            };
            Err(format!(
                "rule file holds {article} {kind}, not a mapping with a name"
            ))
        }
    }
}

/// The platform blocks a promotion moves in a rule (`system_promotion`):
/// each platform whose block's `status` is a string that is not one of
/// `non_promotable`, with that status, in the file's order.
pub fn promotable(root: &Node, non_promotable: &[String]) -> Vec<(String, String)> {
    let Some(Value::Map(platforms)) = root.get("configurations").map(|node| &node.value) else {
        return Vec::new();
    };
    platforms
        .iter()
        .filter_map(|entry| {
            let status = entry.value.get("status")?.value.as_str()?;
            if non_promotable.iter().any(|name| name == status) {
                return None;
            }
            Some((key_text(&entry.key), status.to_owned()))
        })
        .collect()
}

/// A key as text: a string as it is, anything else as YAML writes it
/// (`null`, `true`, `1`).
fn key_text(key: &Node) -> String {
    match &key.value {
        Value::Str(text) => text.to_string(),
        other => other.to_string(),
    }
}

/// Whether `key` is YAML 1.1's merge key: `<<`, written plain.
fn is_merge(key: &Node, source: &str, offsets: &[usize]) -> bool {
    key.value.as_str() == Some("<<") && span(source, offsets, key) == "<<"
}

/// Byte offsets of each character of `source`, and of its end.
fn char_offsets(source: &str) -> Vec<usize> {
    let mut offsets: Vec<usize> = source.char_indices().map(|(at, _)| at).collect();
    offsets.push(source.len());
    offsets
}

fn byte(offsets: &[usize], index: usize) -> usize {
    offsets
        .get(index)
        .or_else(|| offsets.last())
        .copied()
        .unwrap_or(0)
}

fn span<'s>(source: &'s str, offsets: &[usize], node: &Node) -> &'s str {
    let start = byte(offsets, node.start.index);
    let end = byte(offsets, node.end.index).max(start);
    source.get(start..end).unwrap_or_default()
}

/// Where the scalar written from byte `start` ends: after its closing quote
/// for a quoted one (the parser's end runs on over a comment after it), else
/// at `end`, the parser's, without trailing blanks.
fn scalar_end(source: &str, start: usize, end: usize) -> usize {
    let end = end.max(start);
    let mut rest = source.get(start..).unwrap_or_default();
    let mut at = start;
    // A tag (`!!str`) before the value, and the blanks after it.
    if rest.starts_with('!') {
        let tag = rest.find([' ', '\t', '\r', '\n']).unwrap_or(rest.len());
        let blanks = rest[tag..]
            .find(|c: char| !matches!(c, ' ' | '\t'))
            .unwrap_or(rest.len() - tag);
        at += tag + blanks;
        rest = source.get(at..).unwrap_or_default();
    }
    let mut chars = rest.char_indices();
    match chars.next() {
        Some((_, '"')) => {
            while let Some((index, ch)) = chars.next() {
                match ch {
                    '\\' => {
                        chars.next();
                    }
                    '"' => return at + index + 1,
                    _ => {}
                }
            }
            end
        }
        Some((_, '\'')) => {
            let mut chars = rest.char_indices().skip(1).peekable();
            while let Some((index, ch)) = chars.next() {
                if ch == '\'' {
                    if chars.peek().is_some_and(|(_, next)| *next == '\'') {
                        chars.next();
                    } else {
                        return at + index + 1;
                    }
                }
            }
            end
        }
        _ => start + source.get(start..end).unwrap_or_default().trim_end().len(),
    }
}

/// `text` (the source of `document`, without its byte order mark) with each
/// platform block `status` that is one of `statuses` set to `target`
/// (`promote_block_statuses`); `None` when no status is one of them.
///
/// # Errors
///
/// [`Error::Refused`] when a status is an anchor or an alias, a merge key
/// reaches a platform block, or the rewrite would change anything else;
/// [`Error::Unreadable`] for a target or a promoted text that does not
/// read as YAML, and [`Error::NonStringKey`] for a promoted block whose key
/// is not a string: the target first, then the keys, then the promoted text.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
pub fn promote_block_statuses(
    document: &Document,
    statuses: &[String],
    target: &str,
) -> Result<Option<String>, Error> {
    let source = document.source();
    let offsets = char_offsets(source);
    // Each status to rewrite: its bytes, its platform's name as written, and
    // whether that key is a string.
    let mut spans: Vec<(usize, usize, String, bool)> = Vec::new();
    let mut seen: HashSet<*const Node> = HashSet::new();
    if let Some(Value::Map(entries)) = document.root().map(|root| &root.value) {
        for entry in entries {
            let Value::Map(platforms) = &entry.value.value else {
                continue;
            };
            if entry.key.value.as_str() != Some("configurations") {
                continue;
            }
            for platform in platforms {
                if is_merge(&platform.key, source, &offsets) {
                    return Err(Error::Refused(
                        "configurations uses a merge key (<<)".to_owned(),
                    ));
                }
                let Value::Map(fields) = &platform.value.value else {
                    continue;
                };
                // A plain key YAML 1.1 reads as another type (`yes`, `1_0`)
                // is no string to the oracle either.
                let plain = !span(source, &offsets, &platform.key)
                    .trim_start()
                    .starts_with(['"', '\'', '!']);
                let (name, string_key) = match &platform.key.value {
                    Value::Str(name) if !(plain && yaml11_non_string(name)) => {
                        (name.to_string(), true)
                    }
                    _ => (
                        span(source, &offsets, &platform.key).trim().to_owned(),
                        false,
                    ),
                };
                if fields
                    .iter()
                    .any(|field| is_merge(&field.key, source, &offsets))
                {
                    return Err(Error::Refused(format!(
                        "configurations.{name} uses a merge key (<<)"
                    )));
                }
                for field in fields {
                    let value = &field.value;
                    let promoted = field.key.value.as_str() == Some("status")
                        && value
                            .value
                            .as_str()
                            .is_some_and(|status| statuses.iter().any(|s| s == status));
                    if !promoted {
                        continue;
                    }
                    // An alias is its anchor's node, and an anchored scalar
                    // starts at its `&name`: rewriting either changes another
                    // value or breaks the alias.
                    let first = source
                        .get(byte(&offsets, value.start.index)..)
                        .and_then(|rest| rest.chars().next());
                    if !seen.insert(Arc::as_ptr(value)) || matches!(first, Some('&' | '*')) {
                        return Err(Error::Refused(format!(
                            "configurations.{name}.status is an anchor or an alias"
                        )));
                    }
                    let start = byte(&offsets, value.start.index);
                    let end = scalar_end(source, start, byte(&offsets, value.end.index));
                    spans.push((start, end, name.clone(), string_key));
                }
            }
        }
    }
    if spans.is_empty() {
        return Ok(None);
    }
    let replacement = replacement(target)?;
    let mut promoted = source.to_owned();
    let mut ordered = spans.clone();
    ordered.sort_by_key(|span| std::cmp::Reverse(span.0));
    for (start, end, _, _) in &ordered {
        promoted.replace_range(*start..*end, &replacement);
    }
    let mut expected = document
        .root()
        .map_or(serde_json::Value::Null, |root| to_json(root));
    for (_, _, platform, string_key) in &spans {
        if !string_key {
            return Err(Error::NonStringKey(platform.clone()));
        }
        if let Some(block) = expected
            .get_mut("configurations")
            .and_then(|configurations| configurations.get_mut(platform))
            .and_then(serde_json::Value::as_object_mut)
        {
            block.insert(
                "status".into(),
                serde_json::Value::String(target.to_owned()),
            );
        }
    }
    let after = node::load(&promoted).map_err(|error| Error::Unreadable(placed(&error)))?;
    let actual = after
        .root()
        .map_or(serde_json::Value::Null, |root| to_json(root));
    if actual != expected {
        return Err(Error::Refused(
            "promotion would change more than the platform statuses".to_owned(),
        ));
    }
    Ok((promoted != source).then_some(promoted))
}

/// The text a status becomes: `target` as it is when YAML (1.2, and the
/// YAML 1.1 resolvers older readers apply) reads it back as that string,
/// else as a YAML double-quoted scalar.
///
/// # Errors
///
/// [`Error::Unreadable`] for a target that does not read as YAML.
pub fn replacement(target: &str) -> Result<String, Error> {
    let document = node::load(target).map_err(|error| Error::Unreadable(placed(&error)))?;
    let plain = document.root().is_some_and(|root| match &root.value {
        Value::Seq(_) | Value::Map(_) => false,
        Value::Str(text) => text == target,
        _ => target == document.source().trim(),
    }) && !target.starts_with(['"', '\''])
        && !yaml11_non_string(target);
    Ok(if plain {
        target.to_owned()
    } else {
        node::double_quoted(target)
    })
}

/// A load error and where it is (`… (line 3, column 27)`).
pub fn placed(error: &node::LoadError) -> String {
    match &error.mark {
        Some(mark) => format!("{error} (line {}, column {})", mark.line, mark.column),
        None => error.to_string(),
    }
}

/// Whether YAML 1.1's implicit resolvers (PyYAML's) read the plain scalar
/// `text` as something other than a string: a boolean, an integer, a float,
/// null, a timestamp, the merge key or the value key.
fn yaml11_non_string(text: &str) -> bool {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            r"^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$",
            r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
            r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$",
            r"^(?:<<)$",
            r"^(?:~|null|Null|NULL|)$",
            r"^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$",
            r"^(?:=)$",
        ]
        .iter()
        .filter_map(|pattern| Regex::new(pattern).ok())
        .collect()
    });
    patterns.iter().any(|pattern| pattern.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn promote(text: &str, statuses: &[&str], target: &str) -> Result<Option<String>, Error> {
        let document = node::load(text).unwrap();
        let statuses: Vec<String> = statuses.iter().map(|s| (*s).to_owned()).collect();
        promote_block_statuses(&document, &statuses, target)
    }

    const RULE: &str = "name: R\n# configurations: status: STAGING\ndescription: |\n  status: STAGING\nconfigurations:\n  splunk:\n    status: STAGING  # a comment\n    query: x\n    nested:\n      status: STAGING\n  sentinel:\n    status: 'DEVELOPMENT'\n  elastic:\n    status: PRODUCTION\n";

    #[test]
    fn only_the_block_statuses_change() {
        let promoted = promote(RULE, &["STAGING", "DEVELOPMENT"], "PRODUCTION")
            .unwrap()
            .unwrap();
        assert_eq!(
            promoted,
            RULE.replace("    status: STAGING  #", "    status: PRODUCTION  #")
                .replace("'DEVELOPMENT'", "PRODUCTION")
        );
    }

    #[test]
    fn a_comment_after_a_quoted_status_stays() {
        for (status, rest) in [
            ("\"STAGING\"", " # keep\n"),
            ("'STAGING'", "   # keep\n"),
            ("'STA''GING'", " # keep\n"),
            ("\"STA\\\"GING\"", " # keep\n"),
            ("!!str STAGING", " # keep\n"),
            ("!!str 'STAGING'", " # keep\n"),
            ("STAGING", "   # keep\n"),
        ] {
            let text = format!(
                "name: R\nconfigurations:\n  splunk:\n    status: {status}{rest}    query: x\n"
            );
            let document = node::load(&text).unwrap();
            let value = document
                .root()
                .unwrap()
                .get("configurations")
                .unwrap()
                .get("splunk")
                .unwrap()
                .get("status")
                .unwrap()
                .value
                .as_str()
                .unwrap()
                .to_owned();
            let promoted = promote(&text, &[value.as_str()], "PRODUCTION")
                .unwrap()
                .unwrap();
            assert_eq!(promoted, text.replace(status, "PRODUCTION"), "{status}");
        }
    }

    #[test]
    fn crlf_and_unicode_survive() {
        let text = "name: Règle 🦀\r\nconfigurations:\r\n  splunk:\r\n    status: STAGING\r\n    query: \"é\"\r\n";
        let promoted = promote(text, &["STAGING"], "PRODUCTION").unwrap().unwrap();
        assert_eq!(promoted, text.replace("STAGING", "PRODUCTION"));
    }

    #[test]
    fn nothing_to_promote_is_none() {
        assert_eq!(promote(RULE, &["IMPROVING"], "PRODUCTION"), Ok(None));
        assert_eq!(promote("[a]\n", &["STAGING"], "PRODUCTION"), Ok(None));
        // A target equal to the status changes nothing.
        assert_eq!(promote(RULE, &["STAGING"], "STAGING"), Ok(None));
    }

    #[test]
    fn anchors_aliases_and_merge_keys_are_refused() {
        let anchored = "name: R\nconfigurations:\n  splunk:\n    status: &s STAGING\n";
        assert_eq!(
            promote(anchored, &["STAGING"], "PRODUCTION"),
            Err(Error::Refused(
                "configurations.splunk.status is an anchor or an alias".into()
            ))
        );
        let alias = "name: R\nx: &s STAGING\nconfigurations:\n  splunk:\n    status: *s\n";
        assert!(matches!(
            promote(alias, &["STAGING"], "PRODUCTION"),
            Err(Error::Refused(_))
        ));
        let merged = "name: R\nbase: &b {query: x}\nconfigurations:\n  splunk:\n    <<: *b\n    status: STAGING\n";
        assert_eq!(
            promote(merged, &["STAGING"], "PRODUCTION"),
            Err(Error::Refused(
                "configurations.splunk uses a merge key (<<)".into()
            ))
        );
        let top = "name: R\nbase: &b {splunk: {status: X}}\nconfigurations:\n  <<: *b\n";
        assert_eq!(
            promote(top, &["STAGING"], "PRODUCTION"),
            Err(Error::Refused(
                "configurations uses a merge key (<<)".into()
            ))
        );
        // A quoted `<<` is a plain key.
        let quoted = "name: R\nconfigurations:\n  splunk:\n    '<<': 1\n    status: STAGING\n";
        assert!(
            promote(quoted, &["STAGING"], "PRODUCTION")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_rewrite_that_changes_more_is_refused() {
        // In a flow mapping, a plain target with a comma becomes two keys.
        let flow = "name: R\nconfigurations:\n  splunk: {status: STAGING, query: x}\n";
        assert_eq!(
            promote(flow, &["STAGING"], "A, B"),
            Err(Error::Refused(
                "promotion would change more than the platform statuses".into()
            ))
        );
    }

    /// A promoted block whose key is no string fails, named as written; one
    /// left as it is does not.
    #[test]
    fn a_promoted_block_whose_key_is_no_string_fails() {
        for (key, written) in [
            ("1", "1"),
            ("01", "01"),
            ("~", "~"),
            ("null", "null"),
            ("true", "true"),
            ("1.5", "1.5"),
            ("!!int 2", "!!int 2"),
            ("yes", "yes"),
            ("On", "On"),
        ] {
            let text = format!(
                "name: R\nconfigurations:\n  splunk:\n    status: STAGING\n  {key}:\n    status: STAGING\n"
            );
            assert_eq!(
                promote(&text, &["STAGING"], "PRODUCTION"),
                Err(Error::NonStringKey(written.to_owned())),
                "{key}"
            );
            // Not promoted: nothing looks it up.
            let kept = text.replace(
                &format!("  {key}:\n    status: STAGING\n"),
                &format!("  {key}:\n    status: PRODUCTION\n"),
            );
            assert!(
                promote(&kept, &["STAGING"], "PRODUCTION")
                    .unwrap()
                    .is_some()
            );
        }
        // A quoted or tagged key is a string, whatever it reads as.
        for key in ["'1'", "\"yes\"", "!!str 1"] {
            let text = format!("name: R\nconfigurations:\n  {key}:\n    status: STAGING\n");
            assert!(
                promote(&text, &["STAGING"], "PRODUCTION")
                    .unwrap()
                    .is_some(),
                "{key}"
            );
        }
        // A refusal is found first, as the oracle composes every block
        // before it looks one up.
        let refused =
            "name: R\nconfigurations:\n  1:\n    status: STAGING\n  s:\n    status: &a STAGING\n";
        assert!(matches!(
            promote(refused, &["STAGING"], "PRODUCTION"),
            Err(Error::Refused(_))
        ));
    }

    /// Promoted text that does not read back fails the run with the
    /// loader's words and where (a target that closes a flow mapping).
    #[test]
    fn promoted_text_that_does_not_read_back_is_unreadable() {
        let flow = "name: R\nconfigurations:\n  splunk: {status: STAGING, query: x}\n";
        let Err(Error::Unreadable(words)) = promote(flow, &["STAGING"], "LIVE}") else {
            panic!("read back");
        };
        assert!(words.contains(" (line 3, column "), "{words}");
        // The same target in a block mapping reads back.
        assert!(promote(RULE, &["STAGING"], "LIVE}").unwrap().is_some());
    }

    #[test]
    fn a_target_yaml_reads_otherwise_is_json_quoted() {
        assert_eq!(replacement("PRODUCTION").unwrap(), "PRODUCTION");
        assert_eq!(replacement("Pre Production").unwrap(), "Pre Production");
        for target in [
            "yes",
            "On",
            "1_000",
            "0b1",
            "1:20",
            "1.5",
            ".inf",
            "~",
            "2026-01-01",
            "<<",
            "=",
            "12",
            "true",
            "a: b",
            "- a",
            "x #y",
            " x",
            "'x'",
        ] {
            assert!(replacement(target).unwrap().starts_with('"'), "{target}");
        }
        // Text YAML reads back as itself stays as it is, non-ASCII included.
        assert_eq!(replacement("Prod\u{e9}").unwrap(), "Prod\u{e9}");
        // Quoted text keeps its characters: only YAML's escapes are escaped.
        assert_eq!(replacement("a: \u{e9}").unwrap(), "\"a: \u{e9}\"");
        assert_eq!(
            replacement("a\"\\\n\u{1f980}").unwrap(),
            "\"a\\\"\\\\\\n\u{1f980}\""
        );
        assert!(matches!(replacement("@x"), Err(Error::Unreadable(_))));
    }

    #[test]
    fn promotable_blocks_and_names() {
        let document = node::load(RULE).unwrap();
        let root = document.root().unwrap();
        assert_eq!(
            promotable(root, &["PRODUCTION".to_owned()]),
            vec![
                ("splunk".to_owned(), "STAGING".to_owned()),
                ("sentinel".to_owned(), "DEVELOPMENT".to_owned()),
            ]
        );
        assert_eq!(name_error(Some(root)), Ok(()));
        assert_eq!(
            name_error(None),
            Err("rule file is empty, not a mapping with a name".into())
        );
        let nameless = node::load("a: 1\n").unwrap();
        assert_eq!(
            name_error(nameless.root().map(AsRef::as_ref)),
            Err("rule has no name".into())
        );
        // A root that is no mapping: what it holds instead.
        for (text, kind) in [
            ("- a\n", "a sequence"),
            ("x\n", "a string"),
            ("'1'\n", "a string"),
            ("1\n", "an integer"),
            ("1.5\n", "a float"),
            ("true\n", "a boolean"),
            ("~\n", "a null"),
        ] {
            let document = node::load(text).unwrap();
            assert_eq!(
                name_error(document.root().map(AsRef::as_ref)),
                Err(format!("rule file holds {kind}, not a mapping with a name")),
                "{text:?}"
            );
        }
    }

    #[test]
    fn settings_read_the_promotion_table() {
        let statuses = Statuses(
            vec![
                ("STAGING".into(), StatusStrategy::Preview),
                ("PRODUCTION".into(), StatusStrategy::Release),
                ("REMOVED".into(), StatusStrategy::Deletion),
            ],
            None,
        );
        let config = Json::from_node(
            node::load(
                "deployment:\n  promotion:\n    enabled: true\n    promotion_target: LIVE\n",
            )
            .unwrap()
            .root()
            .unwrap(),
        );
        let settings = Settings::new(&config, &statuses);
        assert!(settings.enabled);
        assert_eq!(settings.valid_target(), None);
        assert_eq!(settings.non_promotable, ["PRODUCTION", "REMOVED"]);
        let off = Settings::new(&Json::Null, &statuses);
        assert!(!off.enabled);
        assert_eq!(off.target, None);
    }
}
