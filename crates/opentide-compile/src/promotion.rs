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
//! or under a merge key is not rewritten ([`Error::Refused`]).
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

/// The logger the oracle's promotion logs as.
pub const LOGGER: &str = "opentide.mutation.promotion";

/// The advice of a rule a promotion leaves as it is (`rule_not_promoted`).
pub const NOT_PROMOTED_ADVICE: &str =
    "Write each platform block's status as a plain value, then deploy again";

/// `[promotion]` of `deployment.toml`, with the statuses it is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `enabled`, read as Python reads its truth.
    pub enabled: bool,
    /// `promotion_target`.
    pub target: Option<String>,
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
                .is_some_and(Json::truthy),
            target: promotion
                .and_then(|p| p.get("promotion_target"))
                .and_then(Json::as_str)
                .map(str::to_owned),
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
    /// A case this port does not reproduce as the oracle reports it (a value
    /// YAML 1.1 and 1.2 read differently, text the oracle's parser refuses):
    /// the host leaves the run to the Python implementation.
    Unported(String),
}

/// What `data["name"]` gives for a rule file read as `root`: `Ok` when the
/// file is a mapping with a `name`, else the oracle's exception text
/// (`'name'`, `'NoneType' object is not subscriptable`, `'int' object is not
/// subscriptable`, ...), for the type this loader reads the root as. The
/// oracle reads YAML 1.1, this loader YAML 1.2: a plain scalar the two read
/// as different types (`yes`, `2026-01-01`) is named by its YAML 1.2 type
/// (UC-6.0d, #841).
pub fn name_error(root: Option<&Node>) -> Result<(), String> {
    let not_subscriptable = |name: &str| format!("'{name}' object is not subscriptable");
    let Some(root) = root else {
        return Err(not_subscriptable("NoneType"));
    };
    match &root.value {
        Value::Map(_) if root.get("name").is_some() => Ok(()),
        Value::Map(_) => Err(crate::strategy::python_repr("name")),
        Value::Null => Err(not_subscriptable("NoneType")),
        Value::Seq(_) => Err("list indices must be integers or slices, not str".to_owned()),
        Value::Str(_) | Value::Datetime(_) => {
            Err("string indices must be integers, not 'str'".to_owned())
        }
        Value::Bool(_) => Err(not_subscriptable("bool")),
        Value::Int(_) => Err(not_subscriptable("int")),
        Value::Float(_) => Err(not_subscriptable("float")),
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

fn key_text(key: &Node) -> String {
    match &key.value {
        Value::Str(text) => text.clone(),
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
/// [`Error::Unported`] where the oracle fails the run with its parser's words.
pub fn promote_block_statuses(
    document: &Document,
    statuses: &[String],
    target: &str,
) -> Result<Option<String>, Error> {
    let source = document.source();
    let offsets = char_offsets(source);
    let mut spans: Vec<(usize, usize, String)> = Vec::new();
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
                let name = match &platform.key.value {
                    Value::Str(name) => name.clone(),
                    _ => {
                        return Err(Error::Unported(
                            "a platform key that is not a string".to_owned(),
                        ));
                    }
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
                    spans.push((start, end, name.clone()));
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
    for (start, end, _) in &ordered {
        promoted.replace_range(*start..*end, &replacement);
    }
    let mut expected = document
        .root()
        .map_or(serde_json::Value::Null, |root| to_json(root));
    for (_, _, platform) in &spans {
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
    let after = node::load(&promoted).map_err(|error| Error::Unported(error.to_string()))?;
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

/// The text a status becomes: `target` as it is when YAML reads it back as
/// that string, else as JSON quotes it (`json.dumps`).
///
/// # Errors
///
/// [`Error::Unported`] for a target the oracle's parser refuses outright.
pub fn replacement(target: &str) -> Result<String, Error> {
    let document = node::load(target).map_err(|error| Error::Unported(error.to_string()))?;
    let plain = document.root().is_some_and(|root| match &root.value {
        Value::Seq(_) | Value::Map(_) => false,
        Value::Str(text) => text == target,
        _ => target == document.source().trim(),
    }) && !target.starts_with(['"', '\''])
        && !yaml11_non_string(target);
    Ok(if plain {
        target.to_owned()
    } else {
        json_string(target)
    })
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

/// `text` as `json.dumps` writes a string: ASCII only, `\uXXXX` for the rest.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0_u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
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
        assert_eq!(replacement("a: \u{e9}").unwrap(), "\"a: \\u00e9\"");
        assert_eq!(
            json_string("a\"\\\n\u{1f980}"),
            "\"a\\\"\\\\\\n\\ud83e\\udd80\""
        );
        assert!(matches!(replacement("@x"), Err(Error::Unported(_))));
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
            Err("'NoneType' object is not subscriptable".into())
        );
        let nameless = node::load("a: 1\n").unwrap();
        assert_eq!(
            name_error(nameless.root().map(AsRef::as_ref)),
            Err("'name'".into())
        );
        // A root that is no mapping: `data["name"]`'s TypeError, as Python
        // words it for the type YAML 1.2 reads.
        for (text, error) in [
            ("- a\n", "list indices must be integers or slices, not str"),
            ("x\n", "string indices must be integers, not 'str'"),
            ("'1'\n", "string indices must be integers, not 'str'"),
            ("1\n", "'int' object is not subscriptable"),
            ("1.5\n", "'float' object is not subscriptable"),
            ("true\n", "'bool' object is not subscriptable"),
            ("~\n", "'NoneType' object is not subscriptable"),
        ] {
            let document = node::load(text).unwrap();
            assert_eq!(
                name_error(document.root().map(AsRef::as_ref)),
                Err(error.to_owned()),
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
