//! `lint.toml`: which `opentide lint` checks run, at what severity, and what
//! they demand (`core/lint_config.py` `parse_lint_config`). The merged
//! `[lint]` tables are checked in the oracle's order and the first problem
//! stops, with a message naming the key.
//!
//! A `[filenames]` `pattern` is compiled by the `regex` crate, which has no
//! look-around or back-reference: such a pattern is refused with the crate's
//! own reason. That is an intended difference, recorded as
//! `lint-pattern-regex` in `tests/oracle/config_cases.toml` and in the
//! CHANGELOG entry "Configuration files are read by the Rust engine"
//! (`tests/golden/APPROVED_DIFFS.toml` takes it when a command that reads
//! `lint.toml` runs in Rust).

use regex::Regex;

use super::repr;
use crate::node::{Node, Value};

/// Check names, in the order `opentide lint` runs them.
pub const CHECK_NAMES: [&str; 4] = ["filenames", "metadata", "placeholders", "queries"];
/// Severities a check may be set to.
pub const SEVERITIES: [&str; 3] = ["error", "warning", "info"];
/// How `[filenames]` derives a stem from `name`.
pub const FILENAME_STYLES: [&str; 3] = ["slug", "name", "none"];
/// The object kinds a `[filenames.<kind>]` table configures.
pub const FILENAME_KINDS: [&str; 3] = ["threats", "objectives", "rules"];
/// `metadata.required` when nothing configures it.
pub const DEFAULT_REQUIRED_METADATA: [&str; 2] = ["author", "organisation"];
/// Every key an object's `metadata` block can hold, across schemas
/// (`metadata_keys`; `tests/oracle/config_table.json` holds the oracle's).
pub const METADATA_KEYS: [&str; 10] = [
    "uuid",
    "schema",
    "version",
    "created",
    "modified",
    "tlp",
    "author",
    "contributors",
    "organisation",
    "reviewed",
];

const SOURCE: &str = "lint.toml";
const COMMON_KEYS: [&str; 2] = ["enabled", "severity"];

fn check_keys(name: &str) -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = COMMON_KEYS.to_vec();
    match name {
        "filenames" => {
            keys.extend(["style", "pattern"]);
            keys.extend(FILENAME_KINDS);
        }
        "metadata" => keys.push("required"),
        _ => {}
    }
    keys.sort_unstable();
    keys
}

/// Settings shared by every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckConfig {
    /// Whether the check runs.
    pub enabled: bool,
    /// The severity every finding takes, when set.
    pub severity: Option<String>,
}

/// The `[filenames]` convention.
#[derive(Debug, Clone)]
pub struct FilenameConfig {
    /// `slug`, `name` or `none`.
    pub style: String,
    /// The pattern the whole stem must match, as written.
    pub pattern: Option<String>,
    /// The pattern, anchored at both ends.
    pub regex: Option<Regex>,
    /// The convention of each kind with a `[filenames.<kind>]` table.
    pub kinds: Vec<(String, FilenameConfig)>,
    /// The `lint.toml` key the pattern came from, for messages.
    pub pattern_key: String,
}

impl Default for FilenameConfig {
    fn default() -> Self {
        Self {
            style: "slug".to_owned(),
            pattern: None,
            regex: None,
            kinds: Vec::new(),
            pattern_key: "[filenames].pattern".to_owned(),
        }
    }
}

/// Resolved lint settings.
#[derive(Debug, Clone)]
pub struct LintConfig {
    /// The checks a table configures, by name.
    pub checks: Vec<(String, CheckConfig)>,
    /// `metadata.required`.
    pub required_metadata: Vec<String>,
    /// `[filenames]`.
    pub filenames: FilenameConfig,
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            checks: Vec::new(),
            required_metadata: DEFAULT_REQUIRED_METADATA.map(str::to_owned).to_vec(),
            filenames: FilenameConfig::default(),
        }
    }
}

/// A `lint.toml` value opentide cannot use; the message names the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct LintConfigError(pub String);

fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|name| repr::quote(name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn entries(node: &Node) -> &[crate::node::Entry] {
    match &node.value {
        Value::Map(entries) => entries,
        _ => &[],
    }
}

fn key_of(entry: &crate::node::Entry) -> String {
    entry.key.value.to_string()
}

/// Checks the merged `[lint]` tables (the resolved `lint` table, `None` when
/// there is none).
///
/// # Errors
///
/// The first problem, in the oracle's order and words.
pub fn parse_lint_config(raw: Option<&Node>) -> Result<LintConfig, LintConfigError> {
    let Some(raw) = raw else {
        return Ok(LintConfig::default());
    };
    if !matches!(raw.value, Value::Map(_)) {
        return Err(LintConfigError(format!(
            "{SOURCE} must hold tables, one per check"
        )));
    }
    let mut unknown: Vec<String> = entries(raw)
        .iter()
        .map(key_of)
        .filter(|key| !CHECK_NAMES.contains(&key.as_str()))
        .collect();
    unknown.sort();
    if !unknown.is_empty() {
        return Err(LintConfigError(format!(
            "{SOURCE}: unknown check(s) {}. Known checks: {}",
            quoted(&unknown),
            CHECK_NAMES.join(", ")
        )));
    }
    let mut config = LintConfig::default();
    for name in CHECK_NAMES {
        let Some(table) = raw.get(name) else {
            continue;
        };
        let place = format!("{SOURCE} [{name}]");
        if !matches!(table.value, Value::Map(_)) {
            return Err(LintConfigError(format!("{place} must be a table")));
        }
        let known = check_keys(name);
        let mut unknown: Vec<String> = entries(table)
            .iter()
            .map(key_of)
            .filter(|key| !known.contains(&key.as_str()))
            .collect();
        unknown.sort();
        if name == "filenames" {
            reject_unknown_kinds(table, &unknown)?;
        }
        if !unknown.is_empty() {
            return Err(LintConfigError(format!(
                "{place}: unknown key(s) {}. Known keys: {}",
                quoted(&unknown),
                known.join(", ")
            )));
        }
        let enabled = match table.get("enabled").map(|node| &node.value) {
            None => true,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => {
                let value = table
                    .get("enabled")
                    .map_or_else(String::new, |n| repr::node(n));
                return Err(LintConfigError(format!(
                    "{place}.enabled must be true or false, got {value}"
                )));
            }
        };
        let severity = match table.get("severity") {
            None => None,
            Some(node) => match node.value.as_str() {
                Some(text) if SEVERITIES.contains(&text) => Some(text.to_owned()),
                _ => {
                    return Err(LintConfigError(format!(
                        "{place}.severity must be one of {}, got {}",
                        SEVERITIES.join(", "),
                        repr::node(node)
                    )));
                }
            },
        };
        config
            .checks
            .push((name.to_owned(), CheckConfig { enabled, severity }));
        if name == "metadata"
            && let Some(required) = table.get("required")
        {
            config.required_metadata = required_metadata(required, &place)?;
        }
        if name == "filenames" {
            config.filenames = filename_config(table, "filenames", None)?;
        }
    }
    Ok(config)
}

fn reject_unknown_kinds(table: &Node, unknown: &[String]) -> Result<(), LintConfigError> {
    let tables: Vec<String> = unknown
        .iter()
        .filter(|key| {
            table
                .get(key)
                .is_some_and(|node| matches!(node.value, Value::Map(_)))
        })
        .cloned()
        .collect();
    if let Some(first) = tables.first() {
        return Err(LintConfigError(format!(
            "{SOURCE} [filenames.{first}]: unknown object kind(s) {}. Known kinds: {}",
            quoted(&tables),
            FILENAME_KINDS.join(", ")
        )));
    }
    Ok(())
}

fn compile(raw: &str, place: &str) -> Result<Regex, LintConfigError> {
    // The pattern is checked as written, then anchored on its parsed form
    // (`fullmatch`): wrapping the text would accept an unbalanced `a)(b`,
    // and a verbose (`(?x)`) comment at its end would swallow the wrapper's
    // `)`. The HIR prints as an equivalent pattern without flags or comments.
    Regex::new(raw)
        .and_then(|_| {
            let hir = regex_syntax::Parser::new()
                .parse(raw)
                .map_err(|error| regex::Error::Syntax(error.to_string()))?;
            Regex::new(&format!(r"\A(?:{hir})\z"))
        })
        .map_err(|error| {
            let reason = error
                .to_string()
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or_default()
                .trim()
                .to_owned();
            LintConfigError(format!(
                "{place}.pattern: invalid regular expression '{raw}': {reason}"
            ))
        })
}

fn filename_config(
    table: &Node,
    key: &str,
    base: Option<&FilenameConfig>,
) -> Result<FilenameConfig, LintConfigError> {
    let place = format!("{SOURCE} [{key}]");
    let style = match table.get("style") {
        None => base.map_or_else(|| "slug".to_owned(), |base| base.style.clone()),
        Some(node) => match node.value.as_str() {
            Some(text) if FILENAME_STYLES.contains(&text) => text.to_owned(),
            _ => {
                return Err(LintConfigError(format!(
                    "{place}.style must be one of {}, got {}",
                    FILENAME_STYLES.join(", "),
                    repr::node(node)
                )));
            }
        },
    };
    let mut pattern = base.and_then(|base| base.pattern.clone());
    let mut regex = base.and_then(|base| base.regex.clone());
    let mut pattern_key = base.map_or_else(
        || format!("[{key}].pattern"),
        |base| base.pattern_key.clone(),
    );
    if let Some(node) = table.get("pattern") {
        let Value::Str(raw) = &node.value else {
            return Err(LintConfigError(format!(
                "{place}.pattern must be a string, got {}",
                repr::node(node)
            )));
        };
        if raw.is_empty() {
            return Err(LintConfigError(format!(
                "{place}.pattern must not be empty"
            )));
        }
        regex = Some(compile(raw, &place)?);
        pattern = Some(raw.clone());
        pattern_key = format!("[{key}].pattern");
    }
    let mut config = FilenameConfig {
        style,
        pattern,
        regex,
        kinds: Vec::new(),
        pattern_key,
    };
    if base.is_some() {
        return Ok(config);
    }
    for kind in FILENAME_KINDS {
        let Some(own) = table.get(kind) else {
            continue;
        };
        if !matches!(own.value, Value::Map(_)) {
            return Err(LintConfigError(format!(
                "{place}.{kind} must be a table, got {}",
                repr::node(own)
            )));
        }
        let mut unknown: Vec<String> = entries(own)
            .iter()
            .map(key_of)
            .filter(|name| name != "style" && name != "pattern")
            .collect();
        unknown.sort();
        if !unknown.is_empty() {
            return Err(LintConfigError(format!(
                "{SOURCE} [{key}.{kind}]: unknown key(s) {}. Known keys: pattern, style",
                quoted(&unknown)
            )));
        }
        let own_config = filename_config(own, &format!("{key}.{kind}"), Some(&config))?;
        config.kinds.push((kind.to_owned(), own_config));
    }
    Ok(config)
}

fn required_metadata(value: &Node, place: &str) -> Result<Vec<String>, LintConfigError> {
    let Value::Seq(items) = &value.value else {
        return Err(LintConfigError(format!(
            "{place}.required must be a list of metadata keys"
        )));
    };
    let mut names = Vec::with_capacity(items.len());
    for item in items {
        let Value::Str(name) = &item.value else {
            return Err(LintConfigError(format!(
                "{place}.required must be a list of metadata keys"
            )));
        };
        names.push(name.clone());
    }
    let unknown: Vec<String> = names
        .iter()
        .filter(|name| !METADATA_KEYS.contains(&name.as_str()))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(LintConfigError(format!(
            "{place}.required: unknown metadata field(s) {}. Known fields: {}",
            quoted(&unknown),
            METADATA_KEYS.join(", ")
        )));
    }
    let mut unique: Vec<String> = Vec::new();
    for name in names {
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    Ok(unique)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::toml::parse;

    fn filenames(text: &str) -> Result<LintConfig, LintConfigError> {
        let document = parse(text).unwrap();
        parse_lint_config(Some(&document))
    }

    #[test]
    fn a_pattern_is_checked_as_written_and_matches_the_whole_stem() {
        assert!(filenames("[filenames]\npattern = \"a)(b\"\n").is_err());
        let config = filenames("[filenames]\npattern = \"a|b\"\n").unwrap();
        let regex = config.filenames.regex.unwrap();
        assert!(regex.is_match("a"));
        assert!(!regex.is_match("ab"));
        assert!(!regex.is_match("xa"));
        let either = filenames("[filenames]\npattern = \"a|ab\"\n").unwrap();
        assert!(either.filenames.regex.unwrap().is_match("ab"));
    }

    #[test]
    fn a_verbose_pattern_ending_in_a_comment_is_anchored() {
        // Wrapped as text, `\A(?:(?x)a # c)\z` has its `)` commented out.
        let config = filenames("[filenames]\npattern = '(?x)a # c'\n").unwrap();
        assert_eq!(config.filenames.pattern.as_deref(), Some("(?x)a # c"));
        let regex = config.filenames.regex.unwrap();
        assert!(regex.is_match("a"));
        assert!(!regex.is_match("a # c"));
        assert!(!regex.is_match("ab"));
        let flags = filenames("[filenames]\npattern = '(?i)r-[a-z]+'\n").unwrap();
        let regex = flags.filenames.regex.unwrap();
        assert!(regex.is_match("R-ABC"));
        assert!(!regex.is_match("R-ABC-"));
    }
}
