//! `lint.toml`: which `opentide lint` checks run, at what severity, and what
//! they demand (`core/lint_config.py` `parse_lint_config`). The merged
//! `[lint]` tables are checked in the oracle's order and the first problem
//! stops, with a message naming the key.
//!
//! A `[filenames]` `pattern` is compiled by the `regex` crate, which has no
//! look-around or back-reference: such a pattern is refused with the crate's
//! own reason. That is an intended difference, recorded as
//! `lint-pattern-regex` in `tests/oracle/config_cases.toml` and in the
//! CHANGELOG entry "Configuration files are read as TOML 1.0".

use regex::Regex;

use super::repr;
use crate::node::{Node, Value};

/// Check names, in the order `opentide lint` runs them.
pub const CHECK_NAMES: [&str; 5] = [
    "filenames",
    "metadata",
    "recommended",
    "placeholders",
    "queries",
];
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
const COMMON_KEYS: [&str; 3] = ["enabled", "severity", "codes"];
/// What a `[<check>.codes]` entry takes besides a severity: the finding is dropped.
pub const CODE_OFF: &str = "off";

/// The codes `opentide lint` reports itself, each with the check it belongs
/// to. Every other code in [`opentide_core::codes`] is the analysis engine's,
/// and belongs to `queries`.
pub const LINT_CODE_CHECKS: [(&str, &str); 8] = [
    ("yaml_parse", "filenames"),
    ("name_missing", "filenames"),
    ("filename_mismatch", "filenames"),
    ("filename_pattern", "filenames"),
    ("nested_object_file", "filenames"),
    ("metadata_recommended", "metadata"),
    ("recommended_field_missing", "recommended"),
    ("placeholder", "placeholders"),
];

/// Codes nothing reports any more (`opentide explain` keeps their pages), each
/// with what replaced it. A `codes` table that still names one is accepted
/// with a warning, so an old `lint.toml` keeps working: the entry has no effect.
pub const RETIRED_CODES: [(&str, &str); 5] = [
    (
        "crowdstrike_unsupported",
        "CrowdStrike queries are checked as CQL, with the cql_* codes",
    ),
    (
        "yara_x_incompatible",
        "what YARA-X refuses has its own yara_* codes",
    ),
    (
        "filename_slug",
        "lint reports it as filename_mismatch, under [filenames.codes]",
    ),
    (
        "missing_author",
        "lint reports it as metadata_recommended, under [metadata.codes]",
    ),
    (
        "missing_organisation",
        "lint reports it as metadata_recommended, under [metadata.codes]",
    ),
];

/// The check a finding with this code belongs to, `None` for an unknown code.
pub fn check_of_code(code: &str) -> Option<&'static str> {
    LINT_CODE_CHECKS
        .iter()
        .find(|(known, _)| *known == code)
        .map(|(_, check)| *check)
        .or_else(|| {
            opentide_core::codes::ALL
                .contains(&code)
                .then_some("queries")
        })
}

fn every_code() -> impl Iterator<Item = &'static str> {
    LINT_CODE_CHECKS
        .iter()
        .map(|(code, _)| *code)
        .chain(opentide_core::codes::ALL.iter().copied())
}

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
    /// `[<check>.codes]`: the severity of one code's findings (`error`,
    /// `warning`, `info`) or [`CODE_OFF`], which wins over `severity`. In the
    /// order the file lists them.
    pub codes: Vec<(String, String)>,
}

impl CheckConfig {
    /// What `[<check>.codes]` says of `code`, when it does.
    pub fn code_level(&self, code: &str) -> Option<&str> {
        self.codes
            .iter()
            .find(|(own, _)| own == code)
            .map(|(_, level)| level.as_str())
    }
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
    /// What the file asks of the reader without refusing it: a retired code
    /// in a `codes` table.
    pub warnings: Vec<String>,
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            checks: Vec::new(),
            required_metadata: DEFAULT_REQUIRED_METADATA.map(str::to_owned).to_vec(),
            filenames: FilenameConfig::default(),
            warnings: Vec::new(),
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
        let codes = match table.get("codes") {
            None => Vec::new(),
            Some(node) => code_levels(node, name, &mut config.warnings)?,
        };
        config.checks.push((
            name.to_owned(),
            CheckConfig {
                enabled,
                severity,
                codes,
            },
        ));
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

/// `[<check>.codes]`: each key a code of that check, each value a severity or `off`.
/// A retired code is skipped with a warning.
fn code_levels(
    node: &Node,
    check: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<(String, String)>, LintConfigError> {
    let place = format!("{SOURCE} [{check}.codes]");
    if !matches!(node.value, Value::Map(_)) {
        return Err(LintConfigError(format!("{place} must be a table")));
    }
    let mut levels = Vec::new();
    for entry in entries(node) {
        let code = key_of(entry);
        if let Some((_, replacement)) = RETIRED_CODES.iter().find(|(old, _)| *old == code) {
            warnings.push(format!(
                "{place}: code {} is retired and has no effect: {replacement}",
                repr::quote(&code)
            ));
            continue;
        }
        match check_of_code(&code) {
            None => {
                let hint = opentide_core::suggest::closest(&code, every_code())
                    .map_or_else(String::new, |near| {
                        format!(". Did you mean {}?", repr::quote(near))
                    });
                return Err(LintConfigError(format!(
                    "{place}: unknown code {}{hint}",
                    repr::quote(&code)
                )));
            }
            Some(owner) if owner != check => {
                return Err(LintConfigError(format!(
                    "{place}: code {} belongs to the {owner} check; set it under [{owner}.codes]",
                    repr::quote(&code)
                )));
            }
            Some(_) => {}
        }
        match entry.value.value.as_str() {
            Some(text) if SEVERITIES.contains(&text) || text == CODE_OFF => {
                levels.push((code, text.to_owned()));
            }
            _ => {
                return Err(LintConfigError(format!(
                    "{place}.{code} must be one of {}, {CODE_OFF}, got {}",
                    SEVERITIES.join(", "),
                    repr::node(&entry.value)
                )));
            }
        }
    }
    Ok(levels)
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
                "{place}.pattern: invalid regular expression {raw:?}: {reason}"
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
        pattern = Some(raw.to_string());
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
        names.push(name.to_string());
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

    #[test]
    fn codes_tables_set_a_severity_or_off_per_code() {
        let config = filenames(
            "[queries]\nseverity = \"warning\"\n[queries.codes]\nkql_join_summarize_before_project = \"info\"\nkql_unknown_table = \"off\"\n[filenames.codes]\nfilename_mismatch = \"error\"\n",
        )
        .unwrap();
        let queries = &config
            .checks
            .iter()
            .find(|(name, _)| name == "queries")
            .unwrap()
            .1;
        assert_eq!(queries.severity.as_deref(), Some("warning"));
        assert_eq!(
            queries.code_level("kql_join_summarize_before_project"),
            Some("info")
        );
        assert_eq!(queries.code_level("kql_unknown_table"), Some(CODE_OFF));
        assert_eq!(queries.code_level("kql_table_not_declared"), None);
        let names = &config
            .checks
            .iter()
            .find(|(name, _)| name == "filenames")
            .unwrap()
            .1;
        assert_eq!(names.code_level("filename_mismatch"), Some("error"));
    }

    #[test]
    fn an_unknown_code_is_refused_with_the_nearest_known_one() {
        let error = filenames("[queries.codes]\nkql_unknown_tabel = \"off\"\n").unwrap_err();
        assert_eq!(
            error.0,
            "lint.toml [queries.codes]: unknown code \"kql_unknown_tabel\". Did you mean \"kql_unknown_table\"?"
        );
        let far = filenames("[queries.codes]\nzzzzzzzzzzzzzzzz = \"off\"\n").unwrap_err();
        assert_eq!(
            far.0,
            "lint.toml [queries.codes]: unknown code \"zzzzzzzzzzzzzzzz\""
        );
    }

    #[test]
    fn a_code_under_the_wrong_check_is_refused_naming_its_own() {
        let error = filenames("[filenames.codes]\nkql_unknown_table = \"off\"\n").unwrap_err();
        assert_eq!(
            error.0,
            "lint.toml [filenames.codes]: code \"kql_unknown_table\" belongs to the queries check; set it under [queries.codes]"
        );
        assert!(filenames("[queries.codes]\nfilename_mismatch = \"off\"\n").is_err());
    }

    #[test]
    fn a_codes_value_is_a_severity_or_off() {
        let error = filenames("[queries.codes]\nkql_unknown_table = \"fatal\"\n").unwrap_err();
        assert_eq!(
            error.0,
            "lint.toml [queries.codes].kql_unknown_table must be one of error, warning, info, off, got \"fatal\""
        );
        assert!(filenames("[queries.codes]\nkql_unknown_table = true\n").is_err());
        let table = filenames("[queries]\ncodes = \"off\"\n").unwrap_err();
        assert_eq!(table.0, "lint.toml [queries.codes] must be a table");
    }

    #[test]
    fn every_lint_code_names_its_check() {
        for (code, check) in LINT_CODE_CHECKS {
            assert!(CHECK_NAMES.contains(&check), "{code}");
            assert_eq!(check_of_code(code), Some(check));
        }
        assert_eq!(check_of_code("kql_unknown_table"), Some("queries"));
        assert_eq!(check_of_code("nope"), None);
    }

    #[test]
    fn a_retired_code_is_accepted_with_a_warning_naming_its_replacement() {
        let config =
            filenames("[filenames.codes]\nfilename_slug = \"off\"\nfilename_mismatch = \"info\"\n")
                .unwrap();
        let own = &config
            .checks
            .iter()
            .find(|(name, _)| name == "filenames")
            .unwrap()
            .1;
        assert_eq!(
            own.codes,
            [("filename_mismatch".to_owned(), "info".to_owned())]
        );
        assert_eq!(
            config.warnings,
            [
                "lint.toml [filenames.codes]: code \"filename_slug\" is retired and has no effect: lint reports it as filename_mismatch, under [filenames.codes]"
            ]
        );
        // Under any check, and whatever its value: it is not read.
        let anywhere = filenames("[queries.codes]\nmissing_author = \"nonsense\"\n").unwrap();
        assert_eq!(anywhere.warnings.len(), 1);
        for (code, _) in RETIRED_CODES {
            assert_eq!(check_of_code(code), None, "{code} is retired, not known");
        }
    }
}
