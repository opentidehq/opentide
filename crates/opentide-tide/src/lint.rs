//! The `opentide lint` settings the Tide checks follow (#214): a workspace's
//! `.opentide/configurations/lint.toml`, read as `opentide lint` reads it, so
//! the language server and the CLI agree on filenames and metadata.
//!
//! | `lint.toml` | Decides |
//! | --- | --- |
//! | `[filenames] enabled`, `style`, `pattern`, `severity`, and `[filenames.<kind>]` | `filename_slug`, `filename_pattern` |
//! | `[metadata] enabled`, `required`, `severity` | `missing_author`, `missing_organisation` |
//! | `[recommended] enabled`, `severity` | `recommended_field_missing` |
//!
//! Without a `lint.toml` the defaults are `opentide lint`'s: slug filenames, no
//! pattern, and `author` and `organisation` required. A missing optional field
//! (`[metadata]`, `[recommended]`) is information unless `severity` raises it. The text is read, not
//! checked: the host checks configuration TOML (`opentide-config`), so a
//! value of the wrong type is ignored here and its default kept. The host
//! installs the settings ([`install_lint_settings`]); this crate reads no file.

use opentide_core::Severity;
use std::sync::{OnceLock, RwLock};

/// `.opentide/configurations/lint.toml`, relative to a workspace root.
pub const LINT_CONFIGURATION: &str = ".opentide/configurations/lint.toml";

/// How a file stem derives from an object's `name` (`[filenames] style`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilenameStyle {
    /// `slugify(name)`, the default.
    #[default]
    Slug,
    /// The name less what a file name cannot hold.
    Name,
    /// The stem is not compared with the name.
    None,
}

/// The filename convention of one kind of object.
#[derive(Debug, Clone, Default)]
pub struct FilenameRules {
    pub style: FilenameStyle,
    /// The pattern the whole stem must match, as written in `lint.toml`.
    pub pattern: Option<String>,
    /// [`pattern`](Self::pattern) compiled, anchored at both ends. `None`
    /// when there is no pattern, or the Rust `regex` crate cannot compile it
    /// (look-around, backreferences): the stem is then not checked against
    /// it here, though `opentide lint` checks it.
    compiled: Option<regex::Regex>,
    /// The `lint.toml` key the pattern came from, for the message.
    pattern_key: String,
}

impl FilenameRules {
    /// Whether `stem` matches the pattern; `true` when no pattern applies.
    pub fn matches_pattern(&self, stem: &str) -> bool {
        self.compiled.as_ref().is_none_or(|re| re.is_match(stem))
    }

    /// The key that set the pattern (`[filenames].pattern`, `[filenames.rules].pattern`).
    pub fn pattern_key(&self) -> &str {
        &self.pattern_key
    }

    /// Whether a pattern is checked here.
    pub fn has_pattern(&self) -> bool {
        self.compiled.is_some()
    }
}

/// The settings of the checks `lint.toml` configures.
#[derive(Debug, Clone)]
pub struct LintSettings {
    pub filenames_enabled: bool,
    /// Replaces the severity of `filename_slug` and `filename_pattern`.
    pub filenames_severity: Option<Severity>,
    filenames: FilenameRules,
    /// `[filenames.threats]`, `[filenames.objectives]`, `[filenames.rules]`,
    /// each with its unset keys taken from `[filenames]`.
    kinds: Vec<(String, FilenameRules)>,
    pub metadata_enabled: bool,
    /// Replaces the severity of `missing_author` and `missing_organisation`.
    pub metadata_severity: Option<Severity>,
    /// The metadata keys every object must fill.
    pub required_metadata: Vec<String>,
    pub recommended_enabled: bool,
    /// Replaces the severity of `recommended_field_missing`.
    pub recommended_severity: Option<Severity>,
}

impl Default for LintSettings {
    /// `opentide lint`'s defaults, the checks before `lint.toml` existed.
    fn default() -> Self {
        Self {
            filenames_enabled: true,
            filenames_severity: None,
            filenames: FilenameRules {
                pattern_key: "[filenames].pattern".into(),
                ..FilenameRules::default()
            },
            kinds: Vec::new(),
            metadata_enabled: true,
            metadata_severity: None,
            required_metadata: vec!["author".into(), "organisation".into()],
            recommended_enabled: true,
            recommended_severity: None,
        }
    }
}

impl LintSettings {
    /// The filename convention for an object of `object_type` (`rule`,
    /// `objective`, `threat`), whose `[filenames.<kind>]` table names its
    /// folder (`rules`).
    pub fn filenames_for(&self, object_type: &str) -> &FilenameRules {
        let kind = format!("{object_type}s");
        self.kinds
            .iter()
            .find(|(name, _)| *name == kind)
            .map_or(&self.filenames, |(_, rules)| rules)
    }

    /// Whether `metadata.required` names `key`.
    pub fn requires(&self, key: &str) -> bool {
        self.required_metadata.iter().any(|k| k == key)
    }
}

/// The object kinds a `[filenames.<kind>]` table configures.
const KINDS: [&str; 3] = ["threats", "objectives", "rules"];

/// Read `lint.toml` text over the defaults. Only text that is not TOML is
/// an error; a table or value of the wrong shape keeps its default.
pub fn parse_lint_settings(text: &str) -> Result<LintSettings, String> {
    let value: toml::Value = toml::from_str(text).map_err(|err| format!("lint.toml: {err}"))?;
    let mut settings = LintSettings::default();
    if let Some(table) = value.get("filenames") {
        settings.filenames_enabled = bool_or(table, "enabled", true);
        settings.filenames_severity = severity(table);
        settings.filenames = filename_rules(table, None, "filenames");
        for kind in KINDS {
            if let Some(own) = table.get(kind).filter(|v| v.is_table()) {
                let rules =
                    filename_rules(own, Some(&settings.filenames), &format!("filenames.{kind}"));
                settings.kinds.push((kind.to_string(), rules));
            }
        }
    }
    if let Some(table) = value.get("metadata") {
        settings.metadata_enabled = bool_or(table, "enabled", true);
        settings.metadata_severity = severity(table);
        if let Some(list) = table.get("required").and_then(|v| v.as_array()) {
            let keys: Vec<String> = list
                .iter()
                .filter_map(|k| k.as_str().map(str::to_string))
                .collect();
            if keys.len() == list.len() {
                settings.required_metadata = keys;
            }
        }
    }
    if let Some(table) = value.get("recommended") {
        settings.recommended_enabled = bool_or(table, "enabled", true);
        settings.recommended_severity = severity(table);
    }
    Ok(settings)
}

fn bool_or(table: &toml::Value, key: &str, default: bool) -> bool {
    table
        .get(key)
        .and_then(toml::Value::as_bool)
        .unwrap_or(default)
}

/// A check's `severity`: `error`, `warning` or `info`, as `opentide lint` names them.
fn severity(table: &toml::Value) -> Option<Severity> {
    match table.get("severity").and_then(toml::Value::as_str)? {
        "error" => Some(Severity::Error),
        "warning" => Some(Severity::Warning),
        "info" => Some(Severity::Information),
        _ => None,
    }
}

fn filename_rules(table: &toml::Value, base: Option<&FilenameRules>, key: &str) -> FilenameRules {
    let style = match table.get("style").and_then(toml::Value::as_str) {
        Some("slug") => FilenameStyle::Slug,
        Some("name") => FilenameStyle::Name,
        Some("none") => FilenameStyle::None,
        _ => base.map_or(FilenameStyle::Slug, |b| b.style),
    };
    match table.get("pattern").and_then(toml::Value::as_str) {
        Some(pattern) if !pattern.is_empty() => FilenameRules {
            style,
            pattern: Some(pattern.to_string()),
            // `re.fullmatch`: the whole stem.
            compiled: regex::Regex::new(&format!("^(?:{pattern})$")).ok(),
            pattern_key: format!("[{key}].pattern"),
        },
        _ => match base {
            Some(base) => FilenameRules {
                style,
                ..base.clone()
            },
            None => FilenameRules {
                style,
                pattern_key: format!("[{key}].pattern"),
                ..FilenameRules::default()
            },
        },
    }
}

/// The stem `[filenames] style = "name"` asks for, as opentide's
/// `expected_stem` derives it: the name without the characters a file name
/// cannot hold on Windows or Unix, control characters, the spaces and dots
/// around it, or a trailing `.debug`. `None` when nothing is left.
pub fn name_stem(name: &str) -> Option<String> {
    const FORBIDDEN: [char; 9] = ['>', '<', ':', '"', '\\', '/', '|', '?', '*'];
    let cleaned: String = name
        .chars()
        .filter(|c| !FORBIDDEN.contains(c) && !c.is_ascii_control())
        .collect();
    let mut stem = cleaned.trim_matches([' ', '.']).to_string();
    while let Some(rest) = stem.strip_suffix(".debug") {
        stem = rest.trim_matches([' ', '.']).to_string();
    }
    (!stem.is_empty()).then_some(stem)
}

fn installed() -> &'static RwLock<Option<LintSettings>> {
    static SETTINGS: OnceLock<RwLock<Option<LintSettings>>> = OnceLock::new();
    SETTINGS.get_or_init(|| RwLock::new(None))
}

/// The settings the Tide checks follow, for the whole process: a host
/// installs a root's `lint.toml` when it analyses a document of that root,
/// as it declares the root's datasets. `None` goes back to the defaults.
pub fn install_lint_settings(settings: Option<LintSettings>) {
    *installed()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = settings;
}

/// The installed settings, else the defaults.
pub fn lint_settings() -> LintSettings {
    installed()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_opentide_lints() {
        let s = parse_lint_settings("").unwrap();
        assert!(s.filenames_enabled && s.metadata_enabled);
        assert_eq!(s.filenames_for("rule").style, FilenameStyle::Slug);
        assert!(s.requires("author") && s.requires("organisation"));
        assert!(!s.filenames_for("rule").has_pattern());
        assert!(s.recommended_enabled);
        assert_eq!(s.recommended_severity, None);
    }

    #[test]
    fn reads_the_recommended_table() {
        let s = parse_lint_settings("[recommended]\nseverity = \"warning\"\n").unwrap();
        assert!(s.recommended_enabled);
        assert_eq!(s.recommended_severity, Some(Severity::Warning));
        let s = parse_lint_settings("[recommended]\nenabled = false\n").unwrap();
        assert!(!s.recommended_enabled);
        // It is its own check: `[metadata]` leaves it on.
        let s = parse_lint_settings("[metadata]\nenabled = false\n").unwrap();
        assert!(s.recommended_enabled);
    }

    #[test]
    fn reads_style_pattern_required_and_severity() {
        let s = parse_lint_settings(
            "[filenames]\nstyle = \"none\"\nseverity = \"info\"\npattern = '^\\[SEN\\].+'\n\
             [filenames.rules]\nstyle = \"name\"\n\
             [metadata]\nrequired = [\"author\"]\n",
        )
        .unwrap();
        assert_eq!(s.filenames_for("threat").style, FilenameStyle::None);
        let rules = s.filenames_for("rule");
        assert_eq!(rules.style, FilenameStyle::Name);
        // A kind table inherits the pattern it leaves unset.
        assert!(rules.matches_pattern("[SEN]Example rule"));
        assert!(!rules.matches_pattern("x[SEN]Example rule"));
        assert_eq!(rules.pattern_key(), "[filenames].pattern");
        assert_eq!(s.filenames_severity, Some(Severity::Information));
        assert!(s.requires("author") && !s.requires("organisation"));
    }

    #[test]
    fn a_kind_pattern_names_its_own_key() {
        let s = parse_lint_settings("[filenames.rules]\npattern = 'r-.+'\n").unwrap();
        assert_eq!(
            s.filenames_for("rule").pattern_key(),
            "[filenames.rules].pattern"
        );
        assert!(!s.filenames_for("threat").has_pattern());
    }

    #[test]
    fn disabled_checks_and_bad_values() {
        let s = parse_lint_settings(
            "[filenames]\nenabled = false\nstyle = 3\n[metadata]\nenabled = false\nrequired = [1]\n",
        )
        .unwrap();
        assert!(!s.filenames_enabled && !s.metadata_enabled);
        assert_eq!(s.filenames_for("rule").style, FilenameStyle::Slug);
        assert!(s.requires("organisation"));
        assert!(parse_lint_settings("[filenames").is_err());
    }

    #[test]
    fn a_pattern_rust_cannot_compile_is_not_checked() {
        let s = parse_lint_settings("[filenames]\npattern = '(?<=x)y'\n").unwrap();
        assert!(!s.filenames_for("rule").has_pattern());
        assert!(s.filenames_for("rule").matches_pattern("anything"));
    }

    #[test]
    fn name_stems_match_opentides() {
        assert_eq!(
            name_stem("[SEN]Example rule").as_deref(),
            Some("[SEN]Example rule")
        );
        assert_eq!(name_stem(" a:b/c? ").as_deref(), Some("abc"));
        assert_eq!(name_stem("x.debug").as_deref(), Some("x"));
        assert_eq!(name_stem(" .. "), None);
    }
}
