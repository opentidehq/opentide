//! Datasets a workspace declares in `visibility.toml`, per platform, and the
//! columns a log source lists for its dataset (`visibility::1.0`, #146).
//!
//! A log source's `name` is its dataset: a KQL table (or workspace function)
//! for `sentinel` and `defender_for_endpoint`, a sourcetype for `splunk`, an
//! index pattern or data stream for `elastic`. The engine reads them from the
//! `visibility.toml` text itself ([`DeclaredDatasets::from_visibility`]); a
//! host installs them for the process ([`install`]), again whenever the file
//! changes. The query engines ask [`current`] whether a name a query reads is
//! declared. Checking is opt-in per platform: a workspace with no Splunk log
//! source never gets a warning about a sourcetype.
//!
//! Declarations are per `system`, so a Splunk sourcetype never makes a
//! Sentinel table known.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

/// The kind of dataset a log source's `name` is, by its `system`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DatasetKind {
    /// KQL tables and functions (`sentinel`, `defender_for_endpoint`).
    Tables,
    /// Splunk `sourcetype=`.
    Sourcetypes,
    /// Elastic index patterns and data streams (`index`, ES|QL `FROM`).
    Indices,
}

impl DatasetKind {
    /// The kind a log source of `system` declares; `None` for a system
    /// whose log sources declare nothing to the query checks.
    pub fn of_system(system: &str) -> Option<Self> {
        match system {
            "sentinel" | "defender_for_endpoint" => Some(Self::Tables),
            "splunk" => Some(Self::Sourcetypes),
            "elastic" => Some(Self::Indices),
            _ => None,
        }
    }

    /// What a name of this kind is called in a message (`table`,
    /// `sourcetype`, `index pattern`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Tables => "table",
            Self::Sourcetypes => "sourcetype",
            Self::Indices => "index pattern",
        }
    }

    /// Splunk names match without regard to case; KQL tables and Elastic
    /// indices do not.
    fn case_insensitive(self) -> bool {
        self == Self::Sourcetypes
    }

    /// Whether `declared`, a name or pattern a log source declares, covers
    /// `used`, a name (or pattern) a query reads: `*` in either matches any
    /// run of characters, Splunk names ignore case ([`DeclaredDatasets::status`]).
    pub fn covers(self, declared: &str, used: &str) -> bool {
        let (declared, used) = if self.case_insensitive() {
            (
                declared.to_ascii_lowercase(),
                used.trim().to_ascii_lowercase(),
            )
        } else {
            (declared.to_string(), used.trim().to_string())
        };
        glob_matches(&declared, &used) || (used.contains('*') && glob_matches(&used, &declared))
    }
}

/// What the workspace says about one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declaration {
    /// The workspace has no log source for the platform, so the name is not
    /// checked.
    Unchecked,
    /// A declared name, or a declared pattern, covers it.
    Declared,
    /// The workspace has log sources for the platform, and none covers this
    /// name.
    Undeclared,
}

/// One column a log source lists for its dataset
/// (`[logsources.columns]`, `Name = { type = "...", description = "..." }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredColumn {
    /// The column name as the platform spells it: the key, kept as written.
    pub name: String,
    /// The type, from the system's type set (KQL scalar types, Splunk
    /// `string`/`number`/`boolean`, Elasticsearch field types). `None` when
    /// the entry has none (opentide's validation reports it).
    pub type_name: Option<String>,
    pub description: Option<String>,
}

/// A `[[logsources]]` entry of a system that declares datasets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredSource {
    /// The `system` (`sentinel`, `splunk`, ...).
    pub system: String,
    /// The `name`: the dataset (a table, sourcetype or index pattern).
    pub name: String,
    pub description: Option<String>,
    /// The dataset's columns, in key order.
    pub columns: Vec<DeclaredColumn>,
}

impl DeclaredSource {
    /// The kind of dataset `name` is.
    #[expect(
        clippy::expect_used,
        reason = "from_visibility and from_names keep only systems with a dataset kind; a source built by hand with another system is a caller's bug"
    )]
    pub fn kind(&self) -> DatasetKind {
        DatasetKind::of_system(&self.system).expect("only systems with a dataset kind are kept")
    }
}

/// The declared datasets: the log sources, by platform, in file order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclaredDatasets {
    platforms: BTreeMap<String, Vec<String>>,
    sources: Vec<DeclaredSource>,
}

/// A trimmed, non-empty string value of `key`.
fn string(table: &toml::Table, key: &str) -> Option<String> {
    let value = table.get(key)?.as_str()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

impl DeclaredDatasets {
    /// The datasets the `[[logsources]]` of a `visibility.toml` declare,
    /// with the columns each lists:
    ///
    /// ```toml
    /// [[logsources]]
    /// name = "Contoso_Audit_CL"
    /// description = "Administrative audit events"
    /// system = "sentinel"
    ///
    /// [logsources.columns]
    /// Actor_s = { type = "string", description = "UPN of the account that made the change" }
    /// ```
    ///
    /// A leading byte-order mark is skipped. Text that is not TOML is an
    /// error; a log source without a `name`, of a system that declares no
    /// dataset, or a column that is not a table, is left out (opentide's
    /// validation reports it), and so are the keys of opentide 0.20.0
    /// (`tables = [...]`, `indexes`, `sourcetypes`, `macros`, `indices`,
    /// `data_views`, `ecs`), which the format no longer has.
    pub fn from_visibility(text: &str) -> Result<Self, String> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let file: toml::Table = toml::from_str(text).map_err(|err| err.to_string())?;
        let mut out = Self::default();
        let sources = file.get("logsources").and_then(|v| v.as_array());
        for source in sources.into_iter().flatten().filter_map(|v| v.as_table()) {
            let Some(system) = source.get("system").and_then(|v| v.as_str()) else {
                continue;
            };
            if DatasetKind::of_system(system).is_none() {
                continue;
            }
            let Some(name) = string(source, "name") else {
                continue;
            };
            let columns = source
                .get("columns")
                .and_then(|v| v.as_table())
                .into_iter()
                .flatten()
                .filter(|(column, _)| !column.trim().is_empty())
                .filter_map(|(column, value)| {
                    let value = value.as_table()?;
                    Some(DeclaredColumn {
                        name: column.clone(),
                        type_name: string(value, "type"),
                        description: string(value, "description"),
                    })
                })
                .collect();
            out.push(DeclaredSource {
                system: system.to_string(),
                name,
                description: string(source, "description"),
                columns,
            });
        }
        Ok(out)
    }

    fn push(&mut self, source: DeclaredSource) {
        self.platforms
            .entry(source.system.clone())
            .or_default()
            .push(source.name.clone());
        self.sources.push(source);
    }

    /// Declarations built in code, for tests and hosts that have them already:
    /// one log source, without columns, per `(platform, name)`.
    pub fn from_names<'a>(entries: impl IntoIterator<Item = (&'a str, &'a [&'a str])>) -> Self {
        let mut out = Self::default();
        for (platform, names) in entries {
            if DatasetKind::of_system(platform).is_none() {
                continue;
            }
            for name in names {
                out.push(DeclaredSource {
                    system: platform.to_string(),
                    name: name.to_string(),
                    description: None,
                    columns: Vec::new(),
                });
            }
        }
        out
    }

    /// Nothing declared for any platform.
    pub fn is_empty(&self) -> bool {
        self.platforms.is_empty()
    }

    /// The names (and patterns) the log sources of `platform` declare.
    pub fn names(&self, platform: &str) -> &[String] {
        self.platforms
            .get(platform)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The log sources of `platform`, in file order.
    pub fn sources(&self, platform: &str) -> impl Iterator<Item = &DeclaredSource> {
        self.sources.iter().filter(move |s| s.system == platform)
    }

    /// The log sources of `platform` that list columns.
    pub fn sources_with_columns(&self, platform: &str) -> impl Iterator<Item = &DeclaredSource> {
        self.sources(platform).filter(|s| !s.columns.is_empty())
    }

    /// Whether the workspace has a log source for `platform`: the opt-in for
    /// warning about undeclared names.
    pub fn declares(&self, platform: &str) -> bool {
        !self.names(platform).is_empty()
    }

    /// Whether `name`, as a query reads it, is declared for `platform`.
    ///
    /// A declared name may hold `*` (`*_CL`, `logs-*`), which matches any run
    /// of characters. A name the query reads may hold `*` too (an index
    /// pattern, `sourcetype=win*`): it is declared when a declared pattern
    /// covers it (`logs-*` covers `logs-azure.*`) or when it reaches a
    /// declared name (`win*` reaches `wineventlog`).
    pub fn status(&self, platform: &str, name: &str) -> Declaration {
        let declared = self.names(platform);
        let Some(kind) = DatasetKind::of_system(platform) else {
            return Declaration::Unchecked;
        };
        if declared.is_empty() {
            return Declaration::Unchecked;
        }
        if declared.iter().any(|d| kind.covers(d, name)) {
            Declaration::Declared
        } else {
            Declaration::Undeclared
        }
    }
}

/// `*` in `pattern` matches any run of characters (including none); every
/// other character matches itself.
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && p[pi] != '*' && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn installed() -> &'static RwLock<Arc<DeclaredDatasets>> {
    static INSTALLED: OnceLock<RwLock<Arc<DeclaredDatasets>>> = OnceLock::new();
    INSTALLED.get_or_init(|| RwLock::new(Arc::new(DeclaredDatasets::default())))
}

/// Use `datasets` for the whole process. `None` (or an empty set) declares
/// nothing, so no name is checked.
pub fn install(datasets: Option<DeclaredDatasets>) {
    *installed()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(datasets.unwrap_or_default());
}

/// The datasets in use.
pub fn current() -> Arc<DeclaredDatasets> {
    installed()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob() {
        assert!(glob_matches("*_CL", "MyLog_CL"));
        assert!(glob_matches("*_CL", "_CL"));
        assert!(!glob_matches("*_CL", "MyLog_CLX"));
        assert!(glob_matches("logs-*", "logs-azure.signinlogs-*"));
        assert!(!glob_matches("logs-azure.*", "logs-*"));
        assert!(glob_matches("a*b*c", "aXXbYYc"));
        assert!(!glob_matches("a*b*c", "aXXbYY"));
        assert!(glob_matches("exact", "exact"));
        assert!(!glob_matches("exact", "Exact"));
        assert!(glob_matches("*", ""));
    }

    #[test]
    fn opt_in_per_platform() {
        let d = DeclaredDatasets::from_visibility(
            r#"
[[assets]]
name = "Prod"

[[logsources]]
name = "NTANetAnalytics"
description = "VNet flows."
system = "sentinel"

[[logsources]]
name = "*_CL"
description = "Custom tables."
system = "sentinel"

[[logsources]]
name = "WinEventLog:Security"
description = "Security events."
system = "splunk"

[[logsources]]
name = "logs-*"
description = "Integrations."
system = "elastic"

[[logsources]]
name = "Okta"
description = "Not a query platform."
system = "okta"
"#,
        )
        .unwrap();
        use Declaration::*;
        assert_eq!(d.status("sentinel", "NTANetAnalytics"), Declared);
        assert_eq!(d.status("sentinel", "Custom_CL"), Declared);
        assert_eq!(d.status("sentinel", "SigninLogs"), Undeclared);
        assert_eq!(d.status("sentinel", "ntanetanalytics"), Undeclared);
        // Another platform's names never count.
        assert_eq!(
            d.status("defender_for_endpoint", "NTANetAnalytics"),
            Unchecked
        );
        assert_eq!(d.status("splunk", "wineventlog:security"), Declared);
        assert_eq!(d.status("splunk", "WinEventLog:*"), Declared);
        assert_eq!(d.status("splunk", "syslog"), Undeclared);
        assert_eq!(d.status("elastic", "logs-azure.signinlogs-*"), Declared);
        assert_eq!(d.status("elastic", "winlogbeat-*"), Undeclared);
        assert_eq!(d.status("okta", "Okta"), Unchecked);
        assert_eq!(d.sources("okta").count(), 0);
    }

    #[test]
    fn the_keys_of_0_20_0_declare_nothing() {
        let d = DeclaredDatasets::from_visibility(
            r#"
[[logsources]]
description = "x"
system = "sentinel"
tables = ["SigninLogs"]

[[logsources]]
description = "x"
system = "splunk"
indexes = ["main"]
sourcetypes = ["syslog"]
macros = ["sysmon"]

[[logsources]]
description = "x"
system = "elastic"
indices = ["logs-*"]
data_views = ["x"]
ecs = true
"#,
        )
        .unwrap();
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn columns_are_keyed_by_name_as_written() {
        let d = DeclaredDatasets::from_visibility(
            r#"
[[logsources]]
name = "Contoso_Audit_CL"
description = "Audit events."
system = "sentinel"

[logsources.columns]
Actor_s = { type = "string", description = "UPN of the account that made the change" }
ResultCode_d = { type = "real" }
NotATable = "string"

[[logsources]]
name = "logs-endpoint.events.*"
description = "Endpoint."
system = "elastic"

[logsources.columns]
"process.name" = { type = "keyword" }
"#,
        )
        .unwrap();
        let with: Vec<&DeclaredSource> = d.sources_with_columns("sentinel").collect();
        assert_eq!(with.len(), 1);
        assert_eq!(with[0].name, "Contoso_Audit_CL");
        assert_eq!(with[0].kind(), DatasetKind::Tables);
        assert_eq!(with[0].description.as_deref(), Some("Audit events."));
        assert_eq!(
            with[0].columns,
            [
                DeclaredColumn {
                    name: "Actor_s".into(),
                    type_name: Some("string".into()),
                    description: Some("UPN of the account that made the change".into()),
                },
                DeclaredColumn {
                    name: "ResultCode_d".into(),
                    type_name: Some("real".into()),
                    description: None,
                },
            ]
        );
        let elastic: Vec<&DeclaredSource> = d.sources_with_columns("elastic").collect();
        assert_eq!(elastic[0].columns[0].name, "process.name");
    }

    #[test]
    fn empty_and_invalid() {
        assert!(DeclaredDatasets::from_visibility("").unwrap().is_empty());
        assert!(
            DeclaredDatasets::from_visibility(
                "[[logsources]]\nname = \"  \"\ndescription = \"x\"\nsystem = \"sentinel\"\n"
            )
            .unwrap()
            .is_empty()
        );
        assert!(DeclaredDatasets::from_visibility("[[logsources]\n").is_err());
    }

    #[test]
    fn a_byte_order_mark_is_skipped() {
        let d = DeclaredDatasets::from_visibility(
            "\u{feff}[[logsources]]\nname = \"SigninLogs\"\ndescription = \"x\"\nsystem = \"sentinel\"\n",
        )
        .unwrap();
        assert_eq!(d.status("sentinel", "SigninLogs"), Declaration::Declared);
    }
}
