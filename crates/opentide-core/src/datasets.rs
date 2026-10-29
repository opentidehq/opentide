//! Datasets a workspace declares in `visibility.toml` (tables, indexes,
//! sourcetypes, macros, index patterns, data views), per platform.
//!
//! opentide writes them to `datasets.json` in the workspace catalog
//! (`.opentide/lsp/catalogs/generated/`) and a host installs them for the
//! process ([`install`]). The query engines ask [`current`] whether a name a
//! query reads is declared. Checking is opt-in per platform and kind: a
//! workspace that declares no index for Splunk never gets a warning about an
//! index.
//!
//! Declarations are per `system`, so a Splunk index never makes a Sentinel
//! table known.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

/// A kind of dataset a log source can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DatasetKind {
    /// KQL tables and functions (`sentinel`, `defender_for_endpoint`).
    Tables,
    /// Splunk `index=`.
    Indexes,
    /// Splunk `sourcetype=` and `source=`.
    Sourcetypes,
    /// Splunk macros (`` `wineventlog_security` ``).
    Macros,
    /// Elastic index patterns and data streams (`index`, ES|QL `FROM`).
    Indices,
    /// Elastic data views (`data_view_id`).
    DataViews,
    /// Elastic indices a log source marks as following ECS (`ecs = true`):
    /// the field checks apply to them as to `logs-*` integration data streams.
    EcsIndices,
}

impl DatasetKind {
    /// The key in `visibility.toml` and `datasets.json`.
    pub fn key(self) -> &'static str {
        match self {
            Self::Tables => "tables",
            Self::Indexes => "indexes",
            Self::Sourcetypes => "sourcetypes",
            Self::Macros => "macros",
            Self::Indices => "indices",
            Self::DataViews => "data_views",
            Self::EcsIndices => "ecs_indices",
        }
    }

    /// Splunk names match without regard to case; KQL tables and Elastic
    /// indices do not.
    fn case_insensitive(self) -> bool {
        matches!(self, Self::Indexes | Self::Sourcetypes | Self::Macros)
    }
}

/// What the workspace says about one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declaration {
    /// The workspace declares nothing of this kind for the platform, so the
    /// name is not checked.
    Unchecked,
    /// A declared name, or a declared pattern, covers it.
    Declared,
    /// The workspace declares names of this kind for the platform, and none
    /// covers this one.
    Undeclared,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DatasetsFile {
    #[serde(default)]
    platforms: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

/// The declared datasets, by platform (`sentinel`, `splunk`, ...) and kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclaredDatasets {
    platforms: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl DeclaredDatasets {
    /// `datasets.json` as opentide writes it:
    ///
    /// ```json
    /// {"platforms": {"sentinel": {"tables": ["NTANetAnalytics", "*_CL"]},
    ///                "splunk": {"indexes": ["wineventlog"]}}}
    /// ```
    ///
    /// Other top-level keys (`opentide`, `generator`) are labels and ignored.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: DatasetsFile = serde_json::from_str(text).map_err(|err| err.to_string())?;
        let mut platforms = BTreeMap::new();
        for (platform, kinds) in file.platforms {
            let kinds: BTreeMap<String, Vec<String>> = kinds
                .into_iter()
                .map(|(kind, names)| {
                    let names = names
                        .into_iter()
                        .map(|n| n.trim().to_string())
                        .filter(|n| !n.is_empty())
                        .collect::<Vec<_>>();
                    (kind, names)
                })
                .filter(|(_, names)| !names.is_empty())
                .collect();
            if !kinds.is_empty() {
                platforms.insert(platform, kinds);
            }
        }
        Ok(Self { platforms })
    }

    /// Declarations built in code, for tests and hosts that have them already.
    pub fn from_names<'a>(
        entries: impl IntoIterator<Item = (&'a str, DatasetKind, &'a [&'a str])>,
    ) -> Self {
        let mut platforms: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        for (platform, kind, names) in entries {
            if names.is_empty() {
                continue;
            }
            platforms
                .entry(platform.to_string())
                .or_default()
                .entry(kind.key().to_string())
                .or_default()
                .extend(names.iter().map(|n| n.to_string()));
        }
        Self { platforms }
    }

    /// Nothing declared for any platform.
    pub fn is_empty(&self) -> bool {
        self.platforms.is_empty()
    }

    /// The names (and patterns) declared for `platform` and `kind`.
    pub fn names(&self, platform: &str, kind: DatasetKind) -> &[String] {
        self.platforms
            .get(platform)
            .and_then(|kinds| kinds.get(kind.key()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Whether the workspace declares any name of `kind` for `platform`: the
    /// opt-in for warning about undeclared ones.
    pub fn declares(&self, platform: &str, kind: DatasetKind) -> bool {
        !self.names(platform, kind).is_empty()
    }

    /// Whether `name`, as a query reads it, is declared for `platform`.
    ///
    /// A declared name may hold `*` (`*_CL`, `logs-*`), which matches any run
    /// of characters. A name the query reads may hold `*` too (an index
    /// pattern, `index=win*`): it is declared when a declared pattern covers
    /// it (`logs-*` covers `logs-azure.*`) or when it reaches a declared name
    /// (`win*` reaches `wineventlog`).
    pub fn status(&self, platform: &str, kind: DatasetKind, name: &str) -> Declaration {
        let declared = self.names(platform, kind);
        if declared.is_empty() {
            return Declaration::Unchecked;
        }
        let fold = kind.case_insensitive();
        let norm = |s: &str| {
            if fold {
                s.to_ascii_lowercase()
            } else {
                s.to_string()
            }
        };
        let used = norm(name.trim());
        let covered = declared.iter().any(|d| {
            let d = norm(d);
            glob_matches(&d, &used) || (used.contains('*') && glob_matches(&used, &d))
        });
        if covered {
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
    fn opt_in_per_platform_and_kind() {
        let d = DeclaredDatasets::parse(
            r#"{"opentide": "0.20.0", "platforms": {
                "sentinel": {"tables": ["NTANetAnalytics", "*_CL"]},
                "splunk": {"indexes": ["WinEventLog"], "macros": []},
                "elastic": {"indices": ["logs-*"]}
            }}"#,
        )
        .unwrap();
        use DatasetKind::*;
        use Declaration::*;
        assert_eq!(d.status("sentinel", Tables, "NTANetAnalytics"), Declared);
        assert_eq!(d.status("sentinel", Tables, "Custom_CL"), Declared);
        assert_eq!(d.status("sentinel", Tables, "SigninLogs"), Undeclared);
        assert_eq!(d.status("sentinel", Tables, "ntanetanalytics"), Undeclared);
        // Another platform's names never count.
        assert_eq!(
            d.status("defender_for_endpoint", Tables, "NTANetAnalytics"),
            Unchecked
        );
        assert_eq!(d.status("splunk", Indexes, "wineventlog"), Declared);
        assert_eq!(d.status("splunk", Indexes, "win*"), Declared);
        assert_eq!(d.status("splunk", Indexes, "main"), Undeclared);
        // An empty list is not an opt-in.
        assert_eq!(d.status("splunk", Macros, "anything"), Unchecked);
        assert_eq!(d.status("splunk", Sourcetypes, "anything"), Unchecked);
        assert_eq!(
            d.status("elastic", Indices, "logs-azure.signinlogs-*"),
            Declared
        );
        assert_eq!(d.status("elastic", Indices, "winlogbeat-*"), Undeclared);
        assert_eq!(d.status("elastic", DataViews, "x"), Unchecked);
    }

    #[test]
    fn empty_and_invalid() {
        assert!(DeclaredDatasets::parse("{}").unwrap().is_empty());
        assert!(
            DeclaredDatasets::parse(r#"{"platforms": {"sentinel": {"tables": []}}}"#)
                .unwrap()
                .is_empty()
        );
        assert!(DeclaredDatasets::parse("[").is_err());
        assert!(
            DeclaredDatasets::parse(r#"{"platforms": {"sentinel": {"tables": "x"}}}"#).is_err()
        );
    }
}
