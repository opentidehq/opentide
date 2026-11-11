//! `validate` (UC-2.2, #817; `validation/session.py` and
//! `cli/services/validation.py`): every check over a loaded [`Workspace`],
//! reported as [`Diagnostic`]s, the one finding type the CLI, the SDK, MCP
//! and the language server share.
//!
//! | Check | Codes |
//! | --- | --- |
//! | `id-uniqueness` | `duplicate_id` |
//! | `uuid-format` | `invalid_uuid` |
//! | `schema` | `schema_validation`, `schema_missing`, `yaml_parse`, `missing_uuid`, `invalid_ref`, `vocab_unknown`, `config_enum_unknown`, `chaining_relation_unknown`, `external_id_in_rule`, `deployment_state_*`; warnings `deprecated_field`, `platform_not_enabled` |
//! | `configuration` | `missing_field`, `unknown_key`, `schema_validation`, `promotion_target_unknown`; warnings `asset_unknown` |
//! | `sharing-config` | `sharing.toml`'s codes |
//! | `queries` | the query engines' codes, from the host's [`QueryCheck`] (UC-2.5, #820) |
//! | every run | `nested_object_file` (warning), `scope_no_match` |
//!
//! Not here yet: the compile check (`compile_*`, the deploy payload's;
//! Phase 3, `opentide-compile`) and the online part of `cve`.

pub mod annotate;
pub mod objects;
pub mod scope;
pub mod states;

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;

use indexmap::IndexMap;
use opentide_schema::configuration::{self, Finding};
use opentide_schema::node::{Node, Value};
use opentide_schema::vocab::Vocabularies;
use rayon::prelude::*;
use serde::Serialize;

use crate::diagnostic::{ContextValue, Diagnostic, Severity};
use crate::fs::FileSystem;
use crate::index::Index;
use crate::workspace::Workspace;
use objects::{Graph, ObjectChecks, Subject};
pub use scope::{Scope, Selection};

/// One check `validate` can run (`ValidateCheck`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Check {
    /// `id-uniqueness`.
    IdUniqueness,
    /// `uuid-format`.
    UuidFormat,
    /// `schema`.
    Schema,
    /// `cve`.
    Cve,
    /// `sharing-config`.
    SharingConfig,
    /// `configuration`.
    Configuration,
    /// `queries`.
    Queries,
}

impl Check {
    /// Every check, in the order `--check` lists them.
    pub const ALL: [Self; 7] = [
        Self::IdUniqueness,
        Self::UuidFormat,
        Self::Schema,
        Self::Cve,
        Self::SharingConfig,
        Self::Configuration,
        Self::Queries,
    ];

    /// The default checks, in the order `checks` lists them.
    pub const DEFAULT: [Self; 5] = [
        Self::IdUniqueness,
        Self::UuidFormat,
        Self::Schema,
        Self::Configuration,
        Self::Queries,
    ];

    /// The name `--check` takes.
    pub const fn name(self) -> &'static str {
        match self {
            Self::IdUniqueness => "id-uniqueness",
            Self::UuidFormat => "uuid-format",
            Self::Schema => "schema",
            Self::Cve => "cve",
            Self::SharingConfig => "sharing-config",
            Self::Configuration => "configuration",
            Self::Queries => "queries",
        }
    }

    /// The check `name` names.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|check| check.name() == name)
    }

    /// The codes of the findings that fail this check's status.
    fn issue_codes(self) -> &'static [&'static str] {
        match self {
            Self::IdUniqueness => &["duplicate_id"],
            Self::UuidFormat => &["invalid_uuid"],
            Self::Schema => &[
                "schema_validation",
                "schema_missing",
                "yaml_parse",
                "missing_uuid",
                "invalid_ref",
                "vocab_unknown",
                "config_enum_unknown",
                "chaining_relation_unknown",
                "external_id_in_rule",
                "external_id_shape",
                "deployment_state_uuid_mismatch",
                "deployment_state_platform",
                "deployment_state_shape",
            ],
            Self::Cve => &["invalid_cve"],
            Self::Queries => &["engine_unavailable", "yaml_parse", "scope_no_match"],
            Self::SharingConfig => &[
                "missing_field",
                "duplicate_name",
                "name_invalid",
                "unknown_key",
                "max_tlp_unknown",
                "organisation_uuid_invalid",
                "object_type_unknown",
                "sharing_directory",
                "config_parse",
                "url_invalid",
                "invalid_value",
                "rule_status_unknown",
            ],
            Self::Configuration => &[
                "missing_field",
                "unknown_key",
                "schema_validation",
                "promotion_target_unknown",
                "config_parse",
                "retired_configuration_file",
            ],
        }
    }
}

/// Every code a `validate` finding can carry (`VALIDATION_CODES`): each
/// check's issue and warning codes, `scope_no_match` and
/// `nested_object_file`, sorted. The engine's own query codes are not here.
pub const VALIDATION_CODES: &[&str] = &[
    "api_key_literal",
    "asset_unknown",
    "chaining_relation_unknown",
    "config_enum_unknown",
    "config_parse",
    "cve_lookup_unavailable",
    "deployment_state_platform",
    "deployment_state_shape",
    "deployment_state_uuid_mismatch",
    "deprecated_field",
    "duplicate_id",
    "duplicate_name",
    "engine_unavailable",
    "external_id_in_rule",
    "external_id_shape",
    "invalid_cve",
    "invalid_ref",
    "invalid_uuid",
    "invalid_value",
    "max_tlp_unknown",
    "missing_field",
    "missing_uuid",
    "name_invalid",
    "nested_object_file",
    "not_a_configuration_file",
    "object_type_unknown",
    "organisation_uuid_invalid",
    "platform_not_enabled",
    "promotion_target_unknown",
    "retired_configuration_file",
    "rule_status_unknown",
    "schema_missing",
    "schema_validation",
    "scope_no_match",
    "sharing_directory",
    "unknown_connector",
    "unknown_key",
    "url_invalid",
    "vocab_unknown",
    "yaml_parse",
];

/// `--queries`: how the queries check reports a query the engine rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueriesMode {
    /// As an error (the default).
    #[default]
    Error,
    /// As a warning: the run passes unless `--strict`.
    Warn,
    /// Not checked.
    Off,
}

/// An object whose queries the queries check reads.
#[derive(Debug, Clone)]
pub struct QueryObject<'a> {
    /// Its file.
    pub path: &'a Path,
    /// Its UUID.
    pub uuid: &'a str,
    /// Its family.
    pub family: &'a str,
    /// Its text, as the index read it (after a byte-order mark).
    pub source: &'a str,
}

/// What the queries check found.
#[derive(Debug, Clone, Default)]
pub struct QueryFindings {
    /// Errors (warnings under `--queries warn`), each placed by the engine
    /// (`line` set) and with `context.source` `engine`.
    pub errors: Vec<Diagnostic>,
    /// Warnings.
    pub warnings: Vec<Diagnostic>,
    /// How many queries were checked.
    pub queries: usize,
}

/// The offline query analysis, which the host supplies: the query engines
/// sit above this crate (`opentide-cli`'s `queries::EngineQueries`, UC-2.5,
/// #820).
pub trait QueryCheck: Sync {
    /// The findings of every query `objects` carry, in `ws` (its root, its
    /// configuration files): errors placed by the engine (`line` set), as
    /// warnings when `as_warnings`.
    fn check(
        &self,
        ws: &Workspace,
        objects: &[QueryObject<'_>],
        as_warnings: bool,
    ) -> QueryFindings;
}

/// What a `validate` run does.
#[derive(Clone, Copy, Default)]
pub struct Options<'a> {
    /// `--check`: one check, else the defaults.
    pub check: Option<Check>,
    /// `--file`, `--uuid`, `--type`.
    pub selection: Option<&'a Selection>,
    /// `--strict`.
    pub strict: bool,
    /// `--queries`.
    pub queries: QueriesMode,
    /// The query analysis; without one the queries check reports nothing.
    pub query_check: Option<&'a dyn QueryCheck>,
}

impl std::fmt::Debug for Options<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("check", &self.check)
            .field("selection", &self.selection)
            .field("strict", &self.strict)
            .field("queries", &self.queries)
            .field("query_check", &self.query_check.is_some())
            .finish()
    }
}

/// The report's `stats`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Stats {
    /// Objects the object checks read.
    pub objects_checked: usize,
    /// Whether the objects were checked on several threads.
    pub parallel: bool,
    /// The most threads either phase used.
    pub workers: usize,
    /// Threads of the object checks (0: one thread).
    pub object_workers: usize,
    /// Threads of the UUID scan.
    pub id_workers: usize,
    /// Queries the queries check read, when it ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queries_checked: Option<usize>,
    /// Wall time, in milliseconds.
    pub wall_ms: f64,
}

/// The report: `validate --json`'s `report`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// No error.
    pub ok: bool,
    /// The errors, sorted by file, line, field, object, code and message.
    pub issues: Vec<Diagnostic>,
    /// The warnings, in the order the checks found them.
    pub warnings: Vec<Diagnostic>,
    /// What the run did.
    pub stats: Stats,
}

/// The counts behind the outcome line (`summary`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Objects checked.
    pub objects: usize,
    /// Errors.
    pub errors: usize,
    /// Warnings.
    pub warnings: usize,
    /// Files with an error.
    pub files: usize,
    /// Files with a warning.
    pub warning_files: usize,
    /// Queries checked, when the queries check ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queries: Option<usize>,
    /// Findings `validate --fix` would fix (safe fixes).
    pub fixable: usize,
}

/// Warning codes `--strict` reports without failing.
pub const STRICT_EXEMPT_WARNINGS: [&str; 1] = ["platform_not_enabled"];

/// A `validate` run's result.
#[derive(Debug, Clone)]
pub struct Validation {
    /// Each check run, with `passed` or `failed`, in the order `checks`
    /// lists them.
    pub checks: Vec<(Check, &'static str)>,
    /// The report.
    pub report: Report,
    /// The counts.
    pub summary: Summary,
    /// Whether the run fails: an error, or a warning that is not exempt
    /// under `--strict`.
    pub failed: bool,
    /// Whether a warning that `--strict` would count was reported.
    pub warned: bool,
}

impl Validation {
    /// The process exit code: 1 when the run fails.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.failed)
    }

    /// `checks`, as `validate --json` writes it.
    pub fn checks_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (check, status) in &self.checks {
            map.insert(
                check.name().to_owned(),
                serde_json::json!({"check": check.name(), "status": status}),
            );
        }
        serde_json::Value::Object(map)
    }
}

/// Python's `resolve_worker_count`: no threads under 32 items, else up to 8.
fn workers(items: usize) -> usize {
    if items < 32 { 0 } else { items.min(8) }
}

/// One UUID written in an object file (`_IdScanRow`).
struct IdRow<'a> {
    path: &'a Path,
    family: &'a str,
    uuid: String,
    name: String,
    field_path: Vec<String>,
}

fn id_rows(index: &Index) -> Vec<IdRow<'_>> {
    let mut rows = Vec::new();
    for source in &index.sources {
        let Some(root) = source.document.root() else {
            continue;
        };
        let name = root
            .get("name")
            .map_or_else(String::new, |n| n.value.to_string());
        let uuid = root
            .get("metadata")
            .filter(|m| matches!(m.value, Value::Map(_)))
            .and_then(|m| m.get("uuid"))
            .filter(|uuid| crate::index::truthy(uuid));
        if let Some(uuid) = uuid {
            rows.push(IdRow {
                path: &source.path,
                family: &source.family,
                uuid: uuid.value.to_string(),
                name,
                field_path: vec!["metadata".to_owned(), "uuid".to_owned()],
            });
        }
        if source.family == "objective" {
            let signals = root
                .get("objective")
                .filter(|o| matches!(o.value, Value::Map(_)))
                .and_then(|o| o.get("signals"));
            if let Some(Value::Seq(signals)) = signals.map(|s| &s.value) {
                for (position, signal) in signals.iter().enumerate() {
                    if !matches!(signal.value, Value::Map(_)) {
                        continue;
                    }
                    if let Some(uuid) = signal.get("uuid").filter(|u| crate::index::truthy(u)) {
                        rows.push(IdRow {
                            path: &source.path,
                            family: "signal",
                            uuid: uuid.value.to_string(),
                            name: signal
                                .get("name")
                                .map_or_else(String::new, |n| n.value.to_string()),
                            field_path: vec![
                                "objective".to_owned(),
                                "signals".to_owned(),
                                position.to_string(),
                                "uuid".to_owned(),
                            ],
                        });
                    }
                }
            }
        }
    }
    rows
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `duplicate_id`: one per UUID written again, on the later file, naming
/// the first (`_merge_id_duplicates`).
fn id_uniqueness(index: &Index, scope: &Scope, ws: &Workspace) -> Vec<Diagnostic> {
    let fs = ws.fs().as_ref();
    let rows = id_rows(index);
    let mut first: IndexMap<&str, &IdRow<'_>> = IndexMap::new();
    let mut out = Vec::new();
    for row in &rows {
        let Some(original) = first.get(row.uuid.as_str()).copied() else {
            first.insert(row.uuid.as_str(), row);
            continue;
        };
        let in_scope = scope.is_full()
            || !scope.has_targets()
            || scope
                .targets()
                .iter()
                .any(|t| *t == row.uuid || *t == original.uuid)
            || [row.path, original.path]
                .iter()
                .any(|path| scope.matches_file(fs, path));
        if !in_scope {
            continue;
        }
        let mut origin = IndexMap::new();
        origin.insert(
            "name".to_owned(),
            ContextValue::from(original.name.as_str()),
        );
        origin.insert(
            "file_name".to_owned(),
            ContextValue::from(file_name(original.path)),
        );
        origin.insert(
            "file_path".to_owned(),
            ContextValue::from(original.path.to_string_lossy().into_owned()),
        );
        origin.insert(
            "field_path".to_owned(),
            ContextValue::from(original.field_path.clone()),
        );
        out.push(
            Diagnostic::error(
                "duplicate_id",
                format!(
                    "Duplicated ID {} on {} @ {}; already used by {} @ {}",
                    row.uuid,
                    opentide_schema::vocab::quote(&row.name),
                    file_name(row.path),
                    opentide_schema::vocab::quote(&original.name),
                    file_name(original.path)
                ),
            )
            .object(row.uuid.clone(), row.family)
            .file(row.path)
            .at(row.field_path.clone())
            .with("value", row.uuid.as_str())
            .with("original", ContextValue::Map(origin)),
        );
    }
    out
}

/// A configuration finding as a diagnostic (`object_type` `configuration`).
fn configuration_diagnostic(finding: Finding) -> Diagnostic {
    let severity = if finding.severity == configuration::Severity::Warning {
        Severity::Warning
    } else {
        Severity::Error
    };
    let mut diagnostic = Diagnostic::new(finding.code, severity, finding.message)
        .object("", "configuration")
        .at(finding.field_path);
    diagnostic.file_path = finding.file_path.map(PathBuf::from);
    for (key, value) in finding.context {
        diagnostic.context.insert(key, ContextValue::from(value));
    }
    diagnostic
}

/// The platforms deploy sends to, and the keys that misspell `enabled`
/// (`enabled_systems`, `misspelled_enabled_key`).
fn enabled_platforms(
    platforms: Option<&Node>,
) -> (BTreeSet<String>, std::collections::HashMap<String, String>) {
    let mut enabled = BTreeSet::new();
    let mut misspelled = std::collections::HashMap::new();
    for platform in objects::PLATFORMS {
        let Some(block) = platforms
            .and_then(|p| p.get(platform))
            .and_then(|config| config.get("platform"))
        else {
            continue;
        };
        if matches!(
            block.get("enabled").map(|e| &e.value),
            Some(Value::Bool(true))
        ) {
            enabled.insert(platform.to_owned());
        }
        if let Value::Map(entries) = &block.value {
            for entry in entries {
                let key = entry.key.value.to_string();
                if key != "enabled"
                    && (key.to_lowercase() == "enabled"
                        || opentide_core::suggest::closest(&key.to_lowercase(), ["enabled"])
                            .is_some())
                {
                    misspelled.insert(platform.to_owned(), key);
                    break;
                }
            }
        }
    }
    (enabled, misspelled)
}

/// Python's sort key of an error (`sort_issues`).
fn sort_key(issue: &Diagnostic) -> (String, i64, &[String], &str, &str, &str) {
    (
        issue
            .file_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        issue
            .yaml_line
            .map_or(-1, |line| i64::try_from(line).unwrap_or(i64::MAX)),
        &issue.field_path,
        &issue.object_uuid,
        &issue.code,
        &issue.message,
    )
}

/// The message of a nested object file's warning.
fn nested_message(path: &str, folder: &str) -> String {
    format!(
        "{path} is in a subfolder of {folder} and is not an object instance: it is not indexed, \
         validated, shared, documented or deployed (opentide reads only files directly in \
         {folder}; see https://github.com/opentidehq/opentide/issues/584)"
    )
}

/// When the run started, where the target has a clock.
///
/// The browser build (wasm32-unknown-unknown, which the language server's
/// `opentide/analyze` reaches through [`validate`]) has none: std's
/// `Instant::now` panics there ("time not implemented"), which traps the
/// whole WebAssembly worker. Its runs report a `wall_ms` of 0.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn clock_start() -> Option<Instant> {
    Some(Instant::now())
}

/// The browser build has no clock: see the native [`clock_start`].
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn clock_start() -> Option<Instant> {
    None
}

/// Runs `validate` over `ws`.
#[expect(
    clippy::too_many_lines,
    reason = "the run's phases in the oracle's order (session.py run_validation), read top to bottom"
)]
pub fn validate(ws: &Workspace, options: &Options<'_>) -> Validation {
    let started = clock_start();
    let fs = ws.fs().as_ref();
    let index = ws.index();
    let root = ws.root().to_path_buf();
    let default_selection = Selection::default();
    let selection = options.selection.unwrap_or(&default_selection);
    let scope = Scope::narrow(fs, selection, &[root.clone(), ws.cwd().to_path_buf()]);
    let checks: BTreeSet<Check> = match options.check {
        Some(check) => BTreeSet::from([check]),
        None => Check::DEFAULT
            .into_iter()
            .filter(|check| *check != Check::Queries || options.queries != QueriesMode::Off)
            .collect(),
    };
    let has = |check: Check| checks.contains(&check);
    let resolved = &ws.configuration().resolved;

    let mut graph = Graph::new(index, Vocabularies::bundled(), resolved.get("deployment"));
    let listed = ListedPaths::new(fs, ws.links());
    let work: Vec<Subject<'_>> = index
        .objects
        .iter()
        .filter(|(family, _)| opentide_schema::vocab::OBJECT_TYPES.contains(&family.as_str()))
        .flat_map(|(_, objects)| objects.values())
        .filter(|object| {
            scope.includes_object_with(&object.uuid, &object.family, &object.path, || {
                listed.resolve(&object.path)
            })
        })
        .map(|object| Subject {
            uuid: &object.uuid,
            family: &object.family,
            path: &object.path,
            document: &object.document,
        })
        .collect();
    let object_workers = workers(work.len());
    let id_workers = if has(Check::IdUniqueness) {
        workers(index.sources.len() + index.load_errors.len())
    } else {
        0
    };

    let mut issues: Vec<Diagnostic> = Vec::new();
    let mut warnings: Vec<Diagnostic> = Vec::new();

    let reads_files = has(Check::Schema) || has(Check::Queries);
    let parse_issues: Vec<Diagnostic> = if reads_files {
        index
            .load_errors
            .iter()
            .filter(|error| {
                scope.is_full()
                    || (!scope.excludes_type(&error.family)
                        && (!scope.has_targets()
                            || scope
                                .matches_file_with(&error.path, || listed.resolve(&error.path))))
            })
            .map(|error| {
                Diagnostic::error(error.code, error.message())
                    .object("", error.family.as_str())
                    .file(&error.path)
            })
            .collect()
    } else {
        Vec::new()
    };
    issues.extend(parse_issues.iter().cloned());

    let object_checks = has(Check::UuidFormat) || has(Check::Schema);
    let scoped_checks = object_checks || has(Check::Queries);
    if scope.has_filter() && scoped_checks && work.is_empty() && parse_issues.is_empty() {
        issues.push(
            Diagnostic::error(
                "scope_no_match",
                "No objects matched the validation scope (check --file, --uuid, --type)",
            )
            .with("targets", scope.targets())
            .with("object_types", scope.object_types()),
        );
    } else if scoped_checks && scope.has_file_targets() {
        let selected: Vec<&Path> = work
            .iter()
            .map(|subject| subject.path)
            .chain(
                parse_issues
                    .iter()
                    .filter_map(|issue| issue.file_path.as_deref()),
            )
            .collect();
        for target in scope.unmatched_file_targets(fs, &selected) {
            issues.push(
                Diagnostic::error(
                    "scope_no_match",
                    format!(
                        "--file {} matched no object, so it was not validated",
                        opentide_schema::vocab::quote(&target)
                    ),
                )
                .with("targets", vec![target])
                .with("object_types", Vec::<String>::new()),
            );
        }
    }

    if has(Check::IdUniqueness) {
        issues.extend(id_uniqueness(index, &scope, ws));
    }

    for nested in &index.nested {
        if !scope.is_full() {
            if scope.excludes_type(&nested.family) {
                continue;
            }
            if scope.has_file_targets() && !scope.matches_file(fs, &nested.path) {
                continue;
            }
            if !scope.has_file_targets() && scope.object_types().is_empty() {
                continue;
            }
        }
        let shown = annotate::relative_path(fs, &nested.path, &root);
        let folder = annotate::relative_path(fs, &nested.folder, &root);
        warnings.push(
            Diagnostic::warning("nested_object_file", nested_message(&shown, &folder))
                .object("", nested.family.as_str())
                .file(&nested.path),
        );
    }

    if has(Check::SharingConfig) {
        for finding in sharing_findings(ws) {
            // `_sharing_config_issues`: no object type.
            let diagnostic = configuration_diagnostic(finding).object("", "");
            if diagnostic.is_error() {
                issues.push(diagnostic);
            } else {
                warnings.push(diagnostic);
            }
        }
    }

    if has(Check::Configuration) && (scope.is_full() || checks.len() == 1) {
        for finding in resolved.issues() {
            let diagnostic = configuration_diagnostic(finding);
            if diagnostic.is_error() {
                issues.push(diagnostic);
            } else {
                warnings.push(diagnostic);
            }
        }
    }

    if object_checks {
        if has(Check::Schema) && work.iter().any(|subject| subject.family == "rule") {
            let (enabled, misspelled) = enabled_platforms(resolved.get("platforms"));
            graph.enabled = Some(enabled);
            for platform in misspelled.keys() {
                let file = root
                    .join(".opentide/configurations/platforms")
                    .join(format!("{platform}.toml"));
                let shown = if fs.is_file(&file) {
                    annotate::relative_path(fs, &file, &root)
                } else {
                    format!(".opentide/configurations/platforms/{platform}.toml")
                };
                graph.platform_files.insert(platform.clone(), shown);
            }
            graph.misspelled_enabled = misspelled;
        }
        let checks = ObjectChecks {
            uuid_format: has(Check::UuidFormat),
            schema: has(Check::Schema),
            check_shard: !scope.is_full(),
        };
        let found: Vec<objects::Found> = work
            .par_iter()
            .map(|subject| objects::check_object(subject, &graph, checks, fs, &root))
            .collect();
        for one in found {
            issues.extend(one.issues);
            warnings.extend(one.warnings);
        }
        // Every file that writes an invalid UUID is reported, also one whose
        // object a later file with the same UUID displaced (KG-04).
        if checks.uuid_format {
            let uuid_only = ObjectChecks {
                uuid_format: true,
                schema: false,
                check_shard: false,
            };
            for duplicate in &index.duplicates {
                if !scope.includes_object_with(
                    &duplicate.uuid,
                    &duplicate.family,
                    &duplicate.path,
                    || listed.resolve(&duplicate.path),
                ) {
                    continue;
                }
                let subject = Subject {
                    uuid: &duplicate.uuid,
                    family: &duplicate.family,
                    path: &duplicate.path,
                    document: &duplicate.document,
                };
                issues.extend(objects::check_object(&subject, &graph, uuid_only, fs, &root).issues);
            }
        }
    }
    let mut stats = Stats {
        objects_checked: if object_checks || has(Check::Queries) {
            work.len()
        } else {
            0
        },
        parallel: object_workers > 0 || id_workers > 0,
        workers: object_workers.max(id_workers),
        object_workers,
        id_workers,
        queries_checked: None,
        wall_ms: 0.0,
    };

    if has(Check::Queries) {
        let objects: Vec<QueryObject<'_>> = work
            .iter()
            .map(|subject| QueryObject {
                path: subject.path,
                uuid: subject.uuid,
                family: subject.family,
                source: subject.document.source(),
            })
            .collect();
        if let Some(query_check) = options.query_check {
            let found = query_check.check(ws, &objects, options.queries == QueriesMode::Warn);
            // A query the schema check rejects (an empty one) is its finding, once.
            let rejected: BTreeSet<(Option<PathBuf>, Vec<String>)> = issues
                .iter()
                .filter(|issue| issue.field_path.last().is_some_and(|last| last == "query"))
                .map(query_place)
                .collect();
            issues.extend(
                found
                    .errors
                    .into_iter()
                    .filter(|issue| !rejected.contains(&query_place(issue))),
            );
            warnings.extend(
                found
                    .warnings
                    .into_iter()
                    .filter(|issue| !rejected.contains(&query_place(issue))),
            );
            stats.queries_checked = Some(found.queries);
        }
    }

    if has(Check::Schema) && scope.is_full() {
        for error in states::scan(fs, &root) {
            let shard = error
                .path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut diagnostic = Diagnostic::error(error.code, error.message).with("shard", shard);
            diagnostic.file_path = error.path;
            issues.push(diagnostic);
        }
    }

    issues.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    let mut sources = annotate::Sources::new(fs, index);
    annotate::annotate(&mut issues, &mut sources, &root);
    annotate::annotate(&mut warnings, &mut sources, &root);
    stats.wall_ms = started.map_or(0.0, |started| {
        (started.elapsed().as_secs_f64() * 100_000.0).round() / 100.0
    });

    let report = Report {
        ok: issues.is_empty(),
        issues,
        warnings,
        stats,
    };
    let check_list: Vec<(Check, &'static str)> = match options.check {
        Some(check) => vec![check],
        None => Check::DEFAULT
            .into_iter()
            .filter(|check| checks.contains(check))
            .collect(),
    }
    .into_iter()
    .map(|check| (check, status(&report, check)))
    .collect();
    let warned = report
        .warnings
        .iter()
        .any(|warning| !STRICT_EXEMPT_WARNINGS.contains(&warning.code.as_str()));
    let failed = !report.ok || (options.strict && warned);
    let files_with = |severity: Severity| {
        report
            .issues
            .iter()
            .chain(&report.warnings)
            .filter(|item| item.severity == severity)
            .filter_map(|item| item.path.as_deref())
            .collect::<BTreeSet<_>>()
            .len()
    };
    let summary = Summary {
        objects: report.stats.objects_checked,
        errors: report.issues.len(),
        warnings: report.warnings.len(),
        files: files_with(Severity::Error),
        warning_files: files_with(Severity::Warning),
        queries: report.stats.queries_checked,
        // What `--fix` would apply: the safe fixes that still fit their file
        // (`plan_fixes`), not every finding that offers one.
        fixable: crate::fix::plan(fs, report.issues.iter().chain(&report.warnings))
            .changes
            .len(),
    };
    Validation {
        checks: check_list,
        report,
        summary,
        failed,
        warned,
    }
}

/// The object files discovery listed, resolved as [`FileSystem::resolve`]
/// resolves them, without resolving each path component by component: such
/// a file is in its object folder, so it resolves to its folder resolved
/// (once per folder) and its name, or, when it is a symbolic link, to what
/// the load resolved it to. Selecting one file of a large workspace then
/// resolves a handful of folders, not every object's path.
struct ListedPaths<'a> {
    fs: &'a dyn FileSystem,
    links: &'a HashMap<PathBuf, PathBuf>,
    folders: RefCell<HashMap<PathBuf, PathBuf>>,
}

impl<'a> ListedPaths<'a> {
    fn new(fs: &'a dyn FileSystem, links: &'a HashMap<PathBuf, PathBuf>) -> Self {
        Self {
            fs,
            links,
            folders: RefCell::default(),
        }
    }

    /// `path` (a listed object file) resolved.
    fn resolve(&self, path: &Path) -> PathBuf {
        if let Some(target) = self.links.get(path) {
            return target.clone();
        }
        let (Some(folder), Some(name)) = (path.parent(), path.file_name()) else {
            return self.fs.resolve(path);
        };
        if folder.as_os_str().is_empty() {
            return self.fs.resolve(path);
        }
        self.folders
            .borrow_mut()
            .entry(folder.to_path_buf())
            .or_insert_with(|| self.fs.resolve(folder))
            .join(name)
    }
}

/// Which query a finding is about: a platform block, or the query's own
/// path elsewhere (a hunt).
fn query_place(issue: &Diagnostic) -> (Option<PathBuf>, Vec<String>) {
    let mut path = issue.field_path.clone();
    if path.len() == 3 && path[0] == "configurations" {
        path.truncate(2);
    }
    (issue.file_path.clone(), path)
}

/// The findings of `validate --check sharing-config` (`load_sharing`): the
/// bundled `sharing.toml`, then each configuration folder's.
fn sharing_findings(ws: &Workspace) -> Vec<Finding> {
    let fs = ws.fs().as_ref();
    let mut layers = vec![(
        "<bundled>".to_owned(),
        configuration::bundled::text("sharing.toml").map(str::to_owned),
        false,
    )];
    for folder in &ws.configuration().folders {
        if !fs.is_dir(folder) {
            continue;
        }
        let file = folder.join("sharing.toml");
        let text = fs
            .is_file(&file)
            .then(|| fs.read(&file).ok())
            .flatten()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        layers.push((
            folder.to_string_lossy().into_owned(),
            text,
            fs.is_dir(&folder.join("sharing")),
        ));
    }
    let statuses = ws
        .configuration()
        .resolved
        .get("deployment")
        .map(configuration::checks::status_names)
        .unwrap_or_else(configuration::checks::bundled_status_names);
    configuration::checks::sharing_config_issues(&layers, &statuses)
}

/// Whether a check's own findings fail it (`_status_for_check`).
fn status(report: &Report, check: Check) -> &'static str {
    let failed = match check {
        Check::Configuration => report
            .issues
            .iter()
            .any(|issue| issue.object_type == "configuration"),
        Check::Queries => report.issues.iter().any(|issue| {
            issue.context.get("source").and_then(ContextValue::as_str) == Some("engine")
                || check.issue_codes().contains(&issue.code.as_str())
        }),
        _ => {
            let codes = check.issue_codes();
            report.issues.iter().any(|issue| {
                (codes.contains(&issue.code.as_str()) && issue.object_type != "configuration")
                    || (matches!(check, Check::UuidFormat | Check::Schema)
                        && issue.code == "scope_no_match")
            })
        }
    };
    if failed { "failed" } else { "passed" }
}

impl Workspace {
    /// Runs `validate` ([`validate`]).
    pub fn validate(&self, options: &Options<'_>) -> Validation {
        validate(self, options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_codes_hold_every_checks_codes_sorted() {
        for check in Check::ALL {
            for code in check.issue_codes() {
                assert!(VALIDATION_CODES.contains(code), "{code}");
            }
        }
        for code in STRICT_EXEMPT_WARNINGS {
            assert!(VALIDATION_CODES.contains(&code), "{code}");
        }
        assert!(VALIDATION_CODES.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
