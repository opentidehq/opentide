//! `validate` (UC-2.2, #817): every check over a loaded [`Workspace`],
//! reported as [`Diagnostic`]s, the one finding type the CLI, the SDK, MCP
//! and the language server share.
//!
//! | Check | Codes |
//! | --- | --- |
//! | `id-uniqueness` | `duplicate_id` |
//! | `uuid-format` | `invalid_uuid` |
//! | `schema` | `schema_validation`, `schema_missing`, `yaml_parse`, `missing_uuid`, `invalid_ref`, `vocab_unknown`, `config_enum_unknown`, `chaining_relation_unknown`, `external_id_in_rule`, `exabeam_name_duplicate`, `google_secops_name_duplicate`, `deployment_state_*`, and every platform model's constraint code (`opentide_schema::objects::platform::constraint_codes`); warnings `deprecated_field`, `platform_not_enabled` |
//! | `configuration` | `missing_field`, `unknown_key`, `schema_validation`, `promotion_target_unknown`; warnings `asset_unknown` |
//! | `sharing-config` | `sharing.toml`'s codes |
//! | `queries` | the query engines' codes, from the host's [`QueryCheck`] (UC-2.5, #820) |
//! | `schema`, once nothing else failed | `compile_missing_field`, `compile_invalid_value`, `compile_empty_block`, `compile_invalid_rule`, `compile_failed`, from the host's [`CompileCheck`] |
//! | every run | `nested_object_file` (warning), `scope_no_match`, `file_not_found` |
//!
//! The online part of `cve` asks the host's [`CveCheck`] (UC-4.4, #834);
//! without one it reports nothing. The compile check (#660; UC-2.2, #817)
//! compiles each rule a deploy would compile with the platforms' offline
//! compilers, which sit above this crate (`opentide-compile`'s
//! `validate::Compilers`): the host passes them as [`Options::compile_check`];
//! without them it reports nothing.

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
#[non_exhaustive]
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
                "exabeam_name_duplicate",
                "google_secops_name_duplicate",
                "deployment_state_uuid_mismatch",
                "deployment_state_platform",
                "deployment_state_shape",
            ],
            Self::Cve => &["invalid_cve"],
            Self::Queries => &[
                "engine_unavailable",
                "yaml_parse",
                "scope_no_match",
                "file_not_found",
            ],
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
/// check's issue and warning codes, `scope_no_match`, `file_not_found`,
/// `nested_object_file` and the [`STRICT_EXEMPT_WARNINGS`], sorted. The
/// engine's own query codes are not here.
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
    "exabeam_name_duplicate",
    "external_id_in_rule",
    "external_id_shape",
    "file_not_found",
    "google_secops_name_duplicate",
    "invalid_cve",
    "invalid_ref",
    "invalid_uuid",
    "invalid_value",
    "max_tlp_unknown",
    "microsoft_defender_custom_details_limit",
    "microsoft_defender_impacted_asset_identifier",
    "microsoft_defender_placeholder_limit",
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
#[non_exhaustive]
pub enum QueriesMode {
    /// As an error (the default).
    #[default]
    Error,
    /// As a warning: the run passes unless `--strict`.
    Warn,
    /// Not checked.
    Off,
}

impl QueriesMode {
    /// The mode as `--queries` takes it: `error`, `warn` or `off`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Off => "off",
        }
    }
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

/// What Vulnerability-Lookup answered for one identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CveLookup {
    /// It knows the identifier.
    Found,
    /// It does not.
    NotFound,
    /// It could not be asked: why.
    Unavailable(String),
}

/// The online CVE lookup, which the host supplies: the HTTP client sits
/// above this crate (`opentide-connectors`' `vulnerability`, UC-4.4, #834).
pub trait CveCheck: Sync {
    /// `text` as a canonical identifier (`CVE-2024-3094`), empty when blank
    /// (`canonicalize_identifier`).
    fn canonical(&self, text: &str) -> String;

    /// Whether Vulnerability-Lookup knows `id`, which threat `threat` names.
    fn lookup(&self, threat: &str, id: &str) -> CveLookup;
}

/// A rule the compile check reads.
#[derive(Debug, Clone, Copy)]
pub struct CompileRule<'a> {
    /// Its file.
    pub path: &'a Path,
    /// Its document's root mapping.
    pub root: &'a Node,
}

/// A rule a platform's offline compiler refuses (`compile_issues`): the
/// compiler's code, reason and hint, and the key at fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileFailure {
    /// The platform (`sentinel`).
    pub platform: String,
    /// `compile_missing_field`, `compile_invalid_value`, `compile_empty_block`,
    /// `compile_invalid_rule` or `compile_failed`.
    pub code: String,
    /// The reason, in the reader's words.
    pub message: String,
    /// What to do, when known.
    pub hint: Option<String>,
    /// The key at fault, from the rule's root; empty when the compiler names
    /// none (the finding is then the platform's block).
    pub field_path: Vec<String>,
}

/// The compile check (#660), which the host supplies: the platform compilers
/// sit above this crate (`opentide-compile`'s `validate::Compilers`, UC-2.2,
/// #817). What a deploy would compile must compile.
pub trait CompileCheck: Sync {
    /// For each of `rules`, in order, every platform of `enabled` with an
    /// offline compiler whose block's status deploys and whose compiler
    /// refuses the rule, by platform name.
    fn check(
        &self,
        ws: &Workspace,
        rules: &[CompileRule<'_>],
        enabled: &BTreeSet<String>,
    ) -> Vec<Vec<CompileFailure>>;
}

/// One finding of a plugin platform's own check of a rule's block
/// ([`PlatformConfigurations`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlatformFinding {
    /// Where, inside the block: keys and list indexes as strings.
    pub field_path: Vec<String>,
    /// One sentence.
    pub message: String,
    /// A warning rather than an error.
    pub warning: bool,
}

impl PlatformFinding {
    /// A finding at `field_path` inside the block: an error, or a warning
    /// when `warning` is set.
    pub fn new(field_path: Vec<String>, message: impl Into<String>, warning: bool) -> Self {
        Self {
            field_path,
            message: message.into(),
            warning,
        }
    }
}

/// The configuration blocks of platform plugins (UC-4.5, #835), which the
/// host checks with each plugin's own model: the plugins sit above this
/// crate (`opentide-connectors`, called through the Python binding).
///
/// A rule's `configurations.<platform>` block for a platform [`platforms`]
/// names is not an extra key: its findings are [`check`]'s, as
/// `schema_validation` findings at `configurations.<platform>.<path>`.
///
/// [`platforms`]: PlatformConfigurations::platforms
/// [`check`]: PlatformConfigurations::check
pub trait PlatformConfigurations: Sync {
    /// The plugin platforms whose blocks this check owns.
    fn platforms(&self) -> Vec<String>;
    /// The findings of *block*, the rule's block for *platform*, as JSON.
    fn check(&self, platform: &str, block: &serde_json::Value) -> Vec<PlatformFinding>;
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
    /// The CVE lookup; without one the cve check reports nothing.
    pub cve_check: Option<&'a dyn CveCheck>,
    /// The plugin platforms' block checks; without one a block of a
    /// platform that is not built in is an extra key.
    pub platform_configurations: Option<&'a dyn PlatformConfigurations>,
    /// The platform compilers (the compile check); without them nothing is
    /// compiled.
    pub compile_check: Option<&'a dyn CompileCheck>,
    /// Where a run that may stop keeps what it checked, so that the next
    /// run goes on from there (see [`Options::stop`]).
    pub memo: Option<&'a ObjectMemo>,
    /// Asked between batches of objects: when it returns `true` the run
    /// stops and [`validate_resumable`] returns `None`. What it checked is kept in `memo`; a run given
    /// the same memo, over the same workspace, then reports exactly what an
    /// uninterrupted run would. Without a `memo` it is not asked. The command
    /// line passes neither: its run never stops.
    pub stop: Option<&'a dyn Fn() -> bool>,
}

/// What a run that stopped ([`Options::stop`]) had checked: each object's
/// findings, by the object's file and UUID. It holds findings of one
/// workspace as it was: drop it when anything the checks read changed.
#[derive(Debug, Default)]
pub struct ObjectMemo {
    /// By file, then UUID: a lookup borrows the subject's path and UUID
    /// instead of allocating a key, and a hit clones an `Arc` under the lock,
    /// not the findings (#1945).
    found: std::sync::Mutex<MemoMap>,
}

/// [`ObjectMemo`]'s findings, by file and UUID.
type MemoMap = HashMap<PathBuf, HashMap<String, std::sync::Arc<objects::Found>>>;

impl ObjectMemo {
    /// How many objects it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.found
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(HashMap::len)
            .sum()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for Options<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("check", &self.check)
            .field("selection", &self.selection)
            .field("strict", &self.strict)
            .field("queries", &self.queries)
            .field("query_check", &self.query_check.is_some())
            .field("cve_check", &self.cve_check.is_some())
            .field(
                "platform_configurations",
                &self.platform_configurations.is_some(),
            )
            .field("compile_check", &self.compile_check.is_some())
            .field("memo", &self.memo.is_some())
            .field("stop", &self.stop.is_some())
            .finish()
    }
}

/// The report's `stats`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
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

/// Warning codes `--strict` reports without failing:
/// `platform_not_enabled`, and Microsoft Defender's advisories that wait on
/// a tenant probe (`docs/internal/microsoft-defender-tenant-test.md`):
/// `microsoft_defender_impacted_asset_identifier`, whose rule is Microsoft's
/// advice rather than something Graph is known to refuse (check 11), and
/// `microsoft_defender_custom_details_limit` and
/// `microsoft_defender_placeholder_limit`, limits Microsoft documents without
/// saying what Graph does past them (check 9, #1890).
///
/// A slice, not an array, so a code made exempt does not change its type.
pub const STRICT_EXEMPT_WARNINGS: &[&str] = &[
    "platform_not_enabled",
    opentide_core::codes::MICROSOFT_DEFENDER_IMPACTED_ASSET_IDENTIFIER,
    opentide_core::codes::MICROSOFT_DEFENDER_CUSTOM_DETAILS_LIMIT,
    opentide_core::codes::MICROSOFT_DEFENDER_PLACEHOLDER_LIMIT,
];

/// The object families `validate --type` takes.
pub const OBJECT_TYPES: [&str; 3] = ["rule", "threat", "objective"];

/// An option `validate` refuses before it runs, as the command line refuses
/// it: the usage failure's code, the option, the first value refused, and
/// the message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Refusal {
    /// The usage failure's code (`usage_invalid_choice`).
    pub code: &'static str,
    /// The option (`--type`).
    pub argument: &'static str,
    /// The first value refused.
    pub value: String,
    /// What is wrong and what to pass instead.
    pub message: String,
}

/// The `--type` values that name no object family, refused; `None` when
/// every value is one of [`OBJECT_TYPES`].
pub fn unknown_types(types: &[String]) -> Option<Refusal> {
    let mut unknown: Vec<&str> = types
        .iter()
        .map(String::as_str)
        .filter(|family| !OBJECT_TYPES.contains(family))
        .collect();
    unknown.sort_unstable();
    unknown.dedup();
    let first = (*unknown.first()?).to_owned();
    Some(Refusal {
        code: "usage_invalid_choice",
        argument: "--type",
        value: first,
        message: format!(
            "Unknown object type(s): {}. Choose rule, threat, or objective.",
            unknown.join(", ")
        ),
    })
}

/// A `validate` run's result. Read its fields; it gains fields in minor
/// releases (`refused`), so code outside this crate does not build one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Validation {
    /// Each check run, with `passed` or `failed`, in the order `checks`
    /// lists them.
    pub checks: Vec<(Check, &'static str)>,
    /// The errors and warnings found, and what the run did:
    /// `validate --json`'s `report`.
    pub report: Report,
    /// The counts.
    pub summary: Summary,
    /// Whether the run fails: an error, or a warning that is not exempt
    /// under `--strict`.
    pub failed: bool,
    /// Whether a warning that `--strict` would count was reported.
    pub warned: bool,
    /// The option the run refused before checking anything (an unknown
    /// `--type`), as the command line refuses it; `None` when it ran.
    pub refused: Option<Refusal>,
}

impl Validation {
    /// The process exit code: 1 when the run fails, 2 when it refused an
    /// option, as the command line's usage error.
    pub fn exit_code(&self) -> i32 {
        if self.refused.is_some() {
            return 2;
        }
        i32::from(self.failed)
    }

    /// A run that checked nothing: `refusal` says why.
    fn refusing(refusal: Refusal) -> Self {
        Self::empty(Some(refusal))
    }

    fn empty(refused: Option<Refusal>) -> Self {
        Self {
            checks: Vec::new(),
            report: Report {
                ok: false,
                issues: Vec::new(),
                warnings: Vec::new(),
                stats: Stats {
                    objects_checked: 0,
                    parallel: false,
                    workers: 0,
                    object_workers: 0,
                    id_workers: 0,
                    queries_checked: None,
                    wall_ms: 0.0,
                },
            },
            summary: Summary {
                objects: 0,
                errors: 0,
                warnings: 0,
                files: 0,
                warning_files: 0,
                queries: None,
                fixable: 0,
            },
            failed: true,
            warned: false,
            refused,
        }
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

/// The threads a phase over `items` runs on: one per available core, no
/// more than there are items; `0` when it runs on one thread (one core, or
/// at most one item).
fn workers(items: usize) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    if cores < 2 || items < 2 {
        0
    } else {
        items.min(cores)
    }
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
            .filter(|uuid| crate::index::holds_name(uuid));
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
                    if let Some(uuid) = signal.get("uuid").filter(|u| crate::index::holds_name(u)) {
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

/// `graylog_title_duplicate`: each rule in scope whose enabled Graylog block
/// resolves to the event definition title of another rule's
/// (`graylog_title_issues`): Graylog's alert list cannot tell them apart.
///
/// The titles are grouped once (`graylog::Titles`) and each rule found by its
/// UUID: a scan of every rule per rule was quadratic (#1945).
fn title_duplicates(index: &Index, work: &[Subject<'_>]) -> Vec<Diagnostic> {
    use opentide_schema::objects::platform::graylog::{
        Titles, definition_title, title_duplicate_message,
    };
    let Some(rules) = index.objects.get("rule") else {
        return Vec::new();
    };
    let all: Vec<(&str, &Node)> = rules
        .iter()
        .filter_map(|(uuid, object)| Some((uuid.as_str(), object.root()?)))
        .collect();
    cross_rule_steps(all.len());
    let titles = Titles::new(&all);
    work.iter()
        .filter(|subject| subject.family == "rule")
        .filter_map(|subject| {
            cross_rule_steps(1);
            let root = rules.get(subject.uuid)?.root()?;
            let title = definition_title(root)?;
            let others = titles.duplicates(subject.uuid, title);
            if others.is_empty() {
                return None;
            }
            let (message, suggestion) = title_duplicate_message(title, &others);
            let mut diagnostic = Diagnostic::warning("graylog_title_duplicate", message)
                .object(subject.uuid, "rule")
                .file(subject.path)
                .at(["configurations".to_owned(), "graylog".to_owned()])
                .suggest(Some(suggestion))
                .with("value", title);
            diagnostic.yaml_line = subject.document.locator().yaml_line(&diagnostic.field_path);
            Some(diagnostic)
        })
        .collect()
}

thread_local! {
    /// [`cross_rule_steps`].
    static CROSS_RULE_STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts `n` rules the cross-rule checks (`graylog_title_duplicate`,
/// `exabeam_name_duplicate`, `google_secops_name_duplicate`) looked at on this thread, each rule indexed and
/// each UUID looked up counting one: for the test that holds them to linear
/// (a work count, not a wall clock).
fn cross_rule_steps(n: usize) {
    CROSS_RULE_STEPS.set(CROSS_RULE_STEPS.get() + n);
}

/// `exabeam_name_duplicate` and `exabeam_name_length`: the cross-rule check of
/// Exabeam rule names (`exabeam::name_findings`), over every rule in the
/// workspace, reported on the rules this run validates (`work`). Two enabled Exabeam blocks that
/// resolve to one name (under full case folding) are a duplicate; a block with no
/// `name` whose rule name is over the limit is too long.
fn exabeam_names(index: &Index, work: &[Subject<'_>]) -> Vec<Diagnostic> {
    use opentide_schema::objects::platform::exabeam;
    let mut rules: Vec<(String, &Node, &Path)> = Vec::new();
    for source in &index.sources {
        if source.family != "rule" {
            continue;
        }
        let Some(root) = source.document.root() else {
            continue;
        };
        let Some(uuid) = root
            .get("metadata")
            .filter(|m| matches!(m.value, Value::Map(_)))
            .and_then(|m| m.get("uuid"))
            .filter(|uuid| crate::index::holds_name(uuid))
        else {
            continue;
        };
        rules.push((uuid.value.to_string(), root, &source.path));
    }
    let pairs: Vec<(&str, &Node)> = rules
        .iter()
        .map(|(uuid, root, _)| (uuid.as_str(), *root))
        .collect();
    // The rules this run validates: the subjects already in scope.
    let in_scope: Vec<&str> = work
        .iter()
        .filter(|subject| subject.family == "rule")
        .map(|subject| subject.uuid)
        .collect();
    // Each finding's file by its rule's UUID, the first source of the UUID
    // as a scan finds it, not a scan per finding (#1945).
    let mut paths: HashMap<&str, &Path> = HashMap::with_capacity(rules.len());
    cross_rule_steps(rules.len());
    for (uuid, _, path) in &rules {
        paths.entry(uuid.as_str()).or_insert(*path);
    }
    let mut out = Vec::new();
    for finding in exabeam::name_findings(&pairs, in_scope.iter().copied()) {
        cross_rule_steps(1);
        let Some(path) = paths.get(finding.uuid.as_str()).copied() else {
            continue;
        };
        let mut diagnostic = Diagnostic::error(finding.code, finding.message)
            .object(finding.uuid.clone(), "rule")
            .file(path)
            .at([
                "configurations".to_owned(),
                "exabeam".to_owned(),
                "name".to_owned(),
            ])
            .suggest(Some(finding.suggestion.to_owned()));
        if let Some(value) = finding.value {
            diagnostic = diagnostic.with("value", value);
        }
        out.push(diagnostic);
    }
    out
}

/// `google_secops_name_duplicate`: each rule in scope whose enabled Google
/// SecOps block resolves to the YARA-L rule name of another rule's, compared
/// case-insensitively (`google_secops_name_issues`).
fn name_duplicates(index: &Index, work: &[Subject<'_>]) -> Vec<Diagnostic> {
    use opentide_schema::objects::platform::google_secops::advisories::{
        NAME_DUPLICATE, NameDuplicate, name_duplicates,
    };
    let Some(rules) = index.objects.get("rule") else {
        return Vec::new();
    };
    let all: Vec<(&str, &Node)> = rules
        .iter()
        .filter_map(|(uuid, object)| Some((uuid.as_str(), object.root()?)))
        .collect();
    // The first rule in `work` with each UUID, as a scan of `work` per
    // finding would find it, looked up once per finding (#1945).
    let mut subjects: HashMap<&str, &Subject<'_>> = HashMap::new();
    for subject in work.iter().filter(|subject| subject.family == "rule") {
        cross_rule_steps(1);
        subjects.entry(subject.uuid).or_insert(subject);
    }
    let in_scope = work
        .iter()
        .filter(|subject| subject.family == "rule")
        .map(|subject| subject.uuid);
    name_duplicates(all, in_scope)
        .into_iter()
        .map(|duplicate| {
            cross_rule_steps(1);
            let subject = subjects.get(duplicate.uuid.as_str());
            let mut diagnostic = Diagnostic::error(NAME_DUPLICATE, duplicate.message())
                .object(duplicate.uuid.as_str(), "rule")
                .at(NameDuplicate::field_path())
                .suggest(Some(NameDuplicate::SUGGESTION.to_owned()))
                .with("value", duplicate.name.as_str());
            if let Some(subject) = subject {
                diagnostic = diagnostic.file(subject.path);
                diagnostic.yaml_line = subject.document.locator().yaml_line(&diagnostic.field_path);
            }
            diagnostic
        })
        .collect()
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
        if opentide_schema::configuration::resolve::platform_enabled(platforms, platform) {
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

/// The plugin platforms' blocks of each rule in *work*: the extra-key error
/// the schema reports for such a block makes way for the plugin's own
/// findings, placed inside the block.
fn plugin_blocks(
    plugins: &dyn PlatformConfigurations,
    work: &[Subject<'_>],
    issues: &mut Vec<Diagnostic>,
    warnings: &mut Vec<Diagnostic>,
) {
    let owned = plugins.platforms();
    if owned.is_empty() {
        return;
    }
    for subject in work.iter().filter(|subject| subject.family == "rule") {
        let Some(Value::Map(blocks)) = subject
            .document
            .root()
            .and_then(|root| root.get("configurations"))
            .map(|node| &node.value)
        else {
            continue;
        };
        for block in blocks {
            let platform = block.key.value.to_string();
            if !owned.contains(&platform) || objects::PLATFORMS.contains(&platform.as_str()) {
                continue;
            }
            let place = ["configurations".to_owned(), platform.clone()];
            issues.retain(|issue| {
                !(issue.code == "schema_validation"
                    && issue.file_path.as_deref() == Some(subject.path)
                    && issue.field_path == place)
            });
            let json = opentide_schema::configuration::merge::to_json(&block.value);
            for finding in plugins.check(&platform, &json) {
                let mut field_path = place.to_vec();
                field_path.extend(finding.field_path);
                let message = format!("{platform}: {}", finding.message);
                let diagnostic = if finding.warning {
                    Diagnostic::warning("schema_validation", message)
                } else {
                    Diagnostic::error("schema_validation", message)
                }
                .object(subject.uuid, subject.family)
                .file(subject.path)
                .at(field_path);
                if finding.warning {
                    warnings.push(diagnostic);
                } else {
                    issues.push(diagnostic);
                }
            }
        }
    }
}

/// The compile check's findings (`_compile_issues`, `compile_issues`): one
/// error per rule and platform whose compiler refuses it, at the key at
/// fault, else the platform's block, its line the deepest key of that path
/// the file has.
fn compile_findings(
    ws: &Workspace,
    compile: &dyn CompileCheck,
    work: &[Subject<'_>],
    enabled: &BTreeSet<String>,
) -> Vec<Diagnostic> {
    let rules: Vec<(&Subject<'_>, CompileRule<'_>)> = work
        .iter()
        .filter(|subject| subject.family == "rule")
        .filter_map(|subject| {
            let root = subject.document.root()?;
            Some((
                subject,
                CompileRule {
                    path: subject.path,
                    root: root.as_ref(),
                },
            ))
        })
        .collect();
    let inputs: Vec<CompileRule<'_>> = rules.iter().map(|(_, rule)| *rule).collect();
    let found = compile.check(ws, &inputs, enabled);
    let mut findings = Vec::new();
    for ((subject, _), failures) in rules.iter().zip(found) {
        for failure in failures {
            let field_path = if failure.field_path.is_empty() {
                vec!["configurations".to_owned(), failure.platform.clone()]
            } else {
                failure.field_path
            };
            let mut diagnostic = Diagnostic::error(failure.code, failure.message)
                .object(subject.uuid, "rule")
                .file(subject.path)
                .at(field_path)
                .suggest(failure.hint)
                .with("platform", failure.platform);
            diagnostic.yaml_line = nearest_key_line(root_of(subject), &diagnostic.field_path);
            findings.push(diagnostic);
        }
    }
    findings
}

fn root_of<'d>(subject: &Subject<'d>) -> Option<&'d Node> {
    subject.document.root().map(AsRef::as_ref)
}

/// The line, from 0, of the deepest key of `field_path` the document has:
/// the key at fault, or the block that should hold it (`_nearest_line`).
fn nearest_key_line(root: Option<&Node>, field_path: &[String]) -> Option<usize> {
    let mut node = root?;
    let mut line = None;
    for part in field_path {
        let Value::Map(entries) = &node.value else {
            break;
        };
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.key.value.as_str() == Some(part.as_str()))
        else {
            break;
        };
        line = entry.key.start.line().checked_sub(1);
        node = &entry.value;
    }
    line
}

/// The sort key of an error (`sort_issues`): its file, its line (none
/// first), its field path, object, code and message.
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

/// The entries of a `cve` field: the field's items, or the field itself
/// when it is one value; none when it is absent or null.
fn cve_entries(field: Option<&Node>) -> Vec<&Node> {
    match field.map(|field| (field, &field.value)) {
        None | Some((_, Value::Null)) => Vec::new(),
        Some((_, Value::Seq(items))) => items.iter().map(AsRef::as_ref).collect(),
        Some((field, _)) => vec![field],
    }
}

/// The identifiers of a `cve` field, canonical, each once
/// (`normalize_identifiers`). An entry that is not a string is no
/// identifier: [`cve_non_strings`] names it.
pub fn cve_identifiers(field: Option<&Node>, canonical: &dyn Fn(&str) -> String) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for entry in cve_entries(field) {
        let Value::Str(text) = &entry.value else {
            continue;
        };
        let id = canonical(text);
        if !id.is_empty() && !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// The entries of a `cve` field that are not strings, each as YAML writes
/// it and with its type (`5 (integer, not a string)`), each once.
pub fn cve_non_strings(field: Option<&Node>) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for entry in cve_entries(field) {
        if matches!(entry.value, Value::Str(_)) {
            continue;
        }
        let shown = format!(
            "{} ({}, not a string)",
            entry.value,
            entry.value.type_name()
        );
        if !found.contains(&shown) {
            found.push(shown);
        }
    }
    found
}

/// The findings of one threat's CVE references (`check_cve_issues`): an
/// error naming those Vulnerability-Lookup does not know, a warning naming
/// those it could not be asked about.
fn cve_findings(threat: &crate::index::Object, lookup: &dyn CveCheck) -> Vec<Diagnostic> {
    let field = threat
        .root()
        .and_then(|root| root.get("threat"))
        .filter(|block| matches!(block.value, Value::Map(_)))
        .and_then(|block| block.get("cve"))
        .map(AsRef::as_ref);
    let ids = cve_identifiers(field, &|text| lookup.canonical(text));
    let mut broken: Vec<String> = cve_non_strings(field);
    let mut unchecked: Vec<String> = Vec::new();
    let mut error = String::new();
    for id in ids {
        match lookup.lookup(&threat.uuid, &id) {
            CveLookup::Found => {}
            CveLookup::NotFound => broken.push(id),
            CveLookup::Unavailable(why) => {
                unchecked.push(id);
                error = why;
            }
        }
    }
    let mut found = Vec::new();
    if !broken.is_empty() {
        found.push(
            Diagnostic::error(
                "invalid_cve",
                format!("Invalid CVE references: {}", broken.join(", ")),
            )
            .object(threat.uuid.as_str(), "threat")
            .file(&threat.path)
            .at(["threat", "cve"])
            .suggest(Some(
                "Confirm each identifier on Vulnerability-Lookup (https://vulnerability.circl.lu)."
                    .to_owned(),
            ))
            .with("threat_id", threat.uuid.as_str())
            .with("broken_cve", broken),
        );
    }
    if !unchecked.is_empty() {
        found.push(
            Diagnostic::warning(
                "cve_lookup_unavailable",
                format!(
                    "Could not check CVE references on Vulnerability-Lookup: {} ({error})",
                    unchecked.join(", ")
                ),
            )
            .object(threat.uuid.as_str(), "threat")
            .file(&threat.path)
            .at(["threat", "cve"])
            .suggest(Some(
                "Run `opentide validate --check cve` again once it is reachable.".to_owned(),
            ))
            .with("threat_id", threat.uuid.as_str())
            .with("unchecked_cve", unchecked),
        );
    }
    found
}

/// Runs `validate` over `ws`.
pub fn validate(ws: &Workspace, options: &Options<'_>) -> Validation {
    let never = Options {
        memo: None,
        stop: None,
        ..*options
    };
    // Only a stop hook makes a run return `None`, and `never` has none: the
    // empty report is not reachable.
    validate_resumable(ws, &never).unwrap_or_else(|| Validation::empty(None))
}

/// [`validate`], which may stop ([`Options::stop`]) and go on later
/// ([`Options::memo`]): `None` when it stopped, the same report an
/// uninterrupted run makes otherwise.
#[expect(
    clippy::too_many_lines,
    reason = "the run's phases in the order they run, read top to bottom"
)]
pub fn validate_resumable(ws: &Workspace, options: &Options<'_>) -> Option<Validation> {
    if let Some(refusal) = options
        .selection
        .and_then(|selection| unknown_types(&selection.types))
    {
        return Some(Validation::refusing(refusal));
    }
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
    graph.graylog_tenants =
        opentide_schema::objects::platform::graylog::configured_tenants(resolved.get("platforms"));
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
    let missing = if scoped_checks {
        scope.missing_file_targets(fs)
    } else {
        Vec::new()
    };
    if scope.has_filter() && scoped_checks && work.is_empty() && parse_issues.is_empty() {
        issues.extend(missing.iter().map(|target| file_not_found(target)));
        if scope.selects_beyond(&missing) {
            issues.push(
                Diagnostic::error(
                    "scope_no_match",
                    "No objects matched the validation scope (check --file, --uuid, --type)",
                )
                .with("targets", scope.targets())
                .with("object_types", scope.object_types()),
            );
        }
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
            if missing.contains(&target) {
                issues.push(file_not_found(&target));
                continue;
            }
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

    if has(Check::Cve)
        && let Some(lookup) = options.cve_check
    {
        for threat in index.family("threat") {
            if !scope.includes_object_with(&threat.uuid, &threat.family, &threat.path, || {
                listed.resolve(&threat.path)
            }) {
                continue;
            }
            for diagnostic in cve_findings(threat, lookup) {
                if diagnostic.is_error() {
                    issues.push(diagnostic);
                } else {
                    warnings.push(diagnostic);
                }
            }
        }
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
            let mut diagnostic = configuration_diagnostic(finding);
            // A finding names its file by key (`deployment.toml`): point it at
            // the workspace's own file, when there is one, so it has a path
            // and, from the key's position in it, a line and column (#1659).
            if diagnostic.file_path.is_none()
                && let Some(key) = diagnostic
                    .context
                    .get("file")
                    .and_then(ContextValue::as_str)
            {
                let file = root.join(".opentide/configurations").join(key);
                if fs.is_file(&file) {
                    diagnostic.file_path = Some(file);
                }
            }
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
        let found: Vec<objects::Found> = match (options.memo, options.stop) {
            (Some(memo), Some(stop)) => {
                check_in_batches(&work, memo, stop, &graph, checks, fs, &root)?
            }
            _ => work
                .par_iter()
                .map(|subject| objects::check_object(subject, &graph, checks, fs, &root))
                .collect(),
        };
        for one in found {
            issues.extend(one.issues);
            warnings.extend(one.warnings);
        }
        if checks.schema
            && let Some(plugins) = options.platform_configurations
        {
            plugin_blocks(plugins, &work, &mut issues, &mut warnings);
        }
        if checks.schema {
            warnings.extend(title_duplicates(index, &work));
            issues.extend(exabeam_names(index, &work));
            issues.extend(name_duplicates(index, &work));
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
        // What a deploy would compile must compile (#660), checked only once
        // nothing else failed: a malformed rule, or one naming an object
        // that failed to load, is reported once, for its cause (KG-10).
        if let (Some(compile), Some(enabled)) = (options.compile_check, graph.enabled.as_ref())
            && !enabled.is_empty()
            && issues.is_empty()
        {
            issues.extend(compile_findings(ws, compile, &work, enabled));
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
            // A YARA code the model and the engine both find is shown once. Only
            // an engine *error* replaces the model's: with --queries warn the
            // model's error stays, so validate fails the rule as deploy would,
            // and the engine's warning for the same code is dropped instead.
            issues = without_engine_reported_yara(issues, &found.errors);
            let modelled = model_yara_codes(&issues);
            issues.extend(
                found
                    .errors
                    .into_iter()
                    .filter(|issue| !rejected.contains(&query_place(issue))),
            );
            warnings.extend(found.warnings.into_iter().filter(|issue| {
                !rejected.contains(&query_place(issue))
                    && !modelled.contains(&yara_place(issue, &issue.code))
            }));
            stats.queries_checked = Some(found.queries);
        }
    }

    if has(Check::Schema) && scope.is_full() {
        issues.extend(state_issues(fs, &root));
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
    Some(Validation {
        checks: check_list,
        report,
        summary,
        failed,
        warned,
        refused: None,
    })
}

/// The findings of each of `work`'s objects, in order, checked in batches
/// (each on the threads the host has) with `stop` asked before each; what is
/// checked is kept in `memo`, and an object `memo` holds is not checked
/// again. `None` when `stop` said to stop, which it is never asked before the
/// first batch with an object to check: each call makes progress.
fn check_in_batches(
    work: &[Subject<'_>],
    memo: &ObjectMemo,
    stop: &dyn Fn() -> bool,
    graph: &Graph<'_>,
    checks: ObjectChecks,
    fs: &dyn FileSystem,
    root: &Path,
) -> Option<Vec<objects::Found>> {
    // Objects checked between two asks of `stop`: a few milliseconds on a
    // host with one thread; more on a host with many, so that its threads
    // are not joined every few objects.
    let batch_len = 32.max(4 * rayon::current_num_threads());
    let lock = || {
        memo.found
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    let mut all = Vec::with_capacity(work.len());
    // A call checks one batch before it asks `stop`: a pull that input keeps
    // interrupting still goes on, a batch at a time.
    let mut checked = false;
    for batch in work.chunks(batch_len) {
        let kept: Vec<Option<std::sync::Arc<objects::Found>>> = {
            let held = lock();
            batch
                .iter()
                .map(|subject| {
                    held.get(subject.path)
                        .and_then(|by_uuid| by_uuid.get(subject.uuid))
                        .cloned()
                })
                .collect()
        };
        let fresh_work = kept.iter().any(Option::is_none);
        if fresh_work && checked && stop() {
            return None;
        }
        checked |= fresh_work;
        // Each object's findings, and those to keep when it was checked now;
        // the findings a run reports are its own, cloned here, on the
        // batch's threads and outside the lock.
        let fresh: Vec<(objects::Found, Option<std::sync::Arc<objects::Found>>)> = batch
            .par_iter()
            .zip(kept)
            .map(|(subject, kept)| match kept {
                Some(found) => ((*found).clone(), None),
                None => {
                    let found = objects::check_object(subject, graph, checks, fs, root);
                    let keep = std::sync::Arc::new(found.clone());
                    (found, Some(keep))
                }
            })
            .collect();
        let mut held = lock();
        for (subject, (found, keep)) in batch.iter().zip(fresh) {
            if let Some(keep) = keep {
                // A key is allocated only for what is kept, and the first
                // object checked under a file and UUID stays.
                if !held.contains_key(subject.path) {
                    held.insert(subject.path.to_path_buf(), HashMap::new());
                }
                if let Some(by_uuid) = held.get_mut(subject.path)
                    && !by_uuid.contains_key(subject.uuid)
                {
                    by_uuid.insert(subject.uuid.to_owned(), keep);
                }
            }
            all.push(found);
        }
    }
    Some(all)
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
/// Codes both a platform model and the engine's YARA language report.
const YARA_PREFIXES: [&str; 2] = ["yara_", "bitdefender_yara_"];

fn is_yara_code(code: &str) -> bool {
    YARA_PREFIXES.iter().any(|prefix| code.starts_with(prefix))
}

/// The codes a coded model validator's finding carries (`_model_codes`):
/// HarfangLab names them in a `schema_validation` message (`HarfangLabConfig
/// validation failed with code(s): yara_include`); Bitdefender reports each
/// as its own finding, under its code (bitdefender-1.0).
fn model_codes(issue: &Diagnostic) -> Vec<&str> {
    if is_yara_code(&issue.code) {
        return vec![issue.code.as_str()];
    }
    if issue.code != "schema_validation" {
        return Vec::new();
    }
    let Some((_, codes)) = issue.message.split_once("validation failed with code(s): ") else {
        return Vec::new();
    };
    let codes = codes
        .split(|c: char| {
            !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == ',' || c == ' ')
        })
        .next()
        .unwrap_or_default();
    codes
        .split(", ")
        .map(str::trim)
        .filter(|code| {
            !code.is_empty()
                && code
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .collect()
}

/// `(file, configurations block, code)`: where a YARA code is about.
fn yara_place(issue: &Diagnostic, code: &str) -> (Option<PathBuf>, Vec<String>, String) {
    let block = issue.field_path.iter().take(2).cloned().collect();
    (issue.file_path.clone(), block, code.to_owned())
}

/// The `yara_*` codes the model reports, each at its block (`_model_yara_codes`).
fn model_yara_codes(issues: &[Diagnostic]) -> BTreeSet<(Option<PathBuf>, Vec<String>, String)> {
    issues
        .iter()
        .flat_map(|issue| {
            model_codes(issue)
                .into_iter()
                .filter(|code| is_yara_code(code))
                .map(|code| yara_place(issue, code))
        })
        .collect()
}

/// `issues`, without a model finding the engine already reported with its
/// place (`_without_engine_reported_yara`). The HarfangLab model checks the
/// YARA-language codes a scan decides (`yara_include`, ...) so deploy and the
/// paths without the engine keep them; the engine reports the same code at
/// its line and column. A finding on a `configurations` block is dropped when
/// every code it carries is a `yara_*` code the engine reported as an error
/// (`engine`) in that block of that file. A `harfanglab_*` constraint code
/// keeps it.
fn without_engine_reported_yara(issues: Vec<Diagnostic>, engine: &[Diagnostic]) -> Vec<Diagnostic> {
    let reported: BTreeSet<_> = engine
        .iter()
        .filter(|item| is_yara_code(&item.code))
        .map(|item| yara_place(item, &item.code))
        .collect();
    if reported.is_empty() {
        return issues;
    }
    issues
        .into_iter()
        .filter(|issue| {
            let codes = model_codes(issue);
            codes.is_empty()
                || !codes
                    .iter()
                    .all(|code| is_yara_code(code) && reported.contains(&yara_place(issue, code)))
        })
        .collect()
}

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

/// `--file` names a path where nothing exists.
fn file_not_found(target: &str) -> Diagnostic {
    Diagnostic::error(
        "file_not_found",
        format!(
            "--file {} does not exist, so it was not validated",
            opentide_schema::vocab::quote(target)
        ),
    )
    .with("targets", vec![target.to_owned()])
    .with("object_types", Vec::<String>::new())
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
                    || (check == Check::Schema && is_model_constraint(issue))
                    || (matches!(check, Check::UuidFormat | Check::Schema)
                        && matches!(issue.code.as_str(), "scope_no_match" | "file_not_found"))
            })
        }
    };
    if failed { "failed" } else { "passed" }
}

/// Whether `issue` is a platform block's model finding under its own
/// constraint code (`microsoft_defender_severity`, `graylog_schedule`, ...):
/// the `schema` check runs the models, so it fails on one. The codes are the
/// models' own ([`opentide_schema::objects::platform::constraint_codes`]),
/// and a finding of the query engine (`source: engine`) under the same code
/// stays the `queries` check's.
fn is_model_constraint(issue: &Diagnostic) -> bool {
    issue.object_type != "configuration"
        && issue.context.get("source").and_then(ContextValue::as_str) != Some("engine")
        && opentide_schema::objects::platform::constraint_codes().any(|code| code == issue.code)
}

/// The `deployment_state_*` findings on the shards under
/// `.opentide/states/deployment/` of `root`, each on its shard, before
/// [`annotate`](annotate::annotate) places them.
fn state_issues(fs: &dyn FileSystem, root: &Path) -> Vec<Diagnostic> {
    states::scan(fs, root)
        .into_iter()
        .map(|error| {
            let shard = error
                .path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut diagnostic = Diagnostic::error(error.code, error.message).with("shard", shard);
            diagnostic.file_path = error.path;
            diagnostic
        })
        .collect()
}

impl Workspace {
    /// Runs `validate` ([`validate`]).
    pub fn validate(&self, options: &Options<'_>) -> Validation {
        validate(self, options)
    }

    /// [`validate`](Self::validate) that may stop and go on later
    /// ([`validate_resumable`]).
    pub fn validate_resumable(&self, options: &Options<'_>) -> Option<Validation> {
        validate_resumable(self, options)
    }

    /// The `deployment_state_*` findings a full `validate` run reports on the
    /// deployment state shards, as it reports them (sorted, placed): what an
    /// editor shows again when a shard changes, without checking every object.
    pub fn deployment_state_findings(&self) -> Vec<Diagnostic> {
        let fs = self.fs().as_ref();
        let root = self.root().to_path_buf();
        let mut issues = state_issues(fs, &root);
        issues.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
        let mut sources = annotate::Sources::new(fs, self.index());
        annotate::annotate(&mut issues, &mut sources, &root);
        issues
    }

    /// The `deployment_state_*` finding a run narrowed to `files`
    /// (`validate --file`) files on each rule among them for its own shard,
    /// placed: what an editor that keeps a full run's findings (which file
    /// them on the shards) adds for the rules it has open, without checking
    /// them again. A rule is matched by its path as the index names it,
    /// against each of `files` as given and resolved: only `files` are
    /// resolved, never every rule (an editor asks on each keystroke). It
    /// assumes the default checks (`schema` on), as the editor runs them.
    pub fn rule_shard_findings(&self, files: &[PathBuf]) -> Vec<Diagnostic> {
        let fs = self.fs().as_ref();
        let root = self.root().to_path_buf();
        let wanted: BTreeSet<PathBuf> = files
            .iter()
            .flat_map(|file| [file.clone(), fs.resolve(file)])
            .collect();
        let mut issues: Vec<Diagnostic> = self
            .index()
            .objects
            .get("rule")
            .into_iter()
            .flat_map(|objects| objects.values())
            .filter(|object| wanted.contains(&object.path))
            .filter_map(|object| {
                let subject = Subject {
                    uuid: &object.uuid,
                    family: &object.family,
                    path: &object.path,
                    document: &object.document,
                };
                objects::shard_issue(&subject, fs, &root)
            })
            .collect();
        issues.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
        let mut sources = annotate::Sources::new(fs, self.index());
        annotate::annotate(&mut issues, &mut sources, &root);
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1945: `graylog_title_duplicate`, `exabeam_name_duplicate` and
    /// `google_secops_name_duplicate` index the rules once and find each by its UUID, so their work grows with the
    /// rules, not with their square (a scan of every rule per rule).
    #[test]
    fn cross_rule_checks_look_at_each_rule_a_bounded_number_of_times() {
        use std::sync::Arc;

        use crate::fs::{FileSystem, MemoryFs};
        use crate::root::RootOptions;
        use crate::workspace::{Options as WorkspaceOptions, Workspace};

        let steps = |n: usize| {
            let fs = Arc::new(MemoryFs::new());
            fs.create_dir("/ws/.opentide/configurations");
            fs.create_dir("/ws/objects/rules");
            for i in 0..n {
                // Every tenth rule shares its titles with the one before it.
                let name = format!("Rule é {}", i - usize::from(i % 10 == 9));
                fs.write(
                    format!("/ws/objects/rules/r{i}.yaml"),
                    format!(
                        "name: {name}\nmetadata:\n  uuid: 00000000-0000-4000-8000-{i:012}\n  \
                         schema: rule::1.1\nconfigurations:\n  graylog:\n    enabled: true\n  \
                         exabeam:\n    enabled: true\n  google_secops:\n    enabled: true\n"
                    ),
                );
            }
            let ws = Workspace::open(
                Arc::clone(&fs) as Arc<dyn FileSystem>,
                WorkspaceOptions {
                    roots: RootOptions {
                        repo: Some(PathBuf::from("/ws")),
                        cwd: PathBuf::from("/ws"),
                        ..RootOptions::default()
                    },
                },
            )
            .unwrap();
            let before = CROSS_RULE_STEPS.get();
            let validation = validate(&ws, &Options::default());
            let found = |code: &str| {
                validation
                    .report
                    .issues
                    .iter()
                    .chain(&validation.report.warnings)
                    .filter(|d| d.code == code)
                    .count()
            };
            assert_eq!(found("graylog_title_duplicate"), n / 10 * 2);
            assert_eq!(found("exabeam_name_duplicate"), n / 10 * 2);
            assert_eq!(found("google_secops_name_duplicate"), n / 10 * 2);
            CROSS_RULE_STEPS.get() - before
        };
        let (small, large) = (steps(100), steps(400));
        assert!(
            large < small * 8,
            "{small} steps for 100 rules, {large} for 400"
        );
    }

    #[test]
    fn workers_follow_the_cores_and_never_outnumber_the_items() {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        assert_eq!(workers(0), 0);
        assert_eq!(workers(1), 0, "one item runs on one thread");
        for items in [2, 3, 32, 1000] {
            let expected = if cores < 2 { 0 } else { items.min(cores) };
            assert_eq!(workers(items), expected, "{items} items on {cores} cores");
        }
    }

    /// The platform codes no `schema` finding carries under its own name,
    /// each with where it comes from ([`every_platform_code_is_placed`]).
    const ELSEWHERE: &[(&str, &str)] = &[
        // The query engines' codes: the `queries` check's (`source: engine`).
        ("elastic_dataset_not_declared", "engine"),
        // A Defender block against its query's output (#1885): the KQL
        // engine's errors and lint's advisories.
        ("microsoft_defender_column_not_in_output", "engine"),
        ("microsoft_defender_required_columns", "engine"),
        ("microsoft_defender_column_type", "engine"),
        ("microsoft_defender_unprojected_output", "engine"),
        // Microsoft's documented NRT restrictions (#1890): lint's advisory.
        ("microsoft_defender_nrt_query", "engine"),
        ("graylog_leading_wildcard", "engine"),
        ("graylog_regex_unsupported", "engine"),
        ("graylog_regex_operator", "engine"),
        ("graylog_regex_quote", "engine"),
        ("graylog_open_range", "engine"),
        ("graylog_double_backslash", "engine"),
        ("graylog_analyzed_field", "engine"),
        ("bitdefender_yara_ascii", "engine"),
        ("bitdefender_yara_size", "engine"),
        ("exabeam_parse_error", "engine"),
        ("exabeam_implicit_operator", "engine"),
        ("exabeam_not_equal", "engine"),
        ("exabeam_bare_wildcard", "engine"),
        ("exabeam_leading_slash", "engine"),
        ("exabeam_free_text_special", "engine"),
        ("exabeam_unknown_function", "engine"),
        ("exabeam_function_arity", "engine"),
        ("exabeam_regex", "engine"),
        ("exabeam_range", "engine"),
        ("exabeam_ipv6_range", "engine"),
        ("exabeam_time_exact", "engine"),
        ("exabeam_context_table_or", "engine"),
        ("exabeam_context_table_limit", "engine"),
        ("exabeam_advanced_in_rule", "engine"),
        ("exabeam_keyword_case", "engine"),
        ("exabeam_clause_order", "engine"),
        ("exabeam_pipe_limit", "engine"),
        ("exabeam_rgx_extract_limit", "engine"),
        ("exabeam_reserved_alias", "engine"),
        ("exabeam_group_by_select_star", "engine"),
        ("exabeam_group_by_column", "engine"),
        ("exabeam_foreach_clause", "engine"),
        ("exabeam_foreach_reference", "engine"),
        ("exabeam_foreach_position", "engine"),
        ("exabeam_mixed_boolean", "engine"),
        ("exabeam_implicit_and", "engine"),
        ("exabeam_single_group", "engine"),
        ("exabeam_pipe_misuse", "engine"),
        ("exabeam_wildcard_in_phrase", "engine"),
        ("exabeam_unquoted_value", "engine"),
        ("exabeam_legacy_regex", "engine"),
        ("exabeam_unknown_field", "engine"),
        ("exabeam_string_field_number", "engine"),
        ("exabeam_unknown_value", "engine"),
        ("datadog_parse_error", "engine"),
        ("datadog_unescaped_special", "engine"),
        ("datadog_regex", "engine"),
        ("datadog_cidr", "engine"),
        ("datadog_range", "engine"),
        ("datadog_mixed_boolean", "engine"),
        ("datadog_lowercase_operator", "engine"),
        ("datadog_curly_quote", "engine"),
        ("datadog_wildcard_in_phrase", "engine"),
        ("datadog_unescaped_colon", "engine"),
        ("datadog_symbol_operator", "engine"),
        ("datadog_detached_operator", "engine"),
        ("datadog_full_text_in_rule", "engine"),
        ("datadog_calculated_field_in_rule", "engine"),
        ("datadog_pipelines_only", "engine"),
        ("datadog_unknown_attribute", "engine"),
        // Named checks that report their codes inside one
        // `schema_validation` finding (`<Model> validation failed with
        // code(s): ...`), which the `schema` check fails on.
        ("sysdig_rule_shape", "schema_validation"),
        ("sysdig_tuning_keys", "schema_validation"),
        ("sysdig_priority", "schema_validation"),
        ("sysdig_source", "schema_validation"),
        ("sysdig_exception_shape", "schema_validation"),
        ("sysdig_definition_name", "schema_validation"),
        ("sysdig_definition_duplicate", "schema_validation"),
        ("sysdig_definition_order", "schema_validation"),
        ("sysdig_list_in_value", "schema_validation"),
        ("sysdig_list_self_reference", "schema_validation"),
        ("harfanglab_rule_kind", "schema_validation"),
        ("harfanglab_yara_form", "schema_validation"),
        ("harfanglab_yara_section_header", "schema_validation"),
        ("harfanglab_yara_import", "schema_validation"),
        ("harfanglab_yara_rule_name", "schema_validation"),
    ];

    /// Every platform's code in `opentide_core::codes::ALL` (named
    /// `<platform>_...` after a platform of the registry) has its place: a
    /// finding the `schema` check fails on (a model's constraint code, or
    /// one of its own codes), a block advisory (a warning), or a code no
    /// `schema` finding carries, named below with where it comes from. A new
    /// platform code fails here until it is placed, so the `schema` check's
    /// status cannot miss it (#1893).
    #[test]
    fn every_platform_code_is_placed() {
        use opentide_schema::objects::platform as models;
        let prefixes: Vec<String> = opentide_schema::platforms::PLATFORMS
            .iter()
            .map(|platform| format!("{}_", platform.id))
            .collect();
        let schema: BTreeSet<&str> = models::constraint_codes()
            .chain(Check::Schema.issue_codes().iter().copied())
            .collect();
        let advisories: BTreeSet<&str> = models::bitdefender::advisories::ADVISORY_CODES
            .into_iter()
            .chain(models::graylog::ADVISORY_CODES)
            .chain(models::exabeam::ADVISORY_CODES)
            .chain(models::microsoft_defender::ADVISORY_CODES)
            .chain(models::google_secops::advisories::ADVISORY_CODES)
            .chain(models::datadog::ADVISORY_CODES)
            .chain(models::harfanglab::yara::ADVISORY_CODES)
            .collect();
        let elsewhere: BTreeSet<&str> = ELSEWHERE.iter().map(|(code, _)| *code).collect();
        let mut unplaced = Vec::new();
        for code in opentide_core::codes::ALL {
            if !prefixes
                .iter()
                .any(|prefix| code.starts_with(prefix.as_str()))
            {
                continue;
            }
            // A code may be both (Bitdefender's `bitdefender_criterion_field`
            // is an error on an EDR target and a warning on another), but a
            // code named below is neither.
            let checked = schema.contains(code) || advisories.contains(code);
            if elsewhere.contains(code) {
                assert!(!checked, "{code} is named below and placed too");
            } else if !checked {
                unplaced.push(*code);
            }
        }
        assert_eq!(unplaced, Vec::<&str>::new(), "platform codes with no place");
        // No stale entry: each named code still exists.
        for (code, _) in ELSEWHERE {
            assert!(opentide_core::codes::ALL.contains(code), "{code}");
        }
    }

    /// A constraint code fails the `schema` check on an object's model
    /// finding only: the query engine's finding under the same code stays
    /// the `queries` check's, and a configuration file's the
    /// `configuration` check's.
    #[test]
    fn a_constraint_code_is_the_schema_checks_on_a_model_finding_only() {
        let model = Diagnostic::error("microsoft_defender_severity", "m").object("u", "rule");
        assert!(is_model_constraint(&model));
        let engine = model.clone().with("source", "engine");
        assert!(!is_model_constraint(&engine));
        let configuration =
            Diagnostic::error("microsoft_defender_severity", "m").object("", "configuration");
        assert!(!is_model_constraint(&configuration));
        assert!(!is_model_constraint(&Diagnostic::error(
            "kql_parse_error",
            "m"
        )));
    }

    #[test]
    fn validation_codes_hold_every_checks_codes_sorted() {
        for check in Check::ALL {
            for code in check.issue_codes() {
                assert!(VALIDATION_CODES.contains(code), "{code}");
            }
        }
        for code in STRICT_EXEMPT_WARNINGS {
            assert!(VALIDATION_CODES.contains(code), "{code}");
        }
        assert!(VALIDATION_CODES.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
