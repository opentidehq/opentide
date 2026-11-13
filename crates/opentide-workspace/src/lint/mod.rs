//! `opentide lint`: catalogue hygiene (`cli/services/lint.py`, UC-2.3 #818).
//!
//! Every rule of `LINT_CODES`: a file that does not parse (`yaml_parse`), an
//! object without a name (`name_missing`), a file name that is not the one
//! its name gives (`filename_mismatch`), one the configured pattern refuses
//! (`filename_pattern`), recommended metadata that is missing
//! (`metadata_recommended`), a value `opentide new` marked as a placeholder
//! (`placeholder`), and a YAML file in a subfolder of an object folder
//! (`nested_object_file`). The queries check's findings come from the host
//! ([`LintQueryCheck`], UC-2.5).
//!
//! `lint.toml` ([`opentide_schema::configuration::lint`]) enables the checks,
//! sets their severity, the recommended metadata and the file name
//! convention of each object kind. `--check` runs a check the file disables;
//! `--file` and `--changed` narrow every check to the files they select,
//! though the filenames check still reads every file of the folder, so a
//! stem another file holds is still a collision. `--fix` renames each file
//! whose name is not its object's, unless another file already holds the
//! name.
//!
//! A finding is a [`LintFinding`]: the JSON entry of `lint --json`'s
//! `findings`, key for key in the oracle's order, and the [`Diagnostic`] its
//! frame, SARIF and CI annotations are drawn from. Lint's `info` is
//! [`Severity::Info`]: the JSON says `info`, the frame says `note`.

pub mod stems;

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_schema::configuration::lint::{FilenameConfig, LintConfig};
use opentide_schema::node::{self, Node, Value};
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Value as Json, json};

use crate::diagnostic::{Diagnostic, Severity};
use crate::discover;
use crate::fs::{FileSystem, WriteFs, case_only_rename};
use crate::index::posix;
use crate::validate::Selection;
use crate::validate::annotate::Sources;
use crate::validate::scope::Scope;

pub use stems::{expected_stem, object_stem, slugify, split_object_name, with_object_stem};

/// The object folders lint reads, under `objects/`, in its order.
pub const OBJECT_FAMILIES: [&str; 3] = ["threats", "objectives", "rules"];

/// `LINT_CODES`: the code of each rule.
pub mod codes {
    /// The file does not parse, or is not one mapping.
    pub const PARSE: &str = "yaml_parse";
    /// The object has no name.
    pub const NAME: &str = "name_missing";
    /// The file name is not the one the object's name gives.
    pub const FILENAME: &str = "filename_mismatch";
    /// The file name does not match `[filenames] pattern`.
    pub const FILENAME_PATTERN: &str = "filename_pattern";
    /// Recommended metadata is missing.
    pub const METADATA: &str = "metadata_recommended";
    /// A value `opentide new` marked as a placeholder.
    pub const PLACEHOLDER: &str = "placeholder";
    /// A YAML file in a subfolder of an object folder.
    pub const NESTED: &str = "nested_object_file";
}

/// Every code a lint rule reports (`LINT_CODES.values()`).
pub const LINT_CODES: [&str; 7] = [
    codes::PARSE,
    codes::NAME,
    codes::FILENAME,
    codes::FILENAME_PATTERN,
    codes::METADATA,
    codes::PLACEHOLDER,
    codes::NESTED,
];

/// The step a placeholder finding suggests.
pub const PLACEHOLDER_HELP: &str =
    "replace the value, then delete the '# opentide:placeholder' comment";
const NESTED_OBJECTS_ISSUE: &str = "https://github.com/opentidehq/opentide/issues/584";
/// What the host's `--changed` warning advises when the checkout has no
/// commit yet.
pub const NO_COMMITS_ADVICE: &str = "commit the files, or drop --changed to lint every object file";

/// A lint check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LintCheck {
    /// File names, parse errors, names, nested files.
    Filenames,
    /// Recommended metadata.
    Metadata,
    /// Values `opentide new` marked.
    Placeholders,
    /// The query engines' style findings (the host's, UC-2.5).
    Queries,
}

impl LintCheck {
    /// Every check, in the order `lint.toml` lists them.
    pub const ALL: [Self; 4] = [
        Self::Filenames,
        Self::Metadata,
        Self::Placeholders,
        Self::Queries,
    ];

    /// Its name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Filenames => "filenames",
            Self::Metadata => "metadata",
            Self::Placeholders => "placeholders",
            Self::Queries => "queries",
        }
    }

    /// The check called `name`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|check| check.name() == name)
    }
}

/// A command `next_actions` suggests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextAction {
    /// The command, as a person types it (`opentide lint --fix`).
    pub command: String,
    /// Why.
    pub reason: String,
}

/// What `--changed` selected: the host reads the diff (git), lint narrows
/// to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Changed {
    /// The changed files, absolute; `warning` when the checkout has no commit
    /// yet to diff against (the host words it, with [`NO_COMMITS_ADVICE`]).
    Files {
        /// The files.
        files: Vec<PathBuf>,
        /// Why nothing was selected, when the checkout has no commit.
        warning: Option<String>,
    },
    /// The diff could not be read: the run fails (exit 1) with this message.
    Failed(String),
}

/// The queries check, which the host runs (the query engines sit above this
/// crate: UC-2.5).
pub trait LintQueryCheck: Sync {
    /// The style findings of the object in `file` (its text is `text`, its
    /// path relative to the workspace `relative`), as lint findings of the
    /// `queries` check.
    ///
    /// # Errors
    ///
    /// The engine is not available: lint stops and says so.
    fn check(
        &self,
        file: &Path,
        relative: &str,
        uuid: Option<&str>,
        text: &str,
    ) -> Result<Vec<LintFinding>, String>;
}

/// `lint`'s options.
#[derive(Default)]
pub struct LintOptions<'a> {
    /// `--check`; empty runs the checks `lint.toml` enables.
    pub checks: Vec<LintCheck>,
    /// `--fix`: rename files to their names.
    pub fix: bool,
    /// `--strict`: any finding fails the run.
    pub strict: bool,
    /// `--file`, repeatable.
    pub files: Vec<String>,
    /// `--changed`, as the host read it.
    pub changed: Option<Changed>,
    /// The working directory (`--file` resolves against it too).
    pub cwd: PathBuf,
    /// The queries check; without one it finds nothing.
    pub query_check: Option<&'a dyn LintQueryCheck>,
}

impl std::fmt::Debug for LintOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LintOptions")
            .field("checks", &self.checks)
            .field("fix", &self.fix)
            .field("strict", &self.strict)
            .field("files", &self.files)
            .field("changed", &self.changed)
            .field("cwd", &self.cwd)
            .field("query_check", &self.query_check.is_some())
            .finish()
    }
}

/// One finding: its JSON entry and its diagnostic.
#[derive(Debug, Clone, PartialEq)]
pub struct LintFinding {
    /// The check that found it.
    pub check: LintCheck,
    /// The entry of `findings`, its keys in the oracle's order.
    pub json: IndexMap<String, Json>,
    /// The finding as a diagnostic: what a frame, SARIF and a CI annotation
    /// show (its message may be the parser's, where the JSON keeps lint's).
    pub diagnostic: Diagnostic,
}

impl LintFinding {
    /// A finding of the queries check, from the engine's diagnostic: the host
    /// builds it (UC-2.5); `severity` is lint's (`warning` or `info`).
    pub fn from_engine(relative: &str, uuid: Option<&str>, diagnostic: Diagnostic) -> Self {
        let mut json = IndexMap::new();
        json.insert("check".to_owned(), json!("queries"));
        json.insert("severity".to_owned(), json!(diagnostic.severity.as_str()));
        json.insert("path".to_owned(), json!(relative));
        json.insert(
            "yaml_line".to_owned(),
            json!(diagnostic.line.map(|line| line.saturating_sub(1))),
        );
        json.insert("uuid".to_owned(), json!(uuid));
        json.insert("message".to_owned(), json!(diagnostic.message));
        json.insert("code".to_owned(), json!(diagnostic.code));
        json.insert("field_path".to_owned(), json!(diagnostic.field_path));
        annotate(&mut json, &diagnostic);
        Self {
            check: LintCheck::Queries,
            json,
            diagnostic,
        }
    }

    /// `severity` in the JSON.
    pub fn severity(&self) -> &str {
        self.json
            .get("severity")
            .and_then(Json::as_str)
            .unwrap_or("")
    }

    /// `path` in the JSON.
    pub fn path(&self) -> &str {
        self.json.get("path").and_then(Json::as_str).unwrap_or("")
    }

    /// `code`.
    pub fn code(&self) -> &str {
        &self.diagnostic.code
    }

    /// Whether `--fix` fixed it.
    pub fn is_fixed(&self) -> bool {
        self.json.get("fixed") == Some(&Json::Bool(true))
    }
}

impl Serialize for LintFinding {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.json.serialize(serializer)
    }
}

/// `lint`'s status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LintStatus {
    /// Nothing found.
    Completed,
    /// Findings, none failing the run.
    Issues,
    /// The run failed.
    Failed,
}

/// The counts of `summary`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LintSummary {
    /// Files linted.
    pub files: usize,
    /// Findings `--fix` did not fix.
    pub findings: usize,
    /// Of them, errors.
    pub errors: usize,
    /// Warnings.
    pub warnings: usize,
    /// Notes (`info`).
    pub notes: usize,
    /// Files `--fix` renamed.
    pub fixed: usize,
}

/// What `lint` reports.
#[derive(Debug, Clone, PartialEq)]
pub struct LintReport {
    /// The workspace, resolved.
    pub path: PathBuf,
    /// The checks that ran.
    pub checks: Vec<LintCheck>,
    /// Every finding, in the order the checks found them.
    pub findings: Vec<LintFinding>,
    /// How many `--fix` fixed.
    pub fixed: usize,
    /// The status.
    pub status: LintStatus,
    /// One sentence.
    pub message: String,
    /// The exit code: `0`, `1` (failed), `2` (usage, `lint.toml`).
    pub exit_code: i32,
    /// `failure.code` when the CLI's default (`command_failed`) is not it.
    pub failure_code: Option<&'static str>,
    /// The counts; `None` when the run was refused.
    pub summary: Option<LintSummary>,
    /// The outcome line (`3 files clean`).
    pub outcome: Option<String>,
    /// Whether the outcome line takes `✓` though findings are left (notes
    /// only).
    pub outcome_ok: bool,
    /// `changed` or `selected` when `--changed` or `--file` narrowed it.
    pub scope: Option<&'static str>,
    /// `--file` targets that selected no object file.
    pub unmatched: Vec<String>,
    /// Warnings for the envelope.
    pub warnings: Vec<String>,
    /// The next steps.
    pub next_actions: Vec<NextAction>,
}

impl LintReport {
    /// The command's own keys of `lint --json`, in order: `path`, `checks`,
    /// `findings`, `count`, `fixed`, then `unmatched` and `scope` when set.
    /// The envelope (`ok`, `status`, `message`, `summary`, ...) is the CLI's.
    pub fn payload(&self) -> IndexMap<&'static str, Json> {
        let mut out = IndexMap::new();
        out.insert("path", json!(self.path.to_string_lossy()));
        out.insert(
            "checks",
            json!(self.checks.iter().map(|c| c.name()).collect::<Vec<_>>()),
        );
        out.insert(
            "findings",
            serde_json::to_value(&self.findings).unwrap_or(Json::Null),
        );
        out.insert("count", json!(self.findings.len()));
        out.insert("fixed", json!(self.fixed));
        if !self.unmatched.is_empty() {
            out.insert("unmatched", json!(self.unmatched));
        }
        if let Some(scope) = self.scope {
            out.insert("scope", json!(scope));
        }
        out
    }

    fn refused(path: &Path, checks: Vec<LintCheck>, message: String, exit_code: i32) -> Self {
        Self {
            path: path.to_path_buf(),
            checks,
            findings: Vec::new(),
            fixed: 0,
            status: LintStatus::Failed,
            message,
            exit_code,
            failure_code: (exit_code == 2).then_some("usage_error"),
            summary: None,
            outcome: None,
            outcome_ok: false,
            scope: None,
            unmatched: Vec::new(),
            warnings: Vec::new(),
            next_actions: Vec::new(),
        }
    }
}

/// A value `opentide new` marked: zero-based line, what holds it, 1-based
/// columns, end exclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Marked {
    line: usize,
    label: String,
    column: usize,
    end_column: usize,
}

/// One object file as lint reads it.
#[derive(Debug, Clone, Default)]
struct Record {
    path: PathBuf,
    relative: String,
    /// `threats`, `objectives` or `rules`: which `[filenames.<kind>]` applies.
    kind: Option<String>,
    name: Option<String>,
    uuid: Option<String>,
    metadata: Option<std::sync::Arc<Node>>,
    schema: Option<String>,
    parse_error: Option<String>,
    parse_position: Option<(usize, usize)>,
    expected_stem: Option<String>,
    key_lines: IndexMap<String, usize>,
    placeholders: Vec<Marked>,
    text: Option<String>,
}

/// Runs `lint` on the workspace at `root` with its resolved `config`.
/// Renames go through `writer` (`--fix`); without one, `--fix` renames
/// nothing.
pub fn lint(
    fs: &dyn FileSystem,
    writer: Option<&dyn WriteFs>,
    root: &Path,
    config: &LintConfig,
    options: &LintOptions<'_>,
) -> LintReport {
    lint_with(fs, writer, root, config, options, &Parses::new())
}

/// Object files already parsed, by path: what a [`crate::Workspace`]'s
/// index holds. Lint reads such a file from its parse, not the disk; the
/// parse is the same (`load::parse` reads a file as lint does).
type Parses = std::collections::HashMap<PathBuf, std::sync::Arc<node::Document>>;

/// [`lint`], reading the files `parses` holds from there.
fn lint_with(
    fs: &dyn FileSystem,
    writer: Option<&dyn WriteFs>,
    root: &Path,
    config: &LintConfig,
    options: &LintOptions<'_>,
    parses: &Parses,
) -> LintReport {
    let target = fs.resolve(root);
    let selected: Vec<LintCheck> = if options.checks.is_empty() {
        enabled_checks(config)
    } else {
        options.checks.clone()
    };
    let (object_files, nested) = object_files(fs, &target);
    let candidates: Vec<PathBuf> = object_files.iter().chain(&nested).cloned().collect();
    let scope = match narrow(fs, &target, &candidates, options) {
        Ok(scope) => scope,
        Err(mut refused) => {
            refused.checks = selected;
            return *refused;
        }
    };
    let reported = scope.as_ref().map(|scope| &scope.files);
    let in_scope = |path: &Path| reported.is_none_or(|files| files.contains(&path.to_path_buf()));
    let nested: Vec<PathBuf> = nested.into_iter().filter(|p| in_scope(p)).collect();
    let every = reported.is_none() || selected.contains(&LintCheck::Filenames);
    let mut records: Vec<Record> = object_files
        .iter()
        .filter(|path| every || in_scope(path))
        .map(|path| load_record(fs, &target, path, parses.get(path)))
        .collect();
    let shown: Vec<usize> = (0..records.len())
        .filter(|&index| in_scope(&records[index].path))
        .collect();
    let mut findings: Vec<Draft> = Vec::new();
    if selected.contains(&LintCheck::Metadata) {
        findings.extend(metadata_findings(
            shown.iter().map(|&i| &records[i]),
            &config.required_metadata,
        ));
    }
    if selected.contains(&LintCheck::Placeholders) {
        findings.extend(placeholder_findings(shown.iter().map(|&i| &records[i])));
    }
    let mut engine: Vec<LintFinding> = Vec::new();
    if selected.contains(&LintCheck::Queries)
        && let Some(check) = options.query_check
    {
        // The files are checked on every core and their findings taken in
        // order: the first file the engine refuses still decides the report.
        let checked: Vec<Result<Vec<LintFinding>, String>> = shown
            .par_iter()
            .filter_map(|&index| {
                let record = &records[index];
                let (None, Some(text)) = (&record.parse_error, &record.text) else {
                    return None;
                };
                Some(check.check(&record.path, &record.relative, record.uuid.as_deref(), text))
            })
            .collect();
        for one in checked {
            match one {
                Ok(found) => engine.extend(found),
                Err(message) => {
                    let mut report = LintReport::refused(&target, selected, message, 2);
                    report.failure_code = Some("engine_unavailable");
                    return report;
                }
            }
        }
    }
    let engine_at = findings.len();
    if selected.contains(&LintCheck::Filenames) {
        let reported_set = reported.cloned();
        findings.extend(filename_findings(
            fs,
            writer.filter(|_| options.fix),
            &target,
            &mut records,
            &config.filenames,
            reported_set.as_ref(),
        ));
        rewrite_renamed_paths(&mut findings);
        findings.extend(nested.iter().map(|path| nested_finding(&target, path)));
    }
    // Severity from `lint.toml`, for each check that sets one.
    for draft in &mut findings {
        if let Some(severity) = check_severity(config, draft.check) {
            severity.clone_into(&mut draft.severity);
        }
    }
    for finding in &mut engine {
        if let Some(severity) = check_severity(config, finding.check) {
            finding.json.insert("severity".to_owned(), json!(severity));
            finding.diagnostic.severity = Severity::parse(severity).unwrap_or(Severity::Warning);
        }
    }
    let mut sources = Sources::files(fs);
    let mut all: Vec<LintFinding> = Vec::with_capacity(findings.len() + engine.len());
    let mut drafts = findings.into_iter();
    for draft in drafts.by_ref().take(engine_at) {
        all.push(draft.finish(&target, &mut sources));
    }
    all.extend(engine);
    for draft in drafts {
        all.push(draft.finish(&target, &mut sources));
    }
    report(fs, &target, selected, all, scope, shown.len(), options)
}

/// Lint's file name and metadata findings on one object file: what the
/// language server reports for an open file (KG-03 and KG-05, approved on
/// #893; UC-2.6 wires it), `filename_mismatch` and `metadata_recommended` in
/// place of the editor's `filename_slug`, `missing_author`,
/// `missing_organisation` and `recommended_field_missing`. The checks are
/// the ones `lint.toml` enables, at its severities; the other files of the
/// folder are read for the stems they hold, so a name another object has is
/// expected with its UUID's prefix, as `lint` expects it. A file that is not
/// directly in an object folder has none.
pub fn lint_file(
    fs: &dyn FileSystem,
    root: &Path,
    config: &LintConfig,
    file: &Path,
) -> Vec<LintFinding> {
    editor_findings(
        fs,
        root,
        config,
        Some(&[file.to_path_buf()]),
        &Parses::new(),
    )
}

/// [`lint_file`] on `files`, or on every object file for `None`, in one
/// run, reading the files `parses` holds from there.
fn editor_findings(
    fs: &dyn FileSystem,
    root: &Path,
    config: &LintConfig,
    files: Option<&[PathBuf]>,
    parses: &Parses,
) -> Vec<LintFinding> {
    let checks: Vec<LintCheck> = enabled_checks(config)
        .into_iter()
        .filter(|check| matches!(check, LintCheck::Filenames | LintCheck::Metadata))
        .collect();
    if checks.is_empty() || files.is_some_and(<[PathBuf]>::is_empty) {
        return Vec::new();
    }
    let options = LintOptions {
        checks,
        files: files
            .unwrap_or_default()
            .iter()
            .map(|file| file.to_string_lossy().into_owned())
            .collect(),
        cwd: root.to_path_buf(),
        ..LintOptions::default()
    };
    let report = lint_with(fs, None, root, config, &options, parses);
    report
        .findings
        .into_iter()
        .filter(|finding| matches!(finding.code(), codes::FILENAME | codes::METADATA))
        .collect()
}

fn check_severity(config: &LintConfig, check: LintCheck) -> Option<&str> {
    config
        .checks
        .iter()
        .find(|(name, _)| name == check.name())
        .and_then(|(_, own)| own.severity.as_deref())
}

/// The checks `lint.toml` enables, in their order.
pub fn enabled_checks(config: &LintConfig) -> Vec<LintCheck> {
    LintCheck::ALL
        .into_iter()
        .filter(|check| {
            config
                .checks
                .iter()
                .find(|(name, _)| name == check.name())
                .is_none_or(|(_, own)| own.enabled)
        })
        .collect()
}

/// The object files of each family folder under `objects/` (debug output
/// included, which the filenames check names), and the YAML files in their
/// subfolders.
fn object_files(fs: &dyn FileSystem, root: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let objects = root.join("objects");
    if !fs.is_dir(&objects) {
        return (Vec::new(), Vec::new());
    }
    let mut files = Vec::new();
    let mut nested = Vec::new();
    for family in OBJECT_FAMILIES {
        if let Ok(scan) = discover::scan_including_debug(fs, &objects.join(family)) {
            files.extend(scan.files);
            nested.extend(scan.nested);
        }
    }
    (files, nested)
}

/// The files a narrowed run reports on.
#[derive(Debug, Clone)]
struct Narrowed {
    label: &'static str,
    files: Vec<PathBuf>,
    flags: Vec<String>,
    warning: Option<String>,
}

fn narrow(
    fs: &dyn FileSystem,
    target: &Path,
    candidates: &[PathBuf],
    options: &LintOptions<'_>,
) -> Result<Option<Narrowed>, Box<LintReport>> {
    if options.changed.is_some() && !options.files.is_empty() {
        return Err(Box::new(LintReport::refused(
            target,
            Vec::new(),
            "--changed cannot be combined with --file".to_owned(),
            2,
        )));
    }
    if !options.files.is_empty() {
        let cwd = fs.resolve(&options.cwd);
        let mut roots = vec![target.to_path_buf()];
        if cwd != target {
            roots.push(cwd);
        }
        let selection = Selection {
            files: options.files.clone(),
            ..Selection::default()
        };
        let scope = Scope::narrow(fs, &selection, &roots);
        let objects_dir = target.join("objects");
        let objects: Vec<&Path> = candidates
            .iter()
            .filter(|path| path.parent().and_then(Path::parent) == Some(objects_dir.as_path()))
            .map(PathBuf::as_path)
            .collect();
        let unmatched = scope.unmatched_file_targets(fs, &objects);
        if !unmatched.is_empty() {
            let folders = OBJECT_FAMILIES
                .iter()
                .map(|family| format!("objects/{family}"))
                .collect::<Vec<_>>()
                .join(", ");
            let mut refused = LintReport::refused(
                target,
                Vec::new(),
                format!(
                    "No object file directly in {folders} matched: {}",
                    unmatched.join(", ")
                ),
                1,
            );
            refused.unmatched = unmatched;
            return Err(Box::new(refused));
        }
        let files = candidates
            .iter()
            .filter(|path| scope.matches_file(fs, path))
            .cloned()
            .collect();
        let flags = options
            .files
            .iter()
            .flat_map(|raw| ["--file".to_owned(), raw.clone()])
            .collect();
        return Ok(Some(Narrowed {
            label: "selected",
            files,
            flags,
            warning: None,
        }));
    }
    match &options.changed {
        None => Ok(None),
        Some(Changed::Failed(message)) => Err(Box::new(LintReport::refused(
            target,
            Vec::new(),
            message.clone(),
            1,
        ))),
        Some(Changed::Files { files, warning }) => Ok(Some(Narrowed {
            label: "changed",
            files: candidates
                .iter()
                .filter(|path| files.contains(path))
                .cloned()
                .collect(),
            flags: vec!["--changed".to_owned()],
            warning: warning.clone(),
        })),
    }
}

/// `text` split where YAML breaks lines, without the breaks.
fn lines(text: &str) -> Vec<&str> {
    crate::fix::split_keeping_breaks(text)
        .into_iter()
        .map(|line| line.trim_end_matches(['\r', '\n']))
        .collect()
}

/// A trimmed string with something in it (`_as_str`).
fn as_str(node: Option<&Node>) -> Option<String> {
    node.and_then(|node| node.value.as_str())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn load_record(
    fs: &dyn FileSystem,
    root: &Path,
    path: &Path,
    parsed: Option<&std::sync::Arc<node::Document>>,
) -> Record {
    let relative = path.strip_prefix(root).map_or_else(|_| posix(path), posix);
    let parts: Vec<&str> = relative.split('/').collect();
    let kind = (parts.len() == 3 && parts[0] == "objects").then(|| parts[1].to_owned());
    let mut record = Record {
        path: path.to_path_buf(),
        relative,
        kind,
        ..Record::default()
    };
    if let Some(document) = parsed {
        return read_document(record, document.source().to_owned(), document);
    }
    let bytes = match fs.read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            record.parse_error = Some(error.to_string());
            return record;
        }
    };
    let body = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    let text = match std::str::from_utf8(body) {
        Ok(text) => text.to_owned(),
        Err(error) => {
            record.parse_error = Some(crate::load::not_utf8_problem(body, error.valid_up_to()));
            return record;
        }
    };
    let document = match node::load(&text) {
        Ok(document) => document,
        Err(error) => {
            let mut problem = error.problem.clone();
            if let Some(mark) = error.mark {
                problem.push_str(&format!(" at line {}, column {}", mark.line, mark.column));
                record.parse_position = Some((mark.line, mark.column));
            }
            record.parse_error = Some(problem);
            return record;
        }
    };
    read_document(record, text, &document)
}

/// The record of a file whose `text` parsed to `document`.
fn read_document(mut record: Record, text: String, document: &node::Document) -> Record {
    record.key_lines = top_level_key_lines(&text);
    record.placeholders = placeholder_lines(&text);
    record.text = Some(text);
    if let Some(problem) = crate::load::root_mapping_problem(document) {
        record.parse_error = Some(problem);
        return record;
    }
    let Some(root_node) = document.root() else {
        return record;
    };
    record.name = as_str(root_node.get("name").map(AsRef::as_ref));
    if let Some(metadata) = root_node.get("metadata")
        && matches!(metadata.value, Value::Map(_))
    {
        record.uuid = as_str(metadata.get("uuid").map(AsRef::as_ref));
        record.schema = as_str(metadata.get("schema").map(AsRef::as_ref));
        record.metadata = Some(std::sync::Arc::clone(metadata));
    }
    record
}

/// A top-level key: at column 0, optionally quoted, then a colon.
fn top_level_key() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        #[expect(clippy::expect_used, reason = "a literal pattern")]
        regex::Regex::new(r#"^(?:"([^"]+)"|'([^']+)'|([A-Za-z_][\w.-]*))\s*:(?:\s|$)"#)
            .expect("the pattern compiles")
    })
}

/// The zero-based line of each top-level key, read from the text: the first
/// time each is written.
fn top_level_key_lines(text: &str) -> IndexMap<String, usize> {
    let mut found = IndexMap::new();
    for (number, line) in lines(text).into_iter().enumerate() {
        if let Some(captures) = top_level_key().captures(line)
            && let Some(key) = (1..=3).find_map(|group| captures.get(group))
        {
            found.entry(key.as_str().to_owned()).or_insert(number);
        }
    }
    found
}

struct Patterns {
    placeholder: regex::Regex,
    marked_key: regex::Regex,
    item: regex::Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: std::sync::OnceLock<Patterns> = std::sync::OnceLock::new();
    PATTERNS.get_or_init(|| {
        #[expect(clippy::expect_used, reason = "literal patterns")]
        Patterns {
            placeholder: regex::Regex::new(r"\s#\s*opentide:placeholder\s*$")
                .expect("the pattern compiles"),
            marked_key: regex::Regex::new(
                r"^(?P<lead>\s*(?:-\s+)?)(?P<key>[A-Za-z_][\w.-]*)\s*:(?:\s+|$)",
            )
            .expect("the pattern compiles"),
            item: regex::Regex::new(r"^(?P<lead>(?P<indent>\s*)-\s+)")
                .expect("the pattern compiles"),
        }
    })
}

/// Code points in `text[..byte]`.
fn chars_before(text: &str, byte: usize) -> usize {
    text[..byte].chars().count()
}

/// `text` without leading whitespace.
fn lstrip(text: &str) -> &str {
    text.trim_start()
}

/// `surface[0]`: the key that owns the item on line `number`, and its index.
fn list_item_label(lines: &[&str], number: usize, indent: usize) -> String {
    let mut index = 0;
    for previous in (0..number).rev() {
        let text = lines[previous];
        let stripped = lstrip(text);
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let current = text.chars().count() - stripped.chars().count();
        if current == indent && stripped.starts_with('-') {
            index += 1;
            continue;
        }
        if current < indent {
            if let Some(key) = patterns().marked_key.captures(text) {
                return format!("{}[{index}]", &key["key"]);
            }
            break;
        }
    }
    format!("list item {index}")
}

/// Each placeholder marker: its line, what holds it, and the columns of the
/// value. A block scalar (`description: |`) points at its key, since the
/// value starts on the next line.
fn placeholder_lines(text: &str) -> Vec<Marked> {
    let all = lines(text);
    let mut marked = Vec::new();
    for (number, line) in all.iter().enumerate() {
        let Some(comment) = patterns().placeholder.find(line) else {
            continue;
        };
        let content = line[..comment.start()].trim_end();
        let (start, end, label) = if let Some(key) = patterns().marked_key.captures(content) {
            let whole = key.get(0).map_or(0, |m| m.end());
            let name = key.name("key").map_or((0, 0), |m| (m.start(), m.end()));
            let rest = &content[whole..];
            if ["", "|", ">", "|-", ">-"].contains(&rest) {
                (
                    chars_before(content, name.0),
                    chars_before(content, name.1),
                    key["key"].to_owned(),
                )
            } else {
                (
                    chars_before(content, whole),
                    content.chars().count(),
                    key["key"].to_owned(),
                )
            }
        } else if let Some(item) = patterns().item.captures(content) {
            let lead = item.get(0).map_or(0, |m| m.end());
            let indent = item
                .name("indent")
                .map_or(0, |m| m.as_str().chars().count());
            (
                chars_before(content, lead),
                content.chars().count(),
                list_item_label(&all, number, indent),
            )
        } else {
            let total = content.chars().count();
            (
                total - lstrip(content).chars().count(),
                total,
                "value".to_owned(),
            )
        };
        marked.push(Marked {
            line: number,
            label,
            column: start + 1,
            end_column: end.max(start + 1) + 1,
        });
    }
    marked
}

/// A finding before its diagnostic fields: the oracle's dict, in order.
#[derive(Debug, Clone)]
struct Draft {
    check: LintCheck,
    severity: String,
    path: String,
    yaml_line: Option<usize>,
    uuid: Option<String>,
    /// Keys between `uuid` and `message` (`expected`, `help`, `line`, ...).
    extra: Vec<(&'static str, Json)>,
    message: String,
    /// `fixed` and `from`, after `message`, when `--fix` acted.
    fix_keys: Vec<(&'static str, Json)>,
    code: &'static str,
    field_path: Vec<String>,
    /// The parser's position of a file that does not parse.
    position: Option<(usize, usize)>,
}

impl Draft {
    fn new(
        check: LintCheck,
        severity: &str,
        record: &Record,
        message: String,
        code: &'static str,
        field: Option<&str>,
        yaml_line: Option<usize>,
    ) -> Self {
        Self {
            check,
            severity: severity.to_owned(),
            path: record.relative.clone(),
            yaml_line,
            uuid: record.uuid.clone(),
            extra: Vec::new(),
            message,
            fix_keys: Vec::new(),
            code,
            field_path: field
                .map(|field| vec![field.to_owned()])
                .unwrap_or_default(),
            position: None,
        }
    }

    fn extra(&self, key: &str) -> Option<&Json> {
        self.extra
            .iter()
            .chain(&self.fix_keys)
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    }

    fn fixed(&self) -> bool {
        self.extra("fixed") == Some(&Json::Bool(true))
    }

    /// The JSON entry and the diagnostic (`_add_diagnostic_fields`,
    /// `diagnostic_from_lint_finding`).
    fn finish(self, root: &Path, sources: &mut Sources<'_>) -> LintFinding {
        let diagnostic = self.diagnostic(root, sources);
        let mut json = IndexMap::new();
        json.insert("check".to_owned(), json!(self.check.name()));
        json.insert("severity".to_owned(), json!(self.severity));
        json.insert("path".to_owned(), json!(self.path));
        json.insert("yaml_line".to_owned(), json!(self.yaml_line));
        json.insert("uuid".to_owned(), json!(self.uuid));
        for (key, value) in &self.extra {
            json.insert((*key).to_owned(), value.clone());
        }
        json.insert("message".to_owned(), json!(self.message));
        for (key, value) in &self.fix_keys {
            json.insert((*key).to_owned(), value.clone());
        }
        json.insert("code".to_owned(), json!(self.code));
        json.insert("field_path".to_owned(), json!(self.field_path));
        if let Some((line, column)) = self.position {
            json.insert("line".to_owned(), json!(line));
            json.insert("column".to_owned(), json!(column));
        }
        annotate(&mut json, &diagnostic);
        LintFinding {
            check: self.check,
            json,
            diagnostic,
        }
    }

    fn diagnostic(&self, root: &Path, sources: &mut Sources<'_>) -> Diagnostic {
        let file_path = root.join(&self.path);
        let as_usize = |key: &str| {
            self.extra(key)
                .and_then(Json::as_u64)
                .and_then(|v| usize::try_from(v).ok())
        };
        let mut line = self
            .position
            .map(|(line, _)| line)
            .or_else(|| as_usize("line"));
        let mut column = self
            .position
            .map(|(_, column)| column)
            .or_else(|| as_usize("column"));
        let mut end_column = as_usize("end_column");
        let mut end_line = as_usize("end_line");
        if column.is_some() && end_column.is_none() {
            end_column = column.map(|column| column + 1);
        }
        if line.is_none()
            && let Some(yaml_line) = self.yaml_line
        {
            line = Some(yaml_line + 1);
            if let (Some(text), Some(key)) = (
                sources.line(&file_path, yaml_line + 1),
                self.field_path.first(),
            ) && let Some(found) = text.find(key.as_str())
            {
                let start = chars_before(&text, found) + 1;
                column = Some(start);
                end_column = Some(start + key.chars().count());
            }
        }
        let mut message = self.message.clone();
        let mut notes: Vec<(String, String)> = Vec::new();
        if self.code == codes::PARSE
            && let Some((problem, span, parse_notes)) = sources.yaml_problem(&file_path)
        {
            message = problem;
            line = Some(span.line);
            column = Some(span.column);
            end_column = Some(span.end_column);
            end_line = None;
            notes.extend(parse_notes);
        }
        let expected = self.extra("expected").and_then(Json::as_str);
        let help = if self.code == codes::FILENAME && expected.is_some() && !self.fixed() {
            expected.map(|expected| format!("rename it to {expected}"))
        } else if self.code == codes::NAME {
            Some("add a name: the file name is derived from it".to_owned())
        } else if self.code == codes::METADATA {
            Some("add the missing keys under metadata".to_owned())
        } else {
            self.extra("help")
                .and_then(Json::as_str)
                .filter(|help| !help.is_empty())
                .map(str::to_owned)
        };
        if self.fixed()
            && let Some(from) = self.extra("from").and_then(Json::as_str)
        {
            notes.push(("note".to_owned(), format!("renamed from {from}")));
        }
        let mut diagnostic = Diagnostic::new(
            self.code,
            Severity::parse(&self.severity).unwrap_or(Severity::Warning),
            message,
        )
        .file(file_path)
        .at(self.field_path.iter().cloned());
        diagnostic.object_uuid = self.uuid.clone().unwrap_or_default();
        diagnostic.yaml_line = self.yaml_line;
        diagnostic.path = Some(self.path.clone());
        diagnostic.line = line;
        diagnostic.column = column;
        diagnostic.end_line = end_line.filter(|end| Some(*end) != line).or(line);
        diagnostic.end_column = end_column;
        diagnostic.help = help;
        diagnostic.notes = notes;
        diagnostic
    }
}

/// Adds the diagnostic fields a finding does not have yet (`annotate`:
/// `setdefault`), in their order.
fn annotate(json: &mut IndexMap<String, Json>, diagnostic: &Diagnostic) {
    let fields = [
        ("path", json!(diagnostic.path)),
        ("line", json!(diagnostic.line)),
        ("column", json!(diagnostic.column)),
        ("end_line", json!(diagnostic.end_line)),
        ("end_column", json!(diagnostic.end_column)),
        ("help", json!(diagnostic.help)),
        (
            "fix",
            serde_json::to_value(&diagnostic.fix).unwrap_or(Json::Null),
        ),
        ("explain", json!(diagnostic.explain())),
    ];
    for (key, value) in fields {
        json.entry(key.to_owned()).or_insert(value);
    }
}

/// Whether `metadata.<key>` holds a value an author filled in.
fn has_metadata(record: &Record, key: &str) -> bool {
    let Some(metadata) = &record.metadata else {
        return false;
    };
    if key == "organisation" {
        let named = |node: Option<&std::sync::Arc<Node>>| {
            node.is_some_and(|node| {
                as_str(Some(node)).is_some()
                    || matches!(node.value, Value::Map(_))
                        && as_str(node.get("name").map(AsRef::as_ref)).is_some()
            })
        };
        return named(metadata.get("organisation")) || named(metadata.get("organization"));
    }
    match metadata.get(key).map(|node| &node.value) {
        None | Some(Value::Null) => false,
        Some(Value::Str(text)) => !text.trim().is_empty(),
        Some(Value::Seq(items)) => !items.is_empty(),
        Some(Value::Map(entries)) => !entries.is_empty(),
        Some(_) => true,
    }
}

/// The YAML keys the `metadata` block of the revision `schema` accepts, or
/// `None` when opentide does not know the revision.
fn schema_metadata_keys(schema: &str) -> Option<Vec<String>> {
    let revision = crate::validate::objects::revision_schema(schema)?;
    let metadata = revision.pointer("/properties/metadata")?;
    let resolved = match metadata.get("$ref").and_then(Json::as_str) {
        Some(reference) => {
            let name = reference.rsplit('/').next()?;
            revision.get("$defs")?.get(name)?
        }
        None => metadata,
    };
    let properties = resolved.get("properties")?.as_object()?;
    Some(properties.keys().cloned().collect())
}

fn metadata_findings<'r>(
    records: impl Iterator<Item = &'r Record>,
    required: &[String],
) -> Vec<Draft> {
    if required.is_empty() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for record in records {
        if record.parse_error.is_some() || record.name.is_none() {
            continue;
        }
        let accepted = record.schema.as_deref().and_then(schema_metadata_keys);
        let missing: Vec<&str> = required
            .iter()
            .filter(|key| accepted.as_ref().is_none_or(|keys| keys.contains(key)))
            .filter(|key| !has_metadata(record, key))
            .map(String::as_str)
            .collect();
        if missing.is_empty() {
            continue;
        }
        findings.push(Draft::new(
            LintCheck::Metadata,
            "info",
            record,
            format!("Recommended metadata missing: {}", missing.join(", ")),
            codes::METADATA,
            Some("metadata"),
            record.key_lines.get("metadata").copied(),
        ));
    }
    findings
}

fn placeholder_findings<'r>(records: impl Iterator<Item = &'r Record>) -> Vec<Draft> {
    let mut findings = Vec::new();
    for record in records {
        if record.parse_error.is_some() {
            continue;
        }
        for marked in &record.placeholders {
            let mut draft = Draft::new(
                LintCheck::Placeholders,
                "warning",
                record,
                format!(
                    "{} holds a placeholder value written by opentide new",
                    marked.label
                ),
                codes::PLACEHOLDER,
                None,
                Some(marked.line),
            );
            draft.extra = vec![
                ("help", json!(PLACEHOLDER_HELP)),
                ("line", json!(marked.line + 1)),
                ("column", json!(marked.column)),
                ("end_column", json!(marked.end_column)),
            ];
            findings.push(draft);
        }
    }
    findings
}

/// What a stem claims in its folder: debug or not, and the stem whatever its
/// case.
fn stem_key(path: &Path, stem: &str) -> (bool, String) {
    (stems::is_debug_path(path), stem.to_lowercase())
}

/// Gives each named object the stem its file should have, unique within its
/// folder: a stem already in use claims itself first; another object that
/// wants it gets `-{uuid[:8]}`.
fn assign_expected_stems(records: &mut [Record], filenames: &FilenameConfig) {
    let mut groups: IndexMap<PathBuf, Vec<usize>> = IndexMap::new();
    for (index, record) in records.iter().enumerate() {
        if record.parse_error.is_some() {
            continue;
        }
        let parent = record
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        groups.entry(parent).or_default().push(index);
    }
    for group in groups.values() {
        let mut taken: std::collections::HashSet<(bool, String)> = std::collections::HashSet::new();
        let config = stems::for_kind(filenames, records[group[0]].kind.as_deref());
        for &index in group {
            let record = &mut records[index];
            let stem = object_stem(&record.path);
            if let Some(name) = &record.name
                && expected_stem(name, &config.style).as_deref() == Some(stem.as_str())
            {
                taken.insert(stem_key(&record.path, &stem));
                record.expected_stem = Some(stem);
            }
        }
        for &index in group {
            let record = &mut records[index];
            if record.expected_stem.is_some() {
                continue;
            }
            let Some(name) = &record.name else {
                continue;
            };
            let Some(stem) = expected_stem(name, &config.style) else {
                continue;
            };
            if !taken.contains(&stem_key(&record.path, &stem)) {
                taken.insert(stem_key(&record.path, &stem));
                record.expected_stem = Some(stem);
                continue;
            }
            let suffix: String = record
                .uuid
                .as_deref()
                .unwrap_or("object")
                .chars()
                .take(8)
                .collect();
            let mut candidate = format!("{stem}-{suffix}");
            let mut counter = 1;
            while taken.contains(&stem_key(&record.path, &candidate)) {
                candidate = format!("{stem}-{suffix}-{counter}");
                counter += 1;
            }
            taken.insert(stem_key(&record.path, &candidate));
            record.expected_stem = Some(candidate);
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(|_| posix(path), posix)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn filename_findings(
    fs: &dyn FileSystem,
    writer: Option<&dyn WriteFs>,
    root: &Path,
    records: &mut [Record],
    filenames: &FilenameConfig,
    reported: Option<&Vec<PathBuf>>,
) -> Vec<Draft> {
    use opentide_schema::vocab::quote;
    let mut findings = Vec::new();
    assign_expected_stems(records, filenames);
    for record in records.iter() {
        if reported.is_some_and(|files| !files.contains(&record.path)) {
            continue;
        }
        let config = stems::for_kind(filenames, record.kind.as_deref());
        if let Some(error) = &record.parse_error {
            let mut draft = Draft::new(
                LintCheck::Filenames,
                "error",
                record,
                format!("Could not parse object YAML: {error}"),
                codes::PARSE,
                None,
                None,
            );
            draft.position = record.parse_position;
            findings.push(draft);
            continue;
        }
        let mut current = record.path.clone();
        if record.name.is_none() {
            let what = if config.style == "slug" { " slug" } else { "" };
            findings.push(Draft::new(
                LintCheck::Filenames,
                "error",
                record,
                format!("Object has no name; cannot check filename{what}"),
                codes::NAME,
                Some("name"),
                record.key_lines.get("name").copied(),
            ));
        } else if let Some(expected) = &record.expected_stem
            && *expected != object_stem(&record.path)
        {
            // The suffix stays whole: `x.debug.yaml` becomes `B.debug.yaml`.
            let dest = with_object_stem(&record.path, expected);
            let message = if config.style == "slug" {
                format!(
                    "Filename {} does not match slugify(name)={}",
                    quote(&file_name(&record.path)),
                    quote(expected)
                )
            } else {
                format!(
                    "Filename {} does not match name: expected {}",
                    quote(&file_name(&record.path)),
                    quote(expected)
                )
            };
            let dest_relative = relative(root, &dest);
            let mut draft = Draft::new(
                LintCheck::Filenames,
                "warning",
                record,
                message,
                codes::FILENAME,
                None,
                None,
            );
            draft.extra = vec![("expected", json!(dest_relative))];
            if let Some(writer) = writer {
                if fs.kind(&dest).is_ok() && !case_only_rename(writer, &record.path, &dest) {
                    draft.fix_keys.push(("fixed", json!(false)));
                    draft.message = format!(
                        "{}; --fix skipped because {dest_relative} exists",
                        draft.message
                    );
                } else if writer.rename_file(&record.path, &dest).is_ok() {
                    draft.fix_keys.push(("fixed", json!(true)));
                    draft.fix_keys.push(("from", json!(record.relative)));
                    draft.path = dest_relative;
                    current = dest;
                } else {
                    draft.fix_keys.push(("fixed", json!(false)));
                }
            }
            findings.push(draft);
        }
        if let Some(pattern) = &config.regex
            && !pattern.is_match(&object_stem(&current))
        {
            let mut draft = Draft::new(
                LintCheck::Filenames,
                "warning",
                record,
                format!(
                    "Filename {} does not match the configured filename pattern",
                    quote(&file_name(&current))
                ),
                codes::FILENAME_PATTERN,
                None,
                None,
            );
            draft.extra = vec![(
                "help",
                json!(format!(
                    "rename the file so its name matches the pattern {}",
                    config.pattern.as_deref().unwrap_or_default()
                )),
            )];
            findings.push(draft);
        }
    }
    findings
}

/// Points earlier findings at the path `--fix` just renamed their file to.
fn rewrite_renamed_paths(findings: &mut [Draft]) {
    let renamed: Vec<(String, String)> = findings
        .iter()
        .filter(|draft| draft.fixed())
        .filter_map(|draft| {
            let from = draft.extra("from")?.as_str()?.to_owned();
            Some((from, draft.path.clone()))
        })
        .collect();
    for draft in findings {
        if let Some((_, to)) = renamed.iter().find(|(from, _)| *from == draft.path) {
            draft.path.clone_from(to);
        }
    }
}

/// One YAML file in a subfolder of an object folder.
fn nested_finding(root: &Path, path: &Path) -> Draft {
    let relative = relative(root, path);
    let folder = relative.split('/').take(2).collect::<Vec<_>>().join("/");
    Draft {
        check: LintCheck::Filenames,
        severity: "warning".to_owned(),
        path: relative.clone(),
        yaml_line: None,
        uuid: None,
        extra: Vec::new(),
        message: format!(
            "{relative} is in a subfolder of {folder} and is not an object instance: it is not \
             indexed, validated, shared, documented or deployed (opentide reads only files \
             directly in {folder}; see {NESTED_OBJECTS_ISSUE})"
        ),
        fix_keys: Vec::new(),
        code: codes::NESTED,
        field_path: Vec::new(),
        position: None,
    }
}

fn plural(count: usize, noun: &str) -> String {
    crate::fix::plural(count, noun)
}

/// `root` as `validate` shows it: `./` or `./sub` from inside, `..` above,
/// absolute elsewhere.
fn shown(root: &Path, cwd: &Path) -> String {
    if root == cwd {
        return "./".to_owned();
    }
    if let Ok(rest) = root.strip_prefix(cwd) {
        return format!("./{}", posix(rest));
    }
    if let Ok(rest) = cwd.strip_prefix(root) {
        let up = rest.components().count();
        return format!("{}/", vec![".."; up].join("/"));
    }
    posix(root)
}

/// `3 files clean` or `3 findings in 2 files · 1 warning, 2 notes · 1 fixed`.
fn outcome_line(
    left: &[&LintFinding],
    files: usize,
    fixed: usize,
    root: &Path,
    cwd: &Path,
) -> String {
    let sep = " · ";
    let done = if fixed > 0 {
        format!("{sep}{fixed} fixed")
    } else {
        String::new()
    };
    if left.is_empty() {
        if files == 0 {
            return format!(
                "Catalogue lint passed, but found no object files under {}",
                shown(root, cwd)
            );
        }
        return format!("{} clean{done}", plural(files, "file"));
    }
    let touched: std::collections::BTreeSet<&str> = left.iter().map(|f| f.path()).collect();
    let noun = if left.iter().all(|f| f.severity() == "info") {
        "note"
    } else {
        "finding"
    };
    let mut line = format!(
        "{} in {}",
        plural(left.len(), noun),
        plural(touched.len(), "file")
    );
    let kinds: Vec<String> = [("error", "error"), ("warning", "warning"), ("info", "note")]
        .iter()
        .filter_map(|(severity, noun)| {
            let count = left.iter().filter(|f| f.severity() == *severity).count();
            (count > 0).then(|| plural(count, noun))
        })
        .collect();
    if kinds.len() > 1 {
        line.push_str(sep);
        line.push_str(&kinds.join(", "));
    }
    line + &done
}

fn report(
    fs: &dyn FileSystem,
    target: &Path,
    checks: Vec<LintCheck>,
    findings: Vec<LintFinding>,
    scope: Option<Narrowed>,
    linted: usize,
    options: &LintOptions<'_>,
) -> LintReport {
    let left: Vec<&LintFinding> = findings.iter().filter(|f| !f.is_fixed()).collect();
    let status = if !left.is_empty() && options.strict {
        LintStatus::Failed
    } else if !left.is_empty() {
        LintStatus::Issues
    } else {
        LintStatus::Completed
    };
    let renamable = findings
        .iter()
        .filter(|f| {
            f.json
                .get("expected")
                .is_some_and(|e| !e.is_null() && e != "")
                && !f.is_fixed()
        })
        .count();
    let fixed = findings.iter().filter(|f| f.is_fixed()).count();
    let count = |severity: &str| left.iter().filter(|f| f.severity() == severity).count();
    let summary = LintSummary {
        files: linted,
        findings: left.len(),
        errors: count("error"),
        warnings: count("warning"),
        notes: count("info"),
        fixed,
    };
    let cwd = fs.resolve(&options.cwd);
    let mut outcome = outcome_line(&left, linted, fixed, target, &cwd);
    let mut warnings = Vec::new();
    let mut scope_label = None;
    let mut flags = Vec::new();
    if let Some(scope) = &scope {
        scope_label = Some(scope.label);
        flags.clone_from(&scope.flags);
        warnings.extend(scope.warning.clone());
        if linted == 0 && left.is_empty() {
            outcome = if scope.label == "changed" {
                "No changed object file to lint".to_owned()
            } else {
                "No object file to lint".to_owned()
            };
        }
    }
    let outcome_ok = status != LintStatus::Failed
        && !left.is_empty()
        && left.iter().all(|f| f.severity() == "info");
    let mut next_actions = Vec::new();
    if linted == 0 && scope.is_none() && !crate::root::is_workspace_root(fs, target) {
        next_actions = vec![NextAction {
            command: "opentide setup".to_owned(),
            reason: "no workspace here: create one".to_owned(),
        }];
    }
    if renamable > 0 {
        let narrowed = if flags.is_empty() {
            String::new()
        } else {
            format!(
                " {}",
                shlex::try_join(flags.iter().map(String::as_str)).unwrap_or_default()
            )
        };
        next_actions = vec![NextAction {
            command: format!("opentide lint --fix{narrowed}"),
            reason: format!(
                "rename {renamable} {} to match their names",
                if renamable == 1 { "file" } else { "files" }
            ),
        }];
    }
    LintReport {
        path: target.to_path_buf(),
        checks,
        message: if findings.is_empty() {
            "Catalogue lint passed".to_owned()
        } else {
            "Catalogue lint found issues".to_owned()
        },
        findings,
        fixed,
        status,
        exit_code: i32::from(status == LintStatus::Failed),
        failure_code: (status == LintStatus::Failed).then_some("issues_found"),
        summary: Some(summary),
        outcome: Some(outcome),
        outcome_ok,
        scope: scope_label,
        unmatched: Vec::new(),
        warnings,
        next_actions,
    }
}

impl crate::Workspace {
    /// [`lint_file`] on each of `files`, or on every object file for
    /// `None`, with this workspace's resolved `lint.toml`, in one run that
    /// reads the object files from this workspace's parse: what the language
    /// server reports for its open documents, and for every file when a
    /// client pulls the workspace's diagnostics. A `lint.toml` opentide
    /// cannot use gives none (`lint` refuses to run).
    pub fn editor_lint(&self, files: Option<&[PathBuf]>) -> Vec<LintFinding> {
        let Ok(config) = opentide_schema::configuration::lint::parse_lint_config(
            self.configuration().resolved.get("lint"),
        ) else {
            return Vec::new();
        };
        let parses: Parses = self
            .index()
            .sources
            .iter()
            .map(|source| (source.path.clone(), std::sync::Arc::clone(&source.document)))
            .collect();
        editor_findings(self.fs().as_ref(), self.root(), &config, files, &parses)
    }

    /// `lint` on this workspace, with its resolved `lint.toml`. A `lint.toml`
    /// opentide cannot use refuses the run (exit 2) with the key it names.
    pub fn lint(&self, writer: Option<&dyn WriteFs>, options: &LintOptions<'_>) -> LintReport {
        let root = self.root().to_path_buf();
        match opentide_schema::configuration::lint::parse_lint_config(
            self.configuration().resolved.get("lint"),
        ) {
            Ok(config) => lint(self.fs().as_ref(), writer, &root, &config, options),
            Err(error) => {
                let mut report = LintReport::refused(
                    &self.fs().resolve(&root),
                    options.checks.clone(),
                    error.to_string(),
                    2,
                );
                report.failure_code = None;
                report
            }
        }
    }
}
