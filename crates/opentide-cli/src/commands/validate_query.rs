//! `opentide validate query` offline (`cli/commands/validate.py`
//! `validate_query_cmd`, `cli/services/validation.py`
//! `validate_query_offline`): every query of the rule files directly in the
//! rules folder (or those `--changed`, `--file` and `--uuid` select), and
//! the query files `--file` names, checked by the query engines
//! ([`crate::queries`]). The engine's errors are the run's, as `validate`'s
//! queries check reports them; its warnings and notes are `lint`'s.
//!
//! `--live` on a platform whose tenants cannot check a query (CrowdStrike,
//! HarfangLab, Sysdig) answers `supported: false` here ([`live`], UC-4.2c,
//! #832); a `--live` run that sends queries to tenants stays on the Python
//! CLI, refused as `engine_not_ported` ([`LIVE_NOT_PORTED`]), which
//! `OPENTIDE_ENGINE=compare` hands to Python.

use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use opentide_analysis::{LanguageId, Severity as EngineSeverity};
use opentide_compile::plan::Scope;
use opentide_workspace::validate::QueriesMode;
use opentide_workspace::{FileSystem as _, OsFs, Workspace};

use super::findings;
use super::{Block, ISSUES_FOUND, Report, Terminal, placement};
use crate::env::Env;
use crate::envelope::{Failure, NextAction, USAGE_EXIT_CODE, code};
use crate::json::Json;
use crate::queries::{CheckedQuery, ENGINE, Finding, Profiles, REPORTED_AS_WARNING_NOTE};
use crate::render::diagnostic::{Diagnostic, Severity, SourceFiles, relative_path};
use crate::render::outcome::OutcomeKind;

/// The command's name in the envelope.
pub const COMMAND: &str = "validate query";

/// What a run with `--live` answers: the tenant check is Python's until
/// UC-4.1.
pub const LIVE_NOT_PORTED: &str = "opentide validate query with --live has no Rust \
     implementation yet: unset OPENTIDE_ENGINE, or set it to python or compare.";

/// The platforms the engine checks offline, each with the languages it
/// parses for it (`OFFLINE_QUERY_LANGUAGES`).
pub const OFFLINE_QUERY_LANGUAGES: [(&str, &[&str]); 7] = [
    ("carbon_black_cloud", &["lucene"]),
    ("crowdstrike", &["cql"]),
    ("defender_for_endpoint", &["kql"]),
    ("elastic", &["esql", "eql", "kuery", "lucene"]),
    ("sentinel", &["kql"]),
    ("splunk", &["spl"]),
    ("sysdig", &["falco"]),
];

/// The platforms whose queries a tenant checks (`QUERY_VALIDATION_PLATFORMS`).
pub const LIVE_QUERY_PLATFORMS: [&str; 6] = [
    "carbon_black_cloud",
    "defender_for_endpoint",
    "elastic",
    "sentinel",
    "sentinel_one",
    "splunk",
];

/// The extensions of a query file, each one query in the language it names.
pub const QUERY_FILE_SUFFIXES: [&str; 8] = [
    "kql", "spl", "esql", "eql", "kuery", "lucene", "falco", "cql",
];

/// The help of a rule file whose queries could not be read.
const UNREADABLE_HELP: &str =
    "opentide validate reports the file; fix it, then check its queries again";

/// What `--changed` advises when HEAD names no commit yet.
const NO_COMMITS_ADVICE: &str = "commit the rules, or drop --changed to check every rule";

/// `validate query`'s options.
#[derive(Clone, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the command line's flags, one field each"
)]
pub struct Args {
    /// `--platform`.
    pub platform: Option<String>,
    /// `--strategy`, repeatable.
    pub strategies: Vec<String>,
    /// `--plan`, removed: refused when given.
    pub plan: Option<String>,
    /// `--wide`.
    pub wide: bool,
    /// `--live`.
    pub live: bool,
    /// `--changed`.
    pub changed: bool,
    /// `--file`, repeatable.
    pub files: Vec<String>,
    /// `--uuid`, repeatable.
    pub uuids: Vec<String>,
    /// `--strict`.
    pub strict: bool,
    /// `--queries`, when given.
    pub queries: Option<QueriesMode>,
    /// `--check-timeout`.
    pub check_timeout: Option<String>,
}

/// What a run reads besides its options.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// `--repo`.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// The streams.
    pub terminal: &'a Terminal,
}

/// The languages the engine parses for `platform` offline; `None` when it
/// parses none of its queries.
pub fn offline_languages(platform: &str) -> Option<&'static [&'static str]> {
    OFFLINE_QUERY_LANGUAGES
        .iter()
        .find(|(name, _)| *name == platform)
        .map(|(_, languages)| *languages)
}

/// Whether `target` names a query file, by its extension (any case).
pub fn is_query_file(target: &str) -> bool {
    query_file_language(target).is_some()
}

/// The language a query file's extension names (`.KQL` as `.kql`).
pub fn query_file_language(target: &str) -> Option<LanguageId> {
    let extension = Path::new(target)
        .extension()?
        .to_str()?
        .to_ascii_lowercase();
    QUERY_FILE_SUFFIXES
        .contains(&extension.as_str())
        .then(|| LanguageId::from_extension(&extension))
        .flatten()
}

/// A failed result with the keys every refusal carries: `platform`, `mode`,
/// `supported`. Exit 2 is a usage error (`failure_code`).
fn refused(platform: Option<&str>, message: &str, exit_code: i32, failure_code: &str) -> Report {
    let failure = Failure::new(failure_code, message);
    let mut report = Report::failed(COMMAND, exit_code, failure);
    report.outcome.data = vec![
        (
            "platform".into(),
            Json::opt_str(platform.map(str::to_owned)),
        ),
        ("mode".into(), Json::str("offline")),
        ("supported".into(), Json::Bool(true)),
    ];
    report
}

/// A scope refusal (`_query_scope_refused`): exit 2 a usage error, exit 1
/// a run that could not read its scope.
fn scope_refused(platform: Option<&str>, message: &str, exit_code: i32) -> Report {
    let failure_code = if exit_code == USAGE_EXIT_CODE {
        code::USAGE_ERROR
    } else {
        super::COMMAND_FAILED
    };
    refused(platform, message, exit_code, failure_code)
}

/// A usage error of the command's options: exit 2, no keys of its own.
fn usage(message: impl Into<String>, argument: &str, failure_code: &str) -> Report {
    let mut failure = Failure::new(failure_code, message);
    failure.argument = Some(argument.to_owned());
    Report::failed(COMMAND, USAGE_EXIT_CODE, failure)
}

/// The usage errors the options make offline, before anything runs.
pub fn refuse(args: &Args) -> Option<Report> {
    if let Some(plan) = &args.plan {
        return Some(usage(
            opentide_compile::strategy::removed_plan_message(Some(plan), true),
            "--plan",
            code::USAGE_INVALID_VALUE,
        ));
    }
    if args.queries == Some(QueriesMode::Off) {
        return Some(usage(
            "--queries off skips the queries check, which is all validate query runs",
            "--queries",
            code::USAGE_ERROR,
        ));
    }
    for (flag, used) in [
        ("--strategy", !args.strategies.is_empty()),
        ("--wide", args.wide),
    ] {
        if used {
            return Some(usage(
                format!(
                    "{flag} chooses tenants, so it applies to --live; the offline check reads \
                     every query whatever its status"
                ),
                flag,
                code::USAGE_ERROR,
            ));
        }
    }
    if args.check_timeout.is_some() {
        return Some(usage(
            "--check-timeout is how long a tenant may take, so it applies to --live",
            "--check-timeout",
            code::USAGE_ERROR,
        ));
    }
    None
}

/// The platforms whose `--live` run is this engine's: those whose tenants
/// cannot check a query, answered `supported: false` before any request
/// (`opentide.cli.engines.RUST_LIVE_VALIDATION_PLATFORMS`). Defender,
/// Elastic and SentinelOne check on the tenant: still the Python CLI's.
pub const LIVE_RUST_PLATFORMS: [&str; 3] = ["crowdstrike", "harfanglab", "sysdig"];

/// `validate query --live` (`validate_query_cmd`'s `--live` branch, then
/// `_validate_query_platform`): the usage errors, then a platform whose
/// tenants check no query answers `supported: false`. A run that sends
/// queries to tenants is refused as `engine_not_ported`.
pub fn live(args: &Args, env: &Env) -> Report {
    if let Some(plan) = &args.plan {
        return usage(
            opentide_compile::strategy::removed_plan_message(Some(plan), true),
            "--plan",
            code::USAGE_INVALID_VALUE,
        );
    }
    if args.queries == Some(QueriesMode::Off) {
        return usage(
            "--queries off skips the queries check, which is all validate query runs",
            "--queries",
            code::USAGE_ERROR,
        );
    }
    let (raw, source) = match &args.check_timeout {
        Some(value) => (Some(value.as_str()), "--check-timeout"),
        None => (
            env.get(CHECK_TIMEOUT_ENV)
                .filter(|value| !value.trim().is_empty()),
            CHECK_TIMEOUT_ENV,
        ),
    };
    if let Some(raw) = raw {
        let seconds = raw.trim().parse::<f64>().unwrap_or(f64::NAN);
        if !seconds.is_finite() || seconds <= 0.0 {
            return usage(
                format!(
                    "{source} must be a positive number of seconds, got {}",
                    opentide_connectors::python::python_string_repr(raw)
                ),
                source,
                code::USAGE_INVALID_VALUE,
            );
        }
    }
    for (flag, used) in [
        ("--strict", args.strict),
        ("--queries", args.queries.is_some()),
    ] {
        if used {
            return usage(
                format!("{flag} applies to the offline check: a tenant accepts or rejects a query"),
                flag,
                code::USAGE_ERROR,
            );
        }
    }
    if args.files.iter().any(|target| is_query_file(target)) {
        return usage(
            "a query file is checked offline: --live sends the queries of rules to tenants",
            "--file",
            code::USAGE_ERROR,
        );
    }
    match args.platform.as_deref() {
        Some(platform) if LIVE_RUST_PLATFORMS.contains(&platform) => {
            let message = format!("query validation not supported for {platform}");
            let mut report = Report::error(COMMAND, message);
            let data = vec![
                ("platform".to_owned(), Json::str(platform)),
                ("valid".to_owned(), Json::Null),
                ("supported".to_owned(), Json::Bool(false)),
            ];
            // The envelope writes `error` after the message.
            report.outcome.data = data;
            report
        }
        _ => live_not_ported(),
    }
}

/// `OPENTIDE_QUERY_CHECK_TIMEOUT`: the check timeout when `--check-timeout`
/// gives none (`CHECK_TIMEOUT_ENV`).
pub const CHECK_TIMEOUT_ENV: &str = "OPENTIDE_QUERY_CHECK_TIMEOUT";

/// The refusal of a `--live` run: Python's (`engine_not_ported`).
pub fn live_not_ported() -> Report {
    let mut failure = Failure::new(code::ENGINE_NOT_PORTED, LIVE_NOT_PORTED);
    failure.argument = Some("OPENTIDE_ENGINE".into());
    Report::failed(COMMAND, USAGE_EXIT_CODE, failure)
}

/// One checked query: the rule or query file it is in, as shown and on disk.
struct Check {
    /// The file on disk.
    file_path: PathBuf,
    /// As the result shows it.
    path: String,
    query: CheckedQuery,
}

/// Logs the object files the workspace's index could not load, as the
/// oracle's registry did when the rules folder was first read
/// (`malformed_object_yaml`, `unreadable_object_file`,
/// `missing_identifier_from_model`).
fn log_load_errors(ws: &Workspace, cwd: &Path) {
    let cwd = OsFs.resolve(cwd);
    for error in &ws.index().load_errors {
        if error.code == opentide_workspace::index::MISSING_UUID {
            tracing::error!(
                file = %error.path.display(),
                "missing_identifier_from_model"
            );
            continue;
        }
        let shown = OsFs.resolve(&error.path).strip_prefix(&cwd).map_or_else(
            |_| error.path.to_string_lossy().into_owned(),
            opentide_workspace::index::posix,
        );
        if error.failure == Some(opentide_workspace::load::FailureKind::Unreadable) {
            tracing::error!(path = %shown, error = %error.error, "unreadable_object_file");
        } else {
            tracing::error!(path = %shown, error = %error.error, "malformed_object_yaml");
        }
    }
}

/// The changed rule files (`changed_rule_scope`), with the warning a
/// checkout without commits gives; `Err` with the run's message.
fn changed_scope(
    root: &Path,
    rules: &Path,
    folder: &str,
    cwd: &Path,
    env: &Env,
) -> Result<(Scope, Option<String>), String> {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let workspace = OsFs.resolve(root);
    let source = opentide_compile::git::diff_source(&lookup);
    let changed = opentide_compile::git::changed_paths(&workspace, cwd, &lookup, source).map_err(
        |error| match error {
            opentide_compile::git::GitError::MissingCheckout(searched) => format!(
                "--changed needs a git checkout; no .git was found from {}",
                searched.display()
            ),
            opentide_compile::git::GitError::Failed(message) => message,
        },
    )?;
    let (top, nested) = opentide_compile::git::split_rule_paths(&changed, folder);
    let files = top
        .iter()
        .filter_map(|path| Path::new(path).file_name().map(|name| rules.join(name)))
        .collect();
    tracing::info!(rules = top.len(), "query_scope_changed");
    let warning = opentide_compile::git::no_commits_warning(&workspace, &lookup, NO_COMMITS_ADVICE);
    Ok((Scope { files, nested }, warning))
}

/// Why a rule file has no query the engine could read: not readable, not
/// UTF-8 or not YAML (`_unreadable`); `None` when it is YAML.
fn unreadable_rule(
    bytes: Result<Vec<u8>, String>,
) -> Option<(String, Option<usize>, Option<usize>)> {
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(problem) => return Some((problem, None, None)),
    };
    let body = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        Err(error) => {
            return Some((
                opentide_workspace::load::not_utf8_problem(body, error.valid_up_to()),
                None,
                None,
            ));
        }
    };
    match opentide_schema::node::load(text) {
        Ok(_) => None,
        Err(error) => Some((
            error.problem,
            error.mark.map(|mark| mark.line),
            error.mark.map(|mark| mark.column),
        )),
    }
}

/// An I/O error in the words the operating system gives, without Rust's
/// `(os error N)`.
fn os_problem(error: &std::io::Error) -> String {
    let text = error.to_string();
    match text.rfind(" (os error ") {
        Some(at) if text.ends_with(')') => text[..at].to_owned(),
        _ => text,
    }
}

/// An engine finding as a diagnostic (`diagnostic_from_engine`), reported
/// as `--queries` says: an error, or a warning with a note.
fn engine_diagnostic(
    finding: &Finding,
    file_path: &Path,
    path: &str,
    queries: QueriesMode,
) -> Diagnostic {
    let warn = queries == QueriesMode::Warn;
    let mut diagnostic = Diagnostic::new(
        &finding.code,
        if warn {
            Severity::Warning
        } else {
            Severity::Error
        },
        &finding.message,
    );
    diagnostic.path = Some(path.to_owned());
    diagnostic.file_path = Some(file_path.to_path_buf());
    diagnostic.line = Some(finding.line);
    diagnostic.column = Some(finding.column);
    diagnostic.end_column = Some(finding.end_column);
    diagnostic.end_line = (finding.end_line != finding.line).then_some(finding.end_line);
    diagnostic.field_path.clone_from(&finding.field_path);
    diagnostic.help = Some(crate::queries::engine_help(
        &finding.code,
        &finding.message,
        finding.suggestion.as_deref(),
    ));
    if warn {
        diagnostic
            .notes
            .push(("note".to_owned(), REPORTED_AS_WARNING_NOTE.to_owned()));
    }
    diagnostic
}

/// A diagnostic as the result lists it (`Diagnostic.to_dict`).
pub fn diagnostic_json(item: &Diagnostic) -> Json {
    let number = |value: Option<usize>| value.map_or(Json::Null, Json::from);
    let fix = item.fix.as_ref().map_or(Json::Null, |fix| {
        Json::object([
            ("safe", Json::Bool(fix.safe)),
            (
                "edits",
                Json::Array(
                    fix.edits
                        .iter()
                        .map(|edit| {
                            Json::object([
                                ("line", Json::from(edit.line)),
                                ("column", Json::from(edit.column)),
                                ("end_line", Json::from(edit.last_line())),
                                ("end_column", Json::from(edit.end_column)),
                                ("replacement", Json::str(&edit.replacement)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    });
    Json::object([
        ("code", Json::str(&item.code)),
        ("severity", Json::str(item.severity.as_str())),
        ("message", Json::str(&item.message)),
        ("object_uuid", Json::opt_str(item.object_uuid.clone())),
        (
            "field_path",
            Json::Array(item.field_path.iter().map(Json::str).collect()),
        ),
        ("path", Json::opt_str(item.path.clone())),
        ("line", number(item.line)),
        ("column", number(item.column)),
        ("end_line", number(item.last_line())),
        ("end_column", number(item.end_column)),
        ("help", Json::opt_str(item.help.clone())),
        ("fix", fix),
        ("explain", Json::Str(item.explain())),
    ])
}

/// `count noun` (`plural`).
fn plural(count: usize, noun: &str) -> String {
    super::counted(count, noun)
}

/// The outcome line and its kind when the status does not say it
/// (`findings_outcome`).
fn findings_outcome(
    errors: usize,
    warnings: usize,
    notes: usize,
    (error_files, warning_files): (usize, usize),
    checked: &str,
    failed: bool,
) -> (String, Option<OutcomeKind>) {
    let sep = " · ";
    if errors > 0 || warnings > 0 {
        let (counted, files) = if errors > 0 {
            (plural(errors, "error"), error_files)
        } else {
            (plural(warnings, "warning"), warning_files)
        };
        let place = if files > 0 {
            format!(" in {}", plural(files, "file"))
        } else {
            String::new()
        };
        let line = format!("{counted}{place}{sep}{checked} checked");
        return (line, (!failed).then_some(OutcomeKind::Warning));
    }
    let clean = format!("{checked} valid");
    if notes > 0 {
        return (format!("{clean}{sep}{}", plural(notes, "note")), None);
    }
    (clean, None)
}

/// `opentide validate query`, offline. `--live` is refused before this runs.
#[expect(
    clippy::too_many_lines,
    reason = "the oracle's steps in order (validate_query_offline), read top to bottom"
)]
pub fn run(args: &Args, cx: &Context<'_>) -> Report {
    if args.live {
        return live(args, cx.env);
    }
    if let Some(report) = refuse(args) {
        return report;
    }
    let platform = args.platform.as_deref();
    let queries = args.queries.unwrap_or_default();
    if let Some(name) = platform
        && offline_languages(name).is_none()
    {
        if !LIVE_QUERY_PLATFORMS.contains(&name) {
            let mut report = Report::failed(
                COMMAND,
                1,
                Failure::new(
                    super::COMMAND_FAILED,
                    format!("query validation not supported for {name}"),
                ),
            );
            report.outcome.data = vec![
                ("platform".into(), Json::str(name)),
                ("valid".into(), Json::Null),
                ("supported".into(), Json::Bool(false)),
            ];
            return report;
        }
        let mut report = refused(
            platform,
            &format!(
                "{name} queries are checked on the tenant only; the offline engine does not \
                 parse them. Re-run with --live."
            ),
            USAGE_EXIT_CODE,
            code::USAGE_MISSING_OPTION,
        );
        if let Some(failure) = &mut report.outcome.failure {
            failure.argument = Some("--live".into());
        }
        return report;
    }
    let query_files: Vec<&String> = args
        .files
        .iter()
        .filter(|target| is_query_file(target))
        .collect();
    let rule_targets: Vec<String> = args
        .files
        .iter()
        .filter(|target| !is_query_file(target))
        .cloned()
        .collect();
    if args.changed && !query_files.is_empty() {
        return scope_refused(
            platform,
            "--changed cannot be combined with --file or --uuid",
            USAGE_EXIT_CODE,
        );
    }
    let on_disk = |target: &str| cx.cwd.join(target);
    let missing: Vec<String> = query_files
        .iter()
        .filter(|target| !on_disk(target).is_file())
        .map(|target| (*target).clone())
        .collect();
    if !missing.is_empty() {
        let mut report = scope_refused(
            platform,
            &format!("No such query file: {}", missing.join(", ")),
            USAGE_EXIT_CODE,
        );
        report.outcome.data.push((
            "unmatched".into(),
            Json::Array(missing.iter().map(Json::str).collect()),
        ));
        return report;
    }
    if let Some(name) = platform {
        let languages = offline_languages(name).unwrap_or_default();
        let other: Vec<String> = query_files
            .iter()
            .filter_map(|target| {
                let language = query_file_language(target)?.as_str();
                (!languages.contains(&language)).then(|| format!("{target} ({language})"))
            })
            .collect();
        if !other.is_empty() {
            let mut report = scope_refused(
                platform,
                &format!(
                    "--platform {name} checks {}: not {}",
                    languages.join(", "),
                    other.join(", ")
                ),
                USAGE_EXIT_CODE,
            );
            if let Some(failure) = &mut report.outcome.failure {
                failure.argument = Some("--file".into());
            }
            return report;
        }
    }
    let (_, root_options) = placement(cx.repo, cx.env, cx.cwd);
    let ws = match super::open(root_options) {
        Ok(ws) => ws,
        Err(message) => return Report::error(COMMAND, message),
    };
    let root = ws.root().to_path_buf();
    let fs = ws.fs().as_ref();
    let wanted: Vec<&str> = match platform {
        Some(name) => vec![name],
        None => OFFLINE_QUERY_LANGUAGES
            .iter()
            .map(|(name, _)| *name)
            .collect(),
    };
    // The scope: every rule file directly in the rules folder, or those the
    // flags select. Reading the rules folder reads the workspace, whose
    // files that do not load are logged, as the oracle's registry did.
    let mut warnings = Vec::new();
    let mut rule_files: Vec<PathBuf> = Vec::new();
    let mut scope_label: Option<&str> = Some("selected");
    if !rule_targets.is_empty() || !args.uuids.is_empty() || args.changed || query_files.is_empty()
    {
        if args.changed && (!rule_targets.is_empty() || !args.uuids.is_empty()) {
            return scope_refused(
                platform,
                "--changed cannot be combined with --file or --uuid",
                USAGE_EXIT_CODE,
            );
        }
        log_load_errors(&ws, cx.cwd);
        let (rules_dir, folder) = opentide_compile::dry_run::rules_folder(&ws);
        let local = opentide_compile::plan::local_scope(fs, &rules_dir, &folder);
        if args.changed {
            match changed_scope(&root, &rules_dir, &folder, cx.cwd, cx.env) {
                Ok((scope, warning)) => {
                    rule_files = scope.files;
                    scope_label = Some("changed");
                    if rule_files.is_empty() {
                        warnings.extend(warning);
                    }
                }
                Err(message) => return scope_refused(platform, &message, 1),
            }
        } else if !rule_targets.is_empty() || !args.uuids.is_empty() {
            let request = opentide_compile::dry_run::Request {
                files: rule_targets.clone(),
                uuids: args.uuids.clone(),
                cwd: cx.cwd.to_path_buf(),
                ..Default::default()
            };
            let (scope, unmatched) =
                opentide_compile::dry_run::selected_scope(fs, &ws, &local, &request, cx.cwd);
            if !unmatched.is_empty() {
                let mut report = scope_refused(
                    platform,
                    &format!(
                        "No rule file directly in {folder} matched: {}",
                        unmatched.join(", ")
                    ),
                    1,
                );
                report.outcome.data.push((
                    "unmatched".into(),
                    Json::Array(unmatched.iter().map(Json::str).collect()),
                ));
                return report;
            }
            rule_files = scope.files;
        } else {
            rule_files = local.files;
            scope_label = None;
        }
    }
    // One engine installation for the run: the workspace's datasets apply to
    // the rules' queries and to the query files'.
    let engine = ENGINE.lock().unwrap_or_else(PoisonError::into_inner);
    let profiles = Profiles::install(fs, Some(&root));
    let mut checks: Vec<Check> = Vec::new();
    let mut unreadable: Vec<Diagnostic> = Vec::new();
    for file in &rule_files {
        let bytes = fs.read(file).map_err(|error| os_problem(&error));
        let text = bytes
            .as_ref()
            .ok()
            .and_then(|bytes| crate::queries::decode(bytes).ok());
        let found = text
            .as_deref()
            .map(|text| profiles.check_object(text))
            .unwrap_or_default();
        let path = relative_path(file, Some(&root));
        if found.is_empty() {
            // The engine finds no query in a file it cannot parse: say which.
            if let Some((problem, line, column)) = unreadable_rule(bytes) {
                let mut item = Diagnostic::new(
                    "yaml_parse",
                    Severity::Error,
                    &format!("cannot check this file's queries: {problem}"),
                );
                item.path = Some(path.clone());
                item.file_path = Some(file.clone());
                item.line = line;
                item.column = column;
                item.end_column = column.map(|column| column + 1);
                item.help = Some(UNREADABLE_HELP.to_owned());
                unreadable.push(item);
            }
            continue;
        }
        for query in found {
            if query.placeholder || !query.is_rule_query() {
                continue;
            }
            let block = query.field_path.get(1).map(String::as_str);
            if !block.is_some_and(|block| wanted.contains(&block)) {
                continue;
            }
            checks.push(Check {
                file_path: file.clone(),
                path: path.clone(),
                query,
            });
        }
    }
    let mut cannot_read = Vec::new();
    for target in &query_files {
        let file_path = on_disk(target);
        let shown = {
            let inside = std::fs::canonicalize(&file_path)
                .ok()
                .zip(std::fs::canonicalize(&root).ok())
                .is_some_and(|(file, root)| file.starts_with(root));
            if inside {
                relative_path(&file_path, Some(&root))
            } else {
                target.replace('\\', "/")
            }
        };
        let problem = match std::fs::read(&file_path) {
            Err(error) => Some(os_problem(&error)),
            Ok(bytes) => match crate::queries::decode(&bytes) {
                Err(_) => {
                    let body = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
                    let at = std::str::from_utf8(body)
                        .err()
                        .map_or(0, |error| error.valid_up_to());
                    Some(opentide_workspace::load::not_utf8_problem(body, at))
                }
                Ok(text) if text.trim().is_empty() => Some("it holds no query".to_owned()),
                Ok(text) => {
                    let Some(language) = query_file_language(target) else {
                        continue;
                    };
                    let platform = platform.filter(|name| {
                        offline_languages(name)
                            .is_some_and(|languages| languages.contains(&language.as_str()))
                    });
                    let findings = crate::queries::check_query_text(&text, language, platform);
                    checks.push(Check {
                        file_path: file_path.clone(),
                        path: shown.clone(),
                        query: CheckedQuery {
                            platform: platform.unwrap_or_default().to_owned(),
                            language: language.as_str().to_owned(),
                            field_path: Vec::new(),
                            line: 1,
                            column: 1,
                            placeholder: false,
                            findings,
                        },
                    });
                    None
                }
            },
        };
        if let Some(problem) = problem {
            cannot_read.push(format!("{target}: {problem}"));
        }
    }
    drop(engine);
    let base = || -> Vec<(String, Json)> {
        vec![
            (
                "platform".into(),
                Json::opt_str(platform.map(str::to_owned)),
            ),
            ("mode".into(), Json::str("offline")),
            ("supported".into(), Json::Bool(true)),
        ]
    };
    if !cannot_read.is_empty() {
        let message = format!("Cannot check {}", cannot_read.join("; "));
        let mut report = Report::error(COMMAND, message);
        report.outcome.data = base();
        return report;
    }
    let progress = crate::render::progress::Progress::from_env(cx.env);
    let stderr_first = if progress.enabled() {
        crate::render::progress::event_line(&crate::render::progress::progress_event(
            "queries",
            checks.len(),
            Some(checks.len()),
        ))
    } else {
        String::new()
    };
    let scoped = |data: &mut Vec<(String, Json)>| {
        if let Some(label) = scope_label {
            data.push(("scope".into(), Json::str(label)));
        }
    };
    if checks.is_empty() && unreadable.is_empty() {
        let target = platform.map_or_else(String::new, |name| format!("{name} "));
        let place = match scope_label {
            None => "",
            Some("changed") => "changed ",
            Some(_) => "selected ",
        };
        let message = format!("No {place}rule has a {target}query the engine checks");
        let mut data = base();
        data.push(("queries_validated".into(), Json::from(0usize)));
        scoped(&mut data);
        let mut report = Report::completed(COMMAND, data);
        report.outcome.status = "skipped".into();
        report.outcome.message = message;
        report.outcome.summary = vec![
            ("queries".into(), Json::from(0usize)),
            ("files".into(), Json::from(0usize)),
        ];
        report.warnings = warnings;
        report.stderr_first = stderr_first;
        return report;
    }
    let rejected: Vec<Diagnostic> = checks
        .iter()
        .flat_map(|check| {
            check
                .query
                .findings
                .iter()
                .filter(|finding| finding.severity == EngineSeverity::Error)
                .map(|finding| engine_diagnostic(finding, &check.file_path, &check.path, queries))
        })
        .collect();
    let mut diagnostics = unreadable;
    diagnostics.extend(rejected);
    let count_of = |severity: Severity| {
        diagnostics
            .iter()
            .filter(|item| item.severity == severity)
            .count()
    };
    let files_with = |severity: Severity| {
        diagnostics
            .iter()
            .filter(|item| item.severity == severity)
            .filter_map(|item| item.path.as_deref())
            .filter(|path| !path.is_empty())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    };
    let (errors, warning_count, notes) = (
        count_of(Severity::Error),
        count_of(Severity::Warning),
        count_of(Severity::Note),
    );
    let (error_files, warning_files) = (files_with(Severity::Error), files_with(Severity::Warning));
    let files: std::collections::BTreeSet<&Path> = checks
        .iter()
        .map(|check| check.file_path.as_path())
        .collect();
    let summary = vec![
        ("queries".into(), Json::from(checks.len())),
        ("files".into(), Json::from(files.len())),
        ("errors".into(), Json::from(errors)),
        ("warnings".into(), Json::from(warning_count)),
        ("notes".into(), Json::from(notes)),
        ("error_files".into(), Json::from(error_files)),
        ("warning_files".into(), Json::from(warning_files)),
    ];
    let failed = errors > 0 || (args.strict && warning_count > 0);
    let count = checks.len();
    let checked = format!("{count} {}", if count == 1 { "query" } else { "queries" });
    let (outcome_line, outcome_kind) = findings_outcome(
        errors,
        warning_count,
        notes,
        (error_files, warning_files),
        &checked,
        failed,
    );
    let mut platforms: Vec<&str> = checks
        .iter()
        .map(|check| check.query.platform.as_str())
        .filter(|name| !name.is_empty())
        .collect();
    platforms.sort_unstable();
    platforms.dedup();
    let mut data = base();
    data.push((
        "platforms".into(),
        Json::Array(platforms.iter().map(|name| Json::str(*name)).collect()),
    ));
    data.push(("queries_validated".into(), Json::from(count)));
    data.push((
        "queries".into(),
        Json::Array(
            checks
                .iter()
                .map(|check| {
                    Json::object([
                        ("path", Json::str(&check.path)),
                        (
                            "platform",
                            Json::opt_str(
                                Some(check.query.platform.clone()).filter(|name| !name.is_empty()),
                            ),
                        ),
                        ("language", Json::str(&check.query.language)),
                        (
                            "field_path",
                            Json::Array(check.query.field_path.iter().map(Json::str).collect()),
                        ),
                        ("line", Json::from(check.query.line)),
                        ("column", Json::from(check.query.column)),
                        ("errors", Json::from(check.query.errors())),
                    ])
                })
                .collect(),
        ),
    ));
    data.push((
        "diagnostics".into(),
        Json::Array(diagnostics.iter().map(diagnostic_json).collect()),
    ));
    data.push((
        "engine".into(),
        Json::object([("engine", Json::str(opentide_analysis::VERSION))]),
    ));
    scoped(&mut data);
    let mut report = Report::completed(COMMAND, data);
    report.outcome.status = if failed { "failed" } else { "passed" }.into();
    report.outcome.message = if failed {
        "Queries rejected offline".to_owned()
    } else {
        format!("{checked} valid")
    };
    report.outcome.summary = summary;
    if failed {
        report.outcome.exit_code = 1;
        report.outcome.failure = Some(Failure::new(ISSUES_FOUND, report.outcome.message.clone()));
        let mut next = Vec::new();
        let first = diagnostics
            .iter()
            .find(|item| item.severity == Severity::Error)
            .or_else(|| diagnostics.first());
        if let Some(first) = first {
            next.push(NextAction::new(first.explain(), "how to fix it"));
        }
        next.push(NextAction::new(rerun(args, queries), "check again"));
        report.outcome.next_actions = next;
    }
    report.warnings = warnings;
    report.outcome_line = Some(outcome_line.clone());
    report.outcome_kind = outcome_kind;
    report.stderr_first = stderr_first;
    let terminal = cx.terminal;
    if !terminal.text() {
        return report;
    }
    let frames = terminal.frames(cx.cwd, cx.env);
    let mut body = vec![Block::Raw(frames.render(
        &diagnostics,
        &mut SourceFiles::default(),
        terminal.quiet,
    ))];
    let kind = match outcome_kind {
        Some(OutcomeKind::Warning) => "warning",
        _ => findings::kind_name(&report.outcome.status, !failed),
    };
    let published = findings::publish(
        &diagnostics,
        COMMAND,
        &outcome_line,
        kind,
        terminal.mode,
        cx.env,
        cx.cwd,
    );
    if !published.is_empty() {
        body.push(Block::Raw(published));
    }
    report.body = body;
    report
}

/// The command line that checks the same queries again, quoted as a shell
/// reads it.
fn rerun(args: &Args, queries: QueriesMode) -> String {
    let mut words: Vec<String> = vec!["opentide".into(), "validate".into(), "query".into()];
    if let Some(platform) = &args.platform {
        words.extend(["--platform".into(), platform.clone()]);
    }
    if args.changed {
        words.push("--changed".into());
    }
    for target in &args.files {
        words.extend(["--file".into(), target.clone()]);
    }
    for target in &args.uuids {
        words.extend(["--uuid".into(), target.clone()]);
    }
    if queries != QueriesMode::Error {
        words.extend([
            "--queries".into(),
            super::validate::queries_name(queries).to_owned(),
        ]);
    }
    if args.strict {
        words.push("--strict".into());
    }
    shlex::try_join(words.iter().map(String::as_str)).unwrap_or_else(|_| words.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_files_are_known_by_their_extension_in_any_case() {
        assert_eq!(query_file_language("a/b.KQL"), Some(LanguageId::Kql));
        assert_eq!(query_file_language("x.kuery"), Some(LanguageId::Kuery));
        assert_eq!(query_file_language("x.cql"), Some(LanguageId::Cql));
        assert!(!is_query_file("rule.yaml"));
        assert!(!is_query_file("kql"));
        assert!(!is_query_file("x.sql"));
    }

    #[test]
    fn offline_options_that_choose_tenants_are_refused() {
        let failure = |args: &Args| {
            let report = refuse(args).unwrap();
            assert_eq!(report.outcome.exit_code, 2);
            report.outcome.failure.unwrap()
        };
        let strategy = Args {
            strategies: vec!["PREVIEW".into()],
            ..Args::default()
        };
        assert_eq!(failure(&strategy).argument.as_deref(), Some("--strategy"));
        let wide = Args {
            wide: true,
            ..Args::default()
        };
        assert_eq!(failure(&wide).argument.as_deref(), Some("--wide"));
        let timeout = Args {
            check_timeout: Some("3".into()),
            ..Args::default()
        };
        assert_eq!(
            failure(&timeout).argument.as_deref(),
            Some("--check-timeout")
        );
        let off = Args {
            queries: Some(QueriesMode::Off),
            ..Args::default()
        };
        assert_eq!(failure(&off).code, code::USAGE_ERROR);
        let plan = Args {
            plan: Some("x".into()),
            ..Args::default()
        };
        assert_eq!(failure(&plan).code, code::USAGE_INVALID_VALUE);
        assert!(refuse(&Args::default()).is_none());
    }

    #[test]
    fn a_live_run_is_handed_back() {
        let report = run(
            &Args {
                live: true,
                strategies: vec!["PREVIEW".into()],
                ..Args::default()
            },
            &Context {
                repo: None,
                env: &Env::default(),
                cwd: Path::new("/nonexistent"),
                terminal: &Terminal::plain(crate::mode::Mode::Json),
            },
        );
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.code, code::ENGINE_NOT_PORTED);
        assert!(failure.message.contains("has no Rust implementation yet"));
        assert_eq!(report.outcome.exit_code, 2);
    }

    #[test]
    fn outcome_lines_count_what_was_found() {
        assert_eq!(
            findings_outcome(0, 0, 0, (0, 0), "7 queries", false),
            ("7 queries valid".to_owned(), None)
        );
        assert_eq!(
            findings_outcome(0, 0, 2, (0, 0), "1 query", false),
            ("1 query valid · 2 notes".to_owned(), None)
        );
        assert_eq!(
            findings_outcome(3, 1, 0, (2, 1), "9 queries", true),
            ("3 errors in 2 files · 9 queries checked".to_owned(), None)
        );
        assert_eq!(
            findings_outcome(0, 1, 0, (0, 1), "9 queries", false),
            (
                "1 warning in 1 file · 9 queries checked".to_owned(),
                Some(OutcomeKind::Warning)
            )
        );
        assert_eq!(findings_outcome(0, 1, 0, (0, 0), "9 queries", true).1, None);
    }

    #[test]
    fn the_rerun_keeps_the_scope_and_quotes_it() {
        let args = Args {
            platform: Some("splunk".into()),
            files: vec!["my rules/a.yaml".into()],
            uuids: vec!["u".into()],
            strict: true,
            ..Args::default()
        };
        assert_eq!(
            rerun(&args, QueriesMode::Warn),
            "opentide validate query --platform splunk --file 'my rules/a.yaml' --uuid u \
             --queries warn --strict"
        );
        assert_eq!(
            rerun(&Args::default(), QueriesMode::Error),
            "opentide validate query"
        );
    }

    #[test]
    fn unreadable_rule_files_say_why() {
        assert_eq!(unreadable_rule(Ok(b"a: 1\n".to_vec())), None);
        let (problem, line, column) = unreadable_rule(Ok(b"a: [1\n".to_vec())).unwrap();
        assert!(!problem.is_empty());
        assert!(line.is_some() && column.is_some());
        let (problem, line, _) = unreadable_rule(Ok(b"a: \xff\n".to_vec())).unwrap();
        assert!(problem.contains("not UTF-8"), "{problem}");
        assert_eq!(line, None);
        assert_eq!(
            unreadable_rule(Err("gone".into())),
            Some(("gone".into(), None, None))
        );
        // The OS's own words, which differ by platform: only the
        // `(os error N)` suffix Rust appends is dropped.
        let dir = tempfile::tempdir().unwrap();
        let error = std::fs::read(dir.path().join("missing.yaml")).unwrap_err();
        let code = error.raw_os_error().unwrap();
        let problem = os_problem(&error);
        assert!(!problem.is_empty());
        assert_eq!(format!("{problem} (os error {code})"), error.to_string());
        assert_eq!(os_problem(&std::io::Error::other("gone")), "gone");
    }

    #[test]
    fn a_warned_rejection_carries_its_note() {
        let finding = Finding {
            code: "kql_parse_error".into(),
            severity: EngineSeverity::Error,
            message: "KQL syntax error".into(),
            line: 3,
            column: 2,
            end_line: 3,
            end_column: 5,
            field_path: vec!["configurations".into()],
            suggestion: None,
        };
        let error = engine_diagnostic(
            &finding,
            Path::new("/w/a.yaml"),
            "a.yaml",
            QueriesMode::Error,
        );
        assert_eq!(error.severity, Severity::Error);
        assert!(error.notes.is_empty());
        assert_eq!(error.end_line, None);
        let warned = engine_diagnostic(
            &finding,
            Path::new("/w/a.yaml"),
            "a.yaml",
            QueriesMode::Warn,
        );
        assert_eq!(warned.severity, Severity::Warning);
        assert_eq!(warned.notes[0].1, REPORTED_AS_WARNING_NOTE);
        let json = diagnostic_json(&warned);
        assert_eq!(json.get("end_line"), Some(&Json::from(3usize)));
        assert_eq!(
            json.get("explain"),
            Some(&Json::str("opentide explain kql_parse_error"))
        );
    }
}
