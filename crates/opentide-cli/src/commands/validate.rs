//! `opentide validate` (`cli/commands/validate.py`,
//! `cli/services/validation.py`): the checks of `opentide-workspace`, the
//! queries check on the query engines ([`crate::queries::EngineQueries`]),
//! `--fix` and `--dry-run` as text splices, `--format`/`--output` reports,
//! the CI sinks and `--watch` ([`super::watch`]).

use std::path::{Path, PathBuf};
use std::time::Instant;

use opentide_workspace::fix::{apply_reason, fix_command, fix_phrase, plural};
use opentide_workspace::validate::{
    Check, Options, QueriesMode, STRICT_EXEMPT_WARNINGS, Selection, Validation,
};
use opentide_workspace::{OsFs, root};

use super::findings::{self, diagnostic};
use super::{Block, ISSUES_FOUND, Report, Terminal, placement};
use crate::env::Env;
use crate::envelope::{Failure, NextAction, USAGE_EXIT_CODE, code};
use crate::json::Json;
use crate::mode::Mode;
use crate::queries::EngineQueries;
use crate::render::codeframe::{FixedValue, render_diff, render_fixed};
use crate::render::diagnostic::{Diagnostic, SourceFiles};
use crate::render::report::{ReportFormat, check_report_options};

/// The command's name in the envelope.
pub const COMMAND: &str = "validate";

/// `failure.code` of `--watch` in a mode that cannot redraw.
pub const USAGE_WATCH_NEEDS_TTY: &str = "usage_watch_needs_tty";

/// `validate`'s options.
#[derive(Clone, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the command line's flags, one field each"
)]
pub struct Args {
    /// `--check`.
    pub check: Option<Check>,
    /// `--file`, `--uuid`, `--type`.
    pub selection: Selection,
    /// `--strict`.
    pub strict: bool,
    /// `--queries`, when given.
    pub queries: Option<QueriesMode>,
    /// `--fix`.
    pub fix: bool,
    /// `--dry-run`.
    pub dry_run: bool,
    /// `--watch`.
    pub watch: bool,
    /// `--format`.
    pub format: Option<ReportFormat>,
    /// `--output`.
    pub output: Option<PathBuf>,
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
    /// opentide's version, for a SARIF driver.
    pub version: &'a str,
    /// The streams.
    pub terminal: &'a Terminal,
}

/// `--queries`'s name.
pub fn queries_name(queries: QueriesMode) -> &'static str {
    match queries {
        QueriesMode::Error => "error",
        QueriesMode::Warn => "warn",
        QueriesMode::Off => "off",
    }
}

/// `--queries MODE` when not the default, so a rerun keeps it.
fn queries_flag(queries: QueriesMode) -> Option<&'static str> {
    (queries != QueriesMode::Error).then(|| queries_name(queries))
}

/// A usage error of the command itself: exit 2.
pub fn usage(message: impl Into<String>, argument: &str, failure_code: &str) -> Report {
    let mut failure = Failure::new(failure_code, message);
    failure.argument = Some(argument.to_owned());
    Report::failed(COMMAND, USAGE_EXIT_CODE, failure)
}

/// The usage errors the options make, before anything runs.
pub fn refuse(args: &Args, mode: Mode) -> Option<Report> {
    let format = args.format.unwrap_or(ReportFormat::Text);
    if let Some(failure) = check_report_options(format, args.output.is_some(), mode == Mode::Json) {
        return Some(Report::failed(COMMAND, USAGE_EXIT_CODE, failure));
    }
    let types = ["rule", "threat", "objective"];
    let mut unknown: Vec<&str> = args
        .selection
        .types
        .iter()
        .map(String::as_str)
        .filter(|family| !types.contains(family))
        .collect();
    unknown.sort_unstable();
    unknown.dedup();
    if let Some(first) = unknown.first() {
        return Some(Report::usage(
            COMMAND,
            format!(
                "Unknown object type(s): {}. Choose rule, threat, or objective.",
                unknown.join(", ")
            ),
            code::USAGE_INVALID_CHOICE,
            "--type",
            Some(first),
            &types,
        ));
    }
    if args.dry_run && !args.fix {
        return Some(usage(
            "--dry-run previews --fix. Pass both.",
            "--dry-run",
            code::USAGE_ERROR,
        ));
    }
    if let (Some(queries), Some(check)) = (args.queries, args.check) {
        if check != Check::Queries {
            return Some(usage(
                format!(
                    "--queries sets how the queries check reports; --check {} does not run it",
                    check.name()
                ),
                "--queries",
                code::USAGE_ERROR,
            ));
        }
        if queries == QueriesMode::Off {
            return Some(usage(
                "--check queries runs the queries check and --queries off skips it: pass one of them",
                "--queries",
                code::USAGE_ERROR,
            ));
        }
    }
    if args.watch {
        if args.fix {
            return Some(usage(
                "--watch cannot be combined with --fix: it would rewrite files while you edit them.",
                "--watch",
                code::USAGE_ERROR,
            ));
        }
        if format != ReportFormat::Text {
            return Some(usage(
                "--watch cannot be combined with --format: a watch prints a view, not a report.",
                "--watch",
                code::USAGE_ERROR,
            ));
        }
        if matches!(mode, Mode::Json | Mode::Agent | Mode::Mcp) {
            let mut report = usage(
                format!(
                    "--watch redraws the terminal until Ctrl-C, so it does not run in {} mode",
                    mode.as_str()
                ),
                "--watch",
                USAGE_WATCH_NEEDS_TTY,
            );
            report.next("opentide validate", "validate once");
            return Some(report);
        }
    }
    None
}

/// `path` as `validate` shows a workspace: `./` or `./sub` from inside,
/// `../` above, absolute elsewhere (`_shown_directory`).
pub fn shown_directory(path: &Path, cwd: &Path) -> String {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    if path == cwd {
        return "./".to_owned();
    }
    let posix = |path: &Path| {
        path.components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    };
    if let Ok(rest) = path.strip_prefix(&cwd) {
        return format!("./{}", posix(rest));
    }
    if let Ok(rest) = cwd.strip_prefix(&path) {
        let up = vec![".."; rest.components().count()].join("/");
        return format!("{up}/");
    }
    path.to_string_lossy().replace('\\', "/")
}

/// `3 objects valid · 0.9s` or `2 errors in 1 file · 3 objects checked · 0.9s`
/// (`validate_outcome_line`); `fix` is what `--fix` did.
pub fn outcome_line(
    summary: &opentide_workspace::validate::Summary,
    failed: bool,
    seconds: f64,
    fix: Option<&str>,
) -> String {
    let sep = " · ";
    let objects = plural(summary.objects, "object");
    let took = format!("{seconds:.1}s");
    if !failed && summary.objects == 0 {
        return format!("Validation passed{sep}{took}");
    }
    let hint = if summary.fixable > 0 && fix.is_none() {
        format!("{sep}{} fixable with --fix", summary.fixable)
    } else {
        String::new()
    };
    let queries = summary.queries.map_or_else(String::new, |count| {
        format!(
            "{sep}{count} {}",
            if count == 1 { "query" } else { "queries" }
        )
    });
    if !failed {
        let mut line = format!("{objects} valid{queries}");
        if summary.warnings > 0 {
            line.push_str(&format!("{sep}{}", plural(summary.warnings, "warning")));
        }
        line.push_str(&hint);
        if let Some(fix) = fix {
            line = format!("{fix}{sep}{line}");
        }
        return format!("{line}{sep}{took}");
    }
    let (counted, files) = if summary.errors > 0 {
        (plural(summary.errors, "error"), summary.files)
    } else {
        (plural(summary.warnings, "warning"), summary.warning_files)
    };
    let place = if files > 0 {
        format!(" in {}", plural(files, "file"))
    } else {
        String::new()
    };
    let done = fix.map_or_else(String::new, |fix| {
        let mut chars = fix.chars();
        let first = chars.next().map(|ch| ch.to_lowercase().collect::<String>());
        format!("{sep}{}{}", first.unwrap_or_default(), chars.as_str())
    });
    let checked = if summary.objects > 0 {
        format!("{sep}{objects} checked")
    } else {
        String::new()
    };
    format!("{counted}{place}{done}{hint}{checked}{queries}{sep}{took}")
}

/// What one run of the checks found, as the command reports it.
pub struct Run {
    /// The validation.
    pub validation: Validation,
    /// Every finding, errors then warnings, as the renderers read them.
    pub diagnostics: Vec<Diagnostic>,
    /// The workspace's root.
    pub root: PathBuf,
}

/// Opens the workspace and validates it once; `Err` with the message when
/// the configuration does not resolve.
pub fn validate_once(args: &Args, cx: &Context<'_>) -> Result<Run, String> {
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let ws = super::open(options)?;
    let queries = args.queries.unwrap_or_default();
    let options = Options {
        check: args.check,
        selection: Some(&args.selection),
        strict: args.strict,
        queries,
        query_check: Some(&EngineQueries),
    };
    let validation = ws.validate(&options);
    Ok(run_of(validation, ws.root()))
}

fn run_of(validation: Validation, root: &Path) -> Run {
    let diagnostics = validation
        .report
        .issues
        .iter()
        .chain(&validation.report.warnings)
        .map(diagnostic)
        .collect();
    Run {
        validation,
        diagnostics,
        root: root.to_path_buf(),
    }
}

/// The lines of the warnings `--strict` exempts, which nothing else prints.
fn exempt_lines(validation: &Validation) -> Vec<String> {
    validation
        .report
        .warnings
        .iter()
        .filter(|warning| STRICT_EXEMPT_WARNINGS.contains(&warning.code.as_str()))
        .map(|warning| {
            let mut location = warning.file_path.as_ref().map_or_else(
                || warning.object_uuid.clone(),
                |path| path.to_string_lossy().into_owned(),
            );
            if warning.file_path.is_some()
                && let Some(line) = warning.yaml_line
            {
                location = format!("{location}:{}", line + 1);
            }
            format!(
                "{location}: {}: {}",
                warning.field_path.join("."),
                warning.message
            )
        })
        .collect()
}

/// `checks`: each check run, in the order the run lists them.
fn checks_json(validation: &Validation) -> Json {
    Json::Object(
        validation
            .checks
            .iter()
            .map(|(check, status)| {
                (
                    check.name().to_owned(),
                    Json::object([
                        ("check", Json::str(check.name())),
                        ("status", Json::str(*status)),
                    ]),
                )
            })
            .collect(),
    )
}

/// The JSON of one value `--fix` replaced.
fn change_json(change: &opentide_workspace::fix::FixChange) -> Json {
    super::json(change)
}

/// `opentide validate`.
#[expect(
    clippy::too_many_lines,
    reason = "the command's phases in the oracle's order (validate.py validate_group), read top to bottom"
)]
pub fn run(args: &Args, cx: &Context<'_>) -> Report {
    let started = Instant::now();
    let terminal = cx.terminal;
    if let Some(report) = refuse(args, terminal.mode) {
        return report;
    }
    let format = args.format.unwrap_or(ReportFormat::Text);
    let queries = args.queries.unwrap_or_default();
    let (_, root_options) = placement(cx.repo, cx.env, cx.cwd);
    let mut ws = match super::open(root_options) {
        Ok(ws) => ws,
        Err(message) => return Report::error(COMMAND, message),
    };
    let options = Options {
        check: args.check,
        selection: Some(&args.selection),
        strict: args.strict,
        queries,
        query_check: Some(&EngineQueries),
    };
    let check_name = args.check.map(Check::name);
    let rerun_fix = fix_command(check_name, queries_flag(queries), &args.selection);
    // `--fix`: the plan of the first run, what was written, the second run.
    let mut fix_run = None;
    let validation = if args.fix {
        match ws.validate_fix(&OsFs, &options, args.dry_run) {
            Ok(run) => {
                let validation = run.validation.clone();
                fix_run = Some(run);
                validation
            }
            Err(error) => return Report::error(COMMAND, error.to_string()),
        }
    } else {
        ws.validate(&options)
    };
    let root = ws.root().to_path_buf();
    let run = run_of(validation, &root);
    let validation = &run.validation;
    let summary = validation.summary;
    let failed = validation.failed;
    let scope_full = args.selection.is_empty();
    let empty = !failed && args.check.is_none() && scope_full && summary.objects == 0;
    let message = if failed {
        "Validation failed".to_owned()
    } else if empty {
        format!(
            "Validation passed, but no detection objects were found under {}",
            shown_directory(&root, cx.cwd)
        )
    } else {
        "Validation passed".to_owned()
    };
    let mut data: Vec<(String, Json)> = vec![
        ("checks".into(), checks_json(validation)),
        ("report".into(), super::json(&validation.report)),
    ];
    if let Some(name) = check_name {
        data.push(("check".into(), Json::str(name)));
    }
    data.push(("workspace".into(), Json::str(root.to_string_lossy())));
    let mut warnings = Vec::new();
    if validation.warned {
        warnings.push("Validation reported warnings".to_owned());
    }
    warnings.extend(exempt_lines(validation));
    let mut next = Vec::new();
    if empty && !root::is_workspace_root(&OsFs, &root) {
        next.push(NextAction::new(
            "opentide setup",
            "no workspace here: create one",
        ));
    }
    if failed {
        let first = validation
            .report
            .issues
            .first()
            .or_else(|| validation.report.warnings.first());
        if let Some(first) = first {
            next.push(NextAction::new(
                format!("opentide explain {}", first.code),
                "how to fix it",
            ));
        }
        let mut rerun = vec!["opentide", "validate"];
        if let Some(flag) = queries_flag(queries) {
            rerun.extend(["--queries", flag]);
        }
        next.push(NextAction::new(rerun.join(" "), "check again"));
    }
    if summary.fixable > 0 {
        next.insert(
            0,
            NextAction::new(rerun_fix.clone(), apply_reason(summary.fixable)),
        );
    }
    let mut summary_json = match super::json(&summary) {
        Json::Object(members) => members,
        _ => Vec::new(),
    };
    let mut fix_phrase_text = None;
    let mut unwritten_lines = Vec::new();
    let mut body = Vec::new();
    if let Some(fix) = &fix_run {
        let changes = Json::Array(fix.changes.iter().map(change_json).collect());
        if args.dry_run {
            data.push(("would_fix".into(), changes));
            data.push((
                "diff".into(),
                Json::str(fix.diff.clone().unwrap_or_default()),
            ));
            if !fix.changes.is_empty() {
                next = vec![NextAction::new(
                    rerun_fix.clone(),
                    apply_reason(fix.changes.len()),
                )];
            }
        } else {
            if !fix.changes.is_empty() || fix.unwritten_fixes > 0 {
                next.retain(|action| !action.command.starts_with("opentide validate --fix"));
            }
            for line in &fix.unwritten {
                let warning = format!("Could not write the fix to {line}");
                warnings.push(warning.clone());
                unwritten_lines.push(warning);
            }
            summary_json.push(("fixed".into(), Json::from(fix.changes.len())));
            data.push(("fixed".into(), changes));
        }
        if !fix.changes.is_empty() || fix.unwritten_fixes > 0 || failed {
            fix_phrase_text = Some(fix_phrase(
                fix.changes.len(),
                fix.files,
                args.dry_run,
                fix.unwritten_fixes,
            ));
        }
    }
    let exit_code = validation.exit_code();
    let mut report = Report::completed(COMMAND, data);
    report.outcome.status = if failed { "failed" } else { "passed" }.into();
    report.outcome.message.clone_from(&message);
    report.outcome.exit_code = exit_code;
    report.outcome.summary = summary_json;
    report.outcome.next_actions = next;
    if failed {
        report.outcome.failure = Some(Failure::new(ISSUES_FOUND, message.clone()));
    }
    report.stderr_first = progress_lines(cx.env, &summary);
    // The report file, written whatever the mode.
    if format != ReportFormat::Text {
        let text = findings::report(format, &run.diagnostics, COMMAND, cx.version, cx.env)
            .unwrap_or_default();
        if let Some(output) = &args.output {
            if let Err(error) = findings::write_report(output, cx.cwd, &text) {
                return Report::error(
                    COMMAND,
                    format!("Could not write {}: {error}", output.display()),
                );
            }
        } else if terminal.text() {
            report.whole_stdout = Some(text);
            return report;
        }
    }
    if !terminal.text() {
        report.warnings = warnings;
        return report;
    }
    let frames = terminal.frames(cx.cwd, cx.env);
    let mut shown: Vec<Diagnostic> = run.diagnostics.clone();
    if let Some(fix) = &fix_run {
        if args.dry_run {
            if let Some(diff) = &fix.diff {
                body.push(Block::Raw(render_diff(diff, terminal.stdout.colour)));
            }
            let planned: Vec<(PathBuf, usize, usize)> = fix
                .changes
                .iter()
                .map(|change| (change.file_path.clone(), change.line, change.column))
                .collect();
            shown.retain(|item| {
                !item.file_path.as_ref().is_some_and(|path| {
                    planned.iter().any(|(file, line, column)| {
                        file == path && Some(*line) == item.line && Some(*column) == item.column
                    })
                })
            });
        } else if !terminal.quiet {
            let values: Vec<FixedValue> = fix
                .changes
                .iter()
                .map(|change| FixedValue {
                    file_path: change.file_path.clone(),
                    path: change.path.clone(),
                    line: change.line,
                    column: change.column,
                    before: change.before.clone(),
                    after: change.after.clone(),
                })
                .collect();
            body.push(Block::Raw(render_fixed(
                &values,
                cx.cwd,
                terminal.stdout.colour,
            )));
        }
    }
    if !unwritten_lines.is_empty() && !terminal.quiet {
        body.push(Block::Stderr(terminal.stderr.warnings(&unwritten_lines)));
    }
    body.push(Block::Raw(frames.render(
        &shown,
        &mut SourceFiles::default(),
        terminal.quiet,
    )));
    let line = if empty {
        message
    } else {
        outcome_line(
            &summary,
            failed,
            started.elapsed().as_secs_f64(),
            fix_phrase_text.as_deref(),
        )
    };
    let published = findings::publish(
        &run.diagnostics,
        COMMAND,
        &line,
        findings::kind_name(&report.outcome.status, exit_code == 0),
        terminal.mode,
        cx.env,
        cx.cwd,
    );
    if !published.is_empty() {
        body.push(Block::Raw(published));
    }
    report.body = body;
    report.outcome_line = Some(line);
    report
}

/// `OPENTIDE_PROGRESS=json`'s events for a run that checked `summary`'s
/// objects and queries: one per object, then the queries.
fn progress_lines(env: &Env, summary: &opentide_workspace::validate::Summary) -> String {
    let progress = crate::render::progress::Progress::from_env(env);
    if !progress.enabled() {
        return String::new();
    }
    let mut out = String::new();
    for done in 1..=summary.objects {
        out.push_str(&crate::render::progress::event_line(
            &crate::render::progress::progress_event("objects", done, Some(summary.objects)),
        ));
    }
    if let Some(queries) = summary.queries {
        out.push_str(&crate::render::progress::event_line(
            &crate::render::progress::progress_event("queries", queries, Some(queries)),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_workspace::validate::Summary;

    fn summary() -> Summary {
        Summary {
            objects: 3,
            errors: 0,
            warnings: 0,
            files: 0,
            warning_files: 0,
            queries: Some(1),
            fixable: 0,
        }
    }

    #[test]
    fn outcome_lines() {
        assert_eq!(
            outcome_line(&summary(), false, 0.94, None),
            "3 objects valid · 1 query · 0.9s"
        );
        let mut failed = summary();
        failed.errors = 2;
        failed.files = 1;
        failed.fixable = 1;
        assert_eq!(
            outcome_line(&failed, true, 0.0, None),
            "2 errors in 1 file · 1 fixable with --fix · 3 objects checked · 1 query · 0.0s"
        );
        assert_eq!(
            outcome_line(&failed, true, 0.0, Some("Would fix 1 value in 1 file")),
            "2 errors in 1 file · would fix 1 value in 1 file · 3 objects checked · 1 query · 0.0s"
        );
        let mut warned = summary();
        warned.warnings = 2;
        warned.warning_files = 2;
        warned.queries = None;
        assert_eq!(
            outcome_line(&warned, true, 0.0, None),
            "2 warnings in 2 files · 3 objects checked · 0.0s"
        );
        assert_eq!(
            outcome_line(&warned, false, 0.0, Some("Fixed 1 value in 1 file")),
            "Fixed 1 value in 1 file · 3 objects valid · 2 warnings · 0.0s"
        );
        let mut none = summary();
        none.objects = 0;
        assert_eq!(
            outcome_line(&none, false, 0.0, None),
            "Validation passed · 0.0s"
        );
    }

    #[test]
    fn usage_errors() {
        let mut args = Args {
            dry_run: true,
            ..Args::default()
        };
        let report = refuse(&args, Mode::Plain).unwrap();
        assert_eq!(
            report.outcome.failure.unwrap().argument.as_deref(),
            Some("--dry-run")
        );
        args.dry_run = false;
        args.watch = true;
        let report = refuse(&args, Mode::Json).unwrap();
        let failure = report.outcome.failure.clone().unwrap();
        assert_eq!(failure.code, USAGE_WATCH_NEEDS_TTY);
        assert_eq!(report.outcome.exit_code, 2);
        assert_eq!(report.outcome.next_actions[0].command, "opentide validate");
        assert!(refuse(&args, Mode::Plain).is_none());
        args.watch = false;
        args.selection.types = vec!["rulez".into()];
        let failure = refuse(&args, Mode::Plain).unwrap().outcome.failure.unwrap();
        assert_eq!(failure.suggestion.as_deref(), Some("rule"));
        args.selection.types.clear();
        args.check = Some(Check::Schema);
        args.queries = Some(QueriesMode::Warn);
        assert!(refuse(&args, Mode::Plain).is_some());
        args.check = Some(Check::Queries);
        assert!(refuse(&args, Mode::Plain).is_none());
        args.queries = Some(QueriesMode::Off);
        assert!(refuse(&args, Mode::Plain).is_some());
    }

    #[test]
    fn shown_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        assert_eq!(shown_directory(&root, &root), "./");
        assert_eq!(shown_directory(&root.join("sub"), &root), "./sub");
        assert_eq!(shown_directory(&root, &root.join("sub")), "../");
    }
}
