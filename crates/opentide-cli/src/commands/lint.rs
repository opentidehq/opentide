//! `opentide lint` (`cli/commands/lint.py`): `opentide-workspace`'s lint,
//! its queries check on the query engines
//! ([`crate::queries::EngineLintQueries`]), `--changed` from the git diff
//! `deploy` reads (`opentide_compile::git`), `--format`/`--output` reports
//! and the CI sinks.

use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use opentide_workspace::lint::{Changed, LintCheck, LintOptions, LintStatus, NO_COMMITS_ADVICE};
use opentide_workspace::{FileSystem as _, OsFs};

use super::findings::{self, diagnostic};
use super::{Block, Report, Terminal, placement};
use crate::env::Env;
use crate::envelope::{Failure, NextAction, USAGE_EXIT_CODE};
use crate::json::Json;
use crate::queries::{ENGINE, EngineLintQueries};
use crate::render::diagnostic::{Diagnostic, SourceFiles};
use crate::render::outcome::OutcomeKind;
use crate::render::report::{ReportFormat, check_report_options};

/// The command's name in the envelope.
pub const COMMAND: &str = "lint";

/// `lint`'s options.
#[derive(Clone, Debug, Default)]
pub struct Args {
    /// `--fix`.
    pub fix: bool,
    /// `--strict`.
    pub strict: bool,
    /// `--check`, repeatable.
    pub checks: Vec<LintCheck>,
    /// `--changed`.
    pub changed: bool,
    /// `--file`, repeatable.
    pub files: Vec<String>,
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

/// The object files the run changed (`changed_files_under`): the diff
/// `deploy` reads, every file under the workspace rather than the rules
/// folder's alone.
fn changed_files(root: &Path, cwd: &Path, env: &Env) -> Changed {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let workspace = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let Some(worktree) = opentide_compile::git::worktree(&workspace) else {
        return Changed::Failed(format!(
            "--changed needs a git checkout; no .git was found from {}",
            workspace.display()
        ));
    };
    let source = opentide_compile::git::diff_source(&lookup);
    match opentide_compile::git::changed_paths(&workspace, cwd, &lookup, source) {
        Ok(paths) => {
            let mut files: Vec<PathBuf> = paths
                .iter()
                .map(|entry| worktree.join(entry))
                .filter(|path| path.starts_with(&workspace))
                .collect();
            files.sort();
            files.dedup();
            let warning = if files.is_empty() {
                opentide_compile::git::no_commits_warning(&workspace, &lookup, NO_COMMITS_ADVICE)
            } else {
                None
            };
            Changed::Files { files, warning }
        }
        Err(error) => Changed::Failed(error.message()),
    }
}

/// `opentide lint`.
pub fn run(args: &Args, cx: &Context<'_>) -> Report {
    let terminal = cx.terminal;
    let format = args.format.unwrap_or(ReportFormat::Text);
    if let Some(failure) = check_report_options(
        format,
        args.output.is_some(),
        terminal.mode == crate::mode::Mode::Json,
    ) {
        return Report::failed(COMMAND, USAGE_EXIT_CODE, failure);
    }
    let (_, root_options) = placement(cx.repo, cx.env, cx.cwd);
    let ws = match super::open(root_options) {
        Ok(ws) => ws,
        Err(message) => return Report::error(COMMAND, message),
    };
    let root = ws.root().to_path_buf();
    let changed = (args.changed && args.files.is_empty())
        .then(|| changed_files(&OsFs.resolve(&root), cx.cwd, cx.env));
    let wants_queries = args.checks.is_empty() || args.checks.contains(&LintCheck::Queries);
    let lint = {
        let _engine = wants_queries.then(|| ENGINE.lock().unwrap_or_else(PoisonError::into_inner));
        let queries = wants_queries.then(|| EngineLintQueries::install(&OsFs, &root));
        let options = LintOptions {
            checks: args.checks.clone(),
            fix: args.fix,
            strict: args.strict,
            files: args.files.clone(),
            changed: if args.changed && !args.files.is_empty() {
                // lint refuses `--changed` with `--file` itself.
                Some(Changed::Files {
                    files: Vec::new(),
                    warning: None,
                })
            } else {
                changed
            },
            cwd: cx.cwd.to_path_buf(),
            query_check: queries
                .as_ref()
                .map(|check| check as &dyn opentide_workspace::lint::LintQueryCheck),
        };
        ws.lint(Some(&OsFs), &options)
    };
    // `payload()`'s order, with each finding's keys in its own order.
    let data: Vec<(String, Json)> = lint
        .payload()
        .into_iter()
        .map(|(key, value)| {
            let value = if key == "findings" {
                super::json(&lint.findings)
            } else {
                super::json(&value)
            };
            (key.to_owned(), value)
        })
        .collect();
    let mut report = Report::completed(COMMAND, data);
    report.outcome.status = match lint.status {
        LintStatus::Completed => "completed",
        LintStatus::Issues => "issues",
        LintStatus::Failed => "failed",
    }
    .into();
    report.outcome.message.clone_from(&lint.message);
    report.outcome.exit_code = lint.exit_code;
    if lint.exit_code != 0 {
        report.outcome.failure = Some(Failure::new(
            lint.failure_code.unwrap_or(super::COMMAND_FAILED),
            lint.message.clone(),
        ));
    }
    if let Some(summary) = &lint.summary {
        report.outcome.summary = match super::json(summary) {
            Json::Object(members) => members,
            _ => Vec::new(),
        };
    }
    report.outcome.next_actions = lint
        .next_actions
        .iter()
        .map(|action| NextAction::new(action.command.clone(), action.reason.clone()))
        .collect();
    report.warnings.clone_from(&lint.warnings);
    report.outcome_line.clone_from(&lint.outcome);
    if lint.outcome_ok {
        report.outcome_kind = Some(OutcomeKind::Ok);
    }
    if terminal.mode == crate::mode::Mode::Json && format == ReportFormat::Text {
        return report;
    }
    let diagnostics: Vec<Diagnostic> = lint
        .findings
        .iter()
        .map(|finding| diagnostic(&finding.diagnostic))
        .collect();
    if format != ReportFormat::Text {
        let text =
            findings::report(format, &diagnostics, COMMAND, cx.version, cx.env).unwrap_or_default();
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
        return report;
    }
    let frames = terminal.frames(cx.cwd, cx.env);
    let (text, hidden) = frames.render_notes(
        &diagnostics,
        &mut SourceFiles::default(),
        terminal.quiet,
        terminal.verbose,
    );
    report.body.push(Block::Raw(text));
    let outcome = lint.outcome.clone().unwrap_or_else(|| lint.message.clone());
    let published = findings::publish(
        &diagnostics,
        COMMAND,
        &outcome,
        findings::kind_name(&report.outcome.status, lint.exit_code == 0),
        terminal.mode,
        cx.env,
        cx.cwd,
    );
    if !published.is_empty() {
        report.body.push(Block::Raw(published));
    }
    terminal.hidden_notes_step(&mut report.outcome.next_actions, hidden);
    report
}
