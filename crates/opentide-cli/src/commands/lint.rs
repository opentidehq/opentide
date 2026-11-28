//! `opentide lint`: `opentide-workspace`'s lint,
//! its queries check on the query engines
//! ([`crate::queries::EngineLintQueries`]), `--changed` from the git diff
//! `deploy` reads (`opentide_compile::git`), `--format`/`--output` reports
//! and the CI sinks.

use std::path::{Path, PathBuf};

use opentide_workspace::lint::{Changed, LintCheck, LintOptions, NO_COMMITS_ADVICE};
use opentide_workspace::{FileSystem as _, OsFs};

use super::findings::{self, diagnostic};
use super::result::{ExitCode, Status};
use super::{Block, Report, Terminal, placement};
use crate::env::Env;
use crate::envelope::{Failure, NextAction};
use crate::json::Json;
use crate::queries::EngineLintQueries;
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
    pub format: ReportFormat,
    /// `--output`.
    pub output: Option<PathBuf>,
}

impl From<&crate::tree::LintArgs> for Args {
    fn from(args: &crate::tree::LintArgs) -> Self {
        Self {
            fix: args.fix,
            strict: args.strict,
            checks: args.check.iter().copied().map(LintCheck::from).collect(),
            changed: args.changed,
            files: args.file.clone(),
            format: args.report_format.into(),
            output: args.output.clone(),
        }
    }
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
fn changed_files(root: &Path, cwd: &Path, env: &Env, objects: &[PathBuf]) -> Changed {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let workspace = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let Some(worktree) = opentide_compile::git::worktree(&workspace) else {
        return Changed::Failed {
            message: format!(
                "--changed needs a git checkout; no .git was found from {}",
                workspace.display()
            ),
            exit_code: 1,
        };
    };
    let source = opentide_compile::git::diff_source(&lookup);
    match opentide_compile::git::changed_paths_noted(&workspace, cwd, &lookup, source) {
        Ok((paths, note)) => {
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
            }
            .or(note)
            .or_else(|| {
                opentide_compile::git::uncommitted_warning(
                    &workspace, &lookup, objects, false, &files,
                )
            });
            Changed::Files { files, warning }
        }
        Err(error) => Changed::Failed {
            message: error.message(),
            exit_code: error.exit_code(),
        },
    }
}

/// `opentide lint`.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
pub fn run(args: &Args, cx: &Context<'_>) -> Report {
    let terminal = cx.terminal;
    let format = args.format;
    if let Some(failure) = check_report_options(
        format,
        args.output.is_some(),
        terminal.mode == crate::mode::Mode::Json,
    ) {
        return Report::failed(COMMAND, ExitCode::Usage, failure);
    }
    let (_, root_options) = placement(cx.repo, cx.env, cx.cwd);
    let ws = match super::open_for(COMMAND, root_options) {
        Ok(ws) => ws,
        Err(mut report) => {
            // Every other problem with `lint.toml` exits 2 ("A value lint
            // cannot use"): its syntax error too, with `config_parse` kept
            // (#1659).
            if report.outcome.failure.as_ref().is_some_and(|failure| {
                failure.code == super::CONFIG_PARSE
                    && failure.message.contains("configurations/lint.toml")
            }) {
                report.outcome.exit_code = ExitCode::Usage;
            }
            return *report;
        }
    };
    let root = ws.root().to_path_buf();
    let changed = (args.changed && args.files.is_empty()).then(|| {
        changed_files(
            &OsFs.resolve(&root),
            cx.cwd,
            cx.env,
            &super::object_folders(&ws),
        )
    });
    let wants_queries = args.checks.is_empty() || args.checks.contains(&LintCheck::Queries);
    let lint = {
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
            selected: None,
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
    report.outcome.status = Status::from_text(lint.status.as_str());
    report.outcome.message.clone_from(&lint.message);
    report.outcome.exit_code = ExitCode::of_service(lint.exit_code);
    if lint.exit_code != 0 {
        report.outcome.failure = Some(Failure::new(
            lint.failure_code.unwrap_or(super::COMMAND_FAILED),
            lint.message.clone(),
        ));
    }
    if let Some(summary) = &lint.summary {
        report.outcome.summary = match super::json(summary) {
            Json::Object(members) => members.into_iter().collect(),
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
        findings::kind_name(report.outcome.status.as_str(), lint.exit_code == 0),
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
