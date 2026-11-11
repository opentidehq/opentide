//! `opentide setup` and its file-writing subcommands (`setup_app.py`,
//! `services/setup/orchestrator.py`, `services/setup/plan.py`,
//! `ui/setup.py`): the target, the confirmation, the steps run through a
//! [`Stage`], `--plan`, and what a person reads afterwards (the files
//! written, the outcome line, the numbered next steps).

use std::path::{Path, PathBuf};

use super::files::{self, StepResult, strings};
use super::stage::Stage;
use super::{CiArgs, Context, bad_parameter, confirm_write, needs_input_for, resolved};
use crate::commands::{Block, Report};
use crate::envelope::{Failure, NextAction, USAGE_EXIT_CODE, code};
use crate::json::Json;
use crate::mode::Mode;
use crate::render::outcome::OutcomeKind;
use crate::render::table::columns;
use crate::render::text::{Style, Text};

/// Where a subcommand writes, as the command line names it.
#[derive(Clone, Debug, Default)]
pub struct Paths {
    /// The subcommand's `--path` (or positional path), when given.
    pub own: Option<String>,
    /// The `setup` group's `--path`, when given.
    pub group: Option<String>,
    /// Both the positional path and `--path` were given.
    pub both: bool,
    /// The `setup` group's own options given before the subcommand, which it
    /// would ignore, as its help names them.
    pub group_only: Vec<String>,
}

/// A file-writing subcommand of `setup`.
#[derive(Clone, Debug)]
pub enum Step {
    /// `setup env`.
    Env,
    /// `setup hooks`; `--install/--no-install`.
    Hooks {
        /// Whether to install Git's hook.
        install: bool,
    },
    /// `setup platforms`, the platforms in the flags' order.
    Platforms(Vec<String>),
    /// `setup repo`.
    Repo(files::RepoOptions),
    /// `setup mcp`, the hosts in the flags' order.
    Mcp(Vec<String>),
    /// `setup vscode` (deprecated).
    Vscode(super::vscode::Options),
}

impl Step {
    fn name(&self) -> &'static str {
        match self {
            Step::Env => "env",
            Step::Hooks { .. } => "hooks",
            Step::Platforms(_) => "platforms",
            Step::Repo(_) => "repo",
            Step::Mcp(_) => "mcp",
            Step::Vscode(_) => "vscode",
        }
    }

    fn question(&self) -> &'static str {
        match self {
            Step::Env => "Write .env.example with OPENTIDE_REPO_ROOT?",
            Step::Hooks { .. } => "Configure validate-on-commit hooks?",
            Step::Platforms(_) => "Write these platform configurations?",
            Step::Repo(_) => "Create this repository scaffold?",
            Step::Mcp(_) => "Write these MCP configurations?",
            // `setup vscode` never asks.
            Step::Vscode(_) => "",
        }
    }

    fn cancelled(&self) -> &'static str {
        match self {
            Step::Env => "Environment setup cancelled",
            Step::Hooks { .. } => "Hook setup cancelled",
            Step::Platforms(_) => "Platform setup cancelled",
            Step::Repo(_) => "Repository setup cancelled",
            Step::Mcp(_) => "MCP setup cancelled",
            Step::Vscode(_) => "",
        }
    }

    /// Runs the step into `stage`.
    fn run(&self, stage: &mut Stage, root: &Path, cx: &Context<'_>) -> Result<StepResult, String> {
        match self {
            Step::Env => files::env(stage, root),
            Step::Hooks { install } => super::hooks::hooks(stage, cx.env, root, *install),
            Step::Platforms(platforms) => files::platforms(stage, root, platforms),
            Step::Repo(options) => files::repo(stage, root, options),
            Step::Mcp(hosts) => Ok(files::mcp(
                stage,
                root,
                hosts,
                files::McpServer::from_env(cx.env).as_ref(),
            )),
            Step::Vscode(options) => {
                super::vscode::run(stage, root, *options, cx).map(|done| done.result)
            }
        }
    }
}

/// The target the group and the subcommand agree on (`_group_path`), as
/// given (`.` by default), `--repo` standing in for `.`.
pub(crate) fn target(
    cx: &Context<'_>,
    command: &str,
    paths: &Paths,
) -> Result<PathBuf, Box<Report>> {
    if paths.both {
        return Err(retitled(
            bad_parameter(
                "Pass the repository path once: use --path/-C or the positional PATH, not both.",
                &[],
                None,
            ),
            command,
        ));
    }
    if !paths.group_only.is_empty() {
        let verb = if paths.group_only.len() == 1 {
            "configures"
        } else {
            "configure"
        };
        return Err(retitled(
            bad_parameter(
                &format!(
                    "{} {verb} `opentide setup` itself and would be ignored by `opentide {command}`.",
                    paths.group_only.join(", ")
                ),
                &[],
                None,
            ),
            command,
        ));
    }
    let setup_path = |given: &str| -> PathBuf {
        let path = Path::new(given);
        match cx.repo {
            Some(repo)
                if path == Path::new(".")
                    && resolved(cx.cwd, Path::new(repo)) != resolved(cx.cwd, cx.cwd) =>
            {
                cx.cwd.join(repo)
            }
            _ => path.to_path_buf(),
        }
    };
    let named: Vec<&str> = [paths.group.as_deref(), paths.own.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    let mut targets: Vec<PathBuf> = named
        .iter()
        .map(|path| resolved(cx.cwd, &setup_path(path)))
        .collect();
    targets.dedup();
    if targets.len() > 1 {
        return Err(retitled(
            bad_parameter(
                &format!(
                    "Pass the repository path once: {} name different targets.",
                    named.join(" and ")
                ),
                &[],
                None,
            ),
            command,
        ));
    }
    Ok(setup_path(named.last().copied().unwrap_or(".")))
}

/// `report` as `command`'s.
fn retitled(mut report: Box<Report>, command: &str) -> Box<Report> {
    command.clone_into(&mut report.outcome.command);
    report
}

/// A usage error with `failure.code` `code`.
fn usage(command: &str, failure_code: &str, message: &str) -> Report {
    Report::failed(
        command,
        USAGE_EXIT_CODE,
        Failure::new(failure_code, message),
    )
}

/// The reason a prompt cannot be shown here, if one cannot
/// (`require_interactive`).
pub(crate) fn cannot_prompt(cx: &Context<'_>) -> Option<String> {
    use std::io::IsTerminal as _;
    if cx.mode == Mode::Agent {
        let reader = crate::mode::detect_agent(cx.env).map_or_else(
            || "agent output mode".to_owned(),
            |agent| format!("a coding agent ({agent})"),
        );
        return Some(format!("Interactive setup does not prompt in {reader}."));
    }
    if !std::io::stdin().is_terminal() {
        return Some("Interactive setup requires a terminal.".to_owned());
    }
    None
}

/// The wizards a command opens when its flags answer nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wizard {
    /// `setup`.
    Setup,
    /// `setup repo`.
    Repo,
    /// `setup mcp`.
    Mcp,
}

/// A wizard nobody can answer, refused naming the flags that answer it; at
/// a terminal, the wizard ([`super::wizard`]), its questions asked with
/// inquire.
fn wizard(command: &str, cx: &Context<'_>, flags: &str, kind: Wizard, shown: &Path) -> Report {
    let scripted = format!("Run 'opentide {command}' with --yes and explicit flags ({flags}).");
    if cx.mode == Mode::Json {
        return *needs_input_for(
            command,
            format!(
                "--json cannot drive the interactive wizard. {scripted} Or drop --json to use the wizard."
            ),
        );
    }
    if let Some(reason) = cannot_prompt(cx) {
        return *needs_input_for(command, format!("{reason} {scripted}"));
    }
    let mut prompter = super::wizard::Inquire::new(cx.terminal.stderr.colour);
    let mut stdout = std::io::stdout();
    let mut screen = super::wizard::Screen {
        out: &mut stdout,
        console: cx.terminal.stdout,
        mode: cx.mode,
        version: cx.version,
    };
    interactive(command, kind, &mut prompter, &mut screen, shown, cx)
}

/// Runs the wizard `kind` with `prompter`, then the steps its answers ask
/// for, as the scripted command runs them.
fn interactive(
    command: &str,
    kind: Wizard,
    prompter: &mut dyn super::wizard::Prompter,
    screen: &mut super::wizard::Screen<'_>,
    shown: &Path,
    cx: &Context<'_>,
) -> Report {
    use super::wizard::{self, Gathered, Stop};
    let root = root_of(cx, shown);
    let stopped = |stop: Stop| match stop {
        Stop::Interrupted => {
            // The run reports it: `error: interrupted`, exit 130.
            cx.interrupt.request();
            cancelled(command, "interrupted")
        }
        Stop::Failed(message) => Report::error(command, message),
    };
    match kind {
        Wizard::Setup => {
            let promoting = promotion_enabled(&root, cx);
            let shown_text = shown.to_string_lossy().replace('\\', "/");
            match wizard::setup(prompter, screen, &shown_text, &root, promoting) {
                Err(stop) => stopped(stop),
                Ok(Gathered::Declined(warnings)) => {
                    let mut report = Report::completed(
                        command,
                        vec![("steps".to_owned(), Json::Array(Vec::new()))],
                    );
                    report.outcome.status = "skipped".into();
                    "Setup cancelled; no files were written"
                        .clone_into(&mut report.outcome.message);
                    report.warnings = warnings;
                    report
                }
                Ok(Gathered::Apply(answers)) => {
                    let args = GroupArgs {
                        path: shown_text,
                        repo: answers.repo.clone(),
                        ci: answers.ci.clone(),
                        staging: answers.staging,
                        inflight: answers.inflight,
                        sharing: answers.sharing,
                        explorer_pages: answers.explorer_pages,
                        promotion: answers.promotion,
                        python_version: "3.12".to_owned(),
                        mcp: answers.mcp.clone(),
                        ..GroupArgs::default()
                    };
                    let run_ci = args.ci.is_some();
                    execute(&args, &root, answers.warnings, true, run_ci, None, cx)
                }
            }
        }
        Wizard::Repo => match wizard::repo(prompter, screen, &root) {
            Err(stop) => stopped(stop),
            Ok(None) => cancelled(command, "Repository setup cancelled"),
            Ok(Some(options)) => run_step(command, &Step::Repo(options), &root, cx),
        },
        Wizard::Mcp => match wizard::mcp(prompter, screen, &root) {
            Err(stop) => stopped(stop),
            Ok(None) => cancelled(command, "MCP setup cancelled"),
            Ok(Some(hosts)) => run_step(command, &Step::Mcp(hosts), &root, cx),
        },
    }
}

/// Whether the repository at `root` promotes statuses now: its
/// `[promotion] enabled` over the bundled default (`effective_promotion`).
fn promotion_enabled(root: &Path, cx: &Context<'_>) -> bool {
    let fs = opentide_workspace::OsFs;
    let roots = opentide_workspace::root::resolve(&fs, &super::root_options(root, cx));
    let configured = opentide_workspace::config::resolve_only(&fs, &roots)
        .ok()
        .and_then(|resolved| {
            match resolved
                .get("deployment")
                .and_then(|deployment| deployment.get("promotion"))
                .and_then(|promotion| promotion.get("enabled"))
                .map(|enabled| &enabled.value)
            {
                Some(opentide_schema::node::Value::Bool(enabled)) => Some(*enabled),
                _ => None,
            }
        });
    configured.unwrap_or_else(|| {
        super::promotion_defaults()
            .get("enabled")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    })
}

/// A run this implementation does not cover: `engine_not_ported`.
pub(crate) fn not_ported(command: &str, what: &str) -> Report {
    let mut failure = Failure::new(
        code::ENGINE_NOT_PORTED,
        format!(
            "{what} has no Rust implementation yet: unset OPENTIDE_ENGINE, or set it to python or compare."
        ),
    );
    failure.argument = Some("OPENTIDE_ENGINE".into());
    Report::failed(command, USAGE_EXIT_CODE, failure)
}

/// A cancelled confirmation.
fn cancelled(command: &str, message: &str) -> Report {
    let mut report = Report::completed(command, Vec::new());
    report.outcome.status = "skipped".into();
    message.clone_into(&mut report.outcome.message);
    report
}

/// The absolute target, as the results print it.
fn root_of(cx: &Context<'_>, shown: &Path) -> PathBuf {
    resolved(cx.cwd, shown)
}

/// `opentide setup <step>`.
pub fn subcommand(step: &Step, paths: &Paths, yes: bool, plan: bool, cx: &Context<'_>) -> Report {
    let command = format!("setup {}", step.name());
    let shown = match target(cx, &command, paths) {
        Ok(shown) => shown,
        Err(report) => return *report,
    };
    match step {
        Step::Platforms(chosen) if chosen.is_empty() => {
            return *retitled(
                bad_parameter(
                    "Choose at least one platform flag (e.g. --sentinel --splunk)",
                    &[],
                    None,
                ),
                &command,
            );
        }
        Step::Mcp(hosts) if hosts.is_empty() => {
            if yes || plan {
                return usage(
                    &command,
                    code::USAGE_MISSING_OPTION,
                    "Choose at least one MCP host (--vscode, --cursor, --claude-code, --generic)",
                );
            }
            return wizard(
                &command,
                cx,
                "--vscode, --cursor, --claude-code",
                Wizard::Mcp,
                &shown,
            );
        }
        Step::Repo(options)
            if !yes
                && !plan
                && options.name.is_none()
                && options.org.is_none()
                && options.description.is_none()
                && options.platforms.is_empty() =>
        {
            return wizard(&command, cx, "--name, --platform", Wizard::Repo, &shown);
        }
        Step::Vscode(options) => return vscode(*options, &shown, plan, cx),
        _ => {}
    }
    let root = root_of(cx, &shown);
    if !plan && !yes {
        match confirm_write(&command, &shown, &root, cx, step.question()) {
            Ok(true) => {}
            Ok(false) => return cancelled(&command, step.cancelled()),
            Err(report) => return *report,
        }
    }
    if plan {
        let mut stage = Stage::new();
        let result = match step.run(&mut stage, &root, cx) {
            Ok(result) => result,
            Err(message) => return Report::error(&command, message),
        };
        let planned = planned(&mut stage, &root, step.name(), &result);
        return plan_report(&command, &root, vec![planned], &[], cx);
    }
    run_step(&command, step, &root, cx)
}

/// Runs `step` on `root` and writes what it staged: the report of a
/// confirmed run.
fn run_step(command: &str, step: &Step, root: &Path, cx: &Context<'_>) -> Report {
    let mut stage = Stage::new();
    let result = match step.run(&mut stage, root, cx) {
        Ok(result) => result,
        Err(message) => return Report::error(command, message),
    };
    if let Err(message) = stage.commit() {
        return Report::error(command, message);
    }
    finish(command, result, None, root, cx)
}

/// `opentide setup vscode` (deprecated): it never asks, says it is
/// deprecated first, and fails (exit 1) when the snippets it was asked for
/// could not be written, keeping what it wrote.
fn vscode(options: super::vscode::Options, shown: &Path, plan: bool, cx: &Context<'_>) -> Report {
    const COMMAND: &str = "setup vscode";
    let root = root_of(cx, shown);
    super::vscode::deprecation(cx);
    let mut stage = Stage::new();
    match super::vscode::run(&mut stage, &root, options, cx) {
        Err(message) => Report::error(COMMAND, message),
        Ok(done) if plan => {
            let planned = planned(&mut stage, &root, "vscode", &done.result);
            let mut report = plan_report(COMMAND, &root, vec![planned], &[], cx);
            if done.failed {
                failed(&mut report, done.result.text("message").unwrap_or_default());
            }
            report
        }
        Ok(done) => match stage.commit() {
            Err(message) => Report::error(COMMAND, message),
            Ok(()) => finish(COMMAND, done.result, None, &root, cx),
        },
    }
}

/// `report` as a run that failed with `message`: status `failed`, exit 1,
/// `command_failed` (a service's `status: failed` with `_exit_code`).
fn failed(report: &mut Report, message: &str) {
    report.outcome.status = "failed".into();
    message.clone_into(&mut report.outcome.message);
    report.outcome.exit_code = 1;
    report.outcome.failure = Some(Failure::new(crate::commands::COMMAND_FAILED, message));
    report.outcome.next_actions.clear();
}

// ---------------------------------------------------------------- the plan

/// One step of a plan: its files and warnings.
#[derive(Clone, Debug)]
pub struct Planned {
    step: String,
    files: Vec<(String, &'static str)>,
    warnings: Vec<String>,
}

/// What the step that just ran wrote, and the files it reported left alone.
fn planned(stage: &mut Stage, root: &Path, name: &str, result: &StepResult) -> Planned {
    let mut changes = stage.step();
    changes.sort_by_key(|change| change.path.to_string_lossy().into_owned());
    let mut files: Vec<(String, &'static str)> = changes
        .into_iter()
        .map(|change| (super::shown_relative(&change.path, root), change.action))
        .collect();
    for skipped in result.strings("skipped") {
        let path = Path::new(&skipped);
        let shown = if path.is_absolute() {
            super::shown_relative(path, root)
        } else {
            skipped.replace('\\', "/")
        };
        if !files.iter().any(|(listed, _)| *listed == shown) {
            files.push((shown, "skip"));
        }
    }
    Planned {
        step: name.to_owned(),
        files,
        warnings: result.strings("warnings"),
    }
}

/// The `--plan` document: each step's files, the counts and the outcome line.
fn plan_report(
    command: &str,
    root: &Path,
    steps: Vec<Planned>,
    run_warnings: &[String],
    cx: &Context<'_>,
) -> Report {
    let mut counts = [
        ("create", 0_usize),
        ("merge", 0),
        ("skip", 0),
        ("delete", 0),
    ];
    for step in &steps {
        for (_, action) in &step.files {
            if let Some(count) = counts.iter_mut().find(|(name, _)| name == action) {
                count.1 += 1;
            }
        }
    }
    let count = |name: &str| {
        counts
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(0, |(_, c)| *c)
    };
    let mut warnings: Vec<String> = Vec::new();
    for warning in run_warnings
        .iter()
        .chain(steps.iter().flat_map(|step| step.warnings.iter()))
    {
        if !warnings.contains(warning) {
            warnings.push(warning.clone());
        }
    }
    let writes = count("create") + count("merge");
    let noun = if writes == 1 { "file" } else { "files" };
    let removed = if count("delete") > 0 {
        format!(", {} to remove", count("delete"))
    } else {
        String::new()
    };
    let documents: Vec<Json> = steps
        .iter()
        .map(|step| {
            Json::object([
                ("step", Json::str(&step.step)),
                (
                    "files",
                    Json::Array(
                        step.files
                            .iter()
                            .map(|(path, action)| {
                                Json::object([
                                    ("path", Json::str(path)),
                                    ("action", Json::str(*action)),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("warnings", strings(&step.warnings)),
            ])
        })
        .collect();
    let mut report = Report::completed(
        command,
        vec![
            ("plan".into(), Json::Bool(true)),
            ("path".into(), Json::str(files::shown(root))),
            ("steps".into(), Json::Array(documents)),
        ],
    );
    report.outcome.message = format!(
        "Plan: {writes} {noun} to write ({} new, {} changed){removed} · nothing written",
        count("create"),
        count("merge")
    );
    report.outcome.summary = vec![
        ("create".into(), Json::from(count("create"))),
        ("merge".into(), Json::from(count("merge"))),
        ("skip".into(), Json::from(count("skip"))),
        ("delete".into(), Json::from(count("delete"))),
        ("steps".into(), Json::from(steps.len())),
    ];
    report.outcome_kind = Some(OutcomeKind::Plan);
    report.warnings = warnings;
    if cx.mode != Mode::Json {
        let bold = Style::new("bold");
        let mut lines = Vec::new();
        for step in &steps {
            lines.push(Text::styled(&step.step, &bold));
            if step.files.is_empty() {
                lines.push(Text::styled("  nothing to write", &Style::new("dim")));
                continue;
            }
            let rows: Vec<Vec<Text>> = step
                .files
                .iter()
                .map(|(path, action)| {
                    let style = if *action == "skip" {
                        Style::new("dim")
                    } else {
                        Style::default()
                    };
                    vec![Text::styled(action, &style), Text::styled(path, &bold)]
                })
                .collect();
            lines.extend(columns(&rows, 2, &[]).into_iter().map(|row| {
                let mut line = Text::plain("  ");
                line.append_text(&row);
                line
            }));
        }
        lines.push(Text::default());
        report.body = vec![Block::Lines(lines)];
    }
    report
}

// ---------------------------------------------------------------- the outcome

/// What a written path is for, by prefix.
const PURPOSES: [(&str, &str); 14] = [
    ("objects/", "your detection catalogue"),
    (
        ".opentide/configurations/platforms/",
        "platform configuration",
    ),
    (".github/workflows/", "GitHub Actions pipeline"),
    (".gitlab-ci.yml", "GitLab CI pipeline"),
    ("azure-pipelines", "Azure Pipelines pipeline"),
    (".pre-commit-config.yaml", "validate on commit"),
    (".git/hooks/", "validate on commit"),
    (".vscode/mcp.json", "MCP server for VS Code"),
    (".cursor/", "Cursor configuration"),
    (".mcp.json", "MCP server for Claude Code"),
    (".vscode/", "editor settings"),
    ("README.md", "quick start"),
    (".gitignore", "files git leaves out"),
    (".env.example", "environment template"),
];

fn purpose(path: &str) -> &'static str {
    PURPOSES
        .iter()
        .find(|(prefix, _)| path.starts_with(prefix) || path == prefix.trim_end_matches('/'))
        .map_or("", |(_, purpose)| purpose)
}

/// The steps of a result: its `steps`, or the result itself.
fn steps_of(result: &StepResult) -> Vec<StepResult> {
    match result.get("steps") {
        Some(Json::Array(steps)) => steps
            .iter()
            .filter_map(|step| match step {
                Json::Object(fields) => Some(StepResult {
                    fields: fields.clone(),
                }),
                _ => None,
            })
            .collect(),
        _ => vec![result.clone()],
    }
}

/// Every file the result says it wrote, in order, once.
fn written_files(result: &StepResult) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for step in steps_of(result) {
        for key in ["files", "platform_files"] {
            for item in step.strings(key) {
                let item = item.replace('\\', "/");
                if !item.is_empty() && !seen.contains(&item) {
                    seen.push(item);
                }
            }
        }
    }
    seen
}

/// `path` relative to the working directory when inside it (`display_path`).
fn display_path(path: &Path, cwd: &Path) -> String {
    let absolute = resolved(cwd, path);
    let base = resolved(cwd, cwd);
    let mut shown = match absolute.strip_prefix(&base) {
        Ok(rest) if rest.as_os_str().is_empty() => ".".to_owned(),
        Ok(rest) => rest.to_string_lossy().replace('\\', "/"),
        Err(_) => absolute.to_string_lossy().replace('\\', "/"),
    };
    if absolute.is_dir() && !shown.ends_with('/') {
        shown.push('/');
    }
    shown
}

/// The outcome line and next steps of a finished setup (`setup_outcome`).
fn outcome(
    result: &StepResult,
    name: Option<&str>,
    root: &Path,
    cx: &Context<'_>,
) -> (Option<String>, Vec<NextAction>) {
    let steps = steps_of(result);
    let files = written_files(result);
    let shown = display_path(root, cx.cwd);
    if let Some(repo) = steps
        .iter()
        .find(|step| step.get("scaffolded") == Some(&Json::Bool(true)))
    {
        let title = name
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                repo.text("name")
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| files::folder_name(root));
        let here = resolved(cx.cwd, root) == resolved(cx.cwd, cx.cwd);
        let message = if here {
            format!("Created {title} here")
        } else {
            let bare = shown.trim_end_matches('/');
            let bare = if bare.is_empty() {
                shown.as_str()
            } else {
                bare
            };
            let place = if Path::new(bare).is_absolute() || bare.starts_with('.') {
                bare.to_owned()
            } else {
                format!("./{bare}")
            };
            format!("Created {title} in {place}")
        };
        let mut actions = Vec::new();
        if !here {
            let word = shlex::try_quote(shown.trim_end_matches('/'))
                .map_or_else(|_| shown.clone(), std::borrow::Cow::into_owned);
            actions.push(NextAction::new(format!("cd {word}"), ""));
        }
        actions.push(NextAction::new(
            "opentide generate",
            "schemas, templates and editor snippets",
        ));
        actions.push(NextAction::new(
            "opentide validate",
            "check every object before you commit",
        ));
        actions.truncate(3);
        return (Some(message.trim_end_matches('/').to_owned()), actions);
    }
    match files.as_slice() {
        [] => (None, Vec::new()),
        [one] => (Some(format!("Wrote {one}")), Vec::new()),
        many => (Some(format!("Wrote {} files", many.len())), Vec::new()),
    }
}

/// The files written, one row each, for the text modes (`render_summary`).
fn summary(result: &StepResult) -> Vec<Text> {
    let mut rows: Vec<(String, &str)> = Vec::new();
    if steps_of(result)
        .iter()
        .any(|step| step.get("scaffolded") == Some(&Json::Bool(true)))
    {
        rows.push((
            "objects/{threats,objectives,rules}/".to_owned(),
            "your detection catalogue",
        ));
    }
    rows.extend(written_files(result).into_iter().map(|path| {
        let purpose = purpose(&path);
        (path, purpose)
    }));
    if rows.is_empty() {
        return Vec::new();
    }
    let styled: Vec<Vec<Text>> = rows
        .iter()
        .map(|(path, purpose)| {
            vec![
                Text::styled(path, &Style::new("bold")),
                Text::styled(purpose, &Style::new("dim")),
            ]
        })
        .collect();
    let mut lines: Vec<Text> = columns(&styled, 3, &[])
        .into_iter()
        .map(|row| {
            let mut line = Text::plain("  ");
            line.append_text(&row);
            line
        })
        .collect();
    lines.push(Text::default());
    lines
}

/// A finished run's report (`_emit_setup`).
fn finish(
    command: &str,
    mut result: StepResult,
    name: Option<&str>,
    root: &Path,
    cx: &Context<'_>,
) -> Report {
    let own_message = result
        .take("message")
        .and_then(|message| match message {
            Json::Str(text) => Some(text),
            _ => None,
        })
        .unwrap_or_default();
    let warnings = result.take("warnings");
    let status = result.take("status").and_then(|status| match status {
        Json::Str(text) => Some(text),
        _ => None,
    });
    // A failed or skipped run keeps its own message (`setup_outcome`).
    let (message, actions) = match status.as_deref() {
        Some("failed" | "skipped") => (None, Vec::new()),
        _ => outcome(&result, name, root, cx),
    };
    let body = if cx.mode == Mode::Json || cx.quiet {
        Vec::new()
    } else {
        summary(&result)
    };
    let mut report = Report::completed(command, result.fields);
    report.outcome.message = message.unwrap_or(own_message);
    report.outcome.next_actions = actions;
    report.numbered_next = true;
    if let Some(Json::Array(items)) = warnings {
        for item in items {
            if let Json::Str(text) = item
                && !report.warnings.contains(&text)
            {
                report.warnings.push(text);
            }
        }
    }
    if !body.is_empty() {
        report.body = vec![Block::Lines(body)];
    }
    if let Some(status) = status {
        if status == "failed" {
            let message = report.outcome.message.clone();
            failed(&mut report, &message);
        } else {
            report.outcome.status = status;
        }
    }
    report
}

// ---------------------------------------------------------------- the group

/// `opentide setup`'s own options.
#[derive(Clone, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the command's switches, one field each"
)]
pub struct GroupArgs {
    /// `--path`.
    pub path: String,
    /// `--name`, `--org`, `--description`, `--platform`.
    pub repo: files::RepoOptions,
    /// `--ci`: `github`, `gitlab`, `azure` or `none`.
    pub ci: Option<String>,
    /// The pipeline's options, as `setup ci` takes them (its provider unused).
    pub pipeline: Option<CiArgs>,
    /// `--staging/--no-staging`.
    pub staging: bool,
    /// `--inflight/--no-inflight`.
    pub inflight: bool,
    /// `--sharing`.
    pub sharing: bool,
    /// `--lint-changed`.
    pub lint_changed: bool,
    /// `--explorer-pages`.
    pub explorer_pages: bool,
    /// `--promotion/--no-promotion`.
    pub promotion: Option<bool>,
    /// `--promotion-target`.
    pub promotion_target: Option<String>,
    /// `--python-version`.
    pub python_version: String,
    /// `--default-branch`.
    pub default_branch: Option<String>,
    /// `--vscode-setup`.
    pub vscode_setup: bool,
    /// `--mcp`, in order, once each.
    pub mcp: Vec<String>,
    /// `--skills`.
    pub skills: Vec<String>,
    /// `--plugin`.
    pub plugin: bool,
    /// `--hooks`.
    pub hooks: bool,
    /// `--env`.
    pub env: bool,
    /// `--plan`.
    pub plan: bool,
    /// `--yes`.
    pub yes: bool,
}

/// The CI flags given without a pipeline to write (`_ignored_ci_flag_warnings`).
fn ignored_ci_flags(args: &GroupArgs) -> Vec<String> {
    if args.ci.as_deref().is_some_and(|ci| ci != "none") {
        return Vec::new();
    }
    let mut ignored = Vec::new();
    if args.default_branch.is_some() {
        ignored.push("--default-branch");
    }
    if !args.staging {
        ignored.push("--no-staging");
    }
    if !args.inflight {
        ignored.push("--no-inflight");
    }
    if args.sharing {
        ignored.push("--sharing");
    }
    if args.lint_changed {
        ignored.push("--lint-changed");
    }
    if args.explorer_pages {
        ignored.push("--explorer-pages");
    }
    if args.python_version != "3.12" {
        ignored.push("--python-version");
    }
    if ignored.is_empty() {
        return Vec::new();
    }
    vec![format!(
        "CI flags {} were ignored because no CI platform was selected. Re-run with --ci github, --ci gitlab, or --ci azure.",
        ignored.join(", ")
    )]
}

/// One step of the group's run: its result, recorded and (unless planning)
/// committed.
struct Recorder<'a> {
    stage: Stage,
    root: PathBuf,
    plan: bool,
    steps: Vec<StepResult>,
    planned: Vec<Planned>,
    warnings: Vec<String>,
    /// The message of the step that failed the run, which still wrote what
    /// it wrote (the `vscode` step without its snippets).
    failed: Option<String>,
    cx: &'a Context<'a>,
}

impl Recorder<'_> {
    fn record(&mut self, name: &str, result: StepResult) -> Result<(), String> {
        if self.plan {
            let planned = planned(&mut self.stage, &self.root, name, &result);
            self.planned.push(planned);
        } else {
            self.stage.commit()?;
        }
        for warning in result.strings("warnings") {
            if !self.warnings.contains(&warning) {
                self.warnings.push(warning);
            }
        }
        let mut fields = vec![("step".to_owned(), Json::str(name))];
        fields.extend(result.fields);
        self.steps.push(StepResult { fields });
        Ok(())
    }
}

/// `opentide setup`: a scripted setup, or its plan; at a terminal with
/// nothing on the command line to answer, the wizard.
pub fn group(args: &GroupArgs, cx: &Context<'_>) -> Report {
    const COMMAND: &str = "setup";
    if args.plugin || !args.skills.is_empty() {
        return not_ported(COMMAND, "opentide setup with --skills or --plugin");
    }
    let has_repo = args.repo.name.is_some()
        || args.repo.org.is_some()
        || args.repo.description.is_some()
        || !args.repo.platforms.is_empty();
    let answers = !args.mcp.is_empty() || args.hooks || args.env;
    let only_ci_none = args.ci.as_deref() == Some("none")
        && !args.yes
        && !has_repo
        && !args.vscode_setup
        && !answers;
    let scripted = args.plan
        || (!only_ci_none
            && (args.yes || has_repo || args.ci.is_some() || args.vscode_setup || answers));
    let shown = match target(
        cx,
        COMMAND,
        &Paths {
            own: Some(args.path.clone()),
            ..Paths::default()
        },
    ) {
        Ok(shown) => shown,
        Err(report) => return *report,
    };
    if !scripted {
        return wizard(COMMAND, cx, "--platform, --ci", Wizard::Setup, &shown);
    }
    let root = root_of(cx, &shown);
    if !args.plan && !args.yes {
        match confirm_write(COMMAND, &shown, &root, cx, "Apply this setup?") {
            Ok(true) => {}
            Ok(false) => return cancelled(COMMAND, "Setup cancelled"),
            Err(report) => return *report,
        }
    }
    let consent = args.yes || args.plan;
    let run_ci = args.ci.as_deref().is_some_and(|ci| ci != "none");
    // The other steps asked for, like --ci, leave the scaffold alone.
    let run_repo = has_repo || (consent && !run_ci && !answers && !args.vscode_setup);
    execute(
        args,
        &root,
        ignored_ci_flags(args),
        run_repo,
        run_ci,
        args.repo.name.as_deref(),
        cx,
    )
}

/// Runs the group's steps on `root` (`run_setup`), or plans them; `name` is
/// the `--name` the outcome line takes first.
fn execute(
    args: &GroupArgs,
    root: &Path,
    warnings: Vec<String>,
    run_repo: bool,
    run_ci: bool,
    name: Option<&str>,
    cx: &Context<'_>,
) -> Report {
    const COMMAND: &str = "setup";
    let mut recorder = Recorder {
        stage: Stage::new(),
        root: root.to_path_buf(),
        plan: args.plan,
        steps: Vec::new(),
        planned: Vec::new(),
        warnings,
        failed: None,
        cx,
    };
    let run_warnings = recorder.warnings.clone();
    if let Err(report) = run_steps(&mut recorder, args, run_repo, run_ci) {
        return *report;
    }
    if args.plan {
        let mut report = plan_report(COMMAND, root, recorder.planned, &run_warnings, cx);
        if let Some(message) = &recorder.failed {
            failed(&mut report, message);
        }
        return report;
    }
    let platforms = recorder
        .steps
        .iter()
        .find(|step| step.text("step") == Some("repo"))
        .map(|step| {
            step.get("platforms")
                .cloned()
                .unwrap_or(Json::Array(Vec::new()))
        });
    let mut fields = vec![
        ("path".to_owned(), Json::str(files::shown(root))),
        (
            "steps".to_owned(),
            Json::Array(
                recorder
                    .steps
                    .iter()
                    .map(|step| Json::Object(step.fields.clone()))
                    .collect(),
            ),
        ),
        ("warnings".to_owned(), strings(&recorder.warnings)),
    ];
    match &recorder.failed {
        Some(message) => {
            fields.push(("status".to_owned(), Json::str("failed")));
            fields.push(("message".to_owned(), Json::str(message)));
        }
        None => fields.push(("message".to_owned(), Json::str("Setup complete"))),
    }
    if run_repo && let Some(platforms) = platforms {
        fields.push(("platforms".to_owned(), platforms));
    }
    finish(COMMAND, StepResult { fields }, name, root, cx)
}

fn run_steps(
    recorder: &mut Recorder<'_>,
    args: &GroupArgs,
    run_repo: bool,
    run_ci: bool,
) -> Result<(), Box<Report>> {
    const COMMAND: &str = "setup";
    let cx = recorder.cx;
    let root = recorder.root.clone();
    let failed = |message: String| Box::new(Report::error(COMMAND, message));
    let statuses = || super::statuses(&root, cx);
    if args.promotion.is_some() || args.promotion_target.is_some() {
        let override_ = super::promotion_override(
            &root,
            args.promotion,
            args.promotion_target.as_deref(),
            statuses,
        )
        .map_err(|report| retitled(report, COMMAND))?;
        if !run_ci && let Some(override_) = override_ {
            let mut written = Vec::new();
            if let Some(content) = override_.content {
                recorder.stage.write(&override_.path, content);
                written.push(super::shown_relative(&override_.path, &root));
            }
            recorder
                .record(
                    "promotion",
                    StepResult::new([
                        ("message", Json::str("Promotion configured")),
                        ("files", strings(&written)),
                        ("path", Json::str(files::shown(&root))),
                    ]),
                )
                .map_err(failed)?;
        }
    }
    if run_repo {
        let result = files::repo(&mut recorder.stage, &root, &args.repo).map_err(failed)?;
        recorder.record("repo", result).map_err(failed)?;
    }
    if !args.repo.platforms.is_empty() {
        let result =
            files::platforms(&mut recorder.stage, &root, &args.repo.platforms).map_err(failed)?;
        recorder.record("platforms", result).map_err(failed)?;
    }
    if run_ci {
        let mut ci_args = base_ci_args(args);
        ci_args.promotion = args.promotion;
        ci_args.promotion_target.clone_from(&args.promotion_target);
        let result = ci_step(&mut recorder.stage, &ci_args, &root, cx)
            .map_err(|report| retitled(report, COMMAND))?;
        recorder.record("ci", result).map_err(failed)?;
    }
    if args.env {
        let result = files::env(&mut recorder.stage, &root).map_err(failed)?;
        recorder.record("env", result).map_err(failed)?;
    }
    if args.hooks {
        let result =
            super::hooks::hooks(&mut recorder.stage, cx.env, &root, true).map_err(failed)?;
        recorder.record("hooks", result).map_err(failed)?;
    }
    if !args.mcp.is_empty() {
        let result = files::mcp(
            &mut recorder.stage,
            &root,
            &args.mcp,
            files::McpServer::from_env(cx.env).as_ref(),
        );
        recorder.record("mcp", result).map_err(failed)?;
    }
    if args.vscode_setup {
        super::vscode::deprecation(cx);
        let done = super::vscode::run(
            &mut recorder.stage,
            &root,
            super::vscode::Options::all(),
            cx,
        )
        .map_err(failed)?;
        if done.failed {
            recorder.failed = Some(
                done.result
                    .text("message")
                    .unwrap_or("VS Code setup failed")
                    .to_owned(),
            );
        }
        recorder.record("vscode", done.result).map_err(failed)?;
    }
    Ok(())
}

/// The group's pipeline options as `setup ci` takes them.
fn base_ci_args(args: &GroupArgs) -> CiArgs {
    use opentide_compile::ci::Provider;
    let provider = match args.ci.as_deref() {
        Some("gitlab") => Provider::GitLab,
        Some("azure") => Provider::Azure,
        _ => Provider::GitHub,
    };
    CiArgs {
        provider,
        path: None,
        group_path: None,
        staging: args.staging,
        inflight: args.inflight,
        sharing: args.sharing,
        lint_changed: args.lint_changed,
        promotion: None,
        promotion_target: None,
        python_version: args.python_version.clone(),
        explorer_pages: args.explorer_pages,
        default_branch: args.default_branch.clone(),
        plan: args.plan,
        yes: true,
        group_only: Vec::new(),
    }
}

/// `setup ci` as a step of the group (`run_ci_setup`), into `stage`.
fn ci_step(
    stage: &mut Stage,
    args: &CiArgs,
    root: &Path,
    cx: &Context<'_>,
) -> Result<StepResult, Box<Report>> {
    if let Some(branch) = &args.default_branch
        && !super::is_valid_branch_name(branch)
    {
        return Err(bad_parameter(
            &format!(
                "{} cannot be written into a pipeline; use letters, digits, '.', '_', '/' and '-'",
                super::repr(branch)
            ),
            &["--default-branch"],
            Some("--default-branch"),
        ));
    }
    let run = super::prepare(stage, args, root, cx)?;
    let mut written = Vec::new();
    for (relative, bytes, _) in &run.files {
        if let Some(bytes) = bytes {
            stage.write(&root.join(relative), bytes.clone());
            written.push(relative.clone());
        }
    }
    let mut result = StepResult::new([
        ("message", Json::str("CI pipeline generated")),
        ("path", Json::str(files::shown(root))),
        ("ci", Json::str(args.provider.name())),
        ("platforms", strings(&run.platforms)),
        ("default_branch", Json::str(&run.branch)),
        ("files", strings(&written)),
    ]);
    if !run.warnings.is_empty() {
        result.set("warnings", strings(&run.warnings));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_name_what_each_file_is_for() {
        assert_eq!(purpose(".vscode/mcp.json"), "MCP server for VS Code");
        assert_eq!(purpose(".vscode/extensions.json"), "editor settings");
        assert_eq!(purpose(".gitlab-ci.yml"), "GitLab CI pipeline");
        assert_eq!(purpose(".opentide/hooks/pre-commit"), "");
    }

    #[test]
    fn a_path_outside_the_target_is_shown_through_dot_dot() {
        assert_eq!(
            super::super::shown_relative(
                Path::new("/r/.git/hooks/pre-commit"),
                Path::new("/r/a/b")
            ),
            "../../.git/hooks/pre-commit"
        );
        assert_eq!(
            super::super::shown_relative(Path::new("/r/a/x"), Path::new("/r/a")),
            "x"
        );
        assert_eq!(
            super::super::shown_relative(Path::new("/r/a"), Path::new("/r/a")),
            "."
        );
    }

    #[test]
    fn ci_flags_without_a_pipeline_are_named() {
        let args = GroupArgs {
            staging: false,
            inflight: true,
            sharing: true,
            python_version: "3.12".into(),
            ..GroupArgs::default()
        };
        assert_eq!(
            ignored_ci_flags(&args),
            [
                "CI flags --no-staging, --sharing were ignored because no CI platform was selected. Re-run with --ci github, --ci gitlab, or --ci azure."
            ]
        );
        let with_ci = GroupArgs {
            ci: Some("github".into()),
            ..args
        };
        assert!(ignored_ci_flags(&with_ci).is_empty());
    }

    fn context<'a>(env: &'a crate::env::Env, cwd: &'a Path) -> Context<'a> {
        Context {
            repo: None,
            env,
            cwd,
            mode: Mode::Json,
            version: "0.0.0",
            quiet: false,
            terminal: crate::commands::Terminal::plain(Mode::Json),
            interrupt: crate::app::Interrupt::default(),
            stderr: std::sync::Arc::new(std::sync::Mutex::new(std::io::sink())),
        }
    }

    fn files_of(report: &Report) -> Vec<(String, String, String)> {
        let Some(Json::Array(steps)) = report
            .outcome
            .data
            .iter()
            .find(|(k, _)| k == "steps")
            .map(|(_, v)| v)
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for step in steps {
            let name = step
                .get("step")
                .and_then(|v| match v {
                    Json::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            if let Some(Json::Array(files)) = step.get("files") {
                for file in files {
                    let text = |key: &str| match file.get(key) {
                        Some(Json::Str(s)) => s.clone(),
                        _ => String::new(),
                    };
                    out.push((name.clone(), text("path"), text("action")));
                }
            }
        }
        out
    }

    #[test]
    fn a_plan_writes_nothing_and_lists_what_the_run_writes() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(cwd.join(".gitignore"), "node_modules\r\n").unwrap();
        let env = crate::env::Env::from_pairs([(
            "GIT_CEILING_DIRECTORIES".to_owned(),
            cwd.display().to_string(),
        )]);
        let cx = context(&env, &cwd);
        let args = GroupArgs {
            path: ".".into(),
            repo: files::RepoOptions {
                platforms: vec!["splunk".into()],
                ..files::RepoOptions::default()
            },
            mcp: vec!["cursor".into()],
            env: true,
            plan: true,
            staging: true,
            inflight: true,
            python_version: "3.12".into(),
            ..GroupArgs::default()
        };
        let plan = group(&args, &cx);
        assert_eq!(plan.outcome.exit_code, 0, "{:?}", plan.outcome);
        let listed = files_of(&plan);
        assert!(
            listed.contains(&("repo".into(), ".gitignore".into(), "merge".into())),
            "{listed:?}"
        );
        assert!(
            listed.contains(&("repo".into(), "README.md".into(), "create".into())),
            "{listed:?}"
        );
        assert!(
            listed.contains(&(
                "platforms".into(),
                ".opentide/configurations/platforms/splunk.toml".into(),
                "skip".into()
            )),
            "{listed:?}"
        );
        assert!(
            listed.contains(&("env".into(), ".gitignore".into(), "merge".into())),
            "{listed:?}"
        );
        assert!(
            listed.contains(&("mcp".into(), ".cursor/mcp.json".into(), "create".into())),
            "{listed:?}"
        );
        // Nothing written: the folder holds only what it held.
        let names: Vec<String> = std::fs::read_dir(&cwd)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [".gitignore"]);
        assert_eq!(
            std::fs::read_to_string(cwd.join(".gitignore")).unwrap(),
            "node_modules\r\n"
        );
        // The run writes what the plan listed, CRLF kept.
        let run = group(
            &GroupArgs {
                plan: false,
                yes: true,
                ..args.clone()
            },
            &cx,
        );
        assert_eq!(run.outcome.exit_code, 0, "{:?}", run.outcome);
        for (_, path, action) in &listed {
            if action != "skip" {
                assert!(cwd.join(path).is_file(), "{path}");
            }
        }
        let gitignore = std::fs::read_to_string(cwd.join(".gitignore")).unwrap();
        assert!(
            gitignore.starts_with("node_modules\r\n.opentide/exports/*.export.json\r\n"),
            "{gitignore:?}"
        );
        assert!(gitignore.ends_with(".env\r\n"), "{gitignore:?}");
        // Planned again, everything is already there.
        let again = group(&args, &cx);
        let actions: Vec<String> = files_of(&again)
            .into_iter()
            .map(|(_, _, action)| action)
            .collect();
        assert!(!actions.iter().any(|a| a == "create"), "{actions:?}");
    }
}
