//! The commands that run on this crate (UC-2.4: `info`, `rules unreviewed`;
//! UC-3.2: `generate exports`; UC-3.5: `validate`, `validate query`, `lint`,
//! `explain`; UC-3.1c: `deploy --dry-run`; UC-3.5c: `doctor --offline`,
//! `migrate vocab-scope`; UC-3.5d: `new`, `generate <phase>`).
//!
//! A command reads its arguments and the workspace and returns a
//! [`Report`]: the JSON envelope's parts, and what the text modes print
//! before the outcome line. `app::Run::emit_report` writes it in the run's
//! mode.

pub mod completion;
pub mod cve;
pub mod deploy;
pub mod deploy_promote;
pub mod deploy_replay;
pub mod deploy_retire;
pub mod deploy_send;
pub mod deploy_state;
pub mod doctor;
pub mod doctor_network;
pub mod explain;
pub mod extract;
pub mod findings;
pub mod generate;
pub mod home;
pub mod info;
mod interrupt;
pub mod lint;
pub mod lsp;
pub mod migrate;
pub mod migrate_state;
pub mod new;
pub mod plugin;
pub mod promotion_preview;
pub mod query;
pub mod query_rule;
pub mod result;
pub mod rules;
pub mod setup;
pub mod share;
pub mod skills;
mod template;
pub mod tui;
pub mod validate;
pub mod validate_live;
pub mod validate_query;
pub mod watch;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_workspace::{OsFs, RootOptions, Workspace, root};

use crate::commands::result::{ExitCode, Status};
use crate::env::Env;
use crate::envelope::{Failure, NextAction, Outcome, code};
use crate::json::Json;
use crate::render::outcome::OutcomeKind;
use crate::render::text::Text;

/// `failure.code` of a command that stopped on an error of its own.
pub const COMMAND_FAILED: &str = "command_failed";
/// `failure.code` of a run that found problems and was asked to fail on them.
pub const ISSUES_FOUND: &str = "issues_found";

/// What a command prints.
#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent switches of how a report prints, one field each"
)]
pub struct Report {
    /// The envelope's parts.
    pub outcome: Outcome,
    /// `warning:` lines, and the document's `warnings`.
    pub warnings: Vec<String>,
    /// The outcome line, when it is not the message.
    pub outcome_line: Option<String>,
    /// The outcome line's kind, when the status does not say it.
    pub outcome_kind: Option<OutcomeKind>,
    /// What the text modes print on stdout before the outcome line.
    pub body: Vec<Block>,
    /// The checklist's steps, printed on stderr before anything else.
    pub steps: Vec<crate::render::progress::Step>,
    /// The checklist's total when each finished step writes its
    /// `OPENTIDE_PROGRESS=json` event (in every mode):
    /// `generate`, with its phases named or none.
    pub step_events: Option<usize>,
    /// Log lines the run writes once its checklist rows are printed, after
    /// its last step, so they are not drawn inside the checklist.
    pub after_steps: Vec<AfterSteps>,
    /// The whole of stdout in the text modes, instead of the body and the
    /// outcome (a `--format` report printed without `--output`).
    pub whole_stdout: Option<String>,
    /// No outcome line in the text modes: the body is the output
    /// (`explain <code>`).
    pub body_only: bool,
    /// Written on stderr first, in every mode (`OPENTIDE_PROGRESS=json`'s
    /// events).
    pub stderr_first: String,
    /// The next steps as a numbered list under a `Next steps` header, for a
    /// sequence the reader follows step by step (`setup`).
    pub numbered_next: bool,
    /// The CI job summary's section (Markdown), appended in a text mode
    /// before the result is printed.
    pub ci_summary: Option<String>,
    /// The run ends with its exit code and prints nothing more, in every
    /// mode: no document, no outcome line (`deploy`'s invalid promotion
    /// target, which stops the run in the middle).
    pub bare_exit: bool,
    /// A usage error the command found once it ran (a value refused
    /// after parsing): printed as clap prints a parse error, with the
    /// command's `Usage:` line and `--help` hint.
    pub usage_notes: bool,
}

/// A log line written after the checklist's rows ([`Report::after_steps`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AfterSteps {
    /// `report_nested_object_files`: the object files in subfolders of an
    /// object folder, skipped (#584).
    NestedObjectFiles {
        /// The warning's text.
        detail: String,
        /// The files, as shown.
        files: Vec<String>,
    },
}

impl AfterSteps {
    /// Logs the line.
    pub fn log(&self) {
        match self {
            AfterSteps::NestedObjectFiles { detail, files } => {
                // The files as a JSON array of strings.
                let listed = serde_json::to_string(files).unwrap_or_default();
                tracing::warn!(
                    detail = detail.as_str(),
                    count = files.len(),
                    files = listed.as_str(),
                    issue = NESTED_OBJECTS_ISSUE,
                    "nested_object_file"
                );
            }
        }
    }
}

/// Where the nested-file warning points (`NESTED_OBJECTS_ISSUE`).
pub const NESTED_OBJECTS_ISSUE: &str = "https://github.com/opentidehq/opentide/issues/584";

/// One part of a body.
#[derive(Clone, Debug)]
pub enum Block {
    /// Lines, wrapped at the stream's width when wider.
    Lines(Vec<Text>),
    /// A table, laid out at the stream's width.
    Table(crate::render::table::Table),
    /// Lines wrapped at words on a terminal, each with the indent its
    /// continued rows take (`doctor`'s checklist).
    Hanging(Vec<(Text, usize)>),
    /// Text for stdout, already laid out for the stream.
    Raw(String),
    /// Text for stderr, already laid out for the stream, in its place
    /// among the body's parts.
    Stderr(String),
}

/// Root flags a suggested re-run leaves out: they change how output looks,
/// not what runs (`_PRESENTATION_FLAGS`).
const PRESENTATION_FLAGS: [&str; 5] = ["--json", "--no-color", "--debug", "--quiet", "--verbose"];

/// The streams a command lays its text out for.
#[derive(Clone, Debug)]
pub struct Terminal {
    /// The run's output mode.
    pub mode: crate::mode::Mode,
    /// stdout's styles and width.
    pub stdout: crate::render::outcome::Console,
    /// stderr's styles and width.
    pub stderr: crate::render::outcome::Console,
    /// `--quiet`.
    pub quiet: bool,
    /// `--verbose`: `validate`, `lint` and `validate query` print notes.
    pub verbose: bool,
    /// The arguments as typed: what a suggested re-run repeats.
    pub typed: Vec<String>,
    /// Whether stdout is a terminal.
    pub stdout_tty: bool,
    /// The terminal's width, when there is one.
    pub width: Option<usize>,
}

impl Terminal {
    /// A terminal for tests and machine modes: no styles, no width.
    pub fn plain(mode: crate::mode::Mode) -> Terminal {
        let console = crate::render::outcome::Console {
            colour: crate::render::text::Colour::None,
            width: None,
        };
        Terminal {
            mode,
            stdout: console,
            stderr: console,
            quiet: false,
            verbose: false,
            typed: Vec::new(),
            stdout_tty: false,
            width: None,
        }
    }

    /// Whether the run prints text (not `json`).
    pub fn text(&self) -> bool {
        self.mode != crate::mode::Mode::Json
    }

    /// This invocation as one shell command with `added` at the end, for a
    /// next step (`rerun_command`): the arguments as typed (`--file`,
    /// `--changed`, `--check`, `--repo` kept), less the flags that only
    /// change how output looks.
    pub fn rerun(&self, added: &[&str]) -> String {
        let words: Vec<&str> = std::iter::once("opentide")
            .chain(
                self.typed
                    .iter()
                    .map(String::as_str)
                    .filter(|word| !PRESENTATION_FLAGS.contains(word)),
            )
            .chain(added.iter().copied())
            .collect();
        opentide_core::text::shell_line(words.iter().copied())
    }

    /// `next` with the step that shows the `hidden` notes the code frames
    /// left out (`with_hidden_notes_step`): the command as typed, with
    /// `--verbose`. Nothing changes when no note was hidden.
    pub fn hidden_notes_step(&self, next: &mut Vec<crate::envelope::NextAction>, hidden: usize) {
        // MCP never prints frames, so it hides nothing.
        if hidden == 0 || self.mode == crate::mode::Mode::Mcp {
            return;
        }
        let noun = if hidden == 1 { "note" } else { "notes" };
        next.push(crate::envelope::NextAction::new(
            self.rerun(&["--verbose"]),
            format!("show {hidden} {noun}, such as a missing optional field"),
        ));
    }

    /// How code frames are drawn on stdout.
    pub fn frames(&self, cwd: &Path, env: &Env) -> crate::render::codeframe::Frames {
        let human = self.mode == crate::mode::Mode::Human;
        crate::render::codeframe::Frames {
            colour: self.stdout.colour,
            links: human && self.stdout_tty,
            columns: self.stdout.width,
            highlight: human && self.stdout.colour == crate::render::text::Colour::Full,
            cwd: cwd.to_path_buf(),
            env: env.clone(),
        }
    }
}

impl Report {
    /// A successful report.
    pub fn completed(command: &str, data: impl IntoIterator<Item = (String, Json)>) -> Report {
        Report {
            outcome: Outcome {
                command: command.to_owned(),
                status: Status::Completed,
                message: "Completed successfully".into(),
                data: data.into_iter().collect(),
                exit_code: ExitCode::Success,
                summary: Vec::new(),
                next_actions: Vec::new(),
                failure: None,
            },
            warnings: Vec::new(),
            outcome_line: None,
            outcome_kind: None,
            body: Vec::new(),
            steps: Vec::new(),
            step_events: None,
            after_steps: Vec::new(),
            whole_stdout: None,
            body_only: false,
            stderr_first: String::new(),
            numbered_next: false,
            ci_summary: None,
            bare_exit: false,
            usage_notes: false,
        }
    }

    /// A failure, with `failure.code` `code`.
    pub fn failed(command: &str, exit_code: ExitCode, failure: Failure) -> Report {
        Report {
            outcome: Outcome::failed(command, exit_code, failure),
            warnings: Vec::new(),
            outcome_line: None,
            outcome_kind: None,
            body: Vec::new(),
            steps: Vec::new(),
            step_events: None,
            after_steps: Vec::new(),
            whole_stdout: None,
            body_only: false,
            stderr_first: String::new(),
            numbered_next: false,
            ci_summary: None,
            bare_exit: false,
            usage_notes: false,
        }
    }

    /// A usage error the command found itself: exit 2, with `argument` and
    /// the choice closest to `value` (`opentide_core::suggest`).
    pub fn usage(
        command: &str,
        message: impl Into<String>,
        failure_code: &str,
        argument: &str,
        value: Option<&str>,
        choices: &[&str],
    ) -> Report {
        let mut failure = Failure::new(failure_code, message);
        failure.argument = Some(argument.to_owned());
        failure.suggestion = value
            .and_then(|value| {
                opentide_core::suggest::closest(value, choices.iter().copied())
                    .filter(|choice| *choice != value)
            })
            .map(str::to_owned);
        Report::failed(command, ExitCode::Usage, failure)
    }

    /// An error the command stopped on: exit 1, `command_failed`.
    pub fn error(command: &str, message: impl Into<String>) -> Report {
        Report::failed(
            command,
            ExitCode::Failure,
            Failure::new(COMMAND_FAILED, message),
        )
    }

    /// Adds a next step.
    pub fn next(&mut self, command: &str, reason: &str) {
        self.outcome
            .next_actions
            .push(NextAction::new(command, reason));
    }
}

/// `code`'s re-exports the commands use.
pub use code::{USAGE_INVALID_CHOICE, USAGE_INVALID_VALUE, USAGE_MISSING_OPTION};

/// `value` serialised and read back as an order-keeping [`Json`].
pub fn json<T: serde::Serialize>(value: &T) -> Json {
    serde_json::to_string(value)
        .ok()
        .and_then(|text| Json::parse(&text).ok())
        .unwrap_or(Json::Null)
}

/// Where a run's workspace is: the repository (`--repo`, else
/// `OPENTIDE_REPO_ROOT`, else the nearest workspace root) as it prints it,
/// and the options that open it: `OPENTIDE_REPO_ROOT` is the repository, and
/// `OPENTIDE_TIDE_WORKSPACE` the repository too unless the environment names
/// one and `--repo` is not given.
pub fn placement(repo: Option<&str>, env: &Env, cwd: &Path) -> (String, RootOptions) {
    let from_env = |name: &str| env.get(name).filter(|value| !value.is_empty());
    let given = repo.or_else(|| from_env("OPENTIDE_REPO_ROOT"));
    let shown = match given {
        Some(text) => text.to_owned(),
        None => root::find_workspace_root(&OsFs, cwd)
            .to_string_lossy()
            .into_owned(),
    };
    let repo_path = PathBuf::from(&shown);
    let tide_workspace = if repo.is_some() || from_env("OPENTIDE_TIDE_WORKSPACE").is_none() {
        Some(repo_path.clone())
    } else {
        from_env("OPENTIDE_TIDE_WORKSPACE").map(PathBuf::from)
    };
    let options = RootOptions {
        repo: Some(repo_path.clone()),
        repo_root_env: Some(repo_path),
        tide_workspace_env: tide_workspace,
        cwd: cwd.to_path_buf(),
    };
    (shown, options)
}

/// The repository root `repo`, `env` and `cwd` place, absolute, when
/// neither it nor the `OPENTIDE_TIDE_WORKSPACE` it reads is a workspace
/// root (no `.opentide/` or `objects/`); `None` when one of them is. The one
/// test the commands that write ([`no_workspace`]) and the MCP server's
/// catalogue tools (`mcp::plugin::missing_workspace`) apply, so a layout
/// one serves the other serves too: a repository root with no markers and
/// its detections in `OPENTIDE_TIDE_WORKSPACE` is a workspace.
pub fn unplaced_root(repo: Option<&str>, env: &Env, cwd: &Path) -> Option<PathBuf> {
    let (shown, options) = placement(repo, env, cwd);
    let absolute = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        }
    };
    let root = absolute(Path::new(&shown));
    let found = std::iter::once(root.clone())
        .chain(options.tide_workspace_env.as_deref().map(absolute))
        .any(|path| root::is_workspace_root(&OsFs, &path));
    (!found).then_some(root)
}

/// The refusal of a command that writes into the workspace when `repo`,
/// `env` and `cwd` place none ([`unplaced_root`]): writing there would make
/// that folder a workspace every folder below it discovers (D17, B18:
/// `generate` wrote 20 files into a stray folder and `migrate` reported 0
/// files scanned, both exiting 0). `workspace_not_found`, exit 1, as
/// `opentide new` refuses.
pub fn no_workspace(command: &str, repo: Option<&str>, env: &Env, cwd: &Path) -> Option<Report> {
    let root = unplaced_root(repo, env, cwd)?;
    let mut report = Report::failed(
        command,
        ExitCode::Failure,
        Failure::new(
            new::WORKSPACE_NOT_FOUND,
            format!(
                "No workspace at {}: no .opentide/ or objects/ there or above it",
                root.display()
            ),
        ),
    );
    report.next("opentide setup", "create a workspace first");
    Some(report)
}

/// Opens the workspace `options` place for `command`, or the report of why
/// it does not open. A configuration TOML file that does not parse is
/// `config_parse` (D9, B10: it was `command_failed` with no position), its
/// message `path:line:column: problem`, and `diagnostics` holds the file,
/// line and column, as `docs/cli/json-output.md` documents. A file that
/// cannot be read (permissions, not UTF-8) keeps that code, the only one
/// for a configuration file that stops the run, with its own message and
/// help: it has no syntax to fix. Any other problem is `command_failed`, as
/// before.
pub fn open_for(command: &str, options: RootOptions) -> Result<Workspace, Box<Report>> {
    use opentide_schema::configuration::resolve::ResolveError;
    use opentide_workspace::ConfigError;
    let root = options
        .repo
        .as_deref()
        .map(|repo| options.absolute(repo))
        .unwrap_or_default();
    let error = match Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options { roots: options },
    ) {
        Ok(workspace) => return Ok(workspace),
        Err(error) => error,
    };
    let (path, problem, line, column, unreadable) = match &error {
        ConfigError::Resolve(ResolveError::Parse {
            path,
            message,
            line,
            column,
        }) => (path.clone(), message.clone(), *line, *column, false),
        ConfigError::Unreadable { path, message } => {
            (path.clone(), message.clone(), None, None, true)
        }
        _ => return Err(Box::new(Report::error(command, error.to_string()))),
    };
    // Shown from the workspace root, as 0.28.1 showed it; through a symbolic
    // link (macOS's `/tmp`, a linked checkout) on both resolved.
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let shown = Path::new(&path)
        .strip_prefix(&root)
        .map(Path::to_path_buf)
        .or_else(|_| {
            canonical(Path::new(&path))
                .strip_prefix(canonical(&root))
                .map(Path::to_path_buf)
        })
        .map_or_else(
            |_| path.clone(),
            |relative| relative.to_string_lossy().replace('\\', "/"),
        );
    let place = match (line, column) {
        (Some(line), Some(column)) => format!("{shown}:{line}:{column}"),
        (Some(line), None) => format!("{shown}:{line}"),
        _ => shown.clone(),
    };
    let number = |value: Option<usize>| value.map_or(Json::Null, Json::from);
    let diagnostic = Json::object([
        ("code", Json::str(CONFIG_PARSE)),
        ("severity", Json::str("error")),
        (
            "message",
            Json::Str(if unreadable {
                format!("Could not read the configuration file: {problem}")
            } else {
                format!("Could not parse configuration TOML: {problem}")
            }),
        ),
        ("path", Json::str(&shown)),
        ("file_path", Json::str(&path)),
        ("line", number(line)),
        ("column", number(column)),
        ("end_line", number(line)),
        ("end_column", number(column.map(|column| column + 1))),
        (
            "help",
            Json::str(if unreadable {
                "make the file readable UTF-8 text (its permissions, its encoding), then run \
                 the command again"
            } else {
                "fix the TOML syntax at this position, then run the command again"
            }),
        ),
        ("explain", Json::str("opentide explain config_parse")),
    ]);
    let message = if unreadable {
        format!("{place}: cannot be read: {problem}")
    } else {
        format!("{place}: {problem}")
    };
    let mut report = Report::failed(
        command,
        ExitCode::Failure,
        Failure::new(CONFIG_PARSE, message),
    );
    report
        .outcome
        .data
        .push(("diagnostics".to_owned(), Json::Array(vec![diagnostic])));
    Err(Box::new(report))
}

/// An [`open_for`] refusal as the parts a command that builds its own
/// envelope carries: the failure code, the message and the `diagnostics`.
pub fn refusal_parts(report: &Report) -> (String, String, Option<Json>) {
    let (code, message) = report.outcome.failure.as_ref().map_or_else(
        || (COMMAND_FAILED.to_owned(), report.outcome.message.clone()),
        |failure| (failure.code.clone(), failure.message.clone()),
    );
    let diagnostics = report
        .outcome
        .data
        .iter()
        .find(|(key, _)| key == "diagnostics")
        .map(|(_, value)| value.clone());
    (code, message, diagnostics)
}

/// `failure.code` of a configuration TOML file that does not parse.
pub const CONFIG_PARSE: &str = "config_parse";

/// Opens the workspace `options` place, on disk.
///
/// # Errors
///
/// The configuration does not resolve: the message.
pub fn open(options: RootOptions) -> Result<Workspace, String> {
    Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options { roots: options },
    )
    .map_err(|error| error.to_string())
}

/// `count noun`, with an `s` unless the count is one.
pub fn counted(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts() {
        assert_eq!(counted(1, "rule"), "1 rule");
        assert_eq!(counted(0, "rule"), "0 rules");
    }

    #[test]
    fn a_configuration_file_that_does_not_parse_is_config_parse_with_its_place() {
        // D9, B10 (smoke test): `[platform` in a platform TOML failed every
        // command with `command_failed`, an absolute path and no position.
        let dir = tempfile::tempdir().unwrap();
        let platforms = dir.path().join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&platforms).unwrap();
        std::fs::create_dir_all(dir.path().join("objects")).unwrap();
        std::fs::write(
            platforms.join("sentinel.toml"),
            "enabled = true\n[platform\n",
        )
        .unwrap();
        let (_, options) = placement(None, &Env::default(), dir.path());
        let Err(report) = open_for("validate", options) else {
            panic!("the workspace opened");
        };
        let failure = report.outcome.failure.as_ref().unwrap();
        assert_eq!(failure.code, "config_parse");
        assert_eq!(report.outcome.exit_code, ExitCode::Failure);
        assert!(
            report.outcome.message.contains("sentinel.toml:2:"),
            "{}",
            report.outcome.message
        );
        let Some((_, Json::Array(diagnostics))) = report
            .outcome
            .data
            .iter()
            .find(|(key, _)| key == "diagnostics")
        else {
            panic!("no diagnostics: {:?}", report.outcome.data);
        };
        let Json::Object(first) = &diagnostics[0] else {
            panic!("not an object");
        };
        assert_eq!(first.get("code"), Some(&Json::str("config_parse")));
        assert_eq!(first.get("line"), Some(&Json::from(2usize)));
        assert!(
            matches!(first.get("column"), Some(Json::Int(_))),
            "{first:?}"
        );
        // Placed through a symbolic link, the file is still shown from the
        // workspace root, not as an absolute path.
        #[cfg(unix)]
        {
            let links = tempfile::tempdir().unwrap();
            let link = links.path().join("linked");
            std::os::unix::fs::symlink(dir.path(), &link).unwrap();
            let linked = link.to_string_lossy().into_owned();
            let real = dir.path().to_string_lossy().into_owned();
            let env = Env::default();
            for (repo, cwd) in [
                (None, link.as_path()),
                (Some(linked.as_str()), dir.path()),
                (Some(real.as_str()), link.as_path()),
                (Some(linked.as_str()), links.path()),
            ] {
                let (_, options) = placement(repo, &env, cwd);
                let Err(report) = open_for("validate", options) else {
                    panic!("the workspace opened");
                };
                assert!(
                    report
                        .outcome
                        .message
                        .starts_with(".opentide/configurations/platforms/sentinel.toml:2:"),
                    "{repo:?} from {}: {}",
                    cwd.display(),
                    report.outcome.message
                );
            }
        }
        // generate keeps the code too, on its failed phase.
        let env = Env::default();
        let cx = generate::Context {
            repo: None,
            env: &env,
            cwd: dir.path(),
            proxy: None,
            version: "0.0.0",
        };
        let generated = generate::docs(&generate::DocsArgs::default(), &cx);
        assert_eq!(
            generated.outcome.failure.as_ref().map(|f| f.code.as_str()),
            Some("config_parse")
        );
    }

    #[test]
    fn usage_errors_suggest_the_closest_choice() {
        let report = Report::usage(
            "info",
            "bad",
            USAGE_INVALID_CHOICE,
            "section",
            Some("rulez"),
            &["rules", "threats"],
        );
        assert_eq!(report.outcome.exit_code, ExitCode::Usage);
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.suggestion.as_deref(), Some("rules"));
        assert_eq!(failure.argument.as_deref(), Some("section"));
        let none = Report::usage(
            "info",
            "bad",
            USAGE_INVALID_CHOICE,
            "section",
            Some("zzzzzz"),
            &["rules"],
        );
        assert_eq!(none.outcome.failure.unwrap().suggestion, None);
    }
}

#[cfg(test)]
mod verbose_tests {
    use super::Terminal;
    use crate::mode::Mode;

    fn terminal(mode: Mode, typed: &[&str]) -> Terminal {
        Terminal {
            typed: typed.iter().map(|word| (*word).to_owned()).collect(),
            ..Terminal::plain(mode)
        }
    }

    /// The step repeats the command as typed, less the flags that only
    /// change how output looks, and quotes what a shell would split.
    #[test]
    fn hidden_notes_step_repeats_the_command_with_verbose() {
        let typed = terminal(
            Mode::Plain,
            &[
                "--no-color",
                "--repo",
                "my repo",
                "lint",
                "--check",
                "recommended",
                "--debug",
            ],
        );
        assert_eq!(
            typed.rerun(&["--verbose"]),
            "opentide --repo 'my repo' lint --check recommended --verbose"
        );
        let mut next = Vec::new();
        typed.hidden_notes_step(&mut next, 0);
        assert!(next.is_empty());
        typed.hidden_notes_step(&mut next, 1);
        typed.hidden_notes_step(&mut next, 3);
        assert_eq!(
            next[0].reason,
            "show 1 note, such as a missing optional field"
        );
        assert_eq!(
            next[1].reason,
            "show 3 notes, such as a missing optional field"
        );
        assert_eq!(
            next[0].command,
            "opentide --repo 'my repo' lint --check recommended --verbose"
        );
        // MCP prints no frames: nothing was hidden from it.
        let mut none = Vec::new();
        terminal(Mode::Mcp, &["lint"]).hidden_notes_step(&mut none, 2);
        assert!(none.is_empty());
    }
}

/// The folders of the workspace's object families (`rules`, `objectives`,
/// `threats`, as `paths.toml` places them), for the note on uncommitted
/// object files.
pub fn object_folders(workspace: &opentide_workspace::Workspace) -> Vec<std::path::PathBuf> {
    workspace
        .configuration()
        .object_folders
        .iter()
        .filter_map(|folder| folder.path.clone())
        .collect()
}
