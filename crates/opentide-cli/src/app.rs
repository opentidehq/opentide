//! One run of `opentide`: from the command line to the exit code.
//!
//! [`run`] reads the global flags, resolves the output mode, sets up logging
//! for it, parses the command line with clap, reports usage errors through
//! the contract, runs the command and catches whatever it did not expect
//! ([`crate::crash`]). It writes to the streams it is given, so the binary,
//! the Python and npm launchers and the tests all run the same code.

use crate::catalog;
use crate::crash::{self, Facts, Internal};
use crate::env::Env;
use crate::envelope::{Failure, INTERRUPTED_EXIT_CODE, NextAction, Outcome, USAGE_EXIT_CODE, code};
use crate::json::document_text;
use crate::logging::{self, LogLayer, Sink};
use crate::mode::{self, Inputs, Mode};
use crate::redact::{Redactor, url_secrets, workspace_redactor};
use crate::render::outcome::{Console, OutcomeKind};
use crate::render::text::{Colour, Text};
use crate::usage;
use anstyle::Style;
use clap::FromArgMatches;
use clap::parser::ValueSource;

use crate::tree::{RootCommand, SetupArgs};
use std::cell::RefCell;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// What the embedding process tells the run about itself.
pub struct Host {
    /// opentide's version, as `--version` and the catalogue print it.
    pub version: String,
    /// Whether stdout is a terminal.
    pub stdout_tty: bool,
    /// Whether stderr is a terminal.
    pub stderr_tty: bool,
    /// Where log lines go: stderr.
    pub log_sink: Sink,
    /// The working directory, whose workspace the redactor reads.
    pub cwd: Option<PathBuf>,
    /// The terminal's width in columns, when there is a terminal.
    pub width: Option<usize>,
    /// Ctrl-C for this run: set by the handler ([`install_interrupt_handler`]),
    /// polled by long jobs ([`Interrupt::requested`]).
    pub interrupt: Interrupt,
}

/// Ctrl-C, as one run sees it.
///
/// The first Ctrl-C sets it: long jobs (tenant calls) poll
/// [`Interrupt::requested`], stop and clean up, and the run then prints
/// `error: interrupted` on stderr and exits 130 with no JSON document. A
/// second Ctrl-C, or a run that has not stopped after [`INTERRUPT_GRACE`],
/// ends the process at once with the same line and code.
#[derive(Clone, Debug, Default)]
pub struct Interrupt {
    requested: Arc<AtomicBool>,
    reported: Arc<AtomicBool>,
    at_once: Arc<AtomicBool>,
}

impl Interrupt {
    /// Records a Ctrl-C; whether one was recorded before.
    pub fn request(&self) -> bool {
        self.requested.swap(true, Ordering::SeqCst)
    }

    /// Whether Ctrl-C was pressed: long jobs poll this and stop.
    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Has the first Ctrl-C end the process at once, with no grace: for a
    /// run that blocks without polling [`Interrupt::requested`] and holds
    /// nothing to clean up (`lsp start`'s server on stdio).
    pub fn stop_at_once(&self) {
        self.at_once.store(true, Ordering::SeqCst);
    }

    /// Takes back a Ctrl-C a command handled as its way to stop
    /// (`validate --watch` exits 0): the run then reports no interruption.
    pub fn consume(&self) {
        self.requested.store(false, Ordering::SeqCst);
    }

    /// Prints `error: interrupted` once, whoever reports it first; 130.
    pub fn report(&self, err: &mut dyn Write) -> i32 {
        if !self.reported.swap(true, Ordering::SeqCst) {
            let _ignored = err.write_all(b"error: interrupted\n");
            let _ignored = err.flush();
        }
        INTERRUPTED_EXIT_CODE
    }
}

/// How long the run has to stop after the first Ctrl-C before the process
/// ends without it.
pub const INTERRUPT_GRACE: Duration = Duration::from_secs(5);

/// The parsed root options and global flags: what every command shares.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the root's flags, one field each, as the command line has them"
)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Globals {
    /// `--json`.
    pub json: bool,
    /// `--no-color`.
    pub no_color: bool,
    /// `--debug`.
    pub debug: bool,
    /// `--quiet`.
    pub quiet: bool,
    /// `--verbose`: print notes too.
    pub verbose: bool,
    /// `--version` or `-V`.
    pub version: bool,
    /// `--install-completion`.
    pub install_completion: bool,
    /// `--show-completion`.
    pub show_completion: bool,
    /// `--repo`, as typed on the command line (not from the environment).
    pub repo: Option<String>,
    /// `--proxy`, from the command line or `OPENTIDE_PROXY`.
    pub proxy: Option<String>,
    /// `--data`, as typed on the command line (not from the environment).
    pub data: Option<String>,
}

/// `args` parsed as far as clap can: the global flags, the root's options and
/// the command path, even from a command line with a usage error in it (the
/// error is reported once the run's mode is known).
pub fn lenient_matches(root: &clap::Command, args: &[String]) -> clap::ArgMatches {
    // `--help` is a flag here, so the help's run knows its globals too.
    fn lenient(command: clap::Command) -> clap::Command {
        let command = command.ignore_errors(true).mut_subcommands(lenient);
        if command.get_arguments().any(|arg| arg.get_id() == "help") {
            command.mut_arg("help", |arg| arg.action(clap::ArgAction::SetTrue))
        } else {
            command
        }
    }
    lenient(root.clone())
        .try_get_matches_from(
            std::iter::once(catalog::PROGRAM.to_owned()).chain(args.iter().cloned()),
        )
        .unwrap_or_default()
}

/// The command path `args` name (`["generate", "docs", "rules"]`), as far as
/// it parses.
pub fn command_words(root: &clap::Command, args: &[String]) -> Vec<String> {
    command_path(&lenient_matches(root, args))
}

/// Reads the root's options and the global flags of `args`, parsed into
/// `matches` by [`lenient_matches`].
///
/// A global flag is any of its words before `--`: no option takes a value
/// that starts with `-` but by `=`, so that is what clap reads too, and it
/// still holds where clap stopped short, after a usage error
/// (`valdiate --json`) or after `generate`'s phases (`generate docs --json`).
pub fn globals(args: &[String], matches: &clap::ArgMatches, env: &Env) -> Globals {
    let typed_flag = |name: &str| {
        args.iter()
            .take_while(|word| *word != "--")
            .any(|word| word == name)
    };
    let flag = |id: &str| matches.try_get_one::<bool>(id).ok().flatten() == Some(&true);
    // `--repo` and `--data` as typed: their environment variables are read
    // where the workspace is found.
    let typed = |id: &str| {
        let value = matches.try_get_one::<String>(id).ok().flatten()?;
        (matches.value_source(id) == Some(ValueSource::CommandLine)).then(|| value.clone())
    };
    Globals {
        json: typed_flag("--json"),
        no_color: typed_flag("--no-color"),
        debug: typed_flag("--debug"),
        quiet: typed_flag("--quiet"),
        verbose: typed_flag("--verbose"),
        version: flag("version"),
        install_completion: flag("install_completion"),
        show_completion: flag("show_completion"),
        repo: typed("repo"),
        data: typed("data"),
        proxy: typed("proxy").or_else(|| env.get("OPENTIDE_PROXY").map(str::to_owned)),
    }
}

/// What a run resolved before it started the command.
struct Run<'a> {
    args: Vec<String>,
    root: clap::Command,
    globals: Globals,
    mode: Mode,
    indent: bool,
    env: &'a Env,
    host: &'a Host,
    started: Instant,
}

impl Run<'_> {
    fn duration_ms(&self) -> i64 {
        i64::try_from(self.started.elapsed().as_millis()).unwrap_or(i64::MAX)
    }

    /// Whether Ctrl-C was pressed: long jobs poll this and stop.
    pub fn interrupted(&self) -> bool {
        self.host.interrupt.requested()
    }

    /// Prints `outcome` in this run's mode; its exit code. A run Ctrl-C
    /// stopped prints nothing here: [`run`] reports it. A write that fails
    /// is the run's error ([`run`] reports it).
    fn emit(
        &self,
        outcome: &Outcome,
        lines: &[String],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        if self.interrupted() {
            return Ok(INTERRUPTED_EXIT_CODE);
        }
        match self.mode {
            Mode::Json => {
                let text = document_text(&outcome.document(self.duration_ms()), self.indent);
                out.write_all(text.as_bytes())?;
            }
            _ if outcome.failure.is_some() && outcome.exit_code != 0 => {
                let message = outcome
                    .failure
                    .as_ref()
                    .map_or(outcome.message.as_str(), |failure| failure.message.as_str());
                let console = self.console(self.host.stderr_tty);
                let mut text = console.error(message, &[], self.mode, false);
                text.push_str(&console.next_actions(&outcome.next_actions));
                text.push_str(&console.agent_tip(self.mode));
                err.write_all(text.as_bytes())?;
            }
            Mode::Mcp => {}
            _ => {
                let console = self.console(self.host.stdout_tty);
                let bold = Style::new().bold();
                for line in lines {
                    out.write_all(console.line(&Text::styled(line, &bold)).as_bytes())?;
                }
                out.write_all(
                    console
                        .outcome(OutcomeKind::Ok, &outcome.message)
                        .as_bytes(),
                )?;
                out.write_all(console.next_actions(&outcome.next_actions).as_bytes())?;
            }
        }
        out.flush()?;
        err.flush()?;
        Ok(outcome.exit_code)
    }

    /// A usage error a command found itself once the line parsed: exit 2,
    /// the envelope under `--json`, else clap's error layout for the command
    /// at `path` (its `Usage:` line and `--help` hint).
    fn refuse(
        &self,
        path: &[String],
        failure: Failure,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        let mut root = self.root.clone();
        // Built, every command knows its parents' names (`opentide setup`).
        root.build();
        let rendered = usage::command_at(&root, path)
            .clone()
            .error(clap::error::ErrorKind::ValueValidation, &failure.message)
            .render();
        let problem = usage::UsageError {
            command: path.join(" "),
            failure,
            rendered,
        };
        self.emit_usage(problem, out, err)
    }

    /// A clap parse error: the envelope under `--json`, else clap's own
    /// rendered error on stderr. Exit 2.
    fn emit_usage(
        &self,
        problem: usage::UsageError,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        if self.mode == Mode::Json {
            let outcome = Outcome::failed(&problem.command, USAGE_EXIT_CODE, problem.failure);
            return self.emit(&outcome, &[], out, err);
        }
        let console = self.console(self.host.stderr_tty);
        let text = if console.colour == Colour::Full {
            problem.rendered.ansi().to_string()
        } else {
            problem.rendered.to_string()
        };
        err.write_all(text.as_bytes())?;
        err.write_all(console.agent_tip(self.mode).as_bytes())?;
        err.flush()?;
        Ok(USAGE_EXIT_CODE)
    }

    /// The stream the lines go to: colour in `human` mode, bold and dim only
    /// in `plain` mode, on a terminal that is not `TERM=dumb`; wrapped at its
    /// width there, whole on a pipe. `FORCE_COLOR` (or `CLICOLOR_FORCE`) asks
    /// for colour on a pipe, in CI and under `TERM=dumb` too, in `human` and
    /// `plain` modes ([`Run::forced_colour`]); the other modes stay free of it.
    fn console(&self, tty: bool) -> Console {
        let dumb = self
            .env
            .get("TERM")
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("dumb");
        let colour = match self.mode {
            Mode::Human | Mode::Plain if self.forced_colour() => Colour::Full,
            _ if !tty || dumb => Colour::None,
            Mode::Human => Colour::Full,
            Mode::Plain => Colour::Mono,
            _ => Colour::None,
        };
        Console {
            colour,
            width: self.host.width.filter(|_| tty && colour != Colour::None),
        }
    }

    /// Whether the environment forces colour on this run: `FORCE_COLOR` or
    /// `CLICOLOR_FORCE`, in `human` and `plain` modes. An explicit `--no-color`
    /// wins over it, as `NO_COLOR` does (`Env::colour_choice`).
    fn forced_colour(&self) -> bool {
        matches!(self.mode, Mode::Human | Mode::Plain)
            && !self.globals.no_color
            && self.env.colour_choice() == Some(true)
    }

    /// The help of the command at `path` on `out`; `code`. Coloured in `human`
    /// mode and where the environment forces colour.
    fn help(&self, path: &[String], code: i32, out: &mut dyn Write) -> std::io::Result<i32> {
        let colour = self.mode == Mode::Human || self.forced_colour();
        let text = crate::help::render(&self.root, path, colour);
        out.write_all(text.as_bytes())?;
        out.flush()?;
        Ok(code)
    }

    /// The home screen of a bare `opentide` (`commands::home`), for this
    /// run's terminal; `None` where it cannot be drawn and the help shows.
    fn home(&self) -> Option<String> {
        let cwd = self
            .host
            .cwd
            .clone()
            .or_else(|| std::env::current_dir().ok())?;
        let home = self
            .env
            .get(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .filter(|home| !home.is_empty())
            .map(PathBuf::from);
        let facts = crate::commands::home::gather(
            &self.host.version,
            &cwd,
            self.env.get("OPENTIDE_REPO_ROOT"),
        );
        let console = self.console(self.host.stdout_tty);
        Some(crate::commands::home::render(
            &facts,
            &crate::commands::home::Screen {
                colour: console.colour,
                width: self.host.width.unwrap_or(80),
                cwd: &cwd,
                home: home.as_deref(),
            },
        ))
    }

    /// `--show-completion [SHELL]` (`install` false) or
    /// `--install-completion [SHELL]`: the script on stdout, or installed.
    fn completion(
        &self,
        install: bool,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        use crate::commands::completion;
        let option = if install {
            "--install-completion"
        } else {
            "--show-completion"
        };
        // The shell named after the option: `--show-completion bash`.
        let words: Vec<String> = self
            .args
            .iter()
            .skip_while(|word| !option.eq(*word))
            .skip(1)
            .filter(|word| !word.starts_with('-'))
            .cloned()
            .collect();
        let shell = match completion::named_shell(&words, option) {
            Ok(Some(shell)) => shell,
            Ok(None) => {
                if let Some(shell) = completion::detect(self.env.get("SHELL")) {
                    shell
                } else {
                    let message = format!(
                        "Could not tell which shell this is. Name it: {}",
                        completion::form(option)
                    );
                    return self.refuse(&[], Failure::new(code::USAGE_ERROR, message), out, err);
                }
            }
            Err(message) => {
                let mut failure = Failure::new(code::USAGE_INVALID_VALUE, message);
                failure.argument = Some(option.to_owned());
                return self.refuse(&[], failure, out, err);
            }
        };
        let script = completion::script(shell);
        if !install {
            out.write_all(script.as_bytes())?;
            out.flush()?;
            return Ok(0);
        }
        let home = self
            .env
            .get(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .filter(|home| !home.is_empty())
            .map(PathBuf::from);
        let profile = matches!(shell, "powershell" | "pwsh")
            .then(|| completion::powershell_profile(shell))
            .flatten();
        let installed = home.as_deref().map_or_else(
            || {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no home folder (HOME is not set)",
                ))
            },
            |home| completion::install(shell, &script, home, profile.as_deref()),
        );
        let outcome = match installed {
            Ok(installed) => {
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let shown = completion::person_path(&installed.path, &cwd, home.as_deref());
                let next = if installed.reload.is_empty() {
                    NextAction::new(installed.reason, "")
                } else {
                    NextAction::new(installed.reload, installed.reason)
                };
                Outcome {
                    command: String::new(),
                    status: "completed".into(),
                    message: format!("Installed {shell} completion in {shown}"),
                    data: vec![
                        ("shell".into(), crate::json::Json::Str(shell.to_owned())),
                        (
                            "path".into(),
                            crate::json::Json::Str(installed.path.to_string_lossy().into_owned()),
                        ),
                    ],
                    exit_code: 0,
                    summary: Vec::new(),
                    next_actions: vec![next],
                    failure: None,
                }
            }
            Err(error) => Outcome::failed(
                "",
                1,
                Failure::new(
                    "io_error",
                    format!("Could not install {shell} completion: {error}"),
                ),
            ),
        };
        self.emit(&outcome, &[], out, err)
    }

    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
    fn dispatch(&self, out: &mut dyn Write, err: &mut dyn Write) -> std::io::Result<i32> {
        if self.globals.version {
            writeln!(out, "{} {}", catalog::PROGRAM, self.host.version)?;
            out.flush()?;
            return Ok(0);
        }
        if self.globals.install_completion || self.globals.show_completion {
            return self.completion(self.globals.install_completion, out, err);
        }
        if self.args.is_empty() && self.mode == Mode::Human {
            // A person at a terminal: the home screen (D3), else the help.
            if let Some(screen) = self.home() {
                out.write_all(screen.as_bytes())?;
                out.flush()?;
                return Ok(0);
            }
        }
        if self.args.is_empty() && !self.mode.is_machine() {
            return self.help(&[], 0, out);
        }
        let typed_line =
            std::iter::once(catalog::PROGRAM.to_owned()).chain(self.args.iter().cloned());
        let matches = match self.root.clone().try_get_matches_from(typed_line) {
            Ok(matches) => matches,
            Err(error) => {
                let path = command_words(&self.root, &self.args);
                match error.kind() {
                    clap::error::ErrorKind::DisplayHelp => return self.help(&path, 0, out),
                    // `opentide mcp`: a person gets the group's help, exit 2;
                    // json and agent mode get the usage error below.
                    clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                        if matches!(self.mode, Mode::Human | Mode::Plain) =>
                    {
                        return self.help(&path, USAGE_EXIT_CODE, out);
                    }
                    _ => {}
                }
                let problem = usage::describe(&self.root, &self.args, error);
                return self.emit_usage(problem, out, err);
            }
        };
        let mut words = command_path(&matches);
        let typed = match crate::tree::Cli::from_arg_matches(&matches) {
            Ok(cli) => cli,
            // The tree and its derive disagree: a bug, reported as one.
            Err(error) => return Err(std::io::Error::other(error.to_string())),
        };
        // `generate schemas templates`: the words after `generate` that are
        // no subcommand of it are its phases.
        let mut generate_phases = Vec::new();
        if let Some(RootCommand::Generate(crate::tree::GenerateArgs {
            command: Some(crate::tree::GenerateCommand::Phases(named)),
        })) = &typed.command
        {
            generate_phases.clone_from(named);
            words.truncate(1);
            // The phases end at the first word that starts with `-`
            // (`GeneratePhaseGroup`): what follows is `generate`'s own
            // options, parsed as such, so `generate schemas --bogus` is an
            // unknown option and `generate schemas --help` the group's help.
            if let Some(end) = generate_phases
                .iter()
                .position(|word| word.starts_with('-'))
            {
                let options = generate_phases.split_off(end);
                // The command line up to `generate`, the phases left out.
                let start = self
                    .args
                    .windows(2)
                    .position(|pair| pair[0] == "generate" && pair[1] == generate_phases[0])
                    .unwrap_or_default();
                let mut reparsed = self.args[..=start].to_vec();
                reparsed.extend(options);
                let argv =
                    std::iter::once(catalog::PROGRAM.to_owned()).chain(reparsed.iter().cloned());
                if let Err(error) = self.root.clone().try_get_matches_from(argv) {
                    if error.kind() == clap::error::ErrorKind::DisplayHelp {
                        return self.help(&words, 0, out);
                    }
                    let problem = usage::describe(&self.root, &reparsed, error);
                    return self.emit_usage(problem, out, err);
                }
            }
        }
        if matches.value_source("repo") == Some(ValueSource::CommandLine)
            && let Some(repo) = &self.globals.repo
            && words.first().map(String::as_str) != Some("setup")
            && !self.resolve(repo).is_dir()
        {
            let problem = if self.resolve(repo).exists() {
                "is not a directory"
            } else {
                "does not exist"
            };
            let message = format!("--repo {repo} {problem}");
            let mut failure = Failure::new(code::USAGE_INVALID_VALUE, message);
            failure.argument = Some("--repo".into());
            let mut outcome = Outcome::failed("", USAGE_EXIT_CODE, failure);
            outcome.next_actions = vec![NextAction::new(
                "opentide --help",
                "--repo takes the folder with .opentide/ in it",
            )];
            return self.emit(&outcome, &[], out, err);
        }
        if self.globals.quiet && self.globals.verbose {
            let mut failure = Failure::new(
                code::USAGE_ERROR,
                "--quiet and --verbose cannot be used together",
            );
            failure.argument = Some("--verbose".into());
            let outcome = Outcome::failed("", USAGE_EXIT_CODE, failure);
            return self.emit(&outcome, &[], out, err);
        }
        // The commands dispatched by their clap derive structs (`tree.rs`).
        match &typed.command {
            Some(RootCommand::Info(args)) => {
                let report = self.info(args);
                let code = self.emit_report(&report, out, err);
                // `info catalog`'s document is large (see `release`).
                release(report);
                return code;
            }
            Some(RootCommand::Validate(args)) if args.command.is_none() => {
                return self.run_validate(args, out, err);
            }
            Some(RootCommand::Lint(args)) => {
                let report = self.lint(args);
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::New(crate::tree::NewArgs {
                command: Some(command),
            })) => {
                let report = self.new_object(command);
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::Query(args)) => {
                let report = self.query(args);
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::Explain(args)) => {
                let report = crate::commands::explain::run(args.code.as_deref(), &self.terminal());
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::Commands(_)) => {
                let (data, summary) = catalog::document(&self.host.version);
                let count = catalog::entries(&self.root).len();
                let outcome = Outcome {
                    command: "commands".into(),
                    status: "completed".into(),
                    message: format!("{count} commands"),
                    data,
                    exit_code: 0,
                    summary,
                    next_actions: Vec::new(),
                    failure: None,
                };
                let lines = if self.mode == Mode::Json {
                    Vec::new()
                } else {
                    catalog::tree_lines()
                };
                return self.emit(&outcome, &lines, out, err);
            }
            Some(RootCommand::Generate(args)) => {
                let report = self.generate(args, &generate_phases, &matches);
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::Validate(
                validate @ crate::tree::ValidateArgs {
                    command: Some(crate::tree::ValidateCommand::Query(query)),
                    ..
                },
            )) => {
                let report = self.validate_query(validate, query);
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::Migrate(crate::tree::MigrateArgs {
                command: Some(crate::tree::MigrateCommand::VocabScope(args)),
            })) => {
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::migrate::run(
                    &crate::commands::migrate::Args::from(args),
                    self.globals.repo.as_deref(),
                    self.env,
                    &cwd,
                );
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::Deploy(deploy)) => return self.run_deploy(deploy, out, err),
            Some(RootCommand::Setup(args)) => {
                let report = self.setup(args, &matches);
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::Mcp(crate::tree::McpArgs {
                command: Some(crate::tree::McpCommand::Start(_)),
            })) => {
                // The server never polls the interrupt and serves stdio until
                // its client closes stdin: after a Ctrl-C it does not start
                // ([`run`] reports the interrupt).
                if self.interrupted() {
                    return Ok(INTERRUPTED_EXIT_CODE);
                }
                // stdout is JSON-RPC's: nothing is emitted around the server.
                let places = self.server_places();
                let launch = crate::mcp::Launch {
                    cwd: places.cwd,
                    repo: places.repo,
                    data: places.data,
                    proxy: places.proxy,
                    debug: places.debug,
                };
                return crate::mcp::serve(&launch, &self.host.version);
            }
            Some(RootCommand::Serve(_)) => {
                // As `mcp start`: it does not start after a Ctrl-C.
                if self.interrupted() {
                    return Ok(INTERRUPTED_EXIT_CODE);
                }
                let places = self.server_places();
                let launch = crate::serve::Launch {
                    cwd: places.cwd,
                    repo: places.repo,
                    data: places.data,
                    proxy: places.proxy,
                    debug: places.debug,
                };
                return crate::serve::serve(&launch, &self.host.version, &self.host.interrupt);
            }
            Some(RootCommand::Tui(_)) => return self.run_tui(out, err),
            Some(RootCommand::Lsp(crate::tree::LspArgs {
                command: Some(crate::tree::LspCommand::Start(_)),
            })) => {
                // The server blocks on stdin and polls no interrupt: Ctrl-C
                // ends it at once, with 130, as it ends the Python host.
                self.host.interrupt.stop_at_once();
                // stdout is the protocol's: nothing is emitted around the server.
                return crate::commands::lsp::start_stdio(&self.host.version, err);
            }
            Some(RootCommand::Share(share)) => {
                return match self.share(share, &matches, &words.join(" ")) {
                    Ok(report) => self.emit_report(&report, out, err),
                    Err(failure) => self.refuse(&words, *failure, out, err),
                };
            }
            Some(RootCommand::Doctor(args)) => {
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::doctor::run(
                    args.offline,
                    &crate::commands::doctor::Context {
                        repo: self.globals.repo.as_deref(),
                        env: self.env,
                        cwd: &cwd,
                        version: &self.host.version,
                        text: self.mode != Mode::Json && !self.globals.quiet,
                        proxy: self.globals.proxy.as_deref(),
                    },
                );
                return self.emit_report(&report, out, err);
            }
            Some(RootCommand::Rules(crate::tree::RulesArgs {
                command: Some(crate::tree::RulesCommand::Unreviewed(args)),
            })) => {
                let cwd = self.host.cwd.clone().unwrap_or_default();
                let report = crate::commands::rules::run(
                    &args.older_than,
                    self.globals.repo.as_deref(),
                    self.env,
                    &cwd,
                    jiff::Timestamp::now(),
                    self.mode != Mode::Json,
                );
                return self.emit_report(&report, out, err);
            }
            _ => {}
        }
        // Every command has a typed arm above: a tree and a dispatch that
        // disagree are a bug, reported as one.
        self.emit(&unhandled(&words.join(" ")), &[], out, err)
    }

    /// Where the stdio servers (`mcp start`, `serve`) run: the working
    /// directory and the global options, as the server reads them.
    fn server_places(&self) -> ServerPlaces {
        let resolved =
            |path: Option<&str>| path.map(|path| self.resolve(path).display().to_string());
        ServerPlaces {
            cwd: self.host.cwd.clone(),
            repo: resolved(self.globals.repo.as_deref()),
            data: resolved(self.globals.data.as_deref()),
            proxy: self.globals.proxy.clone(),
            debug: self.globals.debug || self.env.debug_requested(),
        }
    }

    /// `opentide tui`: the terminal UI for a person at a terminal, else the
    /// refusal.
    fn run_tui(&self, out: &mut dyn Write, err: &mut dyn Write) -> std::io::Result<i32> {
        use std::io::IsTerminal as _;
        let place = crate::commands::tui::Place {
            mode: self.mode,
            interactive: std::io::stdin().is_terminal() && self.host.stdout_tty,
            no_color: self.globals.no_color,
            env: self.env,
        };
        if let Some(report) = crate::commands::tui::gate(&place) {
            return self.emit_report(&report, out, err);
        }
        // A person at a terminal: the UI (UC-3.6d), which owns the
        // terminal until it quits.
        #[cfg(feature = "terminal")]
        {
            let launch = crate::tui::Launch {
                repo: self.globals.repo.clone(),
                env: self.env.clone(),
                cwd: self.host.cwd.clone().unwrap_or_default(),
                version: self.host.version.clone(),
            };
            crate::tui::open(&launch)
        }
        // A build without the terminal UI (the WASI build) refuses
        // it, as a run without a terminal is refused above.
        #[cfg(not(feature = "terminal"))]
        {
            let report = crate::commands::tui::unavailable();
            self.emit_report(&report, out, err)
        }
    }

    /// `opentide generate`: the bare pipeline, the phases named as words, or
    /// one of its subcommands. `matches` is only asked where an option came
    /// from.
    fn generate(
        &self,
        args: &crate::tree::GenerateArgs,
        phases: &[String],
        matches: &clap::ArgMatches,
    ) -> crate::commands::Report {
        use crate::commands::{extract, generate};
        use crate::tree::{
            GenerateCommand as Command, GenerateExtractCommand as Extract,
            GenerateInflightCommand as Inflight,
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let cx = generate::Context {
            repo: self.globals.repo.as_deref(),
            env: self.env,
            cwd: &cwd,
            proxy: self.globals.proxy.as_deref(),
            version: &self.host.version,
        };
        let extract_cx = extract::Context {
            repo: self.globals.repo.as_deref(),
            env: self.env,
            cwd: &cwd,
            proxy: self.globals.proxy.as_deref(),
        };
        match &args.command {
            None | Some(Command::Phases(_)) => generate::phases(phases, &cx, &self.host.version),
            Some(Command::Exports(exports)) => generate::exports(exports.into(), &cx),
            Some(Command::Explorer(explorer)) => {
                let typed = matches
                    .subcommand_matches("generate")
                    .and_then(|generate| generate.subcommand_matches("explorer"))
                    .is_some_and(|explorer| {
                        explorer.value_source("visibility_tlp") == Some(ValueSource::CommandLine)
                    });
                generate::explorer(&generate::ExplorerOptions::new(explorer, typed), &cx)
            }
            Some(Command::Docs(docs)) => generate::docs(&docs.into(), &cx),
            Some(Command::Extract(extraction)) => match &extraction.command {
                Some(Extract::Elastic(elastic)) => {
                    extract::elastic(&extract_cx, &elastic.space, elastic.include_prebuilt)
                }
                Some(Extract::Sentinel(_)) => extract::sentinel(&extract_cx),
                Some(Extract::Defender(_)) => extract::defender(&extract_cx),
                // `generate extract` needs a subcommand: clap refused it.
                None => crate::commands::Report::failed(
                    "generate extract",
                    1,
                    Failure::new(
                        code::INTERNAL,
                        "opentide generate extract has no implementation: this is a bug in opentide",
                    ),
                ),
            },
            Some(Command::Inflight(inflight)) => match inflight.command {
                None => generate::inflight_shards(&cx),
                Some(Inflight::Prune(_)) => generate::inflight_prune(&cx),
            },
        }
    }

    /// `opentide validate`: its report, or a `--watch` until Ctrl-C.
    fn run_validate(
        &self,
        args: &crate::tree::ValidateArgs,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        let (parsed, report) = self.validate(args);
        if let Some(report) = report {
            return self.emit_report(&report, out, err);
        }
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let terminal = self.terminal();
        let interrupt = self.host.interrupt.clone();
        let code = crate::commands::watch::run(
            &parsed,
            &crate::commands::validate::Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                terminal: &terminal,
                proxy: self.globals.proxy.as_deref(),
            },
            out,
            err,
            &|| interrupt.requested(),
        )?;
        // Ctrl-C is how a watch stops.
        self.host.interrupt.consume();
        Ok(code)
    }

    /// `opentide new <family>`, from its parsed arguments.
    fn new_object(&self, command: &crate::tree::NewCommand) -> crate::commands::Report {
        use crate::commands::new::{Context, NewArgs, run, stdin_is_terminal};
        let parsed = NewArgs::from(command);
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let can_prompt = self.mode == Mode::Human && stdin_is_terminal();
        // The questions are the setup wizards': drawn on stderr.
        let prompter = std::cell::RefCell::new(crate::commands::setup::wizard::Inquire::new(
            self.terminal().stderr.colour,
        ));
        run(
            &parsed,
            &Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                can_prompt,
                prompter: Some(&prompter),
                interrupt: Some(&self.host.interrupt),
            },
        )
    }

    /// `opentide setup`: the group's own run, or one of its subcommands.
    /// `matches` is only asked where an option came from.
    fn setup(&self, args: &SetupArgs, matches: &clap::ArgMatches) -> crate::commands::Report {
        use crate::commands::setup::files::RepoOptions;
        use crate::commands::setup::run::Step;
        use crate::tree::{SetupCommand as Command, SetupSkillsCommand as Skills};
        let Some(group) = matches.subcommand_matches("setup") else {
            return crate::commands::Report::error("setup", "no setup command");
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        match &args.command {
            None => crate::commands::setup::run::group(
                &crate::commands::setup::run::GroupArgs::from(args),
                &self.setup_context(&cwd),
            ),
            Some(Command::Ci(ci)) => self.setup_ci(args, ci, group),
            Some(Command::Env(env)) => {
                self.setup_step(args, group, Step::Env, &env.target, &env.confirm)
            }
            Some(Command::Hooks(hooks)) => {
                let step = Step::Hooks {
                    install: !hooks.no_install,
                };
                self.setup_step(args, group, step, &hooks.target, &hooks.confirm)
            }
            Some(Command::Platforms(platforms)) => {
                let step = Step::Platforms(platforms.enabled());
                self.setup_step(args, group, step, &platforms.target, &platforms.confirm)
            }
            Some(Command::Repo(repo)) => {
                let step = Step::Repo(RepoOptions::from(&repo.repo));
                self.setup_step(args, group, step, &repo.target, &repo.confirm)
            }
            Some(Command::Mcp(mcp)) => {
                let step = Step::Mcp(mcp.hosts());
                self.setup_step(args, group, step, &mcp.target, &mcp.confirm)
            }
            Some(Command::Vscode(vscode)) => {
                let step = Step::Vscode(crate::commands::setup::vscode::Options {
                    generate: !vscode.no_generate,
                    merge: !vscode.no_merge,
                    mcp: vscode.mcp,
                    ..crate::commands::setup::vscode::Options::from_flags(
                        vscode.settings,
                        vscode.snippets,
                    )
                });
                let confirm = crate::tree::SetupConfirm {
                    plan: vscode.plan,
                    yes: vscode.yes,
                };
                self.setup_step(args, group, step, &vscode.target, &confirm)
            }
            Some(Command::Skills(skills)) => match &skills.command {
                None => self.setup_skills(args, skills, group),
                Some(Skills::Discover(discover)) => {
                    self.setup_skills_catalogue(matches, group, SkillsCommand::Discover(discover))
                }
                Some(Skills::Show(show)) => {
                    self.setup_skills_catalogue(matches, group, SkillsCommand::Show(show))
                }
            },
        }
    }

    /// `opentide setup ci`: its options, and the `setup` group's handed down.
    fn setup_ci(
        &self,
        args: &SetupArgs,
        ci: &crate::tree::SetupCiArgs,
        group: &clap::ArgMatches,
    ) -> crate::commands::Report {
        use crate::commands::setup::{CiArgs, ci as run};
        let own = group.subcommand().map(|(_, own)| own);
        let pipeline = &ci.pipeline;
        let parsed = CiArgs {
            provider: ci.ci_platform.into(),
            path: own
                .is_some_and(|own| given(own, "path"))
                .then(|| ci.path.clone()),
            group_path: given(group, "path").then(|| args.path.clone()),
            staging: !pipeline.no_staging,
            inflight: !pipeline.no_inflight,
            sharing: pipeline.sharing,
            lint_changed: pipeline.lint_changed,
            promotion: pipeline.promotion_choice(),
            promotion_target: pipeline.promotion_target.clone(),
            python_version: pipeline.python_version.clone(),
            explorer_pages: pipeline.explorer_pages,
            default_branch: pipeline.default_branch.clone(),
            plan: ci.confirm.plan || args.plan,
            yes: ci.confirm.yes || args.yes,
            group_only: self.setup_group_only(group),
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        run(&parsed, &self.setup_context(&cwd))
    }

    /// The `setup` group's own options given on the command line before a
    /// subcommand, which it would ignore, named as the group's help names
    /// them (`--staging/--no-staging`).
    fn setup_group_only(&self, group: &clap::ArgMatches) -> Vec<String> {
        let given = |matches: &clap::ArgMatches, id: &str| {
            matches.value_source(id) == Some(ValueSource::CommandLine)
        };
        let setup = self.root.find_subcommand("setup");
        let mut group_only: Vec<String> = Vec::new();
        for arg in setup.into_iter().flat_map(clap::Command::get_arguments) {
            let id = arg.get_id().as_str();
            if matches!(id, "path" | "yes" | "plan") || !given(group, id) {
                continue;
            }
            let long = |arg: &clap::Arg| arg.get_long().map(|long| format!("--{long}"));
            let partner = setup
                .into_iter()
                .flat_map(clap::Command::get_arguments)
                .find(|other| {
                    other.get_id() != arg.get_id()
                        && (other.get_id().as_str() == format!("no_{id}")
                            || id == format!("no_{}", other.get_id().as_str())
                            || (id, other.get_id().as_str()) == ("lint_all", "lint_changed")
                            || (id, other.get_id().as_str()) == ("lint_changed", "lint_all"))
                });
            let name = match (long(arg), partner.and_then(long)) {
                (Some(own), Some(other)) if id.starts_with("no_") || id == "lint_all" => {
                    format!("{other}/{own}")
                }
                (Some(own), Some(other)) => format!("{own}/{other}"),
                (Some(own), None) => own,
                _ => id.to_owned(),
            };
            if !group_only.contains(&name) {
                group_only.push(name);
            }
        }
        group_only
    }

    /// The setup commands' context.
    fn setup_context<'a>(
        &'a self,
        cwd: &'a std::path::Path,
    ) -> crate::commands::setup::Context<'a> {
        crate::commands::setup::Context {
            repo: self.globals.repo.as_deref(),
            env: self.env,
            cwd,
            mode: self.mode,
            version: &self.host.version,
            quiet: self.globals.quiet,
            terminal: self.terminal(),
            interrupt: self.host.interrupt.clone(),
            stderr: self.host.log_sink.clone(),
            proxy: self.globals.proxy.as_deref(),
        }
    }

    /// `opentide setup env|hooks|platforms|repo|mcp|vscode`: the step, where
    /// it writes, and whether to ask first.
    fn setup_step(
        &self,
        args: &SetupArgs,
        group: &clap::ArgMatches,
        step: crate::commands::setup::run::Step,
        target: &crate::tree::SetupTarget,
        confirm: &crate::tree::SetupConfirm,
    ) -> crate::commands::Report {
        use crate::commands::setup::run::{Paths, subcommand};
        let own = group.subcommand().map(|(_, own)| own);
        let flag_given = own.is_some_and(|own| given(own, "path_flag"));
        let positional_given = own.is_some_and(|own| given(own, "path"));
        let paths = Paths {
            own: if flag_given {
                Some(target.path_flag.clone())
            } else if positional_given {
                Some(target.path.clone())
            } else {
                None
            },
            group: given(group, "path").then(|| args.path.clone()),
            both: flag_given && positional_given,
            group_only: self.setup_group_only(group),
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        subcommand(
            &step,
            &paths,
            confirm.yes || args.yes,
            confirm.plan || args.plan,
            &self.setup_context(&cwd),
        )
    }

    /// `opentide setup skills` without a subcommand: the install.
    fn setup_skills(
        &self,
        args: &SetupArgs,
        skills: &crate::tree::SetupSkillsArgs,
        group: &clap::ArgMatches,
    ) -> crate::commands::Report {
        use crate::commands::setup::run::{Paths, SkillsArgs, skills as install};
        let own = group.subcommand().map(|(_, own)| own);
        let paths = Paths {
            own: own
                .is_some_and(|own| given(own, "path"))
                .then(|| skills.path.clone()),
            group: given(group, "path").then(|| args.path.clone()),
            both: false,
            group_only: self.setup_group_only(group),
        };
        let parsed = SkillsArgs {
            options: skills.into(),
            yes: skills.yes || args.yes,
            plan: skills.plan || args.plan,
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        install(&parsed, &paths, &self.setup_context(&cwd))
    }

    /// `opentide info`, from its parsed arguments.
    fn info(&self, args: &crate::tree::InfoArgs) -> crate::commands::Report {
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let parsed = crate::commands::info::Args::from(args);
        crate::commands::info::run(
            &parsed,
            &crate::commands::info::Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                text: self.mode != Mode::Json,
            },
        )
    }

    /// `opentide validate`, from its parsed arguments: its report, or `None`
    /// for a `--watch` the options allow, which runs until Ctrl-C.
    fn validate(
        &self,
        args: &crate::tree::ValidateArgs,
    ) -> (
        crate::commands::validate::Args,
        Option<crate::commands::Report>,
    ) {
        use crate::commands::validate::{Args, Context, run};
        let parsed = Args::from(args);
        if parsed.watch && crate::commands::validate::refuse(&parsed, self.mode).is_none() {
            return (parsed, None);
        }
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let terminal = self.terminal();
        let report = run(
            &parsed,
            &Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                terminal: &terminal,
                proxy: self.globals.proxy.as_deref(),
            },
        );
        (parsed, Some(report))
    }

    /// `opentide validate query`, from its parsed arguments. The options of
    /// `validate` it also takes, typed before `query`, are its own
    /// (`hand_down`); the others are refused, as is one typed on both.
    fn validate_query(
        &self,
        validate: &crate::tree::ValidateArgs,
        query: &crate::tree::ValidateQueryArgs,
    ) -> crate::commands::Report {
        use crate::commands::validate_query::{Args, COMMAND, Context, plugin_live, refusal, run};
        if let Some(problem) = refusal(validate, query) {
            let failure = Failure::new(code::USAGE_INVALID_VALUE, problem);
            return crate::commands::Report::failed(COMMAND, USAGE_EXIT_CODE, failure);
        }
        let parsed = Args::from_cli(validate, query);
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let plugin = parsed
            .platform
            .clone()
            .filter(|platform| crate::plugins::is_plugin(platform));
        if parsed.live && plugin.is_none() {
            return self.validate_query_live(&parsed, &cwd);
        }
        let terminal = self.terminal();
        let interrupt = &self.host.interrupt;
        let interrupted = || interrupt.requested();
        let cx = Context {
            repo: self.globals.repo.as_deref(),
            env: self.env,
            cwd: &cwd,
            terminal: &terminal,
            proxy: self.globals.proxy.as_deref(),
            interrupted: &interrupted,
        };
        match plugin {
            // A platform plugin's live check (UC-4.5).
            Some(platform) if parsed.live => plugin_live(&parsed, &platform, &cx),
            _ => run(&parsed, &cx),
        }
    }

    /// `opentide validate query --live`: the usage checks, then a platform
    /// whose tenants check no query answers `supported: false`, and the
    /// others run on the connectors (`validate_live`). Every run that is
    /// not a usage error adds its section to the CI job summary.
    fn validate_query_live(
        &self,
        parsed: &crate::commands::validate_query::Args,
        cwd: &std::path::Path,
    ) -> crate::commands::Report {
        use crate::commands::{validate_live, validate_query};
        use crate::render::summary;
        if let Some(report) = validate_query::live_usage(parsed, self.env) {
            return report;
        }
        if let Some(mut report) = validate_query::unsupported(parsed) {
            let result = report.outcome.document(0);
            report.ci_summary = Some(summary::query_summary(&result, None));
            return report;
        }
        if parsed.platform.is_none() {
            // A live check reads one platform's tenants: refused, as the
            // oracle refuses it (a usage failure writes no CI job summary).
            return validate_live::report_of(
                validate_query::COMMAND,
                &validate_query::live_without_platform(),
            );
        }
        let interrupt = &self.host.interrupt;
        let interrupted = || interrupt.requested();
        let registry = opentide_connectors::builtin();
        let live = validate_live::run(
            parsed,
            &validate_live::Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd,
                proxy: self.globals.proxy.as_deref(),
                interrupted: &interrupted,
                now: jiff::Timestamp::now(),
                registry: &registry,
            },
        );
        let mut report = live.report(self.env);
        report.ci_summary = Some(summary::query_summary(&live.result_json(), None));
        report
    }

    /// `opentide lint`, from its parsed arguments.
    fn lint(&self, args: &crate::tree::LintArgs) -> crate::commands::Report {
        let parsed = crate::commands::lint::Args::from(args);
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let terminal = self.terminal();
        crate::commands::lint::run(
            &parsed,
            &crate::commands::lint::Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                version: &self.host.version,
                terminal: &terminal,
            },
        )
    }

    /// The streams, as a command lays its text out for them.
    fn terminal(&self) -> crate::commands::Terminal {
        crate::commands::Terminal {
            mode: self.mode,
            stdout: self.console(self.host.stdout_tty),
            stderr: self.console(self.host.stderr_tty),
            quiet: self.globals.quiet,
            verbose: self.globals.verbose,
            typed: self.args.clone(),
            stdout_tty: self.host.stdout_tty,
            width: self.host.width,
        }
    }

    /// `opentide query`, from its parsed arguments (UC-4.2c).
    fn query(&self, args: &crate::tree::QueryArgs) -> crate::commands::Report {
        use crate::commands::query::{Args, Context, run};
        let parsed = Args::from(args);
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let terminal = self.terminal();
        let interrupt = &self.host.interrupt;
        let interrupted = || interrupt.requested();
        let stdin = || {
            let mut text = String::new();
            let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut text);
            text
        };
        run(
            &parsed,
            &Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                proxy: self.globals.proxy.as_deref(),
                terminal: &terminal,
                interrupted: &interrupted,
                stdin: &stdin,
                now: jiff::Timestamp::now(),
                log: &self.host.log_sink,
            },
        )
    }

    /// `opentide deploy --dry-run`, from its parsed arguments.
    fn deploy(&self, args: &crate::tree::DeployArgs) -> crate::commands::deploy::DryRun {
        let parsed = crate::commands::deploy::Args::from(args);
        let cwd = self.host.cwd.clone().unwrap_or_default();
        crate::commands::deploy::run(
            &parsed,
            &crate::commands::deploy::Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
            },
        )
    }

    /// `opentide deploy` without `--dry-run` (UC-4.6, #979): the plan, then
    /// each rule sent through its platform's connector, its line printed as
    /// it ends; the CI job summary's section.
    fn deploy_send(
        &self,
        args: &crate::tree::DeployArgs,
        parsed: crate::commands::deploy::Args,
    ) -> crate::commands::Report {
        use crate::commands::deploy_send::{Args, Context, Lines, run};
        let send_args = Args {
            strategies: parsed.strategies,
            all: parsed.all,
            uuids: parsed.uuids,
            files: parsed.files,
            platform: parsed.platform,
            wide: parsed.wide,
            keep_deprecated: parsed.keep_deprecated,
            skip_promotion: args.skip_promotion,
            skip_unconfigured: args.skip_unconfigured,
            persist_state_externally: args.persist_state_externally,
        };
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let interrupt = &self.host.interrupt;
        let interrupted = || interrupt.requested();
        // The built-in platforms, then the platform plugins (UC-4.5b).
        let registry = crate::plugins::registry();
        let lines = Lines {
            sink: self.host.log_sink.clone(),
            console: self.console(self.host.stderr_tty),
            silent: matches!(self.mode, Mode::Json | Mode::Mcp),
            quiet: self.globals.quiet,
            progress: crate::render::progress::Progress::from_env(self.env).enabled(),
            terminal: self.mode == Mode::Human && self.host.stderr_tty,
            live: (self.mode == Mode::Human && self.host.stderr_tty)
                .then(|| self.host.width.unwrap_or(80)),
        };
        let sent = run(
            &send_args,
            &Context {
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                proxy: self.globals.proxy.as_deref(),
                interrupted: &interrupted,
                now: jiff::Timestamp::now(),
                registry: &registry,
                lines,
                json: self.mode == Mode::Json,
                debug: self.globals.debug,
            },
        );
        let mut report = sent.report();
        report.ci_summary = Some(crate::render::summary::deploy_summary(
            &sent.result_json(),
            None,
            Some(false),
        ));
        report
    }

    /// The CI run's warning of a deploy over the workspace's platforms that
    /// matched no rule (`emit_warning`), on stdout before the result; none
    /// in the machine modes or outside CI.
    fn no_rules_warning(&self, report: &mut crate::commands::Report) {
        if report.outcome.message != opentide_compile::dry_run::NO_RULES_MATCHED {
            return;
        }
        let provider = crate::render::ci::active_provider(self.mode, self.env);
        if let Some(line) = crate::render::ci::warning_line(provider, &report.outcome.message, None)
        {
            report
                .body
                .insert(0, crate::commands::Block::Raw(format!("{line}\n")));
        }
    }

    /// `opentide deploy`: a send, a dry run, or one of its subcommands.
    fn run_deploy(
        &self,
        deploy: &crate::tree::DeployArgs,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        use crate::tree::DeployCommand as Command;
        let cwd = self.host.cwd.clone().unwrap_or_default();
        match &deploy.command {
            Some(Command::ReplayState(replay)) => {
                if self.interrupted() {
                    return Ok(INTERRUPTED_EXIT_CODE);
                }
                crate::commands::deploy_replay::run(&cwd, self.env, &replay.state_commit, out, err)
            }
            Some(Command::Metadata(metadata)) => {
                let platform = clap::ValueEnum::to_possible_value(&metadata.platform)
                    .map(|value| value.get_name().to_owned())
                    .unwrap_or_default();
                let failure = Failure::new(
                    "not_implemented",
                    format!("Metadata deployment is not implemented for {platform}"),
                );
                self.emit(
                    &Outcome::failed("deploy metadata", USAGE_EXIT_CODE, failure),
                    &[],
                    out,
                    err,
                )
            }
            Some(Command::MigrateState(_)) => {
                let report = crate::commands::migrate_state::run(
                    self.globals.repo.as_deref(),
                    self.env,
                    &cwd,
                );
                self.emit_report(&report, out, err)
            }
            None if deploy.dry_run => {
                let run = self.deploy(deploy);
                self.emit_deploy(&run, out, err)
            }
            None => {
                let parsed = crate::commands::deploy::Args::from(deploy);
                if let Some(refused) = crate::commands::deploy::refusal(&parsed) {
                    return self.emit_deploy(&refused, out, err);
                }
                let every_platform = parsed.platform.is_none();
                let mut report = self.deploy_send(deploy, parsed);
                if every_platform {
                    // A run over the workspace's platforms that matched no
                    // rule says so to the CI run as a whole (`emit_warning`).
                    self.no_rules_warning(&mut report);
                }
                self.emit_report(&report, out, err)
            }
        }
    }

    /// Prints a dry run in this run's mode, in the oracle's order: the
    /// progress events, then the plan (stdout), the rules that would fail
    /// (stderr), the CI job summary, the result, and the closing note.
    fn emit_deploy(
        &self,
        run: &crate::commands::deploy::DryRun,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        use crate::render::outcome::{ResultView, render_result};
        use crate::render::{ci, progress, summary};
        if self.interrupted() {
            return Ok(INTERRUPTED_EXIT_CODE);
        }
        let outcome = &run.outcome;
        if progress::Progress::from_env(self.env).enabled() {
            let total = run.compiled.len();
            for (index, platform) in run.compiled.iter().enumerate() {
                let event = progress::progress_event(platform, index + 1, Some(total));
                err.write_all(progress::event_line(&event).as_bytes())?;
            }
            err.flush()?;
        }
        if self.mode == Mode::Json {
            let document = run.document(self.duration_ms());
            out.write_all(document_text(&document, self.indent).as_bytes())?;
            out.flush()?;
            return Ok(outcome.exit_code);
        }
        let stdout = self.console(self.host.stdout_tty);
        let stderr = self.console(self.host.stderr_tty);
        let text_out = self.mode != Mode::Mcp;
        if !run.refused && !self.globals.quiet && text_out {
            for (line, hang) in run.plan_lines() {
                let text = match hang {
                    Some(hang) => stdout.print_line(&line, hang),
                    None => stdout.line(&line),
                };
                out.write_all(text.as_bytes())?;
            }
            out.flush()?;
        }
        if !run.diagnostics.is_empty() {
            // Errors print under --quiet too: the tally that follows counts them.
            let frames = crate::render::codeframe::Frames {
                colour: stderr.colour,
                links: self.mode == Mode::Human && self.host.stderr_tty,
                columns: stderr.width,
                highlight: self.mode == Mode::Human,
                cwd: self.host.cwd.clone().unwrap_or_default(),
                env: self.env.clone(),
            };
            let mut sources = crate::render::diagnostic::SourceFiles::default();
            err.write_all(
                frames
                    .render(&run.diagnostics, &mut sources, false)
                    .as_bytes(),
            )?;
            err.flush()?;
        }
        if !run.refused && outcome.exit_code != USAGE_EXIT_CODE {
            let markdown = summary::fit(
                &summary::deploy_summary(&run.result, None, Some(true)),
                summary::MAX_SUMMARY_BYTES,
            );
            let cwd = self.host.cwd.clone().unwrap_or_default();
            let written = ci::append_summary(&markdown, "deploy", self.mode, self.env, &cwd);
            for line in &written.stdout {
                out.write_all(format!("{line}\n").as_bytes())?;
            }
        }
        let view = ResultView {
            message: outcome.message.clone(),
            outcome: run.outcome_line.clone(),
            status: outcome.status.clone(),
            ok: outcome.ok(),
            outcome_kind: run.plan_kind.then_some(OutcomeKind::Plan),
            failure: outcome
                .failure
                .as_ref()
                .map(|failure| (failure.code.clone(), failure.suggestion.clone())),
            detail: run.detail(),
            advice: run.advice(),
            warnings: run.warnings.clone(),
            next_actions: outcome.next_actions.clone(),
            numbered_next: false,
        };
        let (result_out, result_err) =
            render_result(&view, stdout, stderr, self.mode, self.globals.quiet);
        if text_out {
            out.write_all(result_out.as_bytes())?;
        }
        err.write_all(result_err.as_bytes())?;
        if !run.refused && !self.globals.quiet && text_out {
            let note = Text::styled(
                crate::commands::deploy::DRY_RUN_NOTE,
                &Style::new().dimmed(),
            );
            out.write_all(stdout.line(&note).as_bytes())?;
        }
        out.flush()?;
        err.flush()?;
        Ok(outcome.exit_code)
    }

    /// The width a table or a long line is laid out at on stdout: `COLUMNS`,
    /// else the terminal's, else 80.
    fn stdout_width(&self) -> usize {
        if let Some(columns) = self
            .env
            .get("COLUMNS")
            .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|value| value.parse::<usize>().ok())
        {
            return columns;
        }
        if self.host.stdout_tty {
            self.host.width.unwrap_or(80)
        } else {
            80
        }
    }

    /// Prints `report` in this run's mode; its exit code.
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
    fn emit_report(
        &self,
        report: &crate::commands::Report,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> std::io::Result<i32> {
        use crate::commands::Block;
        use crate::render::outcome::{ResultView, render_result};
        if self.interrupted() {
            return Ok(INTERRUPTED_EXIT_CODE);
        }
        let outcome = &report.outcome;
        if KEEPING_DOCUMENT.with(std::cell::Cell::get) {
            let document = outcome.document(self.duration_ms());
            KEPT_DOCUMENT.with(|kept| *kept.borrow_mut() = Some(document));
        }
        if report.bare_exit {
            out.flush()?;
            err.flush()?;
            return Ok(outcome.exit_code);
        }
        if report.usage_notes
            && let Some(failure) = &outcome.failure
        {
            let words: Vec<String> = outcome
                .command
                .split_whitespace()
                .map(str::to_owned)
                .collect();
            return self.refuse(&words, failure.clone(), out, err);
        }
        if !report.stderr_first.is_empty() {
            err.write_all(report.stderr_first.as_bytes())?;
            err.flush()?;
        }
        // Each finished step's `OPENTIDE_PROGRESS=json` event, in every mode:
        // before its row where the rows print one by one, else all at once.
        let events = report
            .step_events
            .filter(|_| crate::render::progress::Progress::from_env(self.env).enabled());
        let step_event = |done: usize, step: &crate::render::progress::Step, total: usize| {
            crate::render::progress::event_line(&crate::render::progress::progress_event(
                &step.name,
                done,
                Some(total),
            ))
        };
        let rows_one_by_one = !report.steps.is_empty()
            && !matches!(self.mode, Mode::Json | Mode::Mcp)
            && !self.globals.quiet
            && (self.mode != Mode::Human || !self.host.stderr_tty);
        if let Some(total) = events
            && !rows_one_by_one
        {
            for (index, step) in report.steps.iter().enumerate() {
                err.write_all(step_event(index + 1, step, total).as_bytes())?;
            }
            err.flush()?;
        }
        if self.mode == Mode::Json {
            for line in &report.after_steps {
                line.log();
            }
            let mut document = outcome.document(self.duration_ms());
            if let crate::json::Json::Object(members) = &mut document {
                crate::envelope::put_warnings(members, &report.warnings);
            }
            out.write_all(document_text(&document, self.indent).as_bytes())?;
            out.flush()?;
            return Ok(outcome.exit_code);
        }
        let mut logged = false;
        if !report.steps.is_empty() && self.mode != Mode::Mcp && !self.globals.quiet {
            let console = self.console(self.host.stderr_tty);
            if self.mode == Mode::Human && self.host.stderr_tty {
                // The oracle's live display keeps its rows below the lines
                // logged while it runs: they end up above the checklist.
                for line in &report.after_steps {
                    line.log();
                }
                logged = true;
                err.write_all(
                    crate::render::progress::checklist(
                        &report.steps,
                        self.host.width.unwrap_or(80),
                        console.colour,
                    )
                    .as_bytes(),
                )?;
            } else {
                for (index, step) in report.steps.iter().enumerate() {
                    if let Some(total) = events {
                        err.write_all(step_event(index + 1, step, total).as_bytes())?;
                    }
                    err.write_all(
                        console
                            .line(&crate::render::progress::step_line(step))
                            .as_bytes(),
                    )?;
                }
            }
        }
        if !logged && !report.after_steps.is_empty() {
            // Log lines go to the log sink: the rows above reach it first.
            err.flush()?;
            for line in &report.after_steps {
                line.log();
            }
        }
        if let Some(markdown) = &report.ci_summary
            && outcome.exit_code != USAGE_EXIT_CODE
        {
            use crate::render::{ci, summary};
            let markdown = summary::fit(markdown, summary::MAX_SUMMARY_BYTES);
            let cwd = self.host.cwd.clone().unwrap_or_default();
            let written =
                ci::append_summary(&markdown, &outcome.command, self.mode, self.env, &cwd);
            for line in &written.stdout {
                out.write_all(format!("{line}\n").as_bytes())?;
            }
        }
        let stdout = self.console(self.host.stdout_tty);
        let width = self.stdout_width();
        if let Some(whole) = &report.whole_stdout {
            if self.mode != Mode::Mcp {
                out.write_all(whole.as_bytes())?;
            }
            out.flush()?;
            return Ok(outcome.exit_code);
        }
        if self.mode != Mode::Mcp {
            for block in &report.body {
                match block {
                    Block::Lines(lines) => {
                        for line in lines {
                            for row in line.wrap(width, &Text::default()) {
                                out.write_all(stdout.line(&row).as_bytes())?;
                            }
                        }
                    }
                    Block::Table(table) => {
                        for line in table.render(stdout.width) {
                            out.write_all(stdout.line(&line).as_bytes())?;
                        }
                    }
                    Block::Hanging(lines) => {
                        for (line, hang) in lines {
                            out.write_all(stdout.print_line(line, *hang).as_bytes())?;
                        }
                    }
                    Block::Raw(text) => out.write_all(text.as_bytes())?,
                    Block::Stderr(text) => {
                        out.flush()?;
                        err.write_all(text.as_bytes())?;
                        err.flush()?;
                    }
                }
            }
        }
        if report.body_only && outcome.exit_code == 0 {
            out.flush()?;
            err.flush()?;
            return Ok(outcome.exit_code);
        }
        let view = ResultView {
            message: outcome.message.clone(),
            outcome: report.outcome_line.clone(),
            status: outcome.status.clone(),
            ok: outcome.ok(),
            outcome_kind: report.outcome_kind,
            failure: outcome
                .failure
                .as_ref()
                .map(|failure| (failure.code.clone(), failure.suggestion.clone())),
            // A result's `detail` is a `note:` and its `advice` a `help:`
            // under the outcome (`REMEDIATION_FIELDS`).
            detail: data_text(&outcome.data, "detail"),
            advice: data_text(&outcome.data, "advice"),
            warnings: report.warnings.clone(),
            next_actions: outcome.next_actions.clone(),
            numbered_next: report.numbered_next,
        };
        let (text_out, text_err) = render_result(
            &view,
            stdout,
            self.console(self.host.stderr_tty),
            self.mode,
            self.globals.quiet,
        );
        if self.mode != Mode::Mcp {
            out.write_all(text_out.as_bytes())?;
        }
        err.write_all(text_err.as_bytes())?;
        out.flush()?;
        err.flush()?;
        Ok(outcome.exit_code)
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let path = PathBuf::from(path);
        match (&self.host.cwd, path.is_absolute()) {
            (Some(cwd), false) => cwd.join(path),
            _ => path,
        }
    }

    fn workspaces(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(repo) = &self.globals.repo {
            out.push(self.resolve(repo));
        }
        for name in ["OPENTIDE_TIDE_WORKSPACE", "OPENTIDE_REPO_ROOT"] {
            if let Some(value) = self.env.get(name).filter(|value| !value.is_empty()) {
                out.push(self.resolve(value));
            }
        }
        out.extend(self.host.cwd.clone());
        out
    }
}

impl Run<'_> {
    /// `share` and its subcommands (UC-4.4b, #834): the group's options
    /// handed down to the subcommand that takes them too, or refused
    /// (`hand_down`, `refuse_dropped`), then the run.
    fn share(
        &self,
        share: &crate::tree::ShareArgs,
        matches: &clap::ArgMatches,
        path: &str,
    ) -> Result<crate::commands::Report, Box<Failure>> {
        use crate::commands::share::{Args, Context, Mode, run};
        let Some(("share", group)) = matches.subcommand() else {
            return Ok(crate::commands::Report::error(path, "share was not parsed"));
        };
        let typed = |matches: &clap::ArgMatches, id: &str| {
            matches.try_contains_id(id).unwrap_or(false)
                && matches.value_source(id) == Some(ValueSource::CommandLine)
        };
        // The group's options, in its order, with their flags.
        const GROUP: [(&str, &str); 10] = [
            ("target", "--target"),
            ("uuid", "--uuid"),
            ("object_type", "--type"),
            ("file", "--file"),
            ("dry_run", "--dry-run"),
            ("publish", "--publish"),
            ("no_publish", "--no-publish"),
            ("workers", "--workers"),
            ("changed", "--changed"),
            ("since", "--since"),
        ];
        use crate::tree::ShareCommand as Command;
        let mode = match &share.command {
            None | Some(Command::Push(_)) => Mode::Push,
            Some(Command::Preview(_)) => Mode::Preview,
            Some(Command::Status(_)) => Mode::Status,
            Some(Command::Retract(_)) => Mode::Retract,
            Some(Command::Targets(_)) => Mode::Targets,
        };
        let sub = group.subcommand();
        let args = sub.map_or(group, |(_, own)| own);
        let accepts = |id: &str| match mode {
            Mode::Push => true,
            Mode::Preview => matches!(id, "target" | "uuid" | "object_type" | "file" | "workers"),
            Mode::Status => matches!(id, "target" | "uuid" | "object_type" | "file"),
            Mode::Retract => matches!(id, "target" | "uuid" | "object_type" | "file" | "workers"),
            Mode::Targets => false,
        };
        if let Some((name, _)) = sub {
            let mut refused: Vec<&str> = Vec::new();
            let mut twice: Vec<&str> = Vec::new();
            for (id, flag) in GROUP {
                if !typed(group, id) {
                    continue;
                }
                if !accepts(id) {
                    if !refused.contains(&flag) {
                        refused.push(flag);
                    }
                } else if typed(args, id) && !twice.contains(&flag) {
                    twice.push(flag);
                }
            }
            let problem = if !refused.is_empty() {
                let verb = if refused.len() == 1 {
                    "configures"
                } else {
                    "configure"
                };
                Some(format!(
                    "{} {verb} `opentide share` itself and would be ignored by `opentide share \
                     {name}`.",
                    refused.join(", ")
                ))
            } else if !twice.is_empty() {
                Some(format!(
                    "Pass {} once, before or after `{name}`, not both: `opentide share {name}` \
                     would use only the second.",
                    twice.join(", ")
                ))
            } else {
                None
            };
            if let Some(problem) = problem {
                // A usage error, in clap's layout.
                let failure = Failure::new(code::USAGE_INVALID_VALUE, problem);
                return Err(Box::new(failure));
            }
        }
        let parsed = Args::from_cli(share, |id| typed(group, id));
        let cwd = self.host.cwd.clone().unwrap_or_default();
        Ok(run(
            &parsed,
            &Context {
                command: path,
                repo: self.globals.repo.as_deref(),
                env: self.env,
                cwd: &cwd,
                proxy: self.globals.proxy.as_deref(),
                version: &self.host.version,
            },
        ))
    }

    /// `setup skills discover` and `setup skills show` (UC-4.1, #831): the
    /// target the command and its groups name, then the catalogue.
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
    fn setup_skills_catalogue(
        &self,
        matches: &clap::ArgMatches,
        group: &clap::ArgMatches,
        skills_command: SkillsCommand<'_>,
    ) -> crate::commands::Report {
        use crate::commands::skills;
        let cwd = self.host.cwd.clone().unwrap_or_default();
        let path = match skills_command {
            SkillsCommand::Discover(_) => "setup skills discover",
            SkillsCommand::Show(_) => "setup skills show",
        };
        // The groups' own options, which the subcommand would ignore, and
        // their paths, which it takes (`_hand_down`, `_group_path`).
        let mut group_paths: Vec<String> = Vec::new();
        let mut refusal: Option<String> = None;
        let mut current = matches;
        let mut command = self.root.clone();
        let mut words = vec![crate::catalog::PROGRAM.to_owned()];
        while let Some((name, sub)) = current.subcommand() {
            let Some(group) = command.find_subcommand(name).cloned() else {
                break;
            };
            words.push(name.to_owned());
            if sub.subcommand().is_none() {
                break;
            }
            let invoked = sub.subcommand_name().unwrap_or_default().to_owned();
            let ignored: Vec<String> = group
                .get_arguments()
                .filter(|arg| {
                    let id = arg.get_id().as_str();
                    !matches!(id, "path" | "yes" | "plan") && given(sub, id)
                })
                .map(|arg| {
                    let mut names: Vec<String> = Vec::new();
                    if let Some(long) = arg.get_long() {
                        names.push(format!("--{long}"));
                    }
                    if let Some(short) = arg.get_short() {
                        names.push(format!("-{short}"));
                    }
                    names.join("/")
                })
                .collect();
            if !ignored.is_empty() && refusal.is_none() {
                let verb = if ignored.len() == 1 {
                    "configures"
                } else {
                    "configure"
                };
                refusal = Some(format!(
                    "{} {verb} `{}` itself and would be ignored by `{} {invoked}`.",
                    ignored.join(", "),
                    words.join(" "),
                    words.join(" ")
                ));
            }
            if given(sub, "path")
                && let Some(value) = sub.get_one::<String>("path")
            {
                group_paths.push(value.clone());
            }
            current = sub;
            command = group;
        }
        // `setup skills`' own matches, then the subcommand's.
        let leaf = group
            .subcommand()
            .and_then(|(_, skills)| skills.subcommand())
            .map(|(_, leaf)| leaf);
        let usage = |message: String| {
            let mut failure = crate::envelope::Failure::new(code::USAGE_INVALID_VALUE, message);
            failure.argument = None;
            crate::commands::Report::failed(path, USAGE_EXIT_CODE, failure)
        };
        if let Some(refusal) = refusal {
            return usage(refusal);
        }
        let mut warnings = Vec::new();
        let leaf_given = |id: &str| leaf.is_some_and(|leaf| given(leaf, id));
        let own = match skills_command {
            SkillsCommand::Discover(discover) => {
                let flag = leaf_given("path_flag");
                let positional = leaf_given("path");
                if flag && positional {
                    return usage(
                        "Pass the repository path once: use --path/-C or the positional PATH, not both."
                            .to_owned(),
                    );
                }
                if positional {
                    let value = discover.path.clone();
                    let legacy =
                        format!("positional PATH (opentide setup skills discover {value})");
                    if self.mode == Mode::Json {
                        tracing::warn!(
                            legacy = legacy.as_str(),
                            use_instead = "--path/-C",
                            "cli_command_deprecated"
                        );
                    } else {
                        warnings.push(format!("{legacy} is deprecated; use --path/-C"));
                    }
                    Some(value)
                } else if flag {
                    Some(discover.path_flag.clone())
                } else {
                    None
                }
            }
            SkillsCommand::Show(show) => leaf_given("path").then(|| show.path.clone()),
        };
        let setup_path = |given: &str| -> std::path::PathBuf {
            let candidate = std::path::Path::new(given);
            match self.globals.repo.as_deref() {
                Some(repo)
                    if candidate == std::path::Path::new(".")
                        && crate::commands::setup::resolved(&cwd, std::path::Path::new(repo))
                            != crate::commands::setup::resolved(&cwd, &cwd) =>
                {
                    cwd.join(repo)
                }
                _ => cwd.join(candidate),
            }
        };
        let named: Vec<String> = group_paths.into_iter().chain(own).collect();
        let mut targets: Vec<std::path::PathBuf> = named
            .iter()
            .map(|given| crate::commands::setup::resolved(&cwd, &setup_path(given)))
            .collect();
        targets.dedup();
        if targets.len() > 1 {
            return usage(format!(
                "Pass the repository path once: {} name different targets.",
                named.join(" and ")
            ));
        }
        let repo = setup_path(named.last().map_or(".", String::as_str));
        let interrupt = &self.host.interrupt;
        let interrupted = || interrupt.requested();
        let network = skills::Network {
            env: self.env,
            proxy: self.globals.proxy.as_deref(),
            interrupted: &interrupted,
        };
        let mut report = match skills_command {
            SkillsCommand::Discover(discover) => skills::discover(
                &skills::DiscoverArgs {
                    repo,
                    query: discover.query.clone(),
                    installed_only: discover.installed,
                    refresh: discover.refresh,
                },
                network,
                self.stdout_width(),
            ),
            SkillsCommand::Show(show) => skills::show(
                &show.name,
                &repo,
                show.refresh,
                network,
                self.mode == Mode::Json,
            ),
        };
        report.warnings.splice(0..0, warnings);
        report
    }
}

/// Whether `id` was typed on the command line, not defaulted.
fn given(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

/// The subcommands of `setup skills` that read the catalogue.
#[derive(Clone, Copy)]
enum SkillsCommand<'a> {
    Discover(&'a crate::tree::SetupSkillsDiscoverArgs),
    Show(&'a crate::tree::SetupSkillsShowArgs),
}

/// Where a stdio server runs, as its launch takes it.
struct ServerPlaces {
    cwd: Option<PathBuf>,
    repo: Option<String>,
    data: Option<String>,
    proxy: Option<String>,
    debug: bool,
}

/// The subcommand path `matches` ran.
/// The string a result holds at `key`, if any.
fn data_text(data: &[(String, crate::json::Json)], key: &str) -> Option<String> {
    data.iter()
        .find(|(name, _)| name == key)
        .and_then(|(_, value)| match value {
            crate::json::Json::Str(text) => Some(text.clone()),
            _ => None,
        })
}

fn command_path(matches: &clap::ArgMatches) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = matches;
    while let Some((name, sub)) = current.subcommand() {
        words.push(name.to_owned());
        current = sub;
    }
    words
}

thread_local! {
    static LAST_PANIC: RefCell<Option<Internal>> = const { RefCell::new(None) };
}

/// Records each panic's message, location and backtrace for the crash report,
/// instead of printing them: [`run`] reports the panic itself.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let message = crash::panic_message(info.payload());
        let location = info
            .location()
            .map(|location| {
                format!(
                    "at {}:{}:{}\n",
                    location.file(),
                    location.line(),
                    location.column()
                )
            })
            .unwrap_or_default();
        let backtrace = std::backtrace::Backtrace::force_capture();
        LAST_PANIC.with(|last| {
            *last.borrow_mut() = Some(Internal {
                kind: "panic".into(),
                message,
                trace: format!("{location}{backtrace}"),
            });
        });
    }));
}

/// The UTC time now: `2026-11-09T10:11:12Z`, the crash log's stamp
/// `20261109T101112123456Z`, and the log lines' `10:11:12`.
pub fn utc_now() -> (String, String, String) {
    utc_at(SystemTime::now())
}

/// [`utc_now`] at `time`, formatted by jiff (RFC 3339, in UTC).
pub fn utc_at(time: SystemTime) -> (String, String, String) {
    // A moment outside jiff's range (before year -9999 or after the end of
    // 9999) stops at the nearest end of it, not at 1970: the stamp stays
    // ordered with the time that made it.
    let at = jiff::Timestamp::try_from(time).unwrap_or(if time >= SystemTime::UNIX_EPOCH {
        jiff::Timestamp::MAX
    } else {
        jiff::Timestamp::MIN
    });
    let iso = at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
    let stamp = at.strftime("%Y%m%dT%H%M%S%6fZ").to_string();
    let clock = at.strftime("%H:%M:%S").to_string();
    (iso, stamp, clock)
}

/// A log line's time: `2026-11-09 10:11:12` (UTC), the date-time a JSON line
/// carries; a text line under `--debug` shows the time part.
fn log_clock() -> String {
    utc_now()
        .0
        .replace('T', " ")
        .trim_end_matches('Z')
        .to_owned()
}

thread_local! {
    /// Whether [`run_keeping_document`] runs on this thread.
    static KEEPING_DOCUMENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// The JSON document of the report the run printed, as `--json` would
    /// print it, while [`KEEPING_DOCUMENT`] is set.
    static KEPT_DOCUMENT: RefCell<Option<crate::json::Json>> = const { RefCell::new(None) };
}

/// [`run`] for a host that shows a run's output itself (`opentide tui`'s
/// Results tab): the exit code, and the JSON document `--json` would print
/// for the report the run printed, built from the same report (no second
/// run). `None` when the run printed no report (a usage error, a dry run's
/// plan).
pub fn run_keeping_document(
    argv: &[String],
    env: &Env,
    host: &Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> (i32, Option<crate::json::Json>) {
    KEPT_DOCUMENT.with(|kept| kept.borrow_mut().take());
    KEEPING_DOCUMENT.with(|keeping| keeping.set(true));
    let code = run(argv, env, host, out, err);
    KEEPING_DOCUMENT.with(|keeping| keeping.set(false));
    let document = KEPT_DOCUMENT.with(|kept| kept.borrow_mut().take());
    (code, document)
}

/// Runs `opentide` with `argv` (without the program name); the exit code.
pub fn run(
    argv: &[String],
    env: &Env,
    host: &Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    run_with(argv, env, host, out, err, |run, out, err| {
        Ok(run.dispatch(out, err)?)
    })
}

/// What a command returns: its exit code, or an error it did not expect,
/// which is reported as a crash, as a panic is.
pub type CommandResult = Result<i32, Box<dyn std::error::Error + Send + Sync>>;

/// [`run`], with the command step given: everything around it (modes,
/// logging, the crash handler) is the run's.
fn run_with(
    argv: &[String],
    env: &Env,
    host: &Host,
    out: &mut dyn Write,
    err: &mut dyn Write,
    command: impl FnOnce(&Run<'_>, &mut dyn Write, &mut dyn Write) -> CommandResult,
) -> i32 {
    let started = Instant::now();
    let root = catalog::root();
    let matches = lenient_matches(&root, argv);
    let globals = globals(argv, &matches, env);
    let leading = command_path(&matches);
    let mode = mode::resolve(
        Inputs {
            json_flag: globals.json,
            no_color: globals.no_color,
            command: &leading,
            stdout_tty: host.stdout_tty,
        },
        env,
    );
    let debug = globals.debug || env.debug_requested();
    let run = Run {
        indent: mode::json_indent(env, host.stdout_tty),
        args: argv.to_vec(),
        root,
        globals,
        mode,
        env,
        host,
        started,
    };
    let mut redactor = workspace_redactor(&run.workspaces(), env);
    if let Some(proxy) = &run.globals.proxy {
        redactor = redactor.with_secrets(url_secrets(proxy).0);
    }
    let layer = LogLayer::new(
        logging::Config {
            debug,
            quiet: run.globals.quiet,
            // `--json` writes its log lines as JSON too, as OPENTIDE_LOG_JSON=1 does.
            json_lines: mode == Mode::Json || env.boolean("OPENTIDE_LOG_JSON").unwrap_or(false),
        },
        host.log_sink.clone(),
        redactor.clone(),
        log_clock,
    );
    let result = tracing::subscriber::with_default(logging::subscriber(layer), || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| command(&run, out, err)))
    });
    if run.interrupted() {
        // The jobs stopped: one line, no document, whatever they returned.
        return host.interrupt.report(err);
    }
    match result {
        Ok(Ok(code)) => code,
        // The reader went away (`opentide --json commands | head -c1`):
        // nobody reads a report either. Exit 1, quietly, as the CLI always has.
        Ok(Err(error)) if is_broken_pipe(error.as_ref()) => 1,
        Ok(Err(error)) => {
            let internal = Internal::from_error(error.as_ref());
            report_internal(&run, &internal, &redactor, debug, out, err)
        }
        Err(payload) => {
            let internal = LAST_PANIC
                .with(|last| last.borrow_mut().take())
                .unwrap_or_else(|| Internal {
                    kind: "panic".into(),
                    message: crash::panic_message(payload.as_ref()),
                    trace: String::new(),
                });
            report_internal(&run, &internal, &redactor, debug, out, err)
        }
    }
}

fn report_internal(
    run: &Run<'_>,
    internal: &Internal,
    redactor: &Redactor,
    debug: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let words = command_words(&run.root, &run.args).join(" ");
    let facts = Facts::current(&run.host.version);
    let now = utc_now();
    crash::report(
        internal,
        &crash::Report {
            argv: &run.args,
            command: &words,
            mode: run.mode,
            debug,
            env: run.env,
            redactor,
            facts: &facts,
            stderr_tty: run.host.stderr_tty,
            indent: run.indent,
            log_dir: crash::crash_log_dir(run.env),
            now: (now.0, now.1),
        },
        out,
        err,
    )
}

/// Whether `error` is, or wraps, a write to a closed pipe.
fn is_broken_pipe(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// Ctrl-C: `interrupt` is set, and the run stops ([`Interrupt`]). The
/// process ends with `error: interrupted` and 130 on a second Ctrl-C, or when
/// the run has not stopped after [`INTERRUPT_GRACE`].
#[cfg(target_os = "wasi")]
pub fn install_interrupt_handler(interrupt: Interrupt) {
    // WASI delivers no signals: the host ends the module instead.
    let _ = interrupt;
}

/// Ctrl-C: `interrupt` is set, and the run stops ([`Interrupt`]). The
/// process ends with `error: interrupted` and 130 on a second Ctrl-C, or when
/// the run has not stopped after [`INTERRUPT_GRACE`].
#[cfg(not(target_os = "wasi"))]
pub fn install_interrupt_handler(interrupt: Interrupt) {
    // A second install (an embedding host calling `main` twice) keeps the first.
    let _ignored = ctrlc::set_handler(move || {
        if let Some(code) = on_interrupt(&interrupt, &mut std::io::stderr().lock()) {
            std::process::exit(code);
        }
        let interrupt = interrupt.clone();
        std::thread::spawn(move || {
            std::thread::sleep(INTERRUPT_GRACE);
            std::process::exit(interrupt.report(&mut std::io::stderr().lock()));
        });
    });
}

/// One Ctrl-C: the first tells the jobs and returns `None` (the run stops
/// and reports it); a second, or the first in a run that stops at once
/// ([`Interrupt::stop_at_once`]), reports it now and returns the exit code,
/// 130.
pub fn on_interrupt(interrupt: &Interrupt, err: &mut dyn Write) -> Option<i32> {
    if interrupt.request() || interrupt.at_once.load(Ordering::SeqCst) {
        Some(interrupt.report(err))
    } else {
        None
    }
}

/// Set by [`exit`]: the process ends when the run returns.
static PROCESS_ENDS: AtomicBool = AtomicBool::new(false);

/// `opentide` as the whole process: [`main`], then exit with its status.
/// The `opentide` binary calls it; a host that runs commands in its own
/// process (the Python package's `cli_main`) calls [`main`] instead.
pub fn exit(argv: &[String], version: &str) -> ! {
    PROCESS_ENDS.store(true, Ordering::Relaxed);
    std::process::exit(main(argv, version))
}

/// The width of the terminal stderr (else stdout) is, when either is one.
#[cfg(not(target_os = "wasi"))]
fn terminal_width() -> Option<usize> {
    terminal_size::terminal_size_of(std::io::stderr())
        .or_else(|| terminal_size::terminal_size_of(std::io::stdout()))
        .map(|(width, _)| usize::from(width.0))
}

/// The variable a WASI host sets to its terminal's width: WASI preview 1
/// has no call that tells a terminal's size, which the host knows (VS Code's
/// pseudoterminal; the golden harness's pty).
pub const TERMINAL_WIDTH_VARIABLE: &str = "OPENTIDE_TERMINAL_WIDTH";

/// WASI: the width the host names ([`TERMINAL_WIDTH_VARIABLE`]), as
/// natively the terminal itself tells it. The host sets it only when it
/// gives the module a terminal.
#[cfg(target_os = "wasi")]
fn terminal_width() -> Option<usize> {
    std::env::var(TERMINAL_WIDTH_VARIABLE)
        .ok()?
        .parse::<usize>()
        .ok()
        .filter(|width| *width > 0)
}

/// WASI gives a module no working directory: the host names it in `PWD`
/// (a folder it preopened), as a shell does, and relative paths resolve
/// against it from here on. Elsewhere the process has its own.
fn adopt_working_directory() {
    #[cfg(target_os = "wasi")]
    if let Some(pwd) = std::env::var_os("PWD").filter(|pwd| !pwd.is_empty()) {
        let _ignored = std::env::set_current_dir(pwd);
    }
}

/// Frees `value`, unless the process ends when this run returns ([`exit`]):
/// freeing a large document tree (a workspace's index, `info catalog`'s
/// document) takes longer than building it, and the exit reclaims it at no
/// cost. In any other process it is dropped here, so nothing leaks.
pub(crate) fn release<T>(value: T) {
    release_when(value, PROCESS_ENDS.load(Ordering::Relaxed));
}

fn release_when<T>(value: T, process_ends: bool) {
    if process_ends {
        std::mem::forget(value);
    } else {
        drop(value);
    }
}

/// `opentide` in this process: the process's environment and streams.
pub fn main(argv: &[String], version: &str) -> i32 {
    use std::io::IsTerminal;
    adopt_working_directory();
    let env = Env::from_process();
    let cwd = std::env::current_dir().ok();
    // A Tab press (`_OPENTIDE_COMPLETE`): its candidates, before anything
    // else can write to stdout.
    if let Some(code) = crate::commands::completion::answer(argv, &env, cwd.as_deref()) {
        return code;
    }
    install_panic_hook();
    let interrupt = Interrupt::default();
    install_interrupt_handler(interrupt.clone());
    let stderr_sink: Sink = std::sync::Arc::new(std::sync::Mutex::new(std::io::stderr()));
    let host = Host {
        version: version.to_owned(),
        stdout_tty: std::io::stdout().is_terminal(),
        stderr_tty: std::io::stderr().is_terminal(),
        log_sink: stderr_sink,
        cwd,
        width: terminal_width(),
        interrupt,
    };
    // The renderers decide whether to style (`App::console`); the console
    // streams only make a Windows console read what they write.
    let mut out = anstream::AutoStream::always(std::io::stdout()).lock();
    let mut err = anstream::AutoStream::always(std::io::stderr());
    run(argv, &env, &host, &mut out, &mut err)
}

/// A command path of the tree that no handler answers: a bug in opentide
/// (`internal`, exit 1). Every path the tree has is answered.
fn unhandled(path: &str) -> Outcome {
    let message = format!("opentide {path} has no implementation: this is a bug in opentide");
    Outcome::failed(path, 1, Failure::new(code::INTERNAL, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_reports_detail_and_advice_are_its_note_and_help() {
        let mut outcome = Outcome::failed("tui", 2, Failure::new("x", "m"));
        assert_eq!(data_text(&outcome.data, "advice"), None);
        outcome
            .data
            .push(("advice".into(), crate::json::Json::str("do this")));
        outcome
            .data
            .push(("detail".into(), crate::json::Json::Int(1)));
        assert_eq!(
            data_text(&outcome.data, "advice").as_deref(),
            Some("do this")
        );
        // Only a string is a line to print.
        assert_eq!(data_text(&outcome.data, "detail"), None);
    }

    /// Counts its drops, to tell a freed value from a leaked one.
    struct Counted(std::rc::Rc<std::cell::Cell<u32>>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn release_frees_unless_the_process_ends() {
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        release_when(Counted(drops.clone()), false);
        assert_eq!(
            drops.get(),
            1,
            "a run inside a host process frees what it built"
        );
        release_when(Counted(drops.clone()), true);
        assert_eq!(drops.get(), 1, "the binary leaves it to the exit");
    }

    #[test]
    fn a_run_in_process_frees_what_it_releases() {
        // Only `exit` (the binary) sets the switch: `main` and `run`, which
        // the Python package calls in its own process, never leak.
        assert!(!PROCESS_ENDS.load(Ordering::Relaxed));
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        release(Counted(drops.clone()));
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn framework_utc_dates() {
        let at = |secs: u64, micros: u64| {
            utc_at(
                std::time::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros),
            )
        };
        assert_eq!(
            at(0, 0),
            (
                "1970-01-01T00:00:00Z".into(),
                "19700101T000000000000Z".into(),
                "00:00:00".into()
            )
        );
        assert_eq!(
            at(1_794_219_072, 123_456),
            (
                "2026-11-09T10:11:12Z".into(),
                "20261109T101112123456Z".into(),
                "10:11:12".into()
            )
        );
        assert_eq!(at(951_782_400, 0).0, "2000-02-29T00:00:00Z");
        let (iso, stamp, clock) = utc_now();
        assert_eq!(iso.len(), 20);
        assert_eq!(stamp.len(), 22);
        assert_eq!(clock.len(), 8);
    }

    /// The strings humantime gave (checked against Python's `datetime`) for
    /// the instants where a hand-written calendar goes wrong.
    #[test]
    fn framework_utc_stamps_at_calendar_edges() {
        let after = |secs: u64, micros: u64| {
            utc_at(
                std::time::UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_micros(micros),
            )
        };
        let before = |secs: u64| utc_at(std::time::UNIX_EPOCH - Duration::from_secs(secs));
        let table = [
            // 1900 is not a leap year: the day after the 28th is 1 March.
            (
                before(2_203_891_201),
                "1900-02-28T23:59:59Z",
                "19000228T235959000000Z",
            ),
            (
                before(2_203_891_200),
                "1900-03-01T00:00:00Z",
                "19000301T000000000000Z",
            ),
            // The second before 1970.
            (before(1), "1969-12-31T23:59:59Z", "19691231T235959000000Z"),
            (
                after(1_709_210_096, 789_012),
                "2024-02-29T12:34:56Z",
                "20240229T123456789012Z",
            ),
            // 2100 is not a leap year either.
            (
                after(4_107_542_399, 0),
                "2100-02-28T23:59:59Z",
                "21000228T235959000000Z",
            ),
            (
                after(4_107_542_400, 0),
                "2100-03-01T00:00:00Z",
                "21000301T000000000000Z",
            ),
            // A year-end rollover.
            (
                after(1_798_761_599, 999_999),
                "2026-12-31T23:59:59Z",
                "20261231T235959999999Z",
            ),
            (
                after(1_798_761_600, 0),
                "2027-01-01T00:00:00Z",
                "20270101T000000000000Z",
            ),
        ];
        for ((iso, stamp, clock), want_iso, want_stamp) in table {
            assert_eq!((iso.as_str(), stamp.as_str()), (want_iso, want_stamp));
            assert_eq!(clock, &want_iso[11..19]);
        }
    }

    /// jiff ends at `9999-12-30T22:00:00.999999999Z`: a moment past it (or
    /// before its start) stops there instead of becoming 1970.
    #[test]
    fn framework_utc_stamps_stop_at_the_end_of_jiffs_range() {
        let last = 253_402_207_200;
        let (iso, stamp, _) = utc_at(std::time::UNIX_EPOCH + Duration::from_secs(last));
        assert_eq!(iso, "9999-12-30T22:00:00Z");
        assert_eq!(stamp, "99991230T220000000000Z");
        let past = utc_at(std::time::UNIX_EPOCH + Duration::from_secs(last + 1));
        assert_eq!(past.0, "9999-12-30T22:00:00Z");
        assert_eq!(past.1, "99991230T220000999999Z");
        let first = utc_at(std::time::UNIX_EPOCH - Duration::from_secs(377_705_023_202));
        assert_eq!(
            first,
            utc_at(std::time::UNIX_EPOCH - Duration::from_secs(377_705_023_201))
        );
    }

    #[test]
    fn framework_command_words_and_late_global_flags() {
        let root = catalog::root();
        let words = |text: &str| {
            let args: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
            command_words(&root, &args).join(" ")
        };
        assert_eq!(words("generate docs rules --x"), "generate docs rules");
        assert_eq!(words("explain invalid_ref"), "explain");
        assert_eq!(words("--json validate --json query"), "validate query");
        assert_eq!(words("--repo r mcp start --x"), "mcp start");
        assert_eq!(words("valdiate"), "");
        // A global flag after a usage error, or after `generate`'s phases,
        // still counts; after `--` it does not.
        for line in [
            "valdiate --json",
            "validate --bogus --json",
            "generate docs --json",
        ] {
            assert!(globals_of(&root, line, &Env::default()).json, "{line}");
        }
        assert!(!globals_of(&root, "explain -- --json", &Env::default()).json);
    }

    #[test]
    fn framework_globals_read_root_options_and_global_flags() {
        let root = catalog::root();
        let args: Vec<String> = "--repo r --proxy=http://p --debug -V --data d validate --quiet"
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let globals = globals(&args, &lenient_matches(&root, &args), &Env::default());
        assert_eq!(globals.repo.as_deref(), Some("r"));
        assert_eq!(globals.proxy.as_deref(), Some("http://p"));
        // `--quiet` is global: after the command too.
        assert!(globals.debug && globals.version && globals.quiet);
        let env = Env::from_pairs([("OPENTIDE_PROXY", "http://e")]);
        assert_eq!(
            globals_of(&root, "validate", &env).proxy.as_deref(),
            Some("http://e")
        );
    }

    #[derive(Clone, Default)]
    struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Ran {
        code: i32,
        stdout: String,
        stderr: String,
    }

    fn host(tty: bool, sink: &Buffer) -> Host {
        Host {
            version: "9.9.9".into(),
            stdout_tty: tty,
            stderr_tty: tty,
            log_sink: std::sync::Arc::new(std::sync::Mutex::new(sink.clone())),
            cwd: None,
            width: None,
            interrupt: Interrupt::default(),
        }
    }

    fn ran(
        line: &str,
        pairs: &[(&str, &str)],
        tty: bool,
        command: impl FnOnce(&Run<'_>, &mut dyn Write, &mut dyn Write) -> CommandResult,
    ) -> Ran {
        let argv: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        let env = Env::from_pairs(pairs.iter().copied());
        let err = Buffer::default();
        let mut out = Vec::new();
        let code = run_with(
            &argv,
            &env,
            &host(tty, &err),
            &mut out,
            &mut err.clone(),
            command,
        );
        let stderr = String::from_utf8(err.0.lock().unwrap().clone()).unwrap();
        Ran {
            code,
            stdout: String::from_utf8(out).unwrap(),
            stderr,
        }
    }

    fn dispatched(line: &str, pairs: &[(&str, &str)], tty: bool) -> Ran {
        ran(
            line,
            pairs,
            tty,
            |run, out, err| Ok(run.dispatch(out, err)?),
        )
    }

    /// `line` dispatched at a terminal of `width` columns.
    fn dispatched_at(line: &str, pairs: &[(&str, &str)], width: usize) -> Ran {
        let argv: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        let env = Env::from_pairs(pairs.iter().copied());
        let err = Buffer::default();
        let mut out = Vec::new();
        let mut host = host(true, &err);
        host.width = Some(width);
        let code = run_with(
            &argv,
            &env,
            &host,
            &mut out,
            &mut err.clone(),
            |run, out, err| Ok(run.dispatch(out, err)?),
        );
        let stderr = String::from_utf8(err.0.lock().unwrap().clone()).unwrap();
        Ran {
            code,
            stdout: String::from_utf8(out).unwrap(),
            stderr,
        }
    }

    #[test]
    fn framework_usage_error_in_the_text_modes_is_clap_rendering() {
        let word = "--an-option-whose-name-is-wider-than-the-terminal";
        let line = format!("validate {word}");
        for (mode, colour) in [("plain", Colour::Mono), ("human", Colour::Full)] {
            let result = dispatched_at(&line, &[("OPENTIDE_OUTPUT", mode)], 30);
            assert_eq!(result.code, USAGE_EXIT_CODE, "{mode}");
            // A word is never split: the option stays whole on its row.
            assert!(result.stderr.contains(word), "{mode}: {}", result.stderr);
            // clap's error, styled only in `human` mode.
            assert!(
                result.stderr.starts_with("error: ") || result.stderr.starts_with('\u{1b}'),
                "{mode}: {}",
                result.stderr
            );
            assert_eq!(
                result.stderr.contains('\u{1b}'),
                colour == Colour::Full,
                "{mode}: {}",
                result.stderr
            );
        }
        // The agent tip, as the outcome renderer writes it.
        let result = dispatched_at(&line, &[("AI_AGENT", "a")], 30);
        assert!(
            result
                .stderr
                .ends_with("tip: add --json for machine-readable output\n"),
            "{}",
            result.stderr
        );
    }

    const MODES: &[(&str, &[(&str, &str)])] = &[
        ("x", &[("OPENTIDE_OUTPUT", "human")]),
        ("x", &[]),
        ("--json x", &[]),
        ("x", &[("AI_AGENT", "a")]),
        ("mcp start", &[]),
    ];

    #[test]
    fn framework_logging_never_writes_stdout_and_follows_the_mode() {
        for (line, pairs) in MODES {
            for debug in [false, true] {
                let line = if debug {
                    format!("--debug {line}")
                } else {
                    (*line).to_owned()
                };
                let result = ran(&line, pairs, true, |_, _, _| {
                    tracing::debug!(path = "x", "registry_loaded");
                    tracing::warn!("tenant_targets_failed");
                    Ok(0)
                });
                assert_eq!(result.stdout, "", "{line}");
                // `--json` writes its log lines as JSON, as the oracle does.
                let (warned, loaded) = if line.contains("--json") {
                    (
                        "\"event\":\"tenant_targets_failed\",\"level\":\"warning\"",
                        "{\"path\":\"x\",\"event\":\"registry_loaded\",\"level\":\"debug\"",
                    )
                } else {
                    (
                        "warning: Tenant targets failed",
                        "Registry loaded · path: x",
                    )
                };
                assert!(result.stderr.contains(warned), "{line}: {}", result.stderr);
                assert_eq!(result.stderr.contains(loaded), debug, "{line}");
            }
        }
        let quiet = ran("--quiet x", &[], false, |_, _, _| {
            tracing::warn!("hidden");
            tracing::error!("shown");
            Ok(0)
        });
        assert_eq!(quiet.stderr, "error: Shown\n");
        // OPENTIDE_DEBUG and a boolean DEBUG turn debug on; DEBUG='*' does not.
        for (pairs, shown) in [
            (&[("OPENTIDE_DEBUG", "1")][..], true),
            (&[("DEBUG", "true")][..], true),
            (&[("DEBUG", "*")][..], false),
        ] {
            let result = ran("x", pairs, false, |_, _, _| {
                tracing::debug!("seen");
                Ok(0)
            });
            assert_eq!(result.stderr.contains("debug: Seen"), shown, "{pairs:?}");
        }
    }

    #[test]
    fn framework_crash_from_a_panic_and_from_an_error_report_the_same() {
        let state =
            std::env::temp_dir().join(format!("opentide-cli-app-crash-{}", std::process::id()));
        let state_text = state.display().to_string();
        // The state directory on every platform: XDG on Linux, under HOME on
        // macOS, LOCALAPPDATA on Windows.
        let pairs = [
            ("XDG_STATE_HOME", state_text.as_str()),
            ("HOME", state_text.as_str()),
            ("USERPROFILE", state_text.as_str()),
            ("LOCALAPPDATA", state_text.as_str()),
            ("API_TOKEN", "s3cr3t-value"),
        ];
        let panicked = ran(
            "--json validate --token s3cr3t-value",
            &pairs,
            false,
            |_, _, _| panic!("boom with s3cr3t-value inside"),
        );
        assert_eq!(panicked.code, 1);
        let stderr_first = panicked.stderr.lines().next().unwrap();
        assert_eq!(stderr_first, "error[internal]: panic: boom with *** inside");
        assert!(
            panicked
                .stderr
                .contains("  note: crash log, with credentials and tenant names redacted: ")
        );
        assert!(panicked.stderr.contains("  help: this is a bug in opentide; report it: https://github.com/opentidehq/opentide/issues/new?title=Crash+in+opentide+validate&body="));
        assert!(
            panicked
                .stderr
                .ends_with("  help: add --debug to see the traceback\n")
        );
        let document = crate::json::Json::parse(&panicked.stdout).unwrap();
        assert_eq!(
            document.get("command"),
            Some(&crate::json::Json::str("validate"))
        );
        let failure = document.get("failure").unwrap();
        assert_eq!(
            failure.get("code"),
            Some(&crate::json::Json::str("internal"))
        );
        let crate::json::Json::Str(log) = failure.get("crash_log").unwrap() else {
            panic!("no crash log")
        };
        let text = std::fs::read_to_string(log).unwrap();
        assert!(text.starts_with("opentide crash log\n\ntime: "));
        assert!(
            text.contains("arguments: --json validate --token '***'")
                || text.contains("arguments: --json validate --token ***")
        );
        assert!(!text.contains("s3cr3t-value"), "{text}");
        assert!(text.contains("output mode: json"));

        let failed = ran("--json validate", &pairs, false, |_, _, _| {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "gone",
            )))
        });
        assert_eq!(failed.code, 1);
        assert_eq!(
            failed.stderr.lines().next().unwrap(),
            "error[internal]: Error: gone"
        );
        assert!(failed.stdout.contains("\"code\":\"internal\""));

        // --debug prints the trace first; mcp mode never writes stdout; no
        // home means no log, said so.
        let debug = ran(
            "--debug mcp start",
            &[("XDG_STATE_HOME", "relative")],
            false,
            |_, _, _| Err("plain".into()),
        );
        assert_eq!(debug.stdout, "");
        assert!(
            debug.stderr.starts_with("Error: plain\n"),
            "{}",
            debug.stderr
        );
        assert!(
            debug
                .stderr
                .contains("  note: no crash log written: no home directory to keep crash logs in")
        );
        assert!(!debug.stderr.contains("add --debug"));
        // A person at a terminal clicks a short link.
        let human = ran(
            "x",
            &[("OPENTIDE_OUTPUT", "human"), ("HOME", "/nonexistent/x")],
            true,
            |_, _, _| Err("e".into()),
        );
        assert!(
            human
                .stderr
                .contains("\u{1b}]8;;https://github.com/opentidehq/opentide/issues/new?")
        );
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn framework_interrupt_first_tells_the_jobs_second_exits_130() {
        let interrupt = Interrupt::default();
        let mut err = Vec::new();
        // The first Ctrl-C only tells the jobs: the run reports it.
        assert_eq!(on_interrupt(&interrupt, &mut err), None);
        assert!(interrupt.requested());
        assert!(err.is_empty());
        // The second ends the process now, with the one line.
        assert_eq!(on_interrupt(&interrupt, &mut err), Some(130));
        assert_eq!(err, b"error: interrupted\n");
        // Reported once, whoever reports it first.
        assert_eq!(interrupt.report(&mut err), 130);
        assert_eq!(err, b"error: interrupted\n");
    }

    #[test]
    fn framework_interrupt_a_run_that_stops_at_once_exits_130_on_the_first() {
        let interrupt = Interrupt::default();
        interrupt.stop_at_once();
        let mut err = Vec::new();
        assert_eq!(on_interrupt(&interrupt, &mut err), Some(130));
        assert_eq!(err, b"error: interrupted\n");
    }

    /// Runs `test` on a thread of its own and fails if it has not finished
    /// within `limit`: a test that would hang (a server reading the test
    /// process's own stdin, which `cargo test` leaves open) fails fast
    /// instead of holding the run.
    fn within(limit: std::time::Duration, test: impl FnOnce() + Send + 'static) {
        let (done, finished) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            test();
            let _ignored = done.send(());
        });
        match finished.recv_timeout(limit) {
            Ok(()) => thread.join().unwrap(),
            // The test panicked: its panic is the failure.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                std::panic::resume_unwind(thread.join().unwrap_err());
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("the test did not finish within {limit:?}");
            }
        }
    }

    #[test]
    fn framework_interrupt_lets_a_polling_job_clean_up_and_prints_no_document() {
        within(
            Duration::from_secs(60),
            framework_interrupt_lets_a_polling_job_clean_up,
        );
    }

    fn framework_interrupt_lets_a_polling_job_clean_up() {
        // `mcp start` and `serve` serve stdio until the client closes stdin:
        // dispatched after the Ctrl-C, they do not start.
        for line in ["--json commands", "commands", "mcp start", "serve"] {
            let cleaned = std::cell::Cell::new(false);
            let result = ran(line, &[], false, |run, out, err| {
                // Ctrl-C while the job runs: it polls, stops and cleans up.
                assert_eq!(on_interrupt(&run.host.interrupt, &mut Vec::new()), None);
                for _ in 0..3 {
                    if run.interrupted() {
                        cleaned.set(true);
                        break;
                    }
                }
                Ok(run.dispatch(out, err)?)
            });
            assert!(cleaned.get(), "{line}");
            assert_eq!(result.code, 130, "{line}");
            assert_eq!(result.stdout, "", "{line}");
            assert_eq!(result.stderr, "error: interrupted\n", "{line}");
        }
        // A job that fails on its way out is still an interrupt, not a crash.
        let failed = ran("--json validate", &[], false, |run, _, _| {
            run.host.interrupt.request();
            Err("cancelled".into())
        });
        assert_eq!(
            (failed.code, failed.stdout.as_str(), failed.stderr.as_str()),
            (130, "", "error: interrupted\n")
        );
    }

    /// A stream whose every write fails with `kind`.
    struct Failing(std::io::ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(self.0))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from(self.0))
        }
    }

    fn into_failing(line: &str, kind: std::io::ErrorKind) -> (i32, String) {
        let argv: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        let sink = Buffer::default();
        let state = std::env::temp_dir().join(format!(
            "opentide-cli-write-{}-{}",
            std::process::id(),
            line.len()
        ));
        let state_text = state.display().to_string();
        let env = Env::from_pairs([
            ("XDG_STATE_HOME", state_text.as_str()),
            ("HOME", state_text.as_str()),
            ("USERPROFILE", state_text.as_str()),
            ("LOCALAPPDATA", state_text.as_str()),
        ]);
        let code = run(
            &argv,
            &env,
            &host(false, &sink),
            &mut Failing(kind),
            &mut sink.clone(),
        );
        let _ = std::fs::remove_dir_all(&state);
        let stderr = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        (code, stderr)
    }

    #[test]
    fn framework_a_lost_document_is_a_failure_not_success() {
        // `opentide --json commands > /dev/full`: the document is lost, so
        // the run fails as an internal error (exit 1), as the CLI always has.
        for line in [
            "--json commands",
            "commands",
            "--version",
            "--json validate",
        ] {
            let (code, stderr) = into_failing(line, std::io::ErrorKind::StorageFull);
            assert_eq!(code, 1, "{line}");
            assert!(stderr.starts_with("error[internal]: "), "{line}: {stderr}");
        }
        // Help on a full disk too.
        let (code, _) = into_failing("validate --help", std::io::ErrorKind::StorageFull);
        assert_eq!(code, 1);
        // The reader went away: exit 1, quietly.
        let (code, stderr) = into_failing("--json commands", std::io::ErrorKind::BrokenPipe);
        assert_eq!((code, stderr.as_str()), (1, ""));
    }

    /// `line`, whose command no handler answers (a path taken out of the
    /// dispatcher): an internal error.
    fn unhandled_run(line: &str) -> Ran {
        ran(line, &[], false, |run, out, err| {
            Ok(run.emit(&unhandled("query"), &[], out, err)?)
        })
    }

    #[test]
    fn framework_root_version_help_and_refusals() {
        let version = dispatched("--version", &[], false);
        assert_eq!(
            (version.code, version.stdout.as_str()),
            (0, "opentide 9.9.9\n")
        );
        assert_eq!(
            dispatched("-V commands", &[], false).stdout,
            "opentide 9.9.9\n"
        );
        let bare = dispatched("", &[], false);
        assert_eq!(bare.code, 0);
        assert!(bare.stdout.contains("Usage: opentide"), "{}", bare.stdout);
        let help = dispatched("validate query --help", &[], true);
        assert_eq!(help.code, 0);
        assert!(
            help.stdout.contains("opentide validate query"),
            "{}",
            help.stdout
        );
        let json = unhandled_run("--json query --platform x q");
        assert_eq!(json.code, 1);
        assert!(json.stdout.contains("\"code\":\"internal\""));
        let plain = unhandled_run("query --platform x q");
        assert_eq!(
            plain.stderr,
            "error: opentide query has no implementation: this is a bug in opentide\n"
        );
        let sysdig = dispatched("query --platform sysdig q", &[], false);
        assert_eq!(sysdig.code, 2);
        assert_eq!(sysdig.stderr, "error: sysdig has no query runner\n");
        let file =
            std::env::temp_dir().join(format!("opentide-cli-not-a-dir-{}", std::process::id()));
        std::fs::write(&file, "x").unwrap();
        let line = format!("--repo {} validate", file.display());
        let not_dir = dispatched(&line, &[], false);
        assert!(
            not_dir.stderr.starts_with("error: --repo "),
            "{}",
            not_dir.stderr
        );
        assert!(not_dir.stderr.contains(" is not a directory\n"));
        // `setup` creates the repository: a missing --repo is no error there.
        assert!(
            !dispatched("--repo nowhere-at-all setup", &[], false)
                .stderr
                .contains("does not exist")
        );
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn framework_json_indentation_and_one_trailing_newline() {
        let compact = dispatched("--json commands", &[], false);
        assert!(compact.stdout.starts_with("{\"program\""));
        let indented = dispatched("--json commands", &[], true);
        assert!(indented.stdout.starts_with("{\n  \"program\""));
        let forced = dispatched("--json commands", &[("OPENTIDE_JSON_INDENT", "0")], true);
        assert!(forced.stdout.starts_with("{\"program\""));
        for result in [compact, indented, forced] {
            assert!(result.stdout.ends_with("}\n") && !result.stdout.ends_with("\n\n"));
        }
    }

    #[test]
    fn framework_redaction_fuzzed_secrets_never_reach_output_logs_or_crash_logs() {
        let root =
            std::env::temp_dir().join(format!("opentide-cli-redact-fuzz-{}", std::process::id()));
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        // Quotes, backslashes and non-ASCII too: a secret must be redacted
        // as written, before JSON or Debug escapes it.
        let alphabet: Vec<char> =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~!$%^*+\"\\éü日"
                .chars()
                .collect();
        for round in 0..60 {
            let (secret_length, password_length) = (next() % 24, next() % 16);
            let mut word = |length: u64| -> String {
                (0..8 + length)
                    .map(|_| alphabet[usize::try_from(next()).unwrap() % alphabet.len()])
                    .collect()
            };
            let secret = format!("S{}", word(secret_length));
            let password = format!("P{}", word(password_length)).replace(['@', '/', '?', '#'], "x");
            let tenant = format!("tenant-{}", word(4)).replace(['"', '\\', 'é', 'ü', '日'], "t");
            let host = format!(
                "{}.example",
                word(3).to_lowercase().replace(
                    [
                        '.', '~', '!', '$', '%', '^', '*', '+', '_', '"', '\\', 'é', 'ü', '日'
                    ],
                    "a",
                )
            );
            let workspace = root.join(round.to_string());
            let platforms = workspace.join(".opentide/configurations/platforms");
            std::fs::create_dir_all(&platforms).unwrap();
            std::fs::write(
                platforms.join("splunk.toml"),
                format!("[[tenants]]\nname = \"{tenant}\"\nurl = \"https://{host}:8089\"\ntoken = \"$SPLUNK_TOKEN\"\n"),
            )
            .unwrap();
            let state_home = workspace.join("state").display().to_string();
            let repo = workspace.display().to_string();
            let proxy = format!("http://user:{password}@proxy.local:3128");
            // Every other round logs JSON lines (OPENTIDE_LOG_JSON=1).
            let log_json = if round % 2 == 0 { "1" } else { "0" };
            let pairs = [
                ("OPENTIDE_LOG_JSON", log_json),
                ("SPLUNK_TOKEN", secret.as_str()),
                ("HTTPS_PROXY", proxy.as_str()),
                ("XDG_STATE_HOME", state_home.as_str()),
                ("HOME", state_home.as_str()),
                ("USERPROFILE", state_home.as_str()),
                ("LOCALAPPDATA", state_home.as_str()),
            ];
            let line = format!("--debug --json --repo {repo} validate --api-key {secret}");
            let leak = format!(
                "token={secret} proxy {proxy} on {tenant} at {host} Authorization: Bearer {secret}"
            );
            let result = ran(&line, &pairs, false, |_, _, _| {
                tracing::warn!(detail = leak.as_str(), "request_failed");
                tracing::warn!(detail = ?leak, "debug_field");
                // Alone, with no key or scheme a pattern would catch.
                tracing::warn!(detail = secret.as_str(), "secret_alone");
                tracing::warn!(detail = ?secret, "secret_debug");
                tracing::debug!("{}", leak);
                panic!("{leak}")
            });
            let crate::json::Json::Str(log) = crate::json::Json::parse(&result.stdout)
                .unwrap()
                .get("failure")
                .and_then(|failure| failure.get("crash_log"))
                .cloned()
                .unwrap()
            else {
                panic!("no crash log")
            };
            let crash_log = std::fs::read_to_string(log).unwrap();
            for (name, text) in [
                ("stdout", &result.stdout),
                ("stderr", &result.stderr),
                ("crash log", &crash_log),
            ] {
                for value in [&secret, &password, &tenant, &host] {
                    // As written, and as JSON or `{:?}` escapes it.
                    let escaped = value.escape_debug().to_string();
                    assert!(
                        !text.contains(value.as_str()) && !text.contains(escaped.as_str()),
                        "round {round}: {value} in the {name}:\n{text}"
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn framework_repeated_flags_run_as_once_and_the_last_value_wins() {
        let once = dispatched("--json commands", &[], false);
        assert_eq!(once.code, 0);
        for line in [
            "--json commands --json",
            "commands --json --json",
            "--debug --debug --json commands",
            "--quiet --json commands --quiet",
        ] {
            let twice = dispatched(line, &[], false);
            assert_eq!(twice.code, 0, "{line}: {}", twice.stdout);
            assert_eq!(
                normalised(&twice.stdout),
                normalised(&once.stdout),
                "{line}"
            );
        }
        let plain = dispatched("--quiet commands --quiet", &[], false);
        assert_eq!(plain.code, 0);
        assert!(plain.stdout.contains("commands"), "{}", plain.stdout);
        // A flag given twice is parsed: no usage error (a preview runs).
        let strict = dispatched("--json share push --dry-run --dry-run", &[], false);
        assert_ne!(strict.code, USAGE_EXIT_CODE, "{}", strict.stdout);
        assert!(
            !strict.stdout.contains("\"code\":\"usage_"),
            "{}",
            strict.stdout
        );
        // `--repo` twice: the last one is the repository.
        let dir = std::env::temp_dir().display().to_string();
        let last = dispatched(
            &format!("--repo /nowhere-at-all --repo {dir} --json commands"),
            &[],
            false,
        );
        assert_eq!(last.code, 0, "{}", last.stdout);
        let first = dispatched(
            &format!("--repo {dir} --repo /nowhere-at-all --json commands"),
            &[],
            false,
        );
        assert_eq!(first.code, 2);
        assert!(
            first
                .stdout
                .contains("--repo /nowhere-at-all does not exist")
        );
        let root = catalog::root();
        assert_eq!(
            globals_of(
                &root,
                "--repo a --repo=b --proxy p --proxy q x",
                &Env::default()
            ),
            Globals {
                repo: Some("b".into()),
                proxy: Some("q".into()),
                ..Globals::default()
            }
        );
    }

    fn normalised(stdout: &str) -> String {
        regex::Regex::new(r#""duration_ms":\d+"#)
            .unwrap()
            .replace_all(stdout, "")
            .into_owned()
    }

    #[test]
    fn framework_a_separator_before_a_command_name_is_a_usage_error() {
        // `--` ends the options: what follows is no command.
        for line in [
            "--json -- commands",
            "--json validate -- query",
            "--json generate extract -- sentinel",
        ] {
            let run = dispatched(line, &[], false);
            assert_eq!(run.code, USAGE_EXIT_CODE, "{line}: {}", run.stdout);
            assert!(run.stdout.contains("\"code\":\"usage_"), "{}", run.stdout);
        }
        let plain = dispatched("-- commands", &[], false);
        assert_eq!(plain.code, USAGE_EXIT_CODE);
        // `validate -- --json`: after `--`, `--json` is a word where
        // validate expects its command.
        let option = dispatched("--json validate -- --json", &[], false);
        assert_eq!(option.code, 2);
        assert!(
            option.stdout.contains("\"command\":\"validate\""),
            "{}",
            option.stdout
        );
        assert!(option.stdout.contains("\"code\":\"usage_unknown_command\""));
        assert!(option.stdout.contains(r#""argument":"--json""#));
    }

    #[test]
    fn framework_a_share_option_its_subcommand_ignores_is_refused_by_its_flag() {
        for flag in ["--publish", "--no-publish"] {
            let refused = dispatched(&format!("--json share {flag} targets"), &[], false);
            assert_eq!(refused.code, USAGE_EXIT_CODE, "{}", refused.stdout);
            assert!(
                refused.stdout.contains("\"code\":\"usage_invalid_value\""),
                "{}",
                refused.stdout
            );
            let message = format!(
                "\"message\":\"{flag} configures `opentide share` itself and would be ignored \
                 by `opentide share targets`.\""
            );
            assert!(refused.stdout.contains(&message), "{}", refused.stdout);
        }
        // The text modes print it in clap's layout, with the command's usage.
        let plain = dispatched(
            "share --publish status",
            &[("OPENTIDE_OUTPUT", "plain")],
            false,
        );
        assert!(
            plain.stderr.starts_with("error: --publish configures")
                && plain
                    .stderr
                    .contains("\nUsage: opentide share status [OPTIONS]")
                && plain.stderr.contains("For more information, try '--help'."),
            "{}",
            plain.stderr
        );
    }

    #[test]
    fn framework_a_bare_help_group_prints_its_help_to_a_person() {
        for (line, pairs, tty) in [
            ("mcp", &[][..], false),
            ("lsp", &[("OPENTIDE_OUTPUT", "human")][..], true),
        ] {
            let bare = dispatched(line, pairs, tty);
            assert_eq!(bare.code, 2, "{line}");
            assert_eq!(bare.stderr, "", "{line}");
            assert!(
                bare.stdout.contains(&format!("opentide {line}")),
                "{line}: {}",
                bare.stdout
            );
            assert!(bare.stdout.contains("start"), "{line}");
        }
        let new = dispatched("--json new", &[], false);
        assert!(
            new.stdout
                .contains("\"error\":\"missing command: choose from threat, objective, rule\"")
        );
        let agent = dispatched("mcp", &[("AI_AGENT", "a")], false);
        assert!(agent.stdout.is_empty());
        assert!(
            agent
                .stderr
                .starts_with("error: missing command: choose from start\n")
        );
    }

    fn write_platform(workspace: &std::path::Path, tenant: &str) {
        let platforms = workspace.join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&platforms).unwrap();
        std::fs::write(
            platforms.join("splunk.toml"),
            format!("[[tenants]]\nname = \"{tenant}\"\nurl = \"https://splunk.example:8089\"\n"),
        )
        .unwrap();
    }

    #[test]
    fn framework_redaction_is_wired_to_every_source() {
        // The --proxy password, from the command line only.
        let proxy = ran(
            "--proxy http://user:pr0xy-pass@proxy.local:3128 x",
            &[],
            false,
            |_, _, _| {
                tracing::warn!(detail = "auth pr0xy-pass failed", "proxy_failed");
                Ok(0)
            },
        );
        assert!(
            proxy.stderr.contains("warning: Proxy failed"),
            "{}",
            proxy.stderr
        );
        assert!(!proxy.stderr.contains("pr0xy-pass"), "{}", proxy.stderr);
        // The tenants of OPENTIDE_REPO_ROOT's workspace.
        let workspace =
            std::env::temp_dir().join(format!("opentide-cli-repo-root-{}", std::process::id()));
        write_platform(&workspace, "tenant-acme-prod");
        let repo_root = workspace.display().to_string();
        let tenant = ran(
            "x",
            &[("OPENTIDE_REPO_ROOT", repo_root.as_str())],
            false,
            |_, _, _| {
                tracing::warn!(tenant = "tenant-acme-prod", "deploy_failed");
                Ok(0)
            },
        );
        assert!(tenant.stderr.contains("tenant: ***"), "{}", tenant.stderr);
        assert!(!tenant.stderr.contains("acme"), "{}", tenant.stderr);
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn framework_log_json_is_wired_and_redacted_before_escaping() {
        let secret = "s3cr\"et\\v4lué日";
        let pairs = [("OPENTIDE_LOG_JSON", "1"), ("API_TOKEN", secret)];
        let result = ran("x", &pairs, false, |_, _, _| {
            tracing::warn!(detail = secret, "request_failed");
            tracing::warn!(detail = ?secret, "debug_field");
            tracing::warn!("{}", secret);
            Ok(0)
        });
        let lines: Vec<&str> = result.stderr.lines().collect();
        assert_eq!(lines.len(), 3, "{}", result.stderr);
        for line in &lines {
            let document = crate::json::Json::parse(line).unwrap();
            assert!(document.get("event").is_some(), "{line}");
            assert!(!line.contains("s3cr"), "{line}");
            assert!(line.contains("***"), "{line}");
        }
        // Without OPENTIDE_LOG_JSON, the readable line, redacted the same.
        let text = ran("x", &[("API_TOKEN", secret)], false, |_, _, _| {
            tracing::warn!(detail = ?secret, "debug_field");
            Ok(0)
        });
        assert_eq!(text.stderr, "warning: Debug field · detail: \"***\"\n");
    }

    #[test]
    fn framework_a_failing_tenant_request_leaves_no_credential_in_logs_or_crash_logs() {
        // A tenant request that fails (refused), with credentials in the
        // URL's user info and query: the connector's error, logged at every
        // level and ending the run, reaches neither the output, the log nor
        // the crash log. The values are in no variable, so the run's own
        // redaction cannot be what hides them.
        let state = std::env::temp_dir().join(format!(
            "opentide-cli-tenant-failure-{}",
            std::process::id()
        ));
        let state_text = state.display().to_string();
        let pairs = [
            ("XDG_STATE_HOME", state_text.as_str()),
            ("HOME", state_text.as_str()),
            ("USERPROFILE", state_text.as_str()),
            ("LOCALAPPDATA", state_text.as_str()),
        ];
        let (secret, password) = ("q7Zk-tenant-credential-41", "pw-x9Lm3-proxy");
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let url = format!("http://user:{password}@127.0.0.1:{port}/api?token={secret}");
        for line in ["--debug --json x", "--debug x"] {
            let result = ran(line, &pairs, false, |_, _, _| {
                let label = opentide_connectors::TenantLabel::new("splunk", "prod");
                let client = opentide_connectors::HttpClient::new(
                    &label,
                    &opentide_connectors::HttpSettings::default(),
                    &opentide_connectors::Environment::default(),
                    None,
                )?;
                let error = opentide_connectors::runtime::block_on(async {
                    let request = client
                        .request(opentide_connectors::transport::Method::GET, &url)
                        .build()?;
                    let cancel = tokio_util::sync::CancellationToken::new();
                    Ok::<_, opentide_connectors::transport::BuildError>(
                        client.send(request, &cancel).await,
                    )
                })??
                .unwrap_err();
                tracing::error!(detail = %error, "tenant_request_failed");
                tracing::debug!(error = ?error, "tenant_request_debug");
                Err(error.into())
            });
            let mut texts = vec![
                ("stdout", result.stdout.clone()),
                ("stderr", result.stderr.clone()),
            ];
            if let Some(crate::json::Json::Str(log)) = crate::json::Json::parse(&result.stdout)
                .ok()
                .and_then(|document| document.get("failure").cloned())
                .and_then(|failure| failure.get("crash_log").cloned())
            {
                texts.push(("crash log", std::fs::read_to_string(log).unwrap()));
            }
            let all: String = texts.iter().map(|(_, text)| text.as_str()).collect();
            // The failure was reported, by its origin.
            assert!(
                all.contains(&format!("http://127.0.0.1:{port}")),
                "{line}: {all}"
            );
            for (name, text) in &texts {
                for value in [secret, password] {
                    assert!(
                        !text.contains(value),
                        "{line}: {value} in the {name}:\n{text}"
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn framework_crash_log_masks_short_secret_named_variables() {
        let state =
            std::env::temp_dir().join(format!("opentide-cli-short-secret-{}", std::process::id()));
        let state_text = state.display().to_string();
        let pairs = [
            ("XDG_STATE_HOME", state_text.as_str()),
            ("HOME", state_text.as_str()),
            ("USERPROFILE", state_text.as_str()),
            ("LOCALAPPDATA", state_text.as_str()),
            // Too short to be redacted as text, but its name says secret.
            ("OPENTIDE_API_TOKEN", "abc"),
            ("OPENTIDE_LINKS", "none"),
        ];
        let crashed = ran("--json x", &pairs, false, |_, _, _| Err("boom".into()));
        let document = crate::json::Json::parse(&crashed.stdout).unwrap();
        let crate::json::Json::Str(log) = document
            .get("failure")
            .and_then(|failure| failure.get("crash_log"))
            .unwrap()
        else {
            panic!("no crash log")
        };
        let text = std::fs::read_to_string(log).unwrap();
        assert!(text.contains("  OPENTIDE_API_TOKEN=***\n"), "{text}");
        assert!(text.contains("  OPENTIDE_LINKS=none\n"), "{text}");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn framework_mcp_mode_never_writes_stdout_and_error_comes_first() {
        let success = ran("mcp start", &[], false, |run, out, err| {
            let outcome = Outcome {
                command: "mcp start".into(),
                status: "completed".into(),
                message: "done".into(),
                data: Vec::new(),
                exit_code: 0,
                summary: Vec::new(),
                next_actions: Vec::new(),
                failure: None,
            };
            Ok(run.emit(&outcome, &["a line".into()], out, err)?)
        });
        assert_eq!((success.code, success.stdout.as_str()), (0, ""));
        let failed = unhandled_run("--json query --platform x q");
        assert!(
            failed.stdout.starts_with("{\"error\":"),
            "{}",
            failed.stdout
        );
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
    fn framework_small_behaviours() {
        // TERM=DUMB in any case: no SGR, even in human mode on a terminal.
        let dumb = dispatched(
            "deploy",
            &[("OPENTIDE_OUTPUT", "human"), ("TERM", "DUMB")],
            true,
        );
        assert!(!dumb.stderr.contains('\u{1b}'), "{}", dumb.stderr);
        let coloured = dispatched(
            "deploy",
            &[("OPENTIDE_OUTPUT", "human"), ("TERM", "xterm")],
            true,
        );
        assert!(coloured.stderr.contains('\u{1b}'), "{}", coloured.stderr);
        // FORCE_COLOR and CLICOLOR_FORCE colour a pipe, under CI and under
        // TERM=dumb; NO_COLOR and FORCE_COLOR=0 win or switch it off; a
        // machine mode never takes colour.
        let sgr = |pairs: &[(&str, &str)], tty: bool| {
            let ran = dispatched("deploy", pairs, tty);
            assert_ne!(ran.stderr, "", "{pairs:?}");
            ran.stderr.contains('\u{1b}')
        };
        assert!(!sgr(&[], false));
        assert!(sgr(&[("FORCE_COLOR", "1")], false));
        assert!(sgr(&[("CLICOLOR_FORCE", "1")], false));
        assert!(sgr(&[("FORCE_COLOR", "1"), ("CI", "true")], false));
        assert!(sgr(&[("FORCE_COLOR", "1"), ("TERM", "dumb")], true));
        assert!(!sgr(&[("FORCE_COLOR", "0")], false));
        assert!(!sgr(&[("CLICOLOR_FORCE", "0")], false));
        assert!(!sgr(&[("FORCE_COLOR", "1"), ("NO_COLOR", "1")], false));
        assert!(!sgr(
            &[("FORCE_COLOR", "0"), ("CLICOLOR_FORCE", "1")],
            false
        ));
        assert!(!sgr(
            &[("FORCE_COLOR", "1"), ("OPENTIDE_OUTPUT", "agent")],
            false
        ));
        // Blank and unusual values; machine modes (--json, a detected coding
        // agent) and usage errors never take forced colour.
        assert!(!sgr(&[("FORCE_COLOR", "1"), ("NO_COLOR", " ")], false));
        assert!(!sgr(&[("FORCE_COLOR", "no")], false));
        assert!(!sgr(&[("FORCE_COLOR", "off")], false));
        assert!(!sgr(&[("FORCE_COLOR", " ")], false));
        assert!(sgr(&[("FORCE_COLOR", "1"), ("CLICOLOR_FORCE", "0")], false));
        assert!(!sgr(&[("FORCE_COLOR", "1"), ("CLAUDECODE", "1")], false));
        let json = dispatched("--json deploy", &[("FORCE_COLOR", "1")], false);
        assert!(
            !json.stdout.contains('\u{1b}') && !json.stderr.contains('\u{1b}'),
            "{}{}",
            json.stdout,
            json.stderr
        );
        let usage = dispatched("--json nonesuch", &[("FORCE_COLOR", "1")], false);
        assert_eq!(usage.code, 2);
        assert!(!usage.stdout.contains('\u{1b}'), "{}", usage.stdout);
        // OPENTIDE_OUTPUT=human is explicit: it keeps colour at a terminal
        // even with --no-color (documented in global-options.md).
        let human = dispatched("deploy --no-color", &[("OPENTIDE_OUTPUT", "human")], true);
        assert!(human.stderr.contains('\u{1b}'), "{}", human.stderr);
        let human = dispatched(
            "deploy",
            &[("OPENTIDE_OUTPUT", "human"), ("NO_COLOR", "1")],
            true,
        );
        assert!(human.stderr.contains('\u{1b}'), "{}", human.stderr);
        // An explicit --no-color wins over FORCE_COLOR and CLICOLOR_FORCE, as
        // NO_COLOR does, on a pipe and at a terminal.
        let flagged = |pairs: &[(&str, &str)], tty: bool| {
            let ran = dispatched("deploy --no-color", pairs, tty);
            assert_ne!(ran.stderr, "", "{pairs:?}");
            ran.stderr.contains('\u{1b}')
        };
        assert!(!flagged(&[("FORCE_COLOR", "1")], false));
        assert!(!flagged(&[("CLICOLOR_FORCE", "1")], false));
        assert!(!flagged(&[("FORCE_COLOR", "1"), ("TERM", "dumb")], true));
        // --help is coloured where colour is forced, and only there.
        let helped = |line: &str, pairs: &[(&str, &str)]| {
            let ran = dispatched(line, pairs, false);
            assert_eq!(ran.code, 0, "{line} {pairs:?}");
            ran.stdout.contains('\u{1b}')
        };
        assert!(!helped("--help", &[]));
        assert!(helped("--help", &[("FORCE_COLOR", "1")]));
        assert!(helped("validate --help", &[("CLICOLOR_FORCE", "1")]));
        assert!(!helped("--help", &[("FORCE_COLOR", "0")]));
        assert!(!helped(
            "--help",
            &[("FORCE_COLOR", "1"), ("NO_COLOR", "1")]
        ));
        assert!(!helped("--no-color --help", &[("FORCE_COLOR", "1")]));
        assert!(!helped(
            "--help",
            &[("FORCE_COLOR", "1"), ("OPENTIDE_OUTPUT", "agent")]
        ));
        // A bare argv in machine mode is the usage error, not help.
        let bare = dispatched("--json", &[], false);
        assert_eq!(bare.code, 2);
        assert!(
            bare.stdout
                .contains("requires a subcommand but one was not provided"),
            "{}",
            bare.stdout
        );
        // `-h` is no option, as in the Python CLI (#841): `--help` is the
        // one help option.
        let short = dispatched("--json -h", &[], false);
        assert_eq!(short.code, 2, "{}", short.stdout);
        assert!(
            short.stdout.contains("\"code\":\"usage_unknown_option\""),
            "{}",
            short.stdout
        );
        // A flag given a value: clap's usage error.
        let valued = dispatched("--json=1 explain x", &[], false);
        assert_eq!(valued.code, 2);
        assert!(
            valued
                .stderr
                .starts_with("error: unexpected value '1' for '--json' found"),
            "{}",
            valued.stderr
        );
        let missing = dispatched("--json info --platform", &[], false);
        assert!(
            missing
                .stdout
                .contains("\"command\":\"info\",\"duration_ms\""),
            "{}",
            missing.stdout
        );
    }

    /// `--show-completion` and `--install-completion` (#841, D2): clap's
    /// script for the shell named after the option, or the shell the run is
    /// in; a word that is no shell is a usage error naming the form.
    #[test]
    fn completion_scripts_are_shown_and_installed() {
        let shown = dispatched("--show-completion zsh", &[], false);
        assert_eq!(shown.code, 0, "{}", shown.stderr);
        assert!(
            shown.stdout.starts_with("#compdef opentide"),
            "{}",
            shown.stdout
        );
        let detected = dispatched("--show-completion", &[("SHELL", "/usr/bin/fish")], false);
        assert_eq!(detected.code, 0, "{}", detected.stderr);
        let bad = dispatched("--json --show-completion bash zsh", &[], false);
        assert_eq!(bad.code, 2);
        assert!(
            bad.stdout.contains(
                "--show-completion: \\\"bash zsh\\\" is not a supported shell. \
                 Use: opentide --show-completion [bash|zsh|fish|powershell|pwsh]"
            ),
            "{}",
            bad.stdout
        );
        assert!(bad.stdout.contains("\"code\":\"usage_invalid_value\""));
        // At a terminal: clap's layout, the root's usage and the help hint.
        let plain = dispatched(
            "--show-completion bash zsh",
            &[("OPENTIDE_OUTPUT", "plain")],
            false,
        );
        assert_eq!(plain.code, 2);
        assert!(
            plain
                .stderr
                .starts_with("error: --show-completion: \"bash zsh\"")
                && plain
                    .stderr
                    .contains("\nUsage: opentide [OPTIONS] <COMMAND>")
                && plain.stderr.contains("For more information, try '--help'."),
            "{}",
            plain.stderr
        );
        let home = tempfile::tempdir().unwrap();
        let home_text = home.path().display().to_string();
        // The home folder is USERPROFILE on Windows, as Python's Path.home().
        let home_variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let installed = dispatched(
            "--json --install-completion bash",
            &[(home_variable, home_text.as_str())],
            false,
        );
        assert_eq!(installed.code, 0, "{}", installed.stdout);
        assert!(
            installed
                .stdout
                .starts_with("{\"shell\":\"bash\",\"path\":"),
            "{}",
            installed.stdout
        );
        assert!(
            installed.stdout.contains(
                "{\"command\":\"source ~/.bashrc\",\"reason\":\"or restart your shell\"}"
            ),
            "{}",
            installed.stdout
        );
        // The script asks opentide for each Tab press's candidates.
        let installed_script =
            std::fs::read_to_string(home.path().join(".bash_completions/opentide.sh")).unwrap();
        assert!(
            installed_script.contains("_OPENTIDE_COMPLETE=\"bash\""),
            "{installed_script}"
        );
        let homeless = dispatched("--install-completion fish", &[(home_variable, "")], false);
        assert_eq!(homeless.code, 1, "{}", homeless.stderr);
        assert!(
            homeless
                .stderr
                .contains("Could not install fish completion"),
            "{}",
            homeless.stderr
        );
    }

    /// A bare `opentide` at a terminal is the home screen (D3); with no
    /// terminal, the help.
    #[test]
    fn a_bare_run_at_a_terminal_is_the_home_screen() {
        let home = dispatched("", &[("OPENTIDE_OUTPUT", "human")], true);
        assert_eq!(home.code, 0);
        assert!(home.stdout.contains("Suggested next"), "{}", home.stdout);
        let help = dispatched("", &[], false);
        assert_eq!(help.code, 0);
        assert!(help.stdout.contains("Usage: opentide"), "{}", help.stdout);
    }

    /// `--verbose` is a global flag, accepted after the command like
    /// `--quiet`; with `--quiet` it is a usage error (opentide 0.28.1).
    #[test]
    fn verbose_is_a_root_flag_that_quiet_refuses() {
        let root = catalog::root();
        assert!(globals_of(&root, "--verbose lint", &Env::default()).verbose);
        assert!(!globals_of(&root, "lint", &Env::default()).verbose);
        assert!(globals_of(&root, "lint --verbose", &Env::default()).verbose);
        for line in [
            "--quiet --verbose --json commands",
            "--json commands --verbose --quiet",
        ] {
            let both = dispatched(line, &[], false);
            assert_eq!(both.code, USAGE_EXIT_CODE, "{line}: {}", both.stdout);
            assert!(
                both.stdout
                    .contains("--quiet and --verbose cannot be used together"),
                "{}",
                both.stdout
            );
            assert!(
                both.stdout.contains("\"code\":\"usage_error\""),
                "{}",
                both.stdout
            );
            assert!(
                both.stdout.contains("\"argument\":\"--verbose\""),
                "{}",
                both.stdout
            );
        }
        let verbose = dispatched("--verbose --json commands", &[], false);
        assert_eq!(verbose.code, 0, "{}", verbose.stdout);
    }

    fn globals_of(root: &clap::Command, text: &str, env: &Env) -> Globals {
        let args: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
        globals(&args, &lenient_matches(root, &args), env)
    }

    /// `generate <phase>...`: the words after `generate` that are no
    /// subcommand are its phases. An unknown phase is a usage error; with no
    /// phase it is the full pipeline; the subcommands still run as
    /// subcommands.
    #[test]
    fn generate_takes_its_phases_as_words() {
        let unknown = dispatched("--json generate schemas explrer", &[], false);
        assert_eq!(unknown.code, 2, "{}", unknown.stdout);
        assert!(
            unknown.stdout.contains(
                "Unknown generation phase explrer. Pass one or more of: schemas, snippets, templates, vocabs."
            ),
            "{}",
            unknown.stdout
        );
        assert!(unknown.stdout.contains("\"code\":\"usage_invalid_choice\""));
        assert!(unknown.stdout.contains("\"argument\":\"phase\""));
        // The full pipeline runs here (UC-6.0): its six phases, in a folder
        // of its own.
        let folder = tempfile::tempdir().unwrap();
        let line = format!("--json --repo {} generate", folder.path().display());
        let pipeline = dispatched(&line, &[], false);
        assert_eq!(pipeline.code, 0, "{}", pipeline.stdout);
        assert!(
            pipeline.stdout.starts_with(
                "{\"phases\":[\"docs\",\"exports\",\"vocabs\",\"templates\",\"schemas\",\"snippets\"],"
            ),
            "{}",
            pipeline.stdout
        );
        assert!(
            pipeline.stdout.contains("· 6 phases"),
            "{}",
            pipeline.stdout
        );
        // The phases end at the first `-` word: what follows is
        // `generate`'s own options (`GeneratePhaseGroup`).
        for (argv, option) in [
            ("--json generate schemas --bogus", "--bogus"),
            ("--json generate schemas templates --repo .", "--repo"),
        ] {
            let flag = dispatched(argv, &[], false);
            assert_eq!(flag.code, 2, "{}", flag.stdout);
            assert!(
                flag.stdout.contains("\"code\":\"usage_unknown_option\""),
                "{}",
                flag.stdout
            );
            assert!(flag.stdout.contains(option), "{}", flag.stdout);
            assert!(!flag.stdout.contains("generation phase"), "{}", flag.stdout);
        }
        let help = dispatched("generate schemas --help", &[], false);
        assert_eq!(help.code, 0, "{}", help.stdout);
        assert!(
            help.stdout.contains("Usage: opentide generate"),
            "{}",
            help.stdout
        );
        let subcommand = dispatched("--json generate inflight prune --bogus", &[], false);
        assert!(
            subcommand.stdout.contains("usage_unknown_option"),
            "{}",
            subcommand.stdout
        );
    }
}
