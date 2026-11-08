//! `cargo xtask bench`: the plan section 11 benchmarks (UC-0.8, #806).
//!
//! ```text
//! cargo xtask bench [--engine python|rust] [--scale 1|10] [--json] [--out FILE]
//!                   [--runs N] [--warmup N] [--only ID,...] [--workspace DIR]
//!                   [--opentide PATH] [--lsp PATH]
//! cargo xtask bench --check BUDGETS BENCH.json [--previous LAST.json] [--summary FILE]
//! ```
//!
//! The run builds the heavy workspace (seed 20261107), runs every command of
//! [`SCENARIOS`] as fresh processes (a warm-up, then `--runs` measured runs,
//! each in a fresh copy of the workspace) and reports each one's median wall
//! time and median peak RSS (`wait4(2)`) as JSON ([`report::Report`]).
//! `--check` holds such a report to `tests/bench/budgets.toml` and the last
//! `development` result ([`check`]).
//!
//! The modules split computing from running: [`report`] and [`check`] are
//! pure and tested without a process; [`measure`], [`lsp`], [`oracle`] and
//! [`workspace`] spawn processes and touch files.

pub mod check;
pub mod lsp;
pub mod measure;
pub mod oracle;
pub mod report;
pub mod workspace;

use anyhow::{Context, Result, bail};
use report::{CommandResult, Host, Report, SCHEMA_VERSION, Sample};
use serde_json::Value;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

/// The usage of `cargo xtask bench`.
pub const USAGE: &str = "\
usage: cargo xtask bench [--engine python|rust] [--scale 1|10] [--json] [--out FILE]
                         [--runs N] [--warmup N] [--only ID,...] [--workspace DIR]
                         [--opentide PATH] [--lsp PATH]
       cargo xtask bench --check BUDGETS BENCH.json [--previous LAST.json] [--summary FILE]

Runs the plan section 11 benchmarks on the heavy workspace (seed 20261107):
each command as fresh processes, one warm-up and then --runs (5) measured runs,
each in a fresh copy of the workspace; reports the median wall time and the
median peak RSS (wait4) per command. --json prints the report as JSON on
stdout (progress goes to stderr); --out writes it to FILE as well.

  --engine python   the oracle: opentide 0.23.0 from its PyPI wheel
                    (tests/bench/oracle-requirements.txt, hashes verified),
                    installed with uv under the target directory (default)
  --engine rust     the Rust implementations: today only the language
                    server (built --release); every other command reports
                    \"no Rust yet\"
  --scale 1|10      the heavy workspace's size (default 1)
  --only ID,...     run only these commands (ids as in the report)
  --workspace DIR   benchmark this workspace instead of generating one
  --opentide PATH   run this opentide instead of installing the oracle
  --lsp PATH        run this language server for --engine rust

--check holds BENCH.json to BUDGETS (tests/bench/budgets.toml) and, with
--previous, to the last development result: a median or peak RSS more than
10% over its reference fails. It prints a Markdown table per command
(median, RSS, budget, deltas), and appends it to FILE with --summary.

exit status: 0 done or passed, 1 a budget or regression check failed,
2 usage error or the benchmark could not run
";

/// Which implementation runs the commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    /// The oracle: the Python CLI at the frozen tag.
    Python,
    /// The Rust implementations of this workspace.
    Rust,
}

impl Engine {
    fn name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Rust => "rust",
        }
    }
}

/// Which workspace a command runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// The heavy workspace as generated.
    Clean,
    /// The heavy workspace with every platform disabled.
    Warnings,
    /// An empty directory: the command reads no workspace.
    Empty,
}

/// How a command is driven.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `opentide --json <args>`: one process, timed from spawn to exit.
    Cli,
    /// The language server, timed from spawn to the first diagnostics.
    Lsp,
}

/// One benchmarked command.
#[derive(Clone, Copy, Debug)]
pub struct Scenario {
    /// The id budgets and earlier results are matched on.
    pub id: &'static str,
    /// The arguments after `opentide --json`; `{rule}` is the rule file.
    pub args: &'static [&'static str],
    /// The workspace it runs in.
    pub input: Input,
    /// How it is driven.
    pub kind: Kind,
    /// The exit codes a correct run ends with.
    pub exit_codes: &'static [i32],
    /// What its JSON must hold for the run to count; `None` when it holds
    /// what it should.
    pub expect: fn(&Value, &workspace::Workspaces) -> Option<String>,
}

fn json_ok(json: &Value, _: &workspace::Workspaces) -> Option<String> {
    (json["ok"] != Value::Bool(true)).then(|| format!("ok is {}, not true", json["ok"]))
}

fn validate_clean(json: &Value, ws: &workspace::Workspaces) -> Option<String> {
    if json.pointer("/report/ok") != Some(&Value::Bool(true)) {
        return Some("report.ok is not true: the heavy workspace must validate clean".into());
    }
    let checked = json
        .pointer("/report/stats/objects_checked")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let rules = u64::try_from(ws.rules).unwrap_or(u64::MAX);
    (checked < rules)
        .then(|| format!("report.stats.objects_checked is {checked}, fewer than the {rules} rules"))
}

fn validate_warnings(json: &Value, ws: &workspace::Workspaces) -> Option<String> {
    let warnings = json
        .pointer("/report/warnings")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    match ws.expected_warnings {
        Some(expected) => (warnings != expected).then(|| {
            format!("{warnings} warnings, not the {expected} the generated platform blocks give")
        }),
        None => (warnings < ws.rules)
            .then(|| format!("{warnings} warnings, fewer than the {} rules", ws.rules)),
    }
}

fn deploy_dry_run(json: &Value, ws: &workspace::Workspaces) -> Option<String> {
    if json["dry_run"] != Value::Bool(true) {
        return Some("dry_run is not true".into());
    }
    json_ok(json, ws)
}

fn explain(json: &Value, _: &workspace::Workspaces) -> Option<String> {
    (json["code"] != "vocab_unknown").then(|| format!("code is {}", json["code"]))
}

fn lsp(_: &Value, _: &workspace::Workspaces) -> Option<String> {
    None
}

/// The commands of issue #806, in the order they run.
pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        id: "validate_clean",
        args: &["validate"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: validate_clean,
    },
    Scenario {
        id: "validate_warnings",
        args: &["validate"],
        input: Input::Warnings,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: validate_warnings,
    },
    Scenario {
        id: "validate_file",
        args: &["validate", "--file", "{rule}"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: json_ok,
    },
    Scenario {
        id: "lint",
        args: &["lint"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: json_ok,
    },
    Scenario {
        id: "lint_file",
        args: &["lint", "--file", "{rule}"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: json_ok,
    },
    Scenario {
        id: "info",
        args: &["info"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: json_ok,
    },
    Scenario {
        id: "info_catalog",
        args: &["info", "catalog"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: json_ok,
    },
    Scenario {
        id: "deploy_dry_run",
        args: &["deploy", "--dry-run", "--all", "--strategy", "PREVIEW"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: deploy_dry_run,
    },
    Scenario {
        id: "generate_docs",
        args: &["generate", "docs"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: json_ok,
    },
    Scenario {
        id: "generate_exports_navigator",
        args: &["generate", "exports", "navigator"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: json_ok,
    },
    Scenario {
        id: "rules_unreviewed",
        args: &["rules", "unreviewed"],
        input: Input::Clean,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: json_ok,
    },
    Scenario {
        id: "explain",
        args: &["explain", "vocab_unknown"],
        input: Input::Empty,
        kind: Kind::Cli,
        exit_codes: &[0],
        expect: explain,
    },
    Scenario {
        id: "lsp_first_diagnostics",
        args: &["lsp", "start"],
        input: Input::Clean,
        kind: Kind::Lsp,
        exit_codes: &[0],
        expect: lsp,
    },
];

/// The options of a run.
#[derive(Clone, Debug)]
pub struct Options {
    /// The engine.
    pub engine: Engine,
    /// The heavy workspace's scale.
    pub scale: u32,
    /// Print the report as JSON on stdout.
    pub json: bool,
    /// Write the report to this file as well.
    pub out: Option<PathBuf>,
    /// Measured runs per command.
    pub runs: u32,
    /// Unmeasured runs per command before them.
    pub warmup: u32,
    /// Only these command ids.
    pub only: Option<Vec<String>>,
    /// A workspace to benchmark instead of the generated one.
    pub workspace: Option<PathBuf>,
    /// An opentide to run instead of the oracle.
    pub opentide: Option<PathBuf>,
    /// A language server to run for `rust`.
    pub lsp: Option<PathBuf>,
}

/// The arguments of `--check`.
#[derive(Clone, Debug)]
pub struct CheckOptions {
    /// The budgets file.
    pub budgets: PathBuf,
    /// The report to check.
    pub report: PathBuf,
    /// The last `development` result.
    pub previous: Option<PathBuf>,
    /// A file to append the Markdown summary to (`$GITHUB_STEP_SUMMARY`).
    pub summary: Option<PathBuf>,
}

/// What the arguments ask for.
#[derive(Clone, Debug)]
pub enum Mode {
    /// Run the benchmarks.
    Run(Options),
    /// Check a report.
    Check(CheckOptions),
    /// Print the usage.
    Help,
}

/// A path argument made absolute against the working directory: the
/// commands run in a workspace copy, where a relative path means nothing.
fn absolute(text: &str) -> Result<PathBuf> {
    std::path::absolute(text).with_context(|| format!("resolve {text}"))
}

/// Parses the arguments after `bench`.
pub fn parse_args(args: &[String]) -> Result<Mode> {
    let mut options = Options {
        engine: Engine::Python,
        scale: 1,
        json: false,
        out: None,
        runs: 5,
        warmup: 1,
        only: None,
        workspace: None,
        opentide: None,
        lsp: None,
    };
    let mut check: Option<(PathBuf, PathBuf)> = None;
    let mut previous = None;
    let mut summary = None;
    let mut run_only = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--help" | "-h" => return Ok(Mode::Help),
            "--check" => {
                let budgets = PathBuf::from(value()?);
                let report = PathBuf::from(value()?);
                check = Some((budgets, report));
            }
            "--previous" => previous = Some(PathBuf::from(value()?)),
            "--summary" => summary = Some(PathBuf::from(value()?)),
            "--engine" => {
                options.engine = match value()?.as_str() {
                    "python" => Engine::Python,
                    "rust" => Engine::Rust,
                    other => bail!("--engine is python or rust, not `{other}`"),
                };
                run_only = true;
            }
            "--scale" => {
                options.scale = match value()?.as_str() {
                    "1" => 1,
                    "10" => 10,
                    other => bail!("--scale is 1 or 10, not `{other}`"),
                };
                run_only = true;
            }
            "--json" => {
                options.json = true;
                run_only = true;
            }
            "--out" => {
                options.out = Some(absolute(&value()?)?);
                run_only = true;
            }
            "--runs" | "--warmup" => {
                let text = value()?;
                let n: u32 = text
                    .parse()
                    .with_context(|| format!("{arg} takes a count, not `{text}`"))?;
                if arg == "--runs" {
                    if n == 0 {
                        bail!("--runs must be at least 1");
                    }
                    options.runs = n;
                } else {
                    options.warmup = n;
                }
                run_only = true;
            }
            "--only" => {
                let ids: Vec<String> = value()?.split(',').map(str::to_owned).collect();
                for id in &ids {
                    if !SCENARIOS.iter().any(|s| s.id == id) {
                        let known: Vec<&str> = SCENARIOS.iter().map(|s| s.id).collect();
                        bail!(
                            "--only: unknown command `{id}` (known: {})",
                            known.join(", ")
                        );
                    }
                }
                options.only = Some(ids);
                run_only = true;
            }
            "--workspace" => {
                options.workspace = Some(absolute(&value()?)?);
                run_only = true;
            }
            "--opentide" => {
                options.opentide = Some(absolute(&value()?)?);
                run_only = true;
            }
            "--lsp" => {
                options.lsp = Some(absolute(&value()?)?);
                run_only = true;
            }
            other => bail!("unknown option `{other}`"),
        }
    }
    match check {
        Some((budgets, report)) => {
            if run_only {
                bail!("--check takes only --previous and --summary");
            }
            Ok(Mode::Check(CheckOptions {
                budgets,
                report,
                previous,
                summary,
            }))
        }
        None => {
            if previous.is_some() || summary.is_some() {
                bail!("--previous and --summary go with --check");
            }
            Ok(Mode::Run(options))
        }
    }
}

/// `cargo xtask bench`: parses, runs or checks, and prints.
pub fn main(args: &[String]) -> ExitCode {
    let mode = match parse_args(args) {
        Ok(mode) => mode,
        Err(err) => {
            eprint!("xtask bench: {err:#}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match mode {
        Mode::Help => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Mode::Check(options) => match run_check(&options) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(err) => {
                eprintln!("xtask bench --check: {err:#}");
                ExitCode::from(2)
            }
        },
        Mode::Run(options) => match run(&options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("xtask bench: {err:#}");
                ExitCode::from(2)
            }
        },
    }
}

fn run_check(options: &CheckOptions) -> Result<bool> {
    let (outcome, report) = check::check_files(
        &options.budgets,
        &options.report,
        options.previous.as_deref(),
    )?;
    let summary = check::summary_markdown(&outcome, &report);
    print!("{summary}");
    if let Some(path) = &options.summary {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        file.write_all(summary.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
    }
    for failure in &outcome.failures {
        eprintln!("error: {failure}");
    }
    if outcome.passed() {
        eprintln!("bench --check: every command is within its budget");
    } else {
        eprintln!(
            "bench --check: {} failure(s) against {}",
            outcome.failures.len(),
            options.budgets.display()
        );
    }
    Ok(outcome.passed())
}

/// The workspace root and the target directory, from `cargo metadata`, found
/// at run time (as `check-layers` does: never a path compiled in).
fn cargo_paths() -> Result<(PathBuf, PathBuf)> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = std::process::Command::new(&cargo);
    command.args(["metadata", "--format-version", "1", "--no-deps"]);
    if let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
        command.current_dir(dir);
    }
    let output = command.output().context("run cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let metadata: Value = serde_json::from_slice(&output.stdout).context("parse cargo metadata")?;
    let root = metadata["workspace_root"]
        .as_str()
        .context("cargo metadata names no workspace_root")?;
    let target = metadata["target_directory"]
        .as_str()
        .context("cargo metadata names no target_directory")?;
    Ok((PathBuf::from(root), PathBuf::from(target)))
}

/// The engine's program and arguments for a scenario, or why it has none.
enum Program {
    Run(PathBuf, Vec<OsString>),
    Missing(String),
}

fn program(
    scenario: &Scenario,
    engine: Engine,
    opentide: Option<&Path>,
    lsp: Option<&Path>,
    ws: Option<&workspace::Workspaces>,
) -> Program {
    let rule = ws.map(|ws| ws.rule.clone()).unwrap_or_default();
    let args = |prefix: &[&str]| -> Vec<OsString> {
        prefix
            .iter()
            .map(OsString::from)
            .chain(scenario.args.iter().map(|arg| {
                if *arg == "{rule}" {
                    rule.clone().into_os_string()
                } else {
                    OsString::from(arg)
                }
            }))
            .collect()
    };
    match (engine, scenario.kind) {
        (Engine::Python, Kind::Cli) => match opentide {
            Some(opentide) => Program::Run(opentide.to_owned(), args(&["--json"])),
            None => Program::Missing("no opentide".into()),
        },
        (Engine::Python, Kind::Lsp) => match opentide {
            Some(opentide) => Program::Run(
                opentide.to_owned(),
                vec![OsString::from("lsp"), OsString::from("start")],
            ),
            None => Program::Missing("no opentide".into()),
        },
        (Engine::Rust, Kind::Lsp) => match lsp {
            Some(lsp) => Program::Run(lsp.to_owned(), vec![OsString::from("--stdio")]),
            None => Program::Missing("no language server".into()),
        },
        (Engine::Rust, Kind::Cli) => Program::Missing(
            "no Rust yet: the Rust CLI (opentide-cli) is UC-3; the command runs in Python".into(),
        ),
    }
}

/// A command line for a reader.
fn display(program: &Path, args: &[OsString]) -> String {
    let name = program
        .file_name()
        .map_or_else(|| program.to_string_lossy(), |n| n.to_string_lossy());
    let mut text = name.into_owned();
    for arg in args {
        text.push(' ');
        text.push_str(&arg.to_string_lossy());
    }
    text
}

fn run(options: &Options) -> Result<()> {
    let (root, target) = cargo_paths()?;
    let base = target.join("xtask-bench");
    // One work directory per process: two runs at once never share a copy.
    let work = base.join(format!(
        "work-{}-{}-{}",
        options.engine.name(),
        options.scale,
        std::process::id()
    ));
    let outcome = run_in(options, &root, &base, &work);
    if work.exists()
        && let Err(err) = std::fs::remove_dir_all(&work)
    {
        eprintln!("bench: could not remove {}: {err}", work.display());
    }
    outcome
}

fn run_in(options: &Options, root: &Path, base: &Path, work: &Path) -> Result<()> {
    let inject = measure::injected_sleep()?;
    if let Some(sleep) = inject {
        eprintln!(
            "bench: {} is set: every measured run is {} ms slower (test-only)",
            measure::INJECT_SLEEP_ENV,
            sleep.as_millis()
        );
    }

    let selected: Vec<&Scenario> = SCENARIOS
        .iter()
        .filter(|s| {
            options
                .only
                .as_ref()
                .is_none_or(|only| only.iter().any(|id| id == s.id))
        })
        .collect();
    let runnable = |s: &&&Scenario| options.engine == Engine::Python || s.kind == Kind::Lsp;
    let needs_workspace = selected
        .iter()
        .filter(runnable)
        .any(|s| s.input != Input::Empty);

    let (opentide, oracle) = match (options.engine, &options.opentide) {
        (Engine::Python, Some(path)) => (Some(path.clone()), Some(path.display().to_string())),
        (Engine::Python, None) => {
            let (path, version) = oracle::ensure_oracle(root, &base.join("oracle"))?;
            (Some(path), Some(version))
        }
        (Engine::Rust, _) => (None, None),
    };
    let lsp = match (options.engine, &options.lsp) {
        (Engine::Rust, Some(path)) => Some(path.clone()),
        (Engine::Rust, None) if selected.iter().any(|s| s.kind == Kind::Lsp) => {
            Some(oracle::build_lsp(root)?)
        }
        _ => None,
    };

    let workspaces = if needs_workspace {
        let (source, expected_warnings) = match &options.workspace {
            Some(dir) => (dir.clone(), None),
            None => {
                let (dir, blocks) = generate(options.scale, work)?;
                (dir, Some(blocks))
            }
        };
        let with_warnings = selected
            .iter()
            .filter(runnable)
            .any(|s| s.input == Input::Warnings);
        let mut ws = workspace::prepare(&source, work, with_warnings)?;
        // Every platform block of a rule is one `platform_not_enabled`
        // warning once its platform is disabled: exactly as many as the
        // generator wrote; a workspace of one's own must warn once per rule.
        ws.expected_warnings = expected_warnings;
        eprintln!(
            "bench: workspace {} ({} rules{})",
            source.display(),
            ws.rules,
            if with_warnings {
                format!(
                    "; {} platforms disabled for validate_warnings",
                    ws.disabled_platforms
                )
            } else {
                String::new()
            }
        );
        Some(ws)
    } else {
        None
    };

    let mut results = Vec::new();
    for scenario in selected {
        let result = match program(
            scenario,
            options.engine,
            opentide.as_deref(),
            lsp.as_deref(),
            workspaces.as_ref(),
        ) {
            Program::Missing(why) => {
                let command = format!("opentide --json {}", scenario.args.join(" "));
                eprintln!("bench: {}: {why}", scenario.id);
                CommandResult::not_implemented(scenario.id, &command, &why)
            }
            Program::Run(program, args) => measure_scenario(
                scenario,
                &program,
                &args,
                workspaces.as_ref(),
                work,
                options,
                inject,
            )
            .with_context(|| format!("{} ({})", scenario.id, display(&program, &args)))?,
        };
        results.push(result);
    }

    let report = Report {
        schema_version: SCHEMA_VERSION,
        engine: options.engine.name().to_owned(),
        scale: options.scale,
        seed: options.workspace.is_none().then_some(workspace::SEED),
        runs: options.runs,
        warmup: options.warmup,
        oracle,
        host: host(),
        git_sha: git_sha(root),
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        results,
    };
    let json = serde_json::to_string_pretty(&report)? + "\n";
    if let Some(out) = &options.out {
        std::fs::write(out, &json).with_context(|| format!("write {}", out.display()))?;
    }
    if options.json {
        print!("{json}");
    } else {
        print!("{}", table(&report));
    }
    Ok(())
}

/// Generates the heavy workspace under `work` with UC-0.6's generator
/// (`cargo xtask corpus generate --seed 20261107 [--scale 10]`, the same code
/// in process) and returns it with the number of platform blocks its rules
/// hold.
fn generate(scale: u32, work: &Path) -> Result<(PathBuf, usize)> {
    let counts = crate::corpus::generate::Counts::scaled(f64::from(scale))
        .with_context(|| format!("scale {scale}"))?;
    let options = crate::corpus::generate::Options {
        counts,
        ..crate::corpus::generate::Options::new(workspace::SEED)
    };
    let generated = crate::corpus::generate::generate(&options);
    let dir = work.join("generated");
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
    }
    crate::corpus::cli::write_workspace(&generated, &dir)?;
    let blocks = generated
        .family(crate::corpus::workspace::Family::Rule)
        .map(|rule| rule.platforms.len())
        .sum();
    eprintln!(
        "bench: generated the heavy workspace, seed {} ({}, {blocks} platform blocks); digest {}",
        workspace::SEED,
        generated.summary(),
        generated.digest()
    );
    Ok((dir, blocks))
}

fn measure_scenario(
    scenario: &Scenario,
    program: &Path,
    args: &[OsString],
    workspaces: Option<&workspace::Workspaces>,
    work: &Path,
    options: &Options,
    inject: Option<Duration>,
) -> Result<CommandResult> {
    let source = match scenario.input {
        Input::Clean => Some(workspaces.context("no workspace")?.clean.as_path()),
        Input::Warnings => Some(workspaces.context("no workspace")?.warnings.as_path()),
        Input::Empty => None,
    };
    let run_root = work.join("run");
    let mut samples: Vec<Sample> = Vec::new();
    let mut note = None;
    for index in 0..options.warmup + options.runs {
        let measured_run = index >= options.warmup;
        let run_dir = measure::RunDir::prepare(&run_root, source)?;
        let sleep = if measured_run { inject } else { None };
        let sample = match scenario.kind {
            Kind::Cli => {
                let mut command = measure::command(program, args, &run_dir)?;
                let measured = measure::run(&mut command, sleep)?;
                verify_cli(scenario, &run_dir, measured.exit_code, workspaces)?;
                measure::distinct_from_own(measured.sample.peak_rss_bytes, measured.own_peak_rss)?;
                measured.sample
            }
            Kind::Lsp => {
                let ws = workspaces.context("no workspace")?;
                let first = lsp::first_diagnostics(program, args, &run_dir, &ws.rule, sleep)?;
                note = Some(format!(
                    "{}: spawn to the first textDocument/publishDiagnostics for {} \
                     ({} diagnostics) in a workspace of {} rules",
                    display(program, args),
                    ws.rule.display(),
                    first.diagnostics,
                    ws.rules
                ));
                first.sample
            }
        };
        if measured_run {
            samples.push(sample);
        }
    }
    if inject.is_some() {
        note = Some(format!(
            "{}{}was set: the numbers include an injected sleep",
            note.map(|n| n + "; ").unwrap_or_default(),
            measure::INJECT_SLEEP_ENV.to_owned() + " "
        ));
    }
    let command = display(program, args);
    let result = CommandResult::measured(scenario.id, &command, &samples, note);
    #[expect(
        clippy::cast_precision_loss,
        reason = "an RSS in bytes is far below 2^52"
    )]
    let rss_mib = result.peak_rss_bytes.unwrap_or_default() as f64 / (1024.0 * 1024.0);
    eprintln!(
        "bench: {}: median {:.3} s, peak RSS {rss_mib:.1} MiB ({} runs)",
        scenario.id,
        result.median_s.unwrap_or_default(),
        samples.len()
    );
    if run_root.exists() {
        std::fs::remove_dir_all(&run_root)
            .with_context(|| format!("remove {}", run_root.display()))?;
    }
    Ok(result)
}

/// A run counts only when it ended as a correct run ends: the expected exit
/// code, one JSON document on stdout whose `exit_code` agrees (where it has
/// one), and what the scenario expects of it. A benchmark of a command that
/// failed early measures nothing.
fn verify_cli(
    scenario: &Scenario,
    run_dir: &measure::RunDir,
    exit_code: Option<i32>,
    workspaces: Option<&workspace::Workspaces>,
) -> Result<()> {
    let stdout = run_dir.read_stdout()?;
    let stderr = || run_dir.stderr_tail();
    let Some(code) = exit_code else {
        bail!("ended by a signal (stderr: {})", stderr());
    };
    if !scenario.exit_codes.contains(&code) {
        bail!(
            "exited {code}, not {:?} (stdout: {}; stderr: {})",
            scenario.exit_codes,
            stdout.chars().take(600).collect::<String>(),
            stderr()
        );
    }
    let json: Value = serde_json::from_str(&stdout).with_context(|| {
        format!(
            "stdout is not one JSON document: {}",
            stdout.chars().take(300).collect::<String>()
        )
    })?;
    if let Some(reported) = json.get("exit_code")
        && reported.as_i64() != Some(i64::from(code))
    {
        bail!("exited {code} but its JSON says exit_code {reported}");
    }
    let empty = workspace::Workspaces {
        clean: PathBuf::new(),
        warnings: PathBuf::new(),
        rule: PathBuf::new(),
        rules: 0,
        disabled_platforms: 0,
        expected_warnings: None,
    };
    if let Some(problem) = (scenario.expect)(&json, workspaces.unwrap_or(&empty)) {
        bail!("{problem}");
    }
    Ok(())
}

/// A plain table of a report, for a terminal.
pub fn table(report: &Report) -> String {
    let mut out = format!(
        "{} engine, scale {}, median of {} runs (after {} warm-up)\n\n",
        report.engine, report.scale, report.runs, report.warmup
    );
    out.push_str(&format!(
        "{:<28} {:>10} {:>12}\n",
        "command", "median", "peak RSS"
    ));
    for result in &report.results {
        match (result.median_s, result.peak_rss_bytes) {
            (Some(median), Some(rss)) => {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "an RSS in bytes is far below 2^52"
                )]
                let mib = rss as f64 / (1024.0 * 1024.0);
                out.push_str(&format!(
                    "{:<28} {:>8.3} s {:>8.1} MiB\n",
                    result.id, median, mib
                ));
            }
            _ => out.push_str(&format!(
                "{:<28} {}\n",
                result.id,
                result.note.as_deref().unwrap_or("not measured")
            )),
        }
    }
    out
}

fn host() -> Host {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu_model = cpuinfo
        .lines()
        .find_map(|line| line.strip_prefix("model name"))
        .and_then(|rest| rest.split_once(':'))
        .map(|(_, model)| model.trim().to_owned());
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let memory_bytes = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .and_then(|kb| kb.trim().parse::<u64>().ok())
        .map(|kb| kb * 1024);
    let runner_image = match (std::env::var("ImageOS"), std::env::var("ImageVersion")) {
        (Ok(os), Ok(version)) => Some(format!("{os} {version}")),
        _ => None,
    };
    Host {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        cpus: std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
        cpu_model,
        memory_bytes,
        runner_image,
    }
}

fn git_sha(root: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn the_defaults_are_the_python_engine_at_scale_one_with_five_runs() {
        let Mode::Run(options) = parse_args(&[]).unwrap() else {
            panic!("not a run");
        };
        assert_eq!(options.engine, Engine::Python);
        assert_eq!((options.scale, options.runs, options.warmup), (1, 5, 1));
    }

    #[test]
    fn the_verification_command_lines_parse() {
        let Mode::Run(options) = parse_args(&args("--engine python --scale 1 --json")).unwrap()
        else {
            panic!("not a run");
        };
        assert!(options.json);
        let Mode::Check(check) =
            parse_args(&args("--check tests/bench/budgets.toml bench.json")).unwrap()
        else {
            panic!("not a check");
        };
        assert_eq!(check.report, PathBuf::from("bench.json"));
    }

    #[test]
    fn bad_arguments_are_refused() {
        for bad in [
            "--engine go",
            "--scale 2",
            "--runs 0",
            "--only nonesuch",
            "--check budgets.toml",
            "--check a b --engine rust",
            "--previous x",
            "--frobnicate",
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_scenario_id_is_unique_and_named_in_the_budgets() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join("tests/bench/budgets.toml")).unwrap();
        let budgets = check::Budgets::parse(&text).unwrap();
        let mut ids: Vec<&str> = SCENARIOS.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), SCENARIOS.len());
        let budgeted: Vec<&str> = budgets.commands.keys().map(String::as_str).collect();
        assert_eq!(ids, budgeted);
    }

    #[test]
    fn rust_has_only_the_language_server_and_says_no_rust_yet_for_the_rest() {
        for scenario in SCENARIOS {
            let program = program(scenario, Engine::Rust, None, Some(Path::new("lsp")), None);
            match (scenario.kind, program) {
                (Kind::Lsp, Program::Run(_, args)) => assert_eq!(args, ["--stdio"]),
                (Kind::Cli, Program::Missing(why)) => assert!(why.starts_with("no Rust yet")),
                (kind, _) => panic!("{}: {kind:?}", scenario.id),
            }
        }
    }

    #[test]
    fn the_rule_placeholder_becomes_the_rule_file() {
        let ws = workspace::Workspaces {
            clean: PathBuf::new(),
            warnings: PathBuf::new(),
            rule: PathBuf::from("objects/rules/a.yaml"),
            rules: 1,
            disabled_platforms: 1,
            expected_warnings: None,
        };
        let scenario = SCENARIOS.iter().find(|s| s.id == "validate_file").unwrap();
        let Program::Run(_, args) = program(
            scenario,
            Engine::Python,
            Some(Path::new("opentide")),
            None,
            Some(&ws),
        ) else {
            panic!("python runs it");
        };
        assert_eq!(
            args,
            ["--json", "validate", "--file", "objects/rules/a.yaml"]
        );
    }
}
