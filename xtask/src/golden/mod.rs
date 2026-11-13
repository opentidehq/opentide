//! `cargo xtask golden`: records what the frozen Python CLI (the oracle)
//! does, and checks an engine against those recordings (plan §5.1, UC-0.5).
//!
//! The pieces are a library for the comparator (UC-0.7) to reuse:
//!
//! - [`case`]: `cases.toml` and the [`case::Case`] each entry expands to.
//! - [`fixture`]: the fixture workspaces, including generated ones.
//! - [`oracle`]: `ORACLE`, and the oracle installed from PyPI.
//! - [`run`]: one case through an [`run::Engine`], to a normalised recording.
//! - [`normalise`]: what is replaced before recording and comparing.
//! - [`recording`]: the files of a recording, and the differences of two.
//! - [`blob`]: the store of large recorded files, by SHA-256.
//! - [`coverage`]: the coverage report, `COVERAGE.md`.
//!
//! `tests/golden/README.md` holds the review rules.

pub mod blob;
pub mod case;
pub mod coverage;
pub mod fixture;
/// The normaliser, in `opentide-compare` so that the CLI's compare mode shares it.
pub use opentide_compare::normalise;
pub mod oracle;
#[cfg(unix)]
mod pty;
pub mod recording;
pub mod run;
pub mod snapshot;

use anyhow::{Context, Result, bail};
use case::{Case, Spec};
use oracle::Oracle;
use recording::Recording;
use run::RunContext;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// The usage of `cargo xtask golden`.
pub const USAGE: &str = "\
usage: cargo xtask golden <command> [options]

commands:
  record [--check-determinism] [--filter GLOB] [--jobs N] [--oracle FILE --out DIR]
             run every case through the oracle and write tests/golden/cases/
             and COVERAGE.md. --check-determinism runs every case twice and
             fails, writing nothing, unless both runs agree byte for byte
  check [--engine python|rust] [--runner python|node] [--filter GLOB] [--jobs N]
        [--recordings DIR]
             run every case through the engine and compare with the
             recordings; also checks COVERAGE.md and that no recording is
             missing or orphaned
  diff [--engine ...] [--runner ...] [--filter GLOB] [--jobs N] [--recordings DIR]
             check, printing every difference in full
  lock [--oracle FILE]
             rewrite tests/golden/oracle-requirements.txt from ORACLE (uv pip
             compile); with --oracle, the requirements file FILE names, beside it
  coverage   rewrite COVERAGE.md from cases.toml and the recordings

--filter GLOB  only the cases whose id (<command>/<mode>/<fixture>/<variant>), or a
               leading part of it, matches: `explain/*` is every explain case
--engine       python (the oracle, the default); rust: this repository's CLI against
               the recordings, every case, through the comparator and
               tests/golden/APPROVED_DIFFS.toml (UC-6.2: the Rust core is the
               only implementation)
--runner       how --engine rust's candidate is launched: python (the default),
               the PyPI console script of .venv; node, the npm package's `opentide`
               bin (bindings/node/cli.js, after `npm run build` there) under the
               `node` on PATH, which runs the same command line in-process
               (UC-5.3). `--runner node` alone implies --engine rust
--report FILE  with --engine rust: write the JSON report (opentide-compare's RunReport)
--oracle FILE  another oracle file than tests/golden/ORACLE, in its format (a preview
               of the next oracle: tests/golden/ORACLE.next); `record` with it
               needs --out, so that the committed recordings stay the ORACLE's
--out DIR      record into DIR/cases and DIR/blobs instead of tests/golden, and copy
               the oracle file (as DIR/ORACLE) and its requirements there; a case
               that fails is reported and the others are still written; no
               COVERAGE.md. DIR must be outside tests/golden
--recordings DIR
               check against the recordings of `record --out DIR`, with the
               oracle of DIR/ORACLE; no COVERAGE.md check, and with --engine rust
               no stale-ledger check (the ledger is the committed oracle's)

exit status: 0 passed, 1 a difference or a failed case, 2 usage error or the run could not start
";

/// `cargo xtask golden <args>`.
pub fn main(args: &[String]) -> ExitCode {
    match parse(args).and_then(|command| command.run()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("xtask golden: {error:#}");
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Verb {
    Record,
    Check,
    Diff,
    Lock,
    Coverage,
    Help,
}

/// How the candidate of `--engine rust` is launched (`--runner`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Runner {
    /// The PyPI console script of `.venv`.
    Python,
    /// The npm package's `opentide` bin (`bindings/node`), under Node.
    Node,
}

#[derive(Debug, PartialEq, Eq)]
struct Command {
    verb: Verb,
    engine: String,
    runner: Runner,
    filter: Option<String>,
    determinism: bool,
    jobs: Option<usize>,
    report: Option<PathBuf>,
    /// `--oracle FILE`: another oracle file than `tests/golden/ORACLE`.
    oracle: Option<PathBuf>,
    /// `--out DIR` (`record`): the recordings' root instead of `tests/golden`.
    out: Option<PathBuf>,
    /// `--recordings DIR` (`check`, `diff`): the recordings of `record --out DIR`.
    recordings: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<Command> {
    let Some((verb, rest)) = args.split_first() else {
        bail!("missing command\n\n{USAGE}");
    };
    let verb = match verb.as_str() {
        "record" => Verb::Record,
        "check" => Verb::Check,
        "diff" => Verb::Diff,
        "lock" => Verb::Lock,
        "coverage" => Verb::Coverage,
        "help" | "--help" | "-h" => Verb::Help,
        other => bail!("unknown command `{other}`\n\n{USAGE}"),
    };
    let mut command = Command {
        verb,
        engine: "python".into(),
        runner: Runner::Python,
        filter: None,
        determinism: false,
        jobs: None,
        report: None,
        oracle: None,
        out: None,
        recordings: None,
    };
    let mut engine_given = false;
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--filter" => command.filter = Some(value()?),
            "--engine" => {
                command.engine = value()?;
                engine_given = true;
            }
            "--runner" => {
                command.runner = match value()?.as_str() {
                    "python" => Runner::Python,
                    "node" => Runner::Node,
                    other => bail!("unknown runner `{other}`: python or node"),
                };
            }
            "--report" if command.verb != Verb::Record => {
                command.report = Some(PathBuf::from(value()?));
            }
            "--jobs" => {
                let jobs: usize = value()?.parse().context("--jobs needs a number")?;
                command.jobs = Some(jobs.max(1));
            }
            "--check-determinism" if command.verb == Verb::Record => command.determinism = true,
            "--oracle" if matches!(command.verb, Verb::Record | Verb::Lock) => {
                command.oracle = Some(PathBuf::from(value()?));
            }
            "--out" if command.verb == Verb::Record => command.out = Some(PathBuf::from(value()?)),
            "--recordings" if matches!(command.verb, Verb::Check | Verb::Diff) => {
                command.recordings = Some(PathBuf::from(value()?));
            }
            other => bail!("unknown option `{other}` for this command\n\n{USAGE}"),
        }
    }
    if command.verb == Verb::Record
        && (command.engine != "python" || command.runner != Runner::Python)
    {
        bail!("only the oracle records: `record` takes no --engine or --runner");
    }
    if command.runner == Runner::Node {
        if !engine_given {
            command.engine = "rust".into();
        }
        if command.engine != "rust" {
            bail!("--runner node launches the candidate of --engine rust");
        }
    }
    Ok(command)
}

/// The repository's golden directory and the places around it.
pub(crate) struct Layout {
    pub(crate) repo: PathBuf,
    pub(crate) golden: PathBuf,
    pub(crate) target: PathBuf,
    /// Where `cases/` and `blobs/` are: `golden`, or the `--out`/`--recordings` directory.
    recordings: PathBuf,
    /// The size budget of the recordings (`coverage::BUDGET_BYTES`; the tests set their own).
    budget_bytes: u64,
}

impl Layout {
    pub(crate) fn find() -> Result<Layout> {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut command = std::process::Command::new(&cargo);
        command.args(["metadata", "--format-version", "1", "--no-deps"]);
        if let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
            command.current_dir(dir);
        }
        let output = command.output().context("run cargo metadata")?;
        if !output.status.success() {
            bail!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let doc: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("parse cargo metadata")?;
        let repo = PathBuf::from(
            doc["workspace_root"]
                .as_str()
                .context("no workspace_root")?,
        );
        let target = PathBuf::from(
            doc["target_directory"]
                .as_str()
                .context("no target_directory")?,
        );
        Ok(Layout {
            golden: repo.join("tests/golden"),
            recordings: repo.join("tests/golden"),
            repo,
            target,
            budget_bytes: coverage::BUDGET_BYTES,
        })
    }

    fn cases(&self) -> PathBuf {
        self.recordings.join("cases")
    }

    fn blobs(&self) -> PathBuf {
        self.recordings.join("blobs")
    }

    /// Whether the recordings are the committed ones, under `tests/golden`.
    fn committed(&self) -> bool {
        self.recordings == self.golden
    }
}

/// `path` made absolute against the working directory, with `.` and `..` resolved
/// lexically (the path need not exist yet).
fn absolute(path: &Path) -> Result<PathBuf> {
    let joined =
        std::path::absolute(path).with_context(|| format!("resolve {}", path.display()))?;
    let mut out = PathBuf::new();
    for part in joined.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

impl Command {
    fn run(&self) -> Result<bool> {
        if self.verb == Verb::Help {
            print!("{USAGE}");
            return Ok(true);
        }
        let mut layout = Layout::find()?;
        let (oracle_file, oracle, oracle_dir) = self.oracle_file(&mut layout)?;
        if self.verb == Verb::Lock {
            let source = oracle_file
                .strip_prefix(&layout.repo)
                .unwrap_or(&oracle_file)
                .to_string_lossy()
                .replace('\\', "/");
            oracle.lock(&oracle_dir, &source)?;
            println!(
                "golden lock: wrote {}",
                oracle_dir.join(&oracle.requirements).display()
            );
            return Ok(true);
        }
        if self.verb == Verb::Coverage {
            let all = Spec::parse(&read(&layout.golden.join("cases.toml"))?)?.expand()?;
            return write_coverage(&layout, &oracle, &all);
        }
        let engine = match self.engine.as_str() {
            "python" => oracle.provision(&oracle_dir, &oracle::cache_dir(&layout.target))?,
            "rust" if self.verb == Verb::Record => {
                bail!("golden record records the oracle: --engine rust is for check and diff")
            }
            "rust" => match self.runner {
                Runner::Python => crate::compare::candidate(&layout.repo)?,
                Runner::Node => crate::compare::node_candidate(&layout.repo, &layout.target)?,
            },
            other => bail!("unknown engine `{other}`: python or rust"),
        };
        let passed = self.run_with(&layout, &oracle, engine)?;
        if self.verb == Verb::Record && !layout.committed() {
            copy_oracle(&oracle_file, &oracle, &oracle_dir, &layout.recordings)?;
        }
        Ok(passed)
    }

    /// The oracle file this command uses, the oracle and its directory, with
    /// `layout` pointed at the `--out` or `--recordings` directory.
    fn oracle_file(&self, layout: &mut Layout) -> Result<(PathBuf, Oracle, PathBuf)> {
        let committed = layout.golden.join("ORACLE");
        let file = match (&self.oracle, &self.recordings) {
            (Some(file), _) => absolute(file)?,
            (None, Some(dir)) => absolute(&dir.join("ORACLE"))?,
            (None, None) => committed.clone(),
        };
        if let Some(dir) = self.out.as_ref().or(self.recordings.as_ref()) {
            let dir = absolute(dir)?;
            anyhow::ensure!(
                !dir.starts_with(&layout.golden),
                "{} is inside {}: the committed recordings are written by `golden record` alone",
                dir.display(),
                layout.golden.display()
            );
            layout.recordings = dir;
        } else if self.verb == Verb::Record && file != committed {
            bail!(
                "--oracle {} records with --out DIR only: tests/golden/cases are the recordings \
                 of tests/golden/ORACLE",
                file.display()
            );
        }
        let (oracle, dir) = Oracle::read_file(&file)?;
        Ok((file, oracle, dir))
    }

    /// `record`, `check` or `diff` with `engine`, once the repository is found
    /// and the engine installed (the tests pass a stand-in engine).
    fn run_with(&self, layout: &Layout, oracle: &Oracle, engine: run::Engine) -> Result<bool> {
        let spec = Spec::parse(&read(&layout.golden.join("cases.toml"))?)?;
        let all = spec.expand()?;
        let selected = select(&all, self.filter.as_deref())?;
        // Generated fixtures are generated once per run, then copied per case.
        let (fixtures, _generated) = prepare_fixtures(&spec.fixtures, &selected, &layout.repo)?;
        // The version the candidate reports, before the engine moves in.
        let candidate_version = if self.engine == "rust" && self.verb != Verb::Record {
            Some(crate::compare::candidate_version(
                &engine.bin_dir.join("opentide"),
            )?)
        } else {
            None
        };
        let ctx = RunContext {
            repo: layout.repo.clone(),
            fixtures,
            engine,
            git_version: run::git_version(),
            kernel_release: run::kernel_release(),
            temp_parent: run::temp_parent(),
        };
        // Files the cases create get the same permissions on every host.
        #[cfg(unix)]
        rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
        let jobs = self
            .jobs
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(2, |n| n.get()));
        match self.verb {
            Verb::Record => self.record(layout, oracle, &all, &selected, &ctx, jobs),
            _ if self.engine == "rust" => {
                // Every case: the Rust core is the only implementation (UC-6.2, #841).
                crate::compare::golden(
                    &layout.repo,
                    &layout.cases(),
                    &layout.blobs(),
                    &run_all(&selected, &ctx, jobs, "compare"),
                    // A filtered run leaves ledger entries unused: only a whole
                    // run (CI's `Golden check (Rust)`) finds stale ones. The
                    // ledger is the committed oracle's: against a preview's
                    // recordings its entries are not judged stale.
                    self.filter.is_none() && layout.committed(),
                    self.report.as_deref(),
                    self.verb == Verb::Diff,
                    (&oracle.version, candidate_version.as_deref().unwrap_or("")),
                )
            }
            _ => self.check(layout, oracle, &all, &selected, &ctx, jobs),
        }
    }

    fn record(
        &self,
        layout: &Layout,
        oracle: &Oracle,
        all: &[Case],
        selected: &[Case],
        ctx: &RunContext,
        jobs: usize,
    ) -> Result<bool> {
        let started = Instant::now();
        let first = run_all(selected, ctx, jobs, "record");
        let mut failed = report_errors(&first);
        if self.determinism && failed == 0 {
            let second = run_all(selected, ctx, jobs, "record again");
            failed += report_errors(&second);
            for (a, b) in first.iter().zip(&second) {
                if let (Ok(a), Ok(b)) = (a, b) {
                    let differences = a.differences(b);
                    if !differences.is_empty() {
                        failed += 1;
                        eprintln!(
                            "{}: two runs differ\n{}",
                            a.case.id,
                            describe(&differences, 40)
                        );
                    }
                }
            }
        }
        // The committed recordings are all or nothing; a preview keeps what ran.
        if failed > 0 && (layout.committed() || self.determinism) {
            eprintln!("golden record: {failed} case(s) failed; nothing was written");
            return Ok(false);
        }
        let cases_dir = layout.cases();
        for recording in first.iter().flatten() {
            let dir = cases_dir.join(&recording.case.id);
            // Case ids are checked parts (case.rs), so this never leaves cases/.
            anyhow::ensure!(
                dir.starts_with(&cases_dir)
                    && !recording
                        .case
                        .id
                        .split('/')
                        .any(|p| p == ".." || p.is_empty()),
                "case id `{}` would write outside {}",
                recording.case.id,
                cases_dir.display()
            );
            recording.write(&dir, &layout.blobs())?;
        }
        if self.filter.is_none() {
            let wanted: BTreeSet<&str> = all.iter().map(|c| c.id.as_str()).collect();
            for id in recording::recorded_ids(&cases_dir)? {
                if !wanted.contains(id.as_str()) {
                    std::fs::remove_dir_all(cases_dir.join(&id))
                        .with_context(|| format!("remove {id}"))?;
                    eprintln!("golden record: removed the orphaned recording {id}");
                }
            }
            remove_empty_dirs(&cases_dir)?;
            for unused in blob::unused(&layout.blobs(), &used_blobs(layout)?)? {
                std::fs::remove_file(layout.blobs().join(&unused))
                    .with_context(|| format!("remove blob {unused}"))?;
            }
        }
        // A preview's coverage is not reported: it records a part of the cases.
        let complete = if layout.committed() {
            write_coverage(layout, oracle, all)?
        } else {
            true
        };
        println!(
            "golden record: {} case(s) in {:.1}s into {}{}{}",
            selected.len() - failed,
            started.elapsed().as_secs_f64(),
            layout.recordings.display(),
            if self.determinism {
                ", each run twice: deterministic"
            } else {
                ""
            },
            if failed > 0 {
                format!("; {failed} case(s) failed and were not written")
            } else {
                String::new()
            }
        );
        Ok(complete && failed == 0)
    }

    fn check(
        &self,
        layout: &Layout,
        oracle: &Oracle,
        all: &[Case],
        selected: &[Case],
        ctx: &RunContext,
        jobs: usize,
    ) -> Result<bool> {
        let started = Instant::now();
        let results = run_all(selected, ctx, jobs, "check");
        let mut failed = report_errors(&results);
        let cases_dir = layout.cases();
        let limit = if self.verb == Verb::Diff {
            usize::MAX
        } else {
            40
        };
        for actual in results.iter().flatten() {
            let dir = cases_dir.join(&actual.case.id);
            if !dir.join("case.toml").is_file() {
                failed += 1;
                eprintln!(
                    "{}: not recorded (run `cargo xtask golden record`)",
                    actual.case.id
                );
                continue;
            }
            let recorded = match Recording::read(&dir, &layout.blobs()) {
                Ok(recorded) => recorded,
                Err(error) => {
                    failed += 1;
                    eprintln!(
                        "{}: the recording cannot be read: {error:#}",
                        actual.case.id
                    );
                    continue;
                }
            };
            let differences = recorded.differences(actual);
            if !differences.is_empty() {
                failed += 1;
                eprintln!(
                    "{}: differs from the recording\n{}",
                    actual.case.id,
                    describe(&differences, limit)
                );
            }
        }
        if self.filter.is_none() {
            let wanted: BTreeSet<&str> = all.iter().map(|c| c.id.as_str()).collect();
            for id in recording::recorded_ids(&cases_dir)? {
                if !wanted.contains(id.as_str()) {
                    failed += 1;
                    eprintln!(
                        "{id}: recorded, but cases.toml has no such case (run `cargo xtask golden record`)"
                    );
                }
            }
            for unused in blob::unused(&layout.blobs(), &used_blobs(layout)?)? {
                failed += 1;
                eprintln!("blobs/{unused}: no recording uses it (run `cargo xtask golden record`)");
            }
        }
        if layout.committed() {
            let (markdown, complete) = coverage_report(layout, oracle, all)?;
            if read(&layout.golden.join("COVERAGE.md")).ok().as_deref() != Some(markdown.as_str()) {
                failed += 1;
                eprintln!(
                    "COVERAGE.md is out of date (run `cargo xtask golden record` or `golden coverage`)"
                );
            }
            if !complete {
                failed += 1;
            }
        }
        println!(
            "golden {}: {} case(s) against {} in {:.1}s; {}",
            if self.verb == Verb::Diff {
                "diff"
            } else {
                "check"
            },
            selected.len(),
            ctx.engine.name,
            started.elapsed().as_secs_f64(),
            if failed == 0 {
                "all match".to_owned()
            } else {
                format!("{failed} problem(s)")
            }
        );
        Ok(failed == 0)
    }
}

/// The fixtures, with each `generated` one the cases use generated now into
/// a temporary directory (kept alive by the returned guards) and turned into
/// a `copy` of it.
fn prepare_fixtures(
    fixtures: &std::collections::BTreeMap<String, fixture::FixtureSpec>,
    cases: &[Case],
    repo: &Path,
) -> Result<(
    std::collections::BTreeMap<String, fixture::FixtureSpec>,
    Vec<tempfile::TempDir>,
)> {
    let used: BTreeSet<&str> = cases.iter().map(|c| c.fixture.as_str()).collect();
    let mut out = fixtures.clone();
    let mut guards = Vec::new();
    for (name, spec) in fixtures {
        if spec.kind != fixture::FixtureKind::Generated || !used.contains(name.as_str()) {
            continue;
        }
        let dir = tempfile::Builder::new()
            .prefix("golden-fixture-")
            .tempdir()
            .context("create a directory for a generated fixture")?;
        let ws = dir.path().join("ws");
        std::fs::create_dir(&ws).with_context(|| format!("create {}", ws.display()))?;
        spec.materialise(repo, &ws)
            .with_context(|| format!("generate fixture `{name}`"))?;
        let copy = fixture::FixtureSpec {
            kind: fixture::FixtureKind::Copy,
            source: Some(ws.to_string_lossy().into_owned()),
            ..spec.clone()
        };
        out.insert(name.clone(), copy);
        guards.push(dir);
    }
    Ok((out, guards))
}

/// The cases whose id, or a leading part of it, matches `filter` (a glob),
/// or all of them: `explain/*` is every `explain` case, as is `explain`.
fn select(all: &[Case], filter: Option<&str>) -> Result<Vec<Case>> {
    let Some(filter) = filter else {
        return Ok(all.to_vec());
    };
    let pattern = glob::Pattern::new(filter).with_context(|| format!("--filter `{filter}`"))?;
    let selected: Vec<Case> = all
        .iter()
        // `*` stays within one part of the id: `*/json/*/*` is every json
        // case, and so is `*/json`, which matches its first two parts.
        .filter(|c| {
            let options = glob::MatchOptions {
                require_literal_separator: true,
                ..glob::MatchOptions::new()
            };
            c.id.match_indices('/')
                .map(|(end, _)| &c.id[..end])
                .chain([c.id.as_str()])
                .any(|prefix| pattern.matches_with(prefix, options))
        })
        .cloned()
        .collect();
    if selected.is_empty() {
        bail!("--filter `{filter}` matches no case");
    }
    Ok(selected)
}

/// Runs the cases on `jobs` threads; results come back in the cases' order.
pub fn run_all(
    cases: &[Case],
    ctx: &RunContext,
    jobs: usize,
    label: &str,
) -> Vec<Result<Recording>> {
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Result<Recording>>>> =
        Mutex::new((0..cases.len()).map(|_| None).collect());
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..jobs.min(cases.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(case) = cases.get(i) else { break };
                    let result = run::run_case(case, ctx);
                    results
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)[i] = Some(result);
                    let n = done.fetch_add(1, Ordering::SeqCst) + 1;
                    if n % 100 == 0 || n == cases.len() {
                        eprintln!(
                            "golden {label}: {n}/{} case(s), {:.0}s",
                            cases.len(),
                            started.elapsed().as_secs_f64()
                        );
                    }
                }
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .into_iter()
        .map(|slot| slot.unwrap_or_else(|| Err(anyhow::anyhow!("the case did not run"))))
        .collect()
}

fn report_errors(results: &[Result<Recording>]) -> usize {
    let mut failed = 0;
    for result in results {
        if let Err(error) = result {
            failed += 1;
            eprintln!("error: {error:#}");
        }
    }
    failed
}

/// The differences, each diff cut to `limit` lines.
pub fn describe(differences: &[recording::Difference], limit: usize) -> String {
    let mut out = String::new();
    for difference in differences {
        let _ = writeln!(out, "  --- {}", difference.part);
        let lines: Vec<&str> = difference.detail.lines().collect();
        for line in lines.iter().take(limit) {
            let _ = writeln!(out, "  {line}");
        }
        if lines.len() > limit {
            let _ = writeln!(
                out,
                "  … {} more line(s); `cargo xtask golden diff` prints them",
                lines.len() - limit
            );
        }
    }
    out
}

fn coverage_report(layout: &Layout, oracle: &Oracle, all: &[Case]) -> Result<(String, bool)> {
    let commands = layout.cases().join("commands/json/none/default/stdout");
    let paths = coverage::command_paths(&std::fs::read(&commands).with_context(|| {
        format!(
            "read {} (the coverage report lists its command paths)",
            commands.display()
        )
    })?)?;
    let (cases, blobs) = (
        coverage::measure(&layout.cases())?,
        coverage::measure(&layout.blobs())?,
    );
    let size = coverage::Size {
        files: cases.files + blobs.files,
        bytes: cases.bytes + blobs.bytes,
    };
    let report = coverage::report(oracle, &paths, all, size, layout.budget_bytes);
    let mut complete = true;
    for (command, mode) in &report.missing {
        complete = false;
        eprintln!("coverage: `{command}` has no case in {mode} mode");
    }
    for command in &report.unknown {
        complete = false;
        eprintln!(
            "coverage: cases.toml names `{command}`, which `opentide --json commands` does not list"
        );
    }
    if size.bytes > layout.budget_bytes {
        complete = false;
        eprintln!(
            "coverage: the recordings take {} bytes, over the {} byte budget",
            size.bytes, layout.budget_bytes
        );
    }
    Ok((report.markdown, complete))
}

fn write_coverage(layout: &Layout, oracle: &Oracle, all: &[Case]) -> Result<bool> {
    let (markdown, complete) = coverage_report(layout, oracle, all)?;
    let path = layout.golden.join("COVERAGE.md");
    std::fs::write(&path, markdown).with_context(|| format!("write {}", path.display()))?;
    Ok(complete)
}

/// Copies the oracle file and its requirements into the recordings directory
/// `dir` (as `ORACLE` and its own requirements name), so that `--recordings
/// DIR` knows the oracle that recorded them.
fn copy_oracle(file: &Path, oracle: &Oracle, oracle_dir: &Path, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    std::fs::copy(file, dir.join("ORACLE"))
        .with_context(|| format!("copy {} into {}", file.display(), dir.display()))?;
    let requirements = oracle_dir.join(&oracle.requirements);
    if requirements.is_file() {
        std::fs::copy(&requirements, dir.join(&oracle.requirements))
            .with_context(|| format!("copy {} into {}", requirements.display(), dir.display()))?;
    }
    Ok(())
}

fn remove_empty_dirs(dir: &Path) -> Result<bool> {
    let mut empty = true;
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        if entry.file_type().is_ok_and(|t| t.is_dir()) && remove_empty_dirs(&entry.path())? {
            std::fs::remove_dir(entry.path())
                .with_context(|| format!("remove {}", entry.path().display()))?;
        } else {
            empty = false;
        }
    }
    Ok(empty)
}

/// The blobs every recording on disk names.
fn used_blobs(layout: &Layout) -> Result<BTreeSet<String>> {
    #[derive(serde::Deserialize)]
    struct Outcome {
        #[serde(default)]
        files: Vec<recording::FileRecord>,
    }
    let mut used = BTreeSet::new();
    for id in recording::recorded_ids(&layout.cases())? {
        let path = layout.cases().join(&id).join("outcome.toml");
        let outcome: Outcome =
            toml::from_str(&read(&path)?).with_context(|| format!("parse {}", path.display()))?;
        used.extend(outcome.files.into_iter().filter_map(|f| f.blob));
    }
    Ok(used)
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_the_verification_commands() {
        let c = parse(&args(&["record", "--check-determinism"])).unwrap();
        assert!(c.determinism && c.verb == Verb::Record);
        let c = parse(&args(&[
            "check",
            "--engine",
            "python",
            "--filter",
            "validate/*",
            "--jobs",
            "3",
        ]))
        .unwrap();
        assert_eq!(c.verb, Verb::Check);
        assert_eq!(c.filter.as_deref(), Some("validate/*"));
        assert_eq!(c.jobs, Some(3));
        assert!(parse(&args(&["check", "--check-determinism"])).is_err());
        assert!(parse(&args(&["record", "--engine", "rust"])).is_err());
        assert_eq!(c.runner, Runner::Python);
        // The Node runner launches the candidate of `--engine rust`.
        let c = parse(&args(&["check", "--runner", "node"])).unwrap();
        assert_eq!((c.engine.as_str(), c.runner), ("rust", Runner::Node));
        let c = parse(&args(&["diff", "--engine", "rust", "--runner", "node"])).unwrap();
        assert_eq!((c.engine.as_str(), c.runner), ("rust", Runner::Node));
        assert!(parse(&args(&["check", "--engine", "python", "--runner", "node"])).is_err());
        assert!(parse(&args(&["check", "--runner", "deno"])).is_err());
        assert!(parse(&args(&["record", "--runner", "node"])).is_err());
        assert!(parse(&args(&["nope"])).is_err());
        assert!(parse(&args(&["check", "--filter"])).is_err());
    }

    /// A stand-in for the oracle: a shell script that prints differently on a
    /// terminal and on a pipe, writes a file, takes a moment, and exits 3.
    #[cfg(unix)]
    const FAKE_ENGINE: &str = r#"#!/bin/sh
case " $* " in
  *" commands "*)
    if [ "$1" = "--json" ]; then
      printf '{"commands": [{"path": "validate"}, {"path": "commands"}], "duration_ms": 12}\n'
    else
      printf 'validate\ncommands\n'
    fi
    exit 0;;
esac
if [ -t 1 ]; then printf '\033[1mtty\033[0m took 1.5s\n'; else printf 'pipe took 0.4s\n'; fi
echo "home $HOME" >&2
echo "made in $PWD" > out.txt
exit 3
"#;

    #[cfg(unix)]
    const FAKE_CASES: &str = r#"
[defaults]
modes = ["human", "plain", "json", "agent"]
fixtures = ["none"]
timeout_secs = 30

[fixtures.none]
kind = "skeleton"

[fixtures.empty]
kind = "skeleton"
dirs = [".opentide"]

[[case]]
command = "commands"
variant = "default"
args = ["commands"]

[[case]]
command = "validate"
variant = "default"
args = ["validate"]
fixtures = ["none", "empty"]
"#;

    /// A repository with `cases.toml`, and an engine that is [`FAKE_ENGINE`].
    #[cfg(unix)]
    fn fake_repository() -> (tempfile::TempDir, Layout, Oracle, run::Engine) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let golden = repo.join("tests/golden");
        std::fs::create_dir_all(&golden).unwrap();
        std::fs::write(golden.join("cases.toml"), FAKE_CASES).unwrap();
        let install = dir.path().join("engine");
        let bin = install.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("opentide"), FAKE_ENGINE).unwrap();
        std::fs::set_permissions(bin.join("opentide"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let layout = Layout {
            recordings: golden.clone(),
            golden,
            target: repo.join("target"),
            repo,
            budget_bytes: coverage::BUDGET_BYTES,
        };
        let oracle = Oracle {
            tag: "v0.0.0".into(),
            commit: "0".repeat(40),
            package: "opentide".into(),
            version: "0.0.0".into(),
            wheel: "opentide-0.0.0-x.whl".into(),
            wheel_sha256: "0".repeat(64),
            python: "3.13.14".into(),
            platform: "linux-x86_64".into(),
            exclude_newer: "2026-11-08T00:00:00Z".into(),
            requirements: "oracle-requirements.txt".into(),
        };
        let engine = run::Engine {
            name: "fake".into(),
            bin_dir: bin,
            install_dir: install,
            host_paths: Vec::new(),
            known_uuids: std::sync::Arc::default(),
        };
        (dir, layout, oracle, engine)
    }

    #[cfg(unix)]
    fn command(verb: Verb, determinism: bool) -> Command {
        Command {
            verb,
            engine: "python".into(),
            runner: Runner::Python,
            filter: None,
            determinism,
            jobs: Some(2),
            report: None,
            oracle: None,
            out: None,
            recordings: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn records_checks_and_finds_every_kind_of_difference() {
        let (_dir, layout, oracle, engine) = fake_repository();
        let record = command(Verb::Record, true);
        assert!(record.run_with(&layout, &oracle, engine.clone()).unwrap());

        let cases = layout.cases();
        let human = cases.join("validate/human/none/default");
        let stdout = std::fs::read_to_string(human.join("stdout")).unwrap();
        // Human mode ran on a pseudo-terminal, ANSI kept, duration normalised.
        assert_eq!(stdout, "\x1b[1mtty\x1b[0m took <SECONDS>\n");
        let plain = cases.join("validate/plain/empty/default");
        assert_eq!(
            std::fs::read_to_string(plain.join("stdout")).unwrap(),
            "pipe took <SECONDS>\n"
        );
        assert_eq!(
            std::fs::read_to_string(plain.join("stderr")).unwrap(),
            "home <HOME>\n"
        );
        let outcome = std::fs::read_to_string(plain.join("outcome.toml")).unwrap();
        assert!(
            outcome.contains("exit_code = 3") && outcome.contains("path = \"ws/out.txt\""),
            "{outcome}"
        );
        assert_eq!(
            std::fs::read_to_string(plain.join("files/ws/out.txt")).unwrap(),
            "made in <WS>\n"
        );
        let case = std::fs::read_to_string(human.join("case.toml")).unwrap();
        assert!(
            case.contains("kind = \"tty\"") && !case.contains("AI_AGENT"),
            "{case}"
        );
        let coverage = std::fs::read_to_string(layout.golden.join("COVERAGE.md")).unwrap();
        assert!(
            coverage.contains("| `validate` | 2 | 2 | 2 | 2 | empty, none |"),
            "{coverage}"
        );

        // A fresh run matches the recordings.
        assert!(
            command(Verb::Check, false)
                .run_with(&layout, &oracle, engine.clone())
                .unwrap()
        );
        let mut filtered = command(Verb::Check, false);
        filtered.filter = Some("validate/plain/*/*".into());
        assert!(filtered.run_with(&layout, &oracle, engine.clone()).unwrap());

        // A changed byte, an orphaned recording, a stale coverage report: each fails.
        std::fs::write(plain.join("stdout"), "pipe took <SECONDS>!\n").unwrap();
        assert!(
            !command(Verb::Check, false)
                .run_with(&layout, &oracle, engine.clone())
                .unwrap()
        );
        assert!(
            !command(Verb::Diff, false)
                .run_with(&layout, &oracle, engine.clone())
                .unwrap()
        );
        assert!(record.run_with(&layout, &oracle, engine.clone()).unwrap());
        let orphan = cases.join("validate/plain/none/gone");
        Recording::read(&plain, &layout.blobs())
            .unwrap()
            .write(&orphan, &layout.blobs())
            .unwrap();
        assert!(
            !command(Verb::Check, false)
                .run_with(&layout, &oracle, engine.clone())
                .unwrap()
        );
        // Recording again removes the orphan.
        assert!(record.run_with(&layout, &oracle, engine.clone()).unwrap());
        assert!(!orphan.exists());
        std::fs::write(layout.golden.join("COVERAGE.md"), "stale\n").unwrap();
        assert!(
            !command(Verb::Check, false)
                .run_with(&layout, &oracle, engine.clone())
                .unwrap()
        );
        assert!(
            write_coverage(
                &layout,
                &oracle,
                &Spec::parse(FAKE_CASES).unwrap().expand().unwrap()
            )
            .unwrap()
        );
        assert!(
            command(Verb::Check, false)
                .run_with(&layout, &oracle, engine)
                .unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_fails_on_a_missing_recording_an_unused_blob_an_edited_case_and_the_budget() {
        let (_dir, mut layout, oracle, engine) = fake_repository();
        let record = command(Verb::Record, false);
        let check = |layout: &Layout| {
            command(Verb::Check, false)
                .run_with(layout, &oracle, engine.clone())
                .unwrap()
        };
        assert!(record.run_with(&layout, &oracle, engine.clone()).unwrap());
        assert!(check(&layout));

        // A case whose recording directory is gone.
        let gone = layout.cases().join("validate/json/empty/default");
        std::fs::remove_dir_all(&gone).unwrap();
        assert!(!check(&layout));
        assert!(record.run_with(&layout, &oracle, engine.clone()).unwrap());
        assert!(gone.join("case.toml").is_file());

        // A blob no recording names.
        let stray = blob::put(&layout.blobs(), b"no recording names this\n").unwrap();
        assert!(layout.blobs().join(&stray).is_file());
        assert!(!check(&layout));
        assert!(record.run_with(&layout, &oracle, engine.clone()).unwrap());
        assert!(!layout.blobs().join(&stray).exists());

        // A case.toml whose recorded environment was edited.
        let case_toml = layout.cases().join("validate/plain/none/default/case.toml");
        let text = std::fs::read_to_string(&case_toml).unwrap();
        assert!(text.contains("[env]"), "{text}");
        std::fs::write(
            &case_toml,
            text.replacen("[env]\n", "[env]\nEDITED = \"1\"\n", 1),
        )
        .unwrap();
        assert!(!check(&layout));
        assert!(record.run_with(&layout, &oracle, engine.clone()).unwrap());
        assert!(check(&layout));

        // Recordings over the budget: record and check both fail.
        layout.budget_bytes = 16;
        assert!(!check(&layout));
        assert!(!record.run_with(&layout, &oracle, engine.clone()).unwrap());
        let coverage = std::fs::read_to_string(layout.golden.join("COVERAGE.md")).unwrap();
        assert!(coverage.contains("of a 0 MiB budget"), "{coverage}");
    }

    #[cfg(unix)]
    #[test]
    fn a_nondeterministic_engine_fails_the_determinism_check_and_nothing_is_written() {
        let (_dir, layout, oracle, engine) = fake_repository();
        std::fs::write(
            engine.bin_dir.join("opentide"),
            "#!/bin/sh\nod -An -N8 -tx1 /dev/urandom\n",
        )
        .unwrap();
        let mut record = command(Verb::Record, true);
        record.filter = Some("validate/plain/*/*".into());
        assert!(!record.run_with(&layout, &oracle, engine).unwrap());
        assert!(!layout.cases().exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_case_that_times_out_fails_and_nothing_is_written() {
        let (_dir, layout, oracle, engine) = fake_repository();
        std::fs::write(engine.bin_dir.join("opentide"), "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::write(
            layout.golden.join("cases.toml"),
            FAKE_CASES.replace("timeout_secs = 30", "timeout_secs = 1"),
        )
        .unwrap();
        let mut record = command(Verb::Record, false);
        record.filter = Some("validate/plain/none/*".into());
        assert!(!record.run_with(&layout, &oracle, engine).unwrap());
        assert!(!layout.cases().exists());
    }

    #[test]
    fn parses_the_preview_flags() {
        let c = parse(&args(&[
            "record",
            "--oracle",
            "tests/golden/ORACLE.next",
            "--out",
            "target/golden-next",
        ]))
        .unwrap();
        assert_eq!(
            c.oracle.as_deref(),
            Some(Path::new("tests/golden/ORACLE.next"))
        );
        assert_eq!(c.out.as_deref(), Some(Path::new("target/golden-next")));
        let c = parse(&args(&["lock", "--oracle", "x/ORACLE.next"])).unwrap();
        assert_eq!(c.oracle.as_deref(), Some(Path::new("x/ORACLE.next")));
        for verb in ["check", "diff"] {
            let c = parse(&args(&[verb, "--engine", "rust", "--recordings", "d"])).unwrap();
            assert_eq!(c.recordings.as_deref(), Some(Path::new("d")));
        }
        // Each flag belongs to its commands only.
        assert!(parse(&args(&["check", "--oracle", "x"])).is_err());
        assert!(parse(&args(&["check", "--out", "x"])).is_err());
        assert!(parse(&args(&["lock", "--out", "x"])).is_err());
        assert!(parse(&args(&["record", "--recordings", "x"])).is_err());
        assert!(parse(&args(&["coverage", "--oracle", "x"])).is_err());
        assert!(parse(&args(&["record", "--out"])).is_err());
    }

    #[cfg(unix)]
    const NEXT_ORACLE: &str = r#"tag = "v0.0.1"
commit = "1111111111111111111111111111111111111111"
package = "opentide"
version = "0.0.1"
wheel = "opentide-0.0.1-x.whl"
wheel_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
python = "3.13.14"
platform = "linux-x86_64"
exclude_newer = "2026-11-13T00:00:00Z"
requirements = "oracle-requirements.next.txt"
"#;

    #[cfg(unix)]
    #[test]
    fn picks_the_oracle_file_and_the_recordings_directory() {
        let (dir, mut layout, _oracle, _engine) = fake_repository();
        std::fs::write(layout.golden.join("ORACLE.next"), NEXT_ORACLE).unwrap();
        let next = layout.golden.join("ORACLE.next");
        let out = dir.path().join("preview");

        // `record --oracle FILE` without --out would overwrite the committed recordings.
        let mut record = command(Verb::Record, false);
        record.oracle = Some(next.clone());
        let error = record.oracle_file(&mut layout).unwrap_err().to_string();
        assert!(error.contains("--out"), "{error}");
        assert!(layout.committed());

        // --out inside tests/golden is refused, `..` and all.
        record.out = Some(layout.golden.join("cases/../next"));
        let error = record.oracle_file(&mut layout).unwrap_err().to_string();
        assert!(error.contains("inside"), "{error}");

        record.out = Some(out.join("./sub/.."));
        let (file, oracle, oracle_dir) = record.oracle_file(&mut layout).unwrap();
        assert_eq!((file, oracle.version.as_str()), (next.clone(), "0.0.1"));
        assert_eq!(oracle_dir, layout.golden);
        assert_eq!(layout.cases(), out.join("cases"));
        assert_eq!(layout.blobs(), out.join("blobs"));
        assert!(!layout.committed());

        // `check --recordings DIR` reads DIR/ORACLE, which `record --out` copies.
        let mut check = command(Verb::Check, false);
        check.recordings = Some(out.clone());
        assert!(check.oracle_file(&mut layout).is_err());
        std::fs::write(layout.golden.join("oracle-requirements.next.txt"), "pins\n").unwrap();
        copy_oracle(&next, &oracle, &layout.golden, &out).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("ORACLE")).unwrap(),
            NEXT_ORACLE
        );
        assert_eq!(
            std::fs::read_to_string(out.join("oracle-requirements.next.txt")).unwrap(),
            "pins\n"
        );
        let (file, oracle, oracle_dir) = check.oracle_file(&mut layout).unwrap();
        assert_eq!(
            (file, oracle.version.as_str()),
            (out.join("ORACLE"), "0.0.1")
        );
        assert_eq!(oracle_dir, out);

        // No flag: tests/golden/ORACLE and the committed recordings.
        let (_plain_dir, mut plain, _, _) = fake_repository();
        std::fs::write(plain.golden.join("ORACLE"), NEXT_ORACLE).unwrap();
        let (file, _, _) = command(Verb::Check, false).oracle_file(&mut plain).unwrap();
        assert_eq!(file, plain.golden.join("ORACLE"));
        assert!(plain.committed());
    }

    #[cfg(unix)]
    #[test]
    fn records_a_preview_outside_tests_golden_and_checks_against_it() {
        let (dir, mut layout, oracle, engine) = fake_repository();
        let golden_before = std::fs::read_dir(&layout.golden).unwrap().count();
        layout.recordings = dir.path().join("preview");
        let mut record = command(Verb::Record, false);
        record.out = Some(layout.recordings.clone());
        record.filter = Some("validate/*/*/*".into());
        assert!(record.run_with(&layout, &oracle, engine.clone()).unwrap());
        // The preview holds the cases; tests/golden has only its cases.toml.
        assert!(
            layout
                .cases()
                .join("validate/plain/empty/default/case.toml")
                .is_file()
        );
        assert!(!layout.cases().join("commands").exists());
        assert_eq!(
            std::fs::read_dir(&layout.golden).unwrap().count(),
            golden_before
        );
        assert!(!layout.golden.join("COVERAGE.md").exists());

        // Checked against the preview, with no coverage report to compare.
        let mut check = command(Verb::Check, false);
        check.recordings = Some(layout.recordings.clone());
        check.filter = Some("validate/*/*/*".into());
        assert!(check.run_with(&layout, &oracle, engine.clone()).unwrap());
        std::fs::write(
            layout.cases().join("validate/plain/none/default/stdout"),
            "changed\n",
        )
        .unwrap();
        assert!(!check.run_with(&layout, &oracle, engine.clone()).unwrap());
        // A whole check finds the cases the preview did not record.
        check.filter = None;
        assert!(!check.run_with(&layout, &oracle, engine.clone()).unwrap());

        // A failing case is reported; the preview keeps the others.
        std::fs::write(
            layout.golden.join("cases.toml"),
            FAKE_CASES.replace("timeout_secs = 30", "timeout_secs = 1"),
        )
        .unwrap();
        std::fs::write(
            engine.bin_dir.join("opentide"),
            // The `empty` fixture's cases time out; the `none` ones run.
            "#!/bin/sh\n[ -d .opentide ] && sleep 30\necho ran\n",
        )
        .unwrap();
        std::fs::remove_dir_all(&layout.recordings).unwrap();
        assert!(!record.run_with(&layout, &oracle, engine).unwrap());
        assert!(layout.cases().join("validate/plain/none/default").is_dir());
        assert!(!layout.cases().join("validate/plain/empty/default").exists());
    }

    #[test]
    fn filters_by_glob() {
        let spec = Spec::parse(
            "[defaults]\nmodes = [\"plain\", \"json\"]\nfixtures = [\"none\"]\ntimeout_secs = 5\n\
             [fixtures.none]\nkind = \"skeleton\"\n\
             [[case]]\ncommand = \"validate\"\nvariant = \"a\"\nargs = []\n",
        )
        .unwrap();
        let all = spec.expand().unwrap();
        assert_eq!(select(&all, Some("*/json/*/*")).unwrap().len(), 1);
        // A glob over the leading parts of the id selects the cases below them.
        assert_eq!(select(&all, Some("*/json/*")).unwrap().len(), 1);
        assert_eq!(select(&all, Some("validate/*")).unwrap().len(), 2);
        assert_eq!(select(&all, Some("validate")).unwrap().len(), 2);
        // `*` does not cross a `/`, nor match a part of one.
        assert!(select(&all, Some("validate*json")).is_err());
        assert!(select(&all, Some("valid")).is_err());
        assert_eq!(select(&all, Some("validate/*/none/a")).unwrap().len(), 2);
        assert_eq!(select(&all, None).unwrap().len(), 2);
        assert!(select(&all, Some("lint/*")).is_err());
    }
}
