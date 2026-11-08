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
pub mod normalise;
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
  record [--check-determinism] [--filter GLOB] [--jobs N]
             run every case through the oracle and write tests/golden/cases/
             and COVERAGE.md. --check-determinism runs every case twice and
             fails, writing nothing, unless both runs agree byte for byte
  check [--engine python|rust|compare] [--filter GLOB] [--jobs N]
             run every case through the engine and compare with the
             recordings; also checks COVERAGE.md and that no recording is
             missing or orphaned
  diff [--engine ...] [--filter GLOB] [--jobs N]
             check, printing every difference in full
  lock       rewrite tests/golden/oracle-requirements.txt from ORACLE (uv pip compile)
  coverage   rewrite COVERAGE.md from cases.toml and the recordings

--filter GLOB  only the cases whose id (<command>/<mode>/<fixture>/<variant>) matches
--engine       python (the oracle, the default); rust (UC-3) and compare (UC-0.7) come
               later: until then they cannot start (exit status 2)

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

#[derive(Debug, PartialEq, Eq)]
struct Command {
    verb: Verb,
    engine: String,
    filter: Option<String>,
    determinism: bool,
    jobs: Option<usize>,
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
        filter: None,
        determinism: false,
        jobs: None,
    };
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--filter" => command.filter = Some(value()?),
            "--engine" => command.engine = value()?,
            "--jobs" => {
                let jobs: usize = value()?.parse().context("--jobs needs a number")?;
                command.jobs = Some(jobs.max(1));
            }
            "--check-determinism" if command.verb == Verb::Record => command.determinism = true,
            other => bail!("unknown option `{other}` for this command\n\n{USAGE}"),
        }
    }
    if command.engine != "python" && command.verb == Verb::Record {
        bail!("only the oracle records: `record` takes no --engine");
    }
    Ok(command)
}

/// The repository's golden directory and the places around it.
struct Layout {
    repo: PathBuf,
    golden: PathBuf,
    target: PathBuf,
}

impl Layout {
    fn find() -> Result<Layout> {
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
            repo,
            target,
        })
    }

    fn cases(&self) -> PathBuf {
        self.golden.join("cases")
    }

    fn blobs(&self) -> PathBuf {
        self.golden.join("blobs")
    }
}

impl Command {
    fn run(&self) -> Result<bool> {
        if self.verb == Verb::Help {
            print!("{USAGE}");
            return Ok(true);
        }
        let layout = Layout::find()?;
        let oracle = Oracle::parse(&read(&layout.golden.join("ORACLE"))?)?;
        if self.verb == Verb::Lock {
            oracle.lock(&layout.golden)?;
            println!(
                "golden lock: wrote {}",
                layout.golden.join(&oracle.requirements).display()
            );
            return Ok(true);
        }
        let spec = Spec::parse(&read(&layout.golden.join("cases.toml"))?)?;
        let all = spec.expand()?;
        if self.verb == Verb::Coverage {
            return write_coverage(&layout, &oracle, &all);
        }
        let engine = match self.engine.as_str() {
            "python" => oracle.provision(&layout.golden, &oracle::cache_dir(&layout.target))?,
            // The run cannot start: exit status 2, as the usage says.
            "rust" => bail!("--engine rust is not implemented yet; the Rust CLI arrives with UC-3"),
            "compare" => bail!(
                "--engine compare is not implemented yet; UC-0.7 \
                 (https://github.com/opentidehq/opentide/issues/805) implements it"
            ),
            other => bail!("unknown engine `{other}`: python, rust or compare"),
        };
        let selected = select(&all, self.filter.as_deref())?;
        // Generated fixtures are generated once per run, then copied per case.
        let (fixtures, _generated) = prepare_fixtures(&spec.fixtures, &selected, &layout.repo)?;
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
            Verb::Record => self.record(&layout, &oracle, &all, &selected, &ctx, jobs),
            _ => self.check(&layout, &oracle, &all, &selected, &ctx, jobs),
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
        if failed > 0 {
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
        let complete = write_coverage(layout, oracle, all)?;
        println!(
            "golden record: {} case(s) in {:.1}s{}",
            selected.len(),
            started.elapsed().as_secs_f64(),
            if self.determinism {
                ", each run twice: deterministic"
            } else {
                ""
            }
        );
        Ok(complete)
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

/// The cases whose id matches `filter` (a glob), or all of them.
fn select(all: &[Case], filter: Option<&str>) -> Result<Vec<Case>> {
    let Some(filter) = filter else {
        return Ok(all.to_vec());
    };
    let pattern = glob::Pattern::new(filter).with_context(|| format!("--filter `{filter}`"))?;
    let selected: Vec<Case> = all
        .iter()
        // `*` stays within one part of the id: `*/json/*/*` is every json case.
        .filter(|c| {
            pattern.matches_with(
                &c.id,
                glob::MatchOptions {
                    require_literal_separator: true,
                    ..glob::MatchOptions::new()
                },
            )
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
    let report = coverage::report(oracle, &paths, all, size);
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
    if size.bytes > coverage::BUDGET_BYTES {
        complete = false;
        eprintln!(
            "coverage: the recordings take {} bytes, over the {} byte budget",
            size.bytes,
            coverage::BUDGET_BYTES
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
        assert!(parse(&args(&["nope"])).is_err());
        assert!(parse(&args(&["check", "--filter"])).is_err());
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
        // `*` does not cross a `/`.
        assert!(select(&all, Some("*/json/*")).is_err());
        assert_eq!(select(&all, Some("validate/*/none/a")).unwrap().len(), 2);
        assert_eq!(select(&all, None).unwrap().len(), 2);
        assert!(select(&all, Some("lint/*")).is_err());
    }
}
