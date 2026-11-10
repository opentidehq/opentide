//! `cargo xtask <command>`: the repository's Rust tooling (`xtask/AGENTS.md`).
//!
//! Exit status: 0 when the command passed, 1 when a check failed or the
//! command is not implemented yet, 2 on a usage error or when the check could
//! not run (no `cargo metadata`, an unreadable file).

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use xtask::compare;
use xtask::layers::{self, LayerTable, Metadata};
use xtask::{coverage, mutants, parity, parity_inputs};

const USAGE: &str = "\
usage: cargo xtask <command> [options]

commands:
  check-layers [--metadata FILE] [--layers FILE]
                 check that every dependency between workspace crates points
                 down the layer table (xtask/layers.toml, plan section 4).
                 --metadata reads `cargo metadata --format-version 1` output
                 from FILE instead of running cargo; --layers reads another table
  coverage gate --report FILE [--policy FILE] [--metadata FILE]
                 check each workspace crate's line coverage against its gate
                 (xtask/coverage.toml, plan section 5.4). FILE is the export of
                 `cargo llvm-cov report --json --summary-only`; prints a
                 Markdown table for the job summary
  mutants crates [--policy FILE] [--metadata FILE]
                 print the crates the weekly mutation run mutates, one per line
                 (xtask/mutants.toml)
  mutants report --outcomes FILE [--outcomes FILE ...] [--policy FILE]
                 [--baseline FILE] [--issues DIR] [--run-url URL]
                 [--write-baseline FILE --commit SHA]
                 merge cargo-mutants' outcomes.json of every shard and print the
                 scores against the baseline; --issues writes DIR/<crate>.md for
                 each crate whose surviving mutants exceed its threshold;
                 --write-baseline records this run as the baseline
  parity dashboard [--root DIR] [--out FILE] [--check] [--require-inputs]
                   [--engines FILE] [--compare FILE]
                 render the parity dashboard (each command x corpus x mode
                 against the oracle, approved diffs, fault coverage) into FILE,
                 by default docs/internal/parity.md; --check fails when FILE
                 differs from the rendering instead of writing it;
                 --require-inputs fails when the recordings, the ledger or the
                 fault catalogue is missing. --engines
                 reads the engine state (scripts/parity_engines.py), --compare
                 the RunReport JSON of a compare run
  compare --oracle DIR --candidate DIR --command PATH [--case ID]
          [--ledger FILE] [--report FILE]
                 compare a candidate's run with the oracle's, applying the
                 approved-diffs ledger (tests/golden/APPROVED_DIFFS.toml); a
                 run is a folder with exit_code, stdout, stderr, files/ and
                 deleted. --report writes the JSON report to FILE
  compare --check-ledger [--ledger FILE] [--changelog FILE]
                 check the ledger's schema, and that CHANGELOG.md holds each
                 entry's changelog reference
  corpus <command>
                 generate the heavy workspace, run the fault catalogue
                 against the oracle, report coverage (UC-0.6, #804);
                 `cargo xtask corpus help` lists its commands
  config diff --against python [--oracle BIN]
              [--corpus all|fixtures|generated]
                 resolve every fixture and generated workspace's configuration
                 with opentide-schema and compare it, as JSON, and its
                 configuration findings with the oracle's (UC-1.5, #811)
  registry diff --against python [--oracle BIN]
                [--corpus all|fixtures|generated|faults]
                 load every corpus with opentide-workspace and compare its
                 index (objects, UUIDs, types, paths, load errors, references,
                 signals), as JSON, with the Python registry's (UC-2.1, #816)
  validate diff [--filter GLOB] [--keep DIR] [--show-approved]
                 run opentide-workspace's validate on every recorded
                 `validate --json` case that only checks, and compare its
                 report, checks and summary with the recording (UC-2.2, #817)
  codegen        generate schemas, stubs, types and references (UC-1.8, #814)
  golden <record|check|diff|lock|coverage> [options]
                 record what the frozen Python CLI does, and check an engine
                 against the recordings (tests/golden/README.md);
                 `cargo xtask golden help` lists the options
  bench          run the benchmarks against their budgets (UC-0.8, #806)
  vocab <sync|sentinel-attack|diff> [options]
                 the vocabularies: sync and check them against specifications,
                 generate Sentinel's ATT&CK list, compare with the oracle
                 (UC-1.6, #812); `cargo xtask vocab help` lists the options
  schema diff --against python [options]
                 the object models against the oracle: their JSON Schemas,
                 and their verdict on every object file of every corpus
                 (UC-1.3, #809); `cargo xtask schema help` lists the options
  stubs [--check] [--library FILE]
                 generate src/opentide/_native/models.pyi, the stubs of the
                 Tide models' Python classes, from the extension's
                 introspection data (UC-1.9, #815); --check fails on drift
  help           print this message

exit status: 0 passed, 1 check failed or not implemented yet,
2 usage error or the check could not run
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    match command.as_str() {
        "check-layers" => match check_layers(rest) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("xtask check-layers: {error:#}");
                ExitCode::from(2)
            }
        },
        "coverage" => match coverage_command(rest) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("xtask coverage: {error:#}");
                ExitCode::from(2)
            }
        },
        "mutants" => match mutants_command(rest) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("xtask mutants: {error:#}");
                ExitCode::from(2)
            }
        },
        "parity" => match parity_command(rest) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("xtask parity: {error:#}");
                ExitCode::from(2)
            }
        },
        "compare" => match run_compare(rest) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("xtask compare: {error:#}");
                ExitCode::from(2)
            }
        },
        "corpus" => match xtask::corpus::cli::run(rest) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("xtask corpus: {error:#}");
                ExitCode::from(2)
            }
        },
        "config" => match xtask::config::run(rest) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("xtask config: {error:#}");
                ExitCode::from(2)
            }
        },
        "registry" => match xtask::registry::run(rest) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("xtask registry: {error:#}");
                ExitCode::from(2)
            }
        },
        "validate" => match xtask::validate::run(rest) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("xtask validate: {error:#}");
                ExitCode::from(2)
            }
        },
        "codegen" => not_yet("codegen", "UC-1.8", 814),
        "golden" => xtask::golden::main(rest),
        "bench" => xtask::bench::main(rest),
        "vocab" => xtask::vocab::main(rest),
        "schema" => xtask::schema::main(rest),
        "stubs" => xtask::stubs::main(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprint!("xtask: unknown command `{other}`\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// A command whose work item has not landed: it fails, so that no script or
/// CI job can mistake it for a check that passed.
fn not_yet(command: &str, item: &str, issue: u32) -> ExitCode {
    eprintln!(
        "xtask {command}: not implemented yet; {item} \
         (https://github.com/opentidehq/opentide/issues/{issue}) implements it"
    );
    ExitCode::FAILURE
}

/// `compare`: whether the runs are equal, or the ledger is valid.
fn run_compare(args: &[String]) -> Result<bool> {
    let mut options: std::collections::BTreeMap<&str, PathBuf> = std::collections::BTreeMap::new();
    let mut check_ledger = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let name = match arg.as_str() {
            "--check-ledger" => {
                check_ledger = true;
                continue;
            }
            name @ ("--oracle" | "--candidate" | "--command" | "--case" | "--ledger"
            | "--report" | "--changelog") => name,
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        };
        let value = args
            .next()
            .map(PathBuf::from)
            .with_context(|| format!("{name} needs a value"))?;
        options.insert(name, value);
    }
    let root = workspace_root()?;
    let ledger_path = options
        .remove("--ledger")
        .unwrap_or_else(|| root.join(compare::LEDGER));
    let changelog_path = options
        .remove("--changelog")
        .unwrap_or_else(|| root.join("CHANGELOG.md"));
    let changelog = std::fs::read_to_string(&changelog_path)
        .with_context(|| format!("read {}", changelog_path.display()))?;
    let ledger = match compare::read_ledger(&ledger_path, &changelog) {
        Ok(ledger) => ledger,
        Err(error) => {
            eprintln!("error: {error:#}");
            return Ok(false);
        }
    };
    if check_ledger {
        if let Some(extra) = options.keys().next() {
            bail!("--check-ledger takes only --ledger and --changelog, not {extra}");
        }
        println!(
            "compare: {} holds {} approved difference(s), each with every field",
            ledger_path.display(),
            ledger.entries.len()
        );
        return Ok(true);
    }
    let required = |name: &str, options: &mut std::collections::BTreeMap<&str, PathBuf>| {
        options
            .remove(name)
            .with_context(|| format!("{name} is required\n\n{USAGE}"))
    };
    let oracle_dir = required("--oracle", &mut options)?;
    let candidate_dir = required("--candidate", &mut options)?;
    let command = required("--command", &mut options)?
        .to_string_lossy()
        .into_owned();
    let case = options
        .remove("--case")
        .map(|case| case.to_string_lossy().into_owned())
        .unwrap_or_default();
    let report_path = options.remove("--report");

    let oracle = compare::read_run(&oracle_dir)?;
    let candidate = compare::read_run(&candidate_dir)?;
    let mut usage = opentide_compare::ledger::Usage::default();
    let report = opentide_compare::compare(
        opentide_compare::Case {
            command: &command,
            id: &case,
        },
        &oracle,
        &candidate,
        &ledger,
        &mut usage,
    );
    for difference in &report.differences {
        let pointer = difference
            .pointer
            .as_deref()
            .map(|pointer| {
                format!(
                    " at {}",
                    if pointer.is_empty() {
                        "the root"
                    } else {
                        pointer
                    }
                )
            })
            .unwrap_or_default();
        let at = difference
            .at
            .as_deref()
            .map(|at| format!(", {at}"))
            .unwrap_or_default();
        eprintln!(
            "error: {} {}{pointer}{at}\n  oracle:    {}\n  candidate: {}",
            difference.target,
            difference.kind.as_str(),
            difference.oracle,
            difference.candidate
        );
    }
    if let Some(path) = &report_path {
        let text = serde_json::to_string_pretty(&report).context("serialise the report")?;
        std::fs::write(path, text + "\n").with_context(|| format!("write {}", path.display()))?;
    }
    if report.equal {
        println!(
            "compare: `{command}` is equal ({} approved difference(s))",
            report.approved.len()
        );
    } else {
        eprintln!(
            "compare: `{command}` differs: {} difference(s){}",
            report.differences.len() + report.omitted,
            if report.approved.is_empty() {
                String::new()
            } else {
                format!(", {} approved", report.approved.len())
            }
        );
    }
    Ok(report.equal)
}

/// The workspace root, found at run time: the parent of `CARGO_MANIFEST_DIR`
/// (`cargo run` sets it to xtask's folder), else the working directory.
fn workspace_root() -> Result<PathBuf> {
    match std::env::var_os("CARGO_MANIFEST_DIR") {
        Some(dir) => PathBuf::from(dir)
            .parent()
            .map(std::path::Path::to_path_buf)
            .context("CARGO_MANIFEST_DIR has no parent"),
        None => std::env::current_dir().context("read the working directory"),
    }
}

/// Runs the check and prints its report: whether the workspace passed.
fn check_layers(args: &[String]) -> Result<bool> {
    let mut metadata_file: Option<PathBuf> = None;
    let mut layers_file: Option<PathBuf> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--metadata" => &mut metadata_file,
            "--layers" => &mut layers_file,
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        };
        *slot = Some(
            args.next()
                .map(PathBuf::from)
                .with_context(|| format!("{arg} needs a FILE"))?,
        );
    }

    let metadata_text = match &metadata_file {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
        }
        None => cargo_metadata()?,
    };
    let metadata = Metadata::parse(&metadata_text).context("parse the cargo metadata")?;
    // The table of the workspace being checked, never a path compiled in: with
    // a CARGO_TARGET_DIR shared between worktrees, cargo may run a binary that
    // another worktree built.
    let layers_file = match layers_file {
        Some(path) => path,
        None => metadata
            .layer_table()
            .context("the metadata names no workspace_root: pass --layers FILE")?,
    };
    let table_text = std::fs::read_to_string(&layers_file)
        .with_context(|| format!("read {}", layers_file.display()))?;
    let table = LayerTable::parse(&table_text)
        .with_context(|| format!("parse {}", layers_file.display()))?;

    let report = layers::check(&table, &metadata);
    for violation in &report.violations {
        eprintln!("error: {violation}");
    }
    if report.passed() {
        println!(
            "check-layers: {} crates in {} layers; all {} dependencies between them point down",
            report.crates, report.layers, report.edges
        );
    } else {
        eprintln!(
            "check-layers: {} violation(s) of the layer table ({})",
            report.violations.len(),
            layers_file.display()
        );
    }
    Ok(report.passed())
}

/// `coverage gate`: prints the report and returns whether every crate met
/// its gate.
fn coverage_command(args: &[String]) -> Result<bool> {
    let Some(("gate", args)) = args.split_first().map(|(c, r)| (c.as_str(), r)) else {
        bail!("expected `coverage gate`\n\n{USAGE}");
    };
    let mut report_file: Option<PathBuf> = None;
    let mut policy_file: Option<PathBuf> = None;
    let mut metadata_file: Option<PathBuf> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--report" => &mut report_file,
            "--policy" => &mut policy_file,
            "--metadata" => &mut metadata_file,
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        };
        *slot = Some(
            args.next()
                .map(PathBuf::from)
                .with_context(|| format!("{arg} needs a FILE"))?,
        );
    }
    let report_file = report_file.context("--report FILE is required")?;

    let metadata_text = match &metadata_file {
        Some(path) => read(path)?,
        None => cargo_metadata()?,
    };
    let members = coverage::members(&metadata_text).context("parse the cargo metadata")?;
    let policy_file = match policy_file {
        Some(path) => path,
        None => Metadata::parse(&metadata_text)
            .context("parse the cargo metadata")?
            .workspace_root
            .context("the metadata names no workspace_root: pass --policy FILE")?
            .join("xtask")
            .join("coverage.toml"),
    };
    let policy = coverage::Policy::parse(&read(&policy_file)?)
        .with_context(|| format!("parse {}", policy_file.display()))?;
    let errors = coverage::check_policy(&policy, &members);
    if !errors.is_empty() {
        for error in &errors {
            eprintln!("error: {error}");
        }
        eprintln!(
            "coverage: {} error(s) in the policy ({})",
            errors.len(),
            policy_file.display()
        );
        return Ok(false);
    }
    let files = coverage::files(&read(&report_file)?)
        .with_context(|| format!("parse {} as llvm-cov's JSON export", report_file.display()))?;
    let report = coverage::gate(&policy, &members, &files);
    print!("{}", report.markdown());
    Ok(report.passed())
}

/// `mutants crates` and `mutants report`. Surviving mutants are not a
/// failure here: the weekly job files them as issues.
fn mutants_command(args: &[String]) -> Result<()> {
    let Some((sub, args)) = args.split_first() else {
        bail!("expected `mutants crates` or `mutants report`\n\n{USAGE}");
    };
    let mut outcomes: Vec<PathBuf> = Vec::new();
    let mut options: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let name = match (sub.as_str(), arg.as_str()) {
            (_, "--policy")
            | ("crates", "--metadata")
            | (
                "report",
                "--outcomes" | "--baseline" | "--issues" | "--run-url" | "--write-baseline"
                | "--commit",
            ) => arg.as_str(),
            _ => bail!("unknown option `{arg}` for `mutants {sub}`\n\n{USAGE}"),
        };
        let value = args
            .next()
            .with_context(|| format!("{arg} needs a value"))?
            .clone();
        if name == "--outcomes" {
            outcomes.push(PathBuf::from(value));
        } else {
            options.insert(name, value);
        }
    }

    let root = || -> Result<PathBuf> {
        Metadata::parse(&cargo_metadata()?)
            .context("parse the cargo metadata")?
            .workspace_root
            .context("the metadata names no workspace_root")
    };
    let policy_file = match options.get("--policy") {
        Some(path) => PathBuf::from(path),
        None => root()?.join("xtask").join("mutants.toml"),
    };
    let policy = mutants::Policy::parse(&read(&policy_file)?)
        .with_context(|| format!("parse {}", policy_file.display()))?;

    match sub.as_str() {
        "crates" => {
            let metadata_text = match options.get("--metadata") {
                Some(path) => read(std::path::Path::new(path))?,
                None => cargo_metadata()?,
            };
            let members = coverage::members(&metadata_text)
                .context("parse the cargo metadata")?
                .into_iter()
                .map(|member| member.name)
                .collect();
            let active = policy.active(&members).map_err(anyhow::Error::msg)?;
            for krate in active {
                println!("{krate}");
            }
            Ok(())
        }
        "report" => {
            if outcomes.is_empty() {
                bail!("--outcomes FILE is required");
            }
            if options.contains_key("--write-baseline") != options.contains_key("--commit") {
                bail!("--write-baseline FILE and --commit SHA go together");
            }
            let runs = outcomes
                .iter()
                .map(|path| {
                    mutants::parse_run(&read(path)?)
                        .with_context(|| format!("parse {} as outcomes.json", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let report = mutants::merge(&policy, &runs).map_err(anyhow::Error::msg)?;
            let baseline = match options.get("--baseline") {
                Some(path) => {
                    let path = PathBuf::from(path);
                    Some(
                        mutants::Baseline::parse(&read(&path)?)
                            .with_context(|| format!("parse {}", path.display()))?,
                    )
                }
                None => None,
            };
            print!("{}", report.markdown(&policy, baseline.as_ref()));
            if let Some(dir) = options.get("--issues") {
                let dir = PathBuf::from(dir);
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("create {}", dir.display()))?;
                let run_url = options.get("--run-url").map_or("this run", String::as_str);
                for (krate, body) in report.issues(&policy, run_url) {
                    let path = dir.join(format!("{krate}.md"));
                    std::fs::write(&path, body)
                        .with_context(|| format!("write {}", path.display()))?;
                }
            }
            if let Some(path) = options.get("--write-baseline") {
                let commit = options
                    .get("--commit")
                    .context("--write-baseline FILE and --commit SHA go together")?;
                let text = report.baseline(commit).to_toml()?;
                std::fs::write(path, text).with_context(|| format!("write {path}"))?;
            }
            Ok(())
        }
        other => bail!("unknown subcommand `mutants {other}`\n\n{USAGE}"),
    }
}

/// `parity dashboard`: writes (or checks) the page; whether it passed.
fn parity_command(args: &[String]) -> Result<bool> {
    let Some(("dashboard", args)) = args.split_first().map(|(c, r)| (c.as_str(), r)) else {
        bail!("expected `parity dashboard`\n\n{USAGE}");
    };
    let mut root: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut engines: Option<PathBuf> = None;
    let mut compare_report: Option<PathBuf> = None;
    let mut check = false;
    let mut require_inputs = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--check" => {
                check = true;
                continue;
            }
            "--require-inputs" => {
                require_inputs = true;
                continue;
            }
            "--root" => &mut root,
            "--out" => &mut out,
            "--engines" => &mut engines,
            "--compare" => &mut compare_report,
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        };
        *slot = Some(
            args.next()
                .map(PathBuf::from)
                .with_context(|| format!("{arg} needs a value"))?,
        );
    }
    let root = match root {
        Some(root) => root,
        None => Metadata::parse(&cargo_metadata()?)
            .context("parse the cargo metadata")?
            .workspace_root
            .context("the metadata names no workspace_root: pass --root DIR")?,
    };
    let out = out.unwrap_or_else(|| root.join("docs").join("internal").join("parity.md"));

    let inputs = parity_inputs::read(&root, engines.as_deref(), compare_report.as_deref())?;
    if require_inputs {
        let missing = parity_inputs::missing_sources(&inputs);
        if !missing.is_empty() {
            for source in &missing {
                eprintln!("error: missing {source}");
            }
            eprintln!(
                "parity: --require-inputs and {} source(s) missing; nothing written",
                missing.len()
            );
            return Ok(false);
        }
    }
    let errors = parity::check(&inputs);
    if !errors.is_empty() {
        for error in &errors {
            eprintln!("error: {error}");
        }
        eprintln!(
            "parity: {} error(s) in the inputs; nothing written",
            errors.len()
        );
        return Ok(false);
    }
    let page = parity::page(&inputs);
    if check {
        let current = std::fs::read_to_string(&out).unwrap_or_default();
        if parity::same_page(&current, &page) {
            println!("parity: {} is up to date", out.display());
            return Ok(true);
        }
        eprintln!(
            "parity: {} differs from the rendering: run `cargo xtask parity dashboard`",
            out.display()
        );
        return Ok(false);
    }
    std::fs::write(&out, &page).with_context(|| format!("write {}", out.display()))?;
    println!(
        "parity: wrote {} ({} recordings)",
        out.display(),
        inputs.goldens.len()
    );
    Ok(true)
}

fn read(path: &std::path::Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

/// `cargo metadata` for the workspace to check: its members and their
/// declared dependencies, without resolving the dependency graph.
///
/// The workspace is found at run time: from `CARGO_MANIFEST_DIR`, which
/// `cargo run` (the `cargo xtask` alias) sets to this package's directory in
/// the workspace it ran, or else from the working directory.
fn cargo_metadata() -> Result<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    command.args(["metadata", "--format-version", "1", "--no-deps"]);
    if let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
        command.current_dir(dir);
    }
    let output = command
        .output()
        .with_context(|| format!("run {} metadata", cargo.to_string_lossy()))?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("cargo metadata printed something other than UTF-8")
}
