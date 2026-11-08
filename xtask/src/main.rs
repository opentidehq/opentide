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

const USAGE: &str = "\
usage: cargo xtask <command> [options]

commands:
  check-layers [--metadata FILE] [--layers FILE]
                 check that every dependency between workspace crates points
                 down the layer table (xtask/layers.toml, plan section 4).
                 --metadata reads `cargo metadata --format-version 1` output
                 from FILE instead of running cargo; --layers reads another table
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
  codegen        generate schemas, stubs, types and references (UC-1.8, #814)
  golden <record|check|diff|lock|coverage> [options]
                 record what the frozen Python CLI does, and check an engine
                 against the recordings (tests/golden/README.md);
                 `cargo xtask golden help` lists the options
  bench          run the benchmarks against their budgets (UC-0.8, #806)
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
        "codegen" => not_yet("codegen", "UC-1.8", 814),
        "golden" => xtask::golden::main(rest),
        "bench" => not_yet("bench", "UC-0.8", 806),
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
