//! `cargo xtask <command>`: the repository's Rust tooling (`xtask/AGENTS.md`).
//!
//! Exit status: 0 when the command passed, 1 when a check failed or the
//! command is not implemented yet, 2 on a usage error or when the check could
//! not run (no `cargo metadata`, an unreadable file).

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use xtask::layers::{self, LayerTable, Metadata};

const USAGE: &str = "\
usage: cargo xtask <command> [options]

commands:
  check-layers [--metadata FILE] [--layers FILE]
                 check that every dependency between workspace crates points
                 down the layer table (xtask/layers.toml, plan section 4).
                 --metadata reads `cargo metadata --format-version 1` output
                 from FILE instead of running cargo; --layers reads another table
  corpus <command>
                 generate the heavy workspace, run the fault catalogue
                 against the oracle, report coverage (UC-0.6, #804);
                 `cargo xtask corpus help` lists its commands
  codegen        generate schemas, stubs, types and references (UC-1.8, #814)
  golden         record and check the oracle's goldens (UC-0.5, #803)
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
        "corpus" => match xtask::corpus::cli::run(rest) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("xtask corpus: {error:#}");
                ExitCode::from(2)
            }
        },
        "codegen" => not_yet("codegen", "UC-1.8", 814),
        "golden" => not_yet("golden", "UC-0.5", 803),
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
