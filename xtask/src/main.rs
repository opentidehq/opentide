//! `cargo xtask <command>`: the repository's Rust tooling (`xtask/AGENTS.md`).
//!
//! Exit status: 0 when the command passed, 1 when a check failed or the
//! command is not implemented yet, 2 on a usage error or when the check could
//! not run (no `cargo metadata`, an unreadable file).

// Slicing a `str` by byte index panics off a char boundary, and this crate
// reads the repository's files and tools' output: every slice is checked or
// says why it is safe (#1946; the lint moves to `[workspace.lints]` once every
// crate is clean).
#![warn(clippy::string_slice)]

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use xtask::coverage;
use xtask::layers::{self, LayerTable, Metadata};

/// The repository's Rust tooling.
///
/// Exit status: 0 passed, 1 a check failed or the command is not implemented
/// yet, 2 a usage error or the check could not run.
#[derive(Parser)]
#[command(
    name = "xtask",
    bin_name = "cargo xtask",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check that every dependency between workspace crates points down the
    /// layer table (xtask/layers.toml, plan section 4)
    CheckLayers(CheckLayersArgs),
    /// Check each workspace crate's line coverage against its gate
    /// (xtask/coverage.toml, plan section 5.4)
    Coverage {
        #[command(subcommand)]
        command: CoverageCmd,
    },
    /// Run every operation of tests/conformance/manifest.json on every corpus
    /// through the Rust, Python and Node SDKs and require byte-identical
    /// documents (UC-5.4, #839)
    Conformance(xtask::conformance::cli::ConformanceArgs),
    /// Generate the heavy workspace, run the fault catalogue against the
    /// oracle, report coverage (UC-0.6, #804); `corpus help` lists its commands
    Corpus {
        #[command(subcommand)]
        command: xtask::corpus::cli::Cmd,
    },
    /// For each fault kind `opentide validate` reports, the language server's
    /// published diagnostics against validate's findings (UC-2.6, #821)
    Lsp {
        #[command(subcommand)]
        command: xtask::lsp::Cmd,
    },
    /// Write the artifacts generated from the Rust model (the platform
    /// templates); `--check` compares them (UC-1.8, #814)
    Codegen(xtask::codegen::CodegenArgs),
    /// The recorded-HTTP cassettes of tests/cassettes (UC-4.1, #831)
    Cassettes {
        #[command(subcommand)]
        command: xtask::cassettes::Cmd,
    },
    /// Run the benchmarks against their budgets (UC-0.8, #806)
    Bench(xtask::bench::BenchArgs),
    /// Count each language's parse and analysis in instructions (callgrind) and
    /// hold them to tests/bench/instructions.toml (#1571, ADR 0014)
    Throughput(xtask::throughput::ThroughputArgs),
    /// The vocabularies: sync, generate and ingest (UC-1.6, #812);
    /// `vocab --help` lists the commands
    Vocab {
        #[command(subcommand)]
        command: xtask::vocab::Cmd,
    },
    /// Check every model field's description against its row in the field
    /// tables of the specifications checkout
    ///
    /// The checkout is DIR, else $OPENTIDE_SPECIFICATIONS_ROOT, else
    /// ../specifications: specs/platforms/*.md, specs/objects/*-1.0.md and
    /// specs/metadata.md. --list prints each row it matched with a model field.
    ///
    /// Exit status: 0 no drift, 1 drift (or fewer rows matched than the
    /// floor), 2 usage error or no checkout.
    SpecFields(xtask::spec_fields::SpecFieldsArgs),
    /// Generate src/opentide/_native/models.pyi and sdk.pyi from the
    /// extension's introspection data (UC-1.9, #815; UC-5.2b, #837)
    Stubs(xtask::stubs::StubsArgs),
}

#[derive(Args)]
struct CheckLayersArgs {
    /// Read `cargo metadata --format-version 1` output from FILE instead of
    /// running cargo
    #[arg(long, value_name = "FILE")]
    metadata: Option<PathBuf>,
    /// Read another layer table than the workspace's xtask/layers.toml
    #[arg(long, value_name = "FILE")]
    layers: Option<PathBuf>,
}

#[derive(Subcommand)]
enum CoverageCmd {
    /// Print a Markdown table of every crate's coverage and fail below a gate
    Gate {
        /// The export of `cargo llvm-cov report --json --summary-only`
        #[arg(long, value_name = "FILE")]
        report: PathBuf,
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        metadata: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    // The benchmarks call this binary for their child processes; those modes are
    // not part of the command line.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if let [verb, rest @ ..] = raw.as_slice()
        && verb == "bench"
        && let Some(code) = xtask::bench::internal(rest)
    {
        return code;
    }
    let command = Cli::parse().command;
    match command {
        Cmd::CheckLayers(args) => verdict("check-layers", check_layers(&args)),
        Cmd::Coverage { command } => verdict("coverage", coverage_command(&command)),
        Cmd::Conformance(args) => status("conformance", xtask::conformance::cli::run(&args)),
        Cmd::Corpus { command } => status("corpus", xtask::corpus::cli::run_command(&command)),
        Cmd::Lsp { command } => status("lsp", xtask::lsp::run(&command)),
        Cmd::Codegen(args) => status("codegen", xtask::codegen::run(&args)),
        Cmd::Cassettes { command } => status("cassettes", xtask::cassettes::run(&command)),
        Cmd::Bench(args) => xtask::bench::main(args),
        Cmd::Throughput(args) => xtask::throughput::main(&args),
        Cmd::Vocab { command } => xtask::vocab::main(&command),
        Cmd::SpecFields(args) => xtask::spec_fields::main(&args),
        Cmd::Stubs(args) => xtask::stubs::main(&args),
    }
}

/// A check's result as the exit status: 0 passed, 1 failed, 2 could not run.
fn verdict(name: &str, result: Result<bool>) -> ExitCode {
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("xtask {name}: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// A command's own exit code, or 2 when it could not run.
fn status(name: &str, result: Result<u8>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("xtask {name}: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// Runs the check and prints its report: whether the workspace passed.
fn check_layers(args: &CheckLayersArgs) -> Result<bool> {
    let metadata_text = match &args.metadata {
        Some(path) => read(path)?,
        None => cargo_metadata()?,
    };
    let metadata = Metadata::parse(&metadata_text).context("parse the cargo metadata")?;
    // The table of the workspace being checked, never a path compiled in: with
    // a CARGO_TARGET_DIR shared between worktrees, cargo may run a binary that
    // another worktree built.
    let layers_file = match &args.layers {
        Some(path) => path.clone(),
        None => metadata
            .layer_table()
            .context("the metadata names no workspace_root: pass --layers FILE")?,
    };
    let table_text = read(&layers_file)?;
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
fn coverage_command(command: &CoverageCmd) -> Result<bool> {
    let CoverageCmd::Gate {
        report: report_file,
        policy: policy_file,
        metadata: metadata_file,
    } = command;
    let metadata_text = match metadata_file {
        Some(path) => read(path)?,
        None => cargo_metadata()?,
    };
    let members = coverage::members(&metadata_text).context("parse the cargo metadata")?;
    let policy_file = match policy_file {
        Some(path) => path.clone(),
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
    let files = coverage::files(&read(report_file)?)
        .with_context(|| format!("parse {} as llvm-cov's JSON export", report_file.display()))?;
    let report = coverage::gate(&policy, &members, &files);
    print!("{}", report.markdown());
    Ok(report.passed())
}

fn read(path: &Path) -> Result<String> {
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
