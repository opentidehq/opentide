//! `cargo xtask <command>`: the repository's Rust tooling (`xtask/AGENTS.md`).
//!
//! Exit status: 0 when the command passed, 1 when a check failed or the
//! command is not implemented yet, 2 on a usage error or when the check could
//! not run (no `cargo metadata`, an unreadable file).

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use xtask::compare;
use xtask::layers::{self, LayerTable, Metadata};
use xtask::{coverage, mutants};

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
    /// The crates the weekly mutation run mutates, and its report
    /// (xtask/mutants.toml)
    Mutants {
        #[command(subcommand)]
        command: MutantsCmd,
    },
    /// Compare a candidate's run with the oracle's, applying the approved-diffs
    /// ledger (tests/golden/APPROVED_DIFFS.toml), or check the ledger itself
    Compare(CompareArgs),
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
    /// Resolve every fixture and generated workspace's configuration with
    /// opentide-schema and compare it with the oracle's (UC-1.5, #811)
    Config {
        #[command(subcommand)]
        command: xtask::config::Cmd,
    },
    /// Load every corpus with opentide-workspace and compare its index with
    /// the Python registry's (UC-2.1, #816)
    Registry {
        #[command(subcommand)]
        command: xtask::registry::Cmd,
    },
    /// For each fault kind `opentide validate` reports, the language server's
    /// published diagnostics against validate's findings (UC-2.6, #821)
    Lsp {
        #[command(subcommand)]
        command: xtask::lsp::Cmd,
    },
    /// Run opentide-workspace's validate on every recorded `validate --json`
    /// case and compare it with the recording (UC-2.2, #817; UC-2.3, #818)
    Validate {
        #[command(subcommand)]
        command: xtask::diff_args::DiffCmd,
    },
    /// Run opentide-workspace's lint on every recorded `lint --json` case and
    /// compare it with the recording (UC-2.3, #818)
    Lint {
        #[command(subcommand)]
        command: xtask::diff_args::DiffCmd,
    },
    /// Write the artifacts generated from the Rust model (the platform
    /// templates); `--check` compares them (UC-1.8, #814)
    Codegen(xtask::codegen::CodegenArgs),
    /// Record the MCP sessions from the Python server and replay them against
    /// the Rust server (UC-3.7, #829)
    Mcp {
        #[command(subcommand)]
        command: xtask::mcp::Cmd,
    },
    /// The recorded-HTTP cassettes of tests/cassettes (UC-4.1, #831)
    Cassettes {
        #[command(subcommand)]
        command: xtask::cassettes::Cmd,
    },
    /// Record what the frozen Python CLI does, and check an engine against the
    /// recordings (tests/golden/README.md); `golden --help` lists the commands
    Golden {
        #[command(subcommand)]
        command: xtask::golden::Cmd,
    },
    /// Run the benchmarks against their budgets (UC-0.8, #806)
    Bench(xtask::bench::BenchArgs),
    /// The deploy compile's request bodies against the oracle's (UC-3.1, #823)
    Payloads {
        #[command(subcommand)]
        command: xtask::payloads::Cmd,
    },
    /// The vocabularies: sync, generate, compare and ingest (UC-1.6, #812);
    /// `vocab --help` lists the commands
    Vocab {
        #[command(subcommand)]
        command: xtask::vocab::Cmd,
    },
    /// The object models against the oracle: their JSON Schemas, and their
    /// verdict on every object file of every corpus (UC-1.3, #809)
    Schema {
        #[command(subcommand)]
        command: xtask::schema::Cmd,
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

#[derive(Subcommand)]
enum MutantsCmd {
    /// Print the crates the weekly mutation run mutates, one per line
    Crates {
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        metadata: Option<PathBuf>,
    },
    /// Merge cargo-mutants' outcomes.json of every shard and print the scores
    /// against the baseline
    Report {
        /// One shard's outcomes.json; repeat for every shard
        #[arg(long, value_name = "FILE", required = true)]
        outcomes: Vec<PathBuf>,
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        baseline: Option<PathBuf>,
        /// Write DIR/<crate>.md for each crate whose surviving mutants exceed
        /// its threshold
        #[arg(long, value_name = "DIR")]
        issues: Option<PathBuf>,
        #[arg(long, value_name = "URL")]
        run_url: Option<String>,
        /// Record this run as the baseline
        #[arg(long, value_name = "FILE", requires = "commit")]
        write_baseline: Option<PathBuf>,
        #[arg(long, value_name = "SHA", requires = "write_baseline")]
        commit: Option<String>,
    },
}

#[derive(Args)]
struct CompareArgs {
    /// Check the ledger's schema, and that CHANGELOG.md holds each entry's
    /// changelog reference, instead of comparing two runs
    #[arg(
        long,
        conflicts_with_all = ["oracle", "candidate", "command", "case", "report"]
    )]
    check_ledger: bool,
    /// The oracle's run: a folder with exit_code, stdout, stderr, files/ and
    /// deleted
    #[arg(long, value_name = "DIR", required_unless_present = "check_ledger")]
    oracle: Option<PathBuf>,
    #[arg(long, value_name = "DIR", required_unless_present = "check_ledger")]
    candidate: Option<PathBuf>,
    #[arg(long, value_name = "PATH", required_unless_present = "check_ledger")]
    command: Option<String>,
    #[arg(long, value_name = "ID", default_value = "")]
    case: String,
    #[arg(long, value_name = "FILE")]
    ledger: Option<PathBuf>,
    /// Write the JSON report to FILE
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    changelog: Option<PathBuf>,
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
        Cmd::Mutants { command } => verdict("mutants", mutants_command(&command).map(|()| true)),
        Cmd::Compare(args) => verdict("compare", run_compare(&args)),
        Cmd::Conformance(args) => status("conformance", xtask::conformance::cli::run(&args)),
        Cmd::Corpus { command } => status("corpus", xtask::corpus::cli::run_command(&command)),
        Cmd::Config { command } => status("config", xtask::config::run(&command)),
        Cmd::Registry { command } => status("registry", xtask::registry::run(&command)),
        Cmd::Lsp { command } => status("lsp", xtask::lsp::run(&command)),
        Cmd::Validate { command } => status("validate", xtask::validate::run(&command)),
        Cmd::Lint { command } => status("lint", xtask::lint::run(&command)),
        Cmd::Codegen(args) => status("codegen", xtask::codegen::run(&args)),
        Cmd::Mcp { command } => status("mcp", xtask::mcp::run(&command)),
        Cmd::Cassettes { command } => status("cassettes", xtask::cassettes::run(&command)),
        Cmd::Golden { command } => xtask::golden::main(command),
        Cmd::Bench(args) => xtask::bench::main(args),
        Cmd::Payloads { command } => xtask::payloads::main(&command),
        Cmd::Vocab { command } => xtask::vocab::main(&command),
        Cmd::Schema { command } => xtask::schema::main(&command),
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

/// `compare`: whether the runs are equal, or the ledger is valid.
fn run_compare(args: &CompareArgs) -> Result<bool> {
    let root = workspace_root()?;
    let ledger_path = args
        .ledger
        .clone()
        .unwrap_or_else(|| root.join(compare::LEDGER));
    let changelog_path = args
        .changelog
        .clone()
        .unwrap_or_else(|| root.join("CHANGELOG.md"));
    let changelog = read(&changelog_path)?;
    let ledger = match compare::read_ledger(&ledger_path, &changelog) {
        Ok(ledger) => ledger,
        Err(error) => {
            eprintln!("error: {error:#}");
            return Ok(false);
        }
    };
    if args.check_ledger {
        println!(
            "compare: {} holds {} approved difference(s), each with every field",
            ledger_path.display(),
            ledger.entries.len()
        );
        return Ok(true);
    }
    // clap requires all three unless `--check-ledger` is given.
    let (Some(oracle_dir), Some(candidate_dir), Some(command)) =
        (&args.oracle, &args.candidate, &args.command)
    else {
        bail!("--oracle, --candidate and --command are required");
    };
    let case = &args.case;
    let report_path = args.report.as_deref();

    let oracle = compare::read_run(oracle_dir)?;
    let candidate = compare::read_run(candidate_dir)?;
    let mut usage = opentide_compare::ledger::Usage::default();
    let report = opentide_compare::compare(
        opentide_compare::Case { command, id: case },
        &oracle,
        &candidate,
        &ledger,
        &mut usage,
    );
    print_differences(&report);
    if let Some(path) = report_path {
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

/// Each difference of a comparison, on stderr.
fn print_differences(report: &opentide_compare::CaseReport) {
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
}

/// The workspace root, found at run time: the parent of `CARGO_MANIFEST_DIR`
/// (`cargo run` sets it to xtask's folder), else the working directory.
fn workspace_root() -> Result<PathBuf> {
    match std::env::var_os("CARGO_MANIFEST_DIR") {
        Some(dir) => PathBuf::from(dir)
            .parent()
            .map(Path::to_path_buf)
            .context("CARGO_MANIFEST_DIR has no parent"),
        None => std::env::current_dir().context("read the working directory"),
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

/// `mutants crates` and `mutants report`. Surviving mutants are not a
/// failure here: the weekly job files them as issues.
fn mutants_command(command: &MutantsCmd) -> Result<()> {
    let policy_arg = match command {
        MutantsCmd::Crates { policy, .. } | MutantsCmd::Report { policy, .. } => policy,
    };
    let policy_file = match policy_arg {
        Some(path) => path.clone(),
        None => Metadata::parse(&cargo_metadata()?)
            .context("parse the cargo metadata")?
            .workspace_root
            .context("the metadata names no workspace_root")?
            .join("xtask")
            .join("mutants.toml"),
    };
    let policy = mutants::Policy::parse(&read(&policy_file)?)
        .with_context(|| format!("parse {}", policy_file.display()))?;

    match command {
        MutantsCmd::Crates { metadata, .. } => {
            let metadata_text = match metadata {
                Some(path) => read(path)?,
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
        MutantsCmd::Report {
            outcomes,
            baseline,
            issues,
            run_url,
            write_baseline,
            commit,
            ..
        } => report_mutants(
            &policy,
            outcomes,
            baseline.as_deref(),
            issues.as_deref(),
            run_url.as_deref(),
            write_baseline.as_deref().zip(commit.as_deref()),
        ),
    }
}

/// `mutants report`: the shards merged and scored against the baseline.
fn report_mutants(
    policy: &mutants::Policy,
    outcomes: &[PathBuf],
    baseline: Option<&Path>,
    issues: Option<&Path>,
    run_url: Option<&str>,
    write_baseline: Option<(&Path, &str)>,
) -> Result<()> {
    let runs = outcomes
        .iter()
        .map(|path| {
            mutants::parse_run(&read(path)?)
                .with_context(|| format!("parse {} as outcomes.json", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let report = mutants::merge(policy, &runs).map_err(anyhow::Error::msg)?;
    let baseline = match baseline {
        Some(path) => Some(
            mutants::Baseline::parse(&read(path)?)
                .with_context(|| format!("parse {}", path.display()))?,
        ),
        None => None,
    };
    print!("{}", report.markdown(policy, baseline.as_ref()));
    if let Some(dir) = issues {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        for (krate, body) in report.issues(policy, run_url.unwrap_or("this run")) {
            let path = dir.join(format!("{krate}.md"));
            std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        }
    }
    // clap makes `--write-baseline` and `--commit` require each other.
    if let Some((path, commit)) = write_baseline {
        let text = report.baseline(commit).to_toml()?;
        std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
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
