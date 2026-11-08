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
  parity dashboard [--root DIR] [--out FILE] [--check]
                 render the parity dashboard (each command x corpus x mode
                 against the oracle, approved diffs, fault coverage) into FILE,
                 by default docs/internal/parity.md; --check fails when FILE
                 differs from the rendering instead of writing it
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
            (_, "--policy" | "--metadata")
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
                    .context("--write-baseline needs --commit SHA")?;
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
    let mut check = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--check" => {
                check = true;
                continue;
            }
            "--root" => &mut root,
            "--out" => &mut out,
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

    let inputs = parity_inputs::read(&root)?;
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
        if current == page {
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
