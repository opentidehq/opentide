//! `cargo xtask vocab`: the vocabularies' tooling (UC-1.6, #812).
//!
//! - `sync [--check]` ([`sync`]): the bundled vocabularies and schema pins
//!   against `opentidehq/specifications`, and the lockfile; CI's vocabulary
//!   drift gate runs `--check`.
//! - `sentinel-attack [--check] [--stix-dir DIR]` ([`sentinel`]): Sentinel's
//!   ATT&CK v18 list from MITRE's STIX bundles.
//! - `diff --against python` ([`diff`]): `opentide_schema::vocab` against the
//!   oracle, on every corpus.

pub mod diff;
pub mod sentinel;
pub mod sync;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};

/// The usage.
pub const USAGE: &str = "\
usage: cargo xtask vocab <command> [options]

commands:
  sync [--check] [--specifications DIR]
                 copy the vocabularies and schema pins of opentidehq/specifications
                 (DIR, else $OPENTIDE_SPECIFICATIONS_ROOT, else ../specifications)
                 over the bundled ones and rewrite data/specifications.lock.json;
                 --check fails on any drift instead. Without a checkout, --check
                 compares the lockfile with the bundle alone
  sentinel-attack [--check] [--stix-dir DIR]
                 write src/opentide/data/sentinel/attack-v18.json from MITRE's
                 STIX bundles (downloaded, or read from an attack-stix-data
                 checkout DIR); --check fails when the file would change
  diff --against python [--fixture NAME ...] [--python PATH] [--per-field N]
       [--report FILE]
                 resolve every vocabulary value of every corpus (the fixtures of
                 tests/golden/cases.toml) and generated misspellings with the
                 oracle and with opentide-schema, and compare; suggestion
                 differences on corpus values must be in tests/golden/vocab/APPROVED.toml
  help           print this message

exit status: 0 passed, 1 a check failed, 2 usage error or the check could not run
";

/// Runs `cargo xtask vocab ARGS`.
pub fn main(args: &[String]) -> ExitCode {
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "sync" => run_sync(rest),
        "sentinel-attack" => run_sentinel(rest),
        "diff" => diff::parse(rest).and_then(|options| diff::run(&options)),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => {
            eprint!("xtask vocab: unknown command `{other}`\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// The repository root: the parent of xtask's manifest directory, found at
/// run time (`CARGO_MANIFEST_DIR` as `cargo run` sets it), else the working
/// directory.
fn repo_root() -> Result<PathBuf> {
    match std::env::var_os("CARGO_MANIFEST_DIR") {
        Some(dir) => Path::new(&dir)
            .parent()
            .map(Path::to_path_buf)
            .context("CARGO_MANIFEST_DIR has no parent"),
        None => std::env::current_dir().context("the working directory"),
    }
}

fn run_sync(args: &[String]) -> Result<bool> {
    let mut check = false;
    let mut specifications = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--check" => check = true,
            "--specifications" => {
                specifications = Some(PathBuf::from(
                    args.next().context("--specifications needs a directory")?,
                ));
            }
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    let repo = repo_root()?;
    let specifications = specifications
        .or_else(|| std::env::var_os(sync::SPECIFICATIONS_ENV).map(PathBuf::from))
        .unwrap_or_else(|| repo.join("../specifications"));
    let mut out = String::new();
    let passed = sync::run(&sync::Paths::new(&repo, &specifications), check, &mut out);
    print!("{out}");
    passed
}

fn run_sentinel(args: &[String]) -> Result<bool> {
    let mut check = false;
    let mut stix_dir = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--check" => check = true,
            "--stix-dir" => {
                stix_dir = Some(PathBuf::from(
                    args.next().context("--stix-dir needs a directory")?,
                ));
            }
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    let repo = repo_root()?;
    sentinel::run(
        &repo.join("src/opentide/data/vocabulary/att&ck.vocab.toml"),
        &repo.join("src/opentide/data/sentinel/attack-v18.json"),
        stix_dir.as_deref(),
        check,
    )
}
