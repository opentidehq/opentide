//! `cargo xtask vocab`: the vocabularies' tooling (UC-1.6, #812).
//!
//! - `sync [--check]` ([`sync`]): the bundled vocabularies and schema pins
//!   against `opentidehq/specifications`, and the lockfile; CI's vocabulary
//!   drift gate runs `--check`.
//! - `sentinel-attack [--check] [--stix-dir DIR]` ([`sentinel`]): Sentinel's
//!   ATT&CK v18 list from MITRE's STIX bundles.
//! - `diff --against python` ([`diff`]): `opentide_schema::vocab` against the
//!   oracle, on every corpus.
//! - `ingest [--check|--apply]` ([`ingest`]): the weekly ATT&CK and MISP
//!   ingest into the specifications' vocabularies.
//! - `malapi [--check|--apply]` ([`malapi`]): the MalAPI vocabulary scraped
//!   from malapi.io, by hand.

pub mod diff;
pub mod ingest;
pub mod malapi;
pub mod sentinel;
pub mod sync;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};

/// `cargo xtask vocab <command>`: the vocabularies. Exit status: 0 passed, 1 a
/// check failed, 2 usage error or the check could not run.
#[derive(clap::Subcommand, Debug)]
pub enum Cmd {
    /// Copy the vocabularies and schema pins of opentidehq/specifications over
    /// the bundled ones and rewrite data/specifications.lock.json; --check fails
    /// on any drift instead. Without a checkout, --check compares the lockfile
    /// with the bundle alone
    Sync {
        /// Fail on any drift instead of writing
        #[arg(long)]
        check: bool,
        /// The checkout: DIR, else $OPENTIDE_SPECIFICATIONS_ROOT, else
        /// ../specifications
        #[arg(long, value_name = "DIR")]
        specifications: Option<PathBuf>,
    },
    /// Write src/opentide/data/sentinel/attack-v18.json from MITRE's STIX
    /// bundles (downloaded, or read from an attack-stix-data checkout)
    SentinelAttack {
        /// Fail when the file would change
        #[arg(long)]
        check: bool,
        /// Read the STIX bundles from an attack-stix-data checkout
        #[arg(long, value_name = "DIR")]
        stix_dir: Option<PathBuf>,
    },
    /// Resolve every vocabulary value of every corpus (the fixtures of
    /// tests/golden/cases.toml) and generated misspellings with the oracle and
    /// with opentide-schema, and compare; suggestion differences on corpus
    /// values must be in tests/golden/vocab/APPROVED.toml
    Diff(diff::Options),
    /// Fetch the latest MITRE ATT&CK STIX release and the MISP threat-actor
    /// galaxy, and merge them into the specifications checkout's att&ck,
    /// att&ck.groups, mitigations, datasources and actors vocabularies with
    /// per-key versions; --apply writes them and syncs the bundle, otherwise it
    /// exits 1 when they would change. Schema pins never move
    Ingest(ingest::Options),
    /// Scrape malapi.io's attack categories and API pages (or read saved
    /// pages) and merge them into the specifications checkout's malapi
    /// vocabulary with per-key versions; --apply writes it and syncs the
    /// bundle, otherwise it exits 1 when it would change. A run the site stops
    /// part-way keeps the keys it did not reach; --apply writes it, unsynced,
    /// and exits 1
    Malapi(malapi::Options),
}

/// Runs `cargo xtask vocab <command>`.
pub fn main(command: &Cmd) -> ExitCode {
    let result = match command {
        Cmd::Sync {
            check,
            specifications,
        } => run_sync(*check, specifications.clone()),
        Cmd::SentinelAttack { check, stix_dir } => run_sentinel(*check, stix_dir.as_deref()),
        Cmd::Ingest(options) => repo_root().and_then(|root| ingest::run(&root, options)),
        Cmd::Malapi(options) => repo_root().and_then(|root| malapi::run(&root, options)),
        Cmd::Diff(options) => diff::run(options),
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

fn run_sync(check: bool, specifications: Option<PathBuf>) -> Result<bool> {
    let repo = repo_root()?;
    let specifications = specifications
        .or_else(|| std::env::var_os(sync::SPECIFICATIONS_ENV).map(PathBuf::from))
        .unwrap_or_else(|| repo.join("../specifications"));
    let mut out = String::new();
    let passed = sync::run(&sync::Paths::new(&repo, &specifications), check, &mut out);
    print!("{out}");
    passed
}

fn run_sentinel(check: bool, stix_dir: Option<&Path>) -> Result<bool> {
    let repo = repo_root()?;
    sentinel::run(
        &repo.join("src/opentide/data/vocabulary/att&ck.vocab.toml"),
        &repo.join("src/opentide/data/sentinel/attack-v18.json"),
        stix_dir,
        check,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `vocab <args>` as the command line parses it: the exit status of a
    /// usage error, else of the run.
    fn exit(args: &[&str]) -> ExitCode {
        match crate::parse_subcommand::<Cmd>(args) {
            Ok(command) => main(&command),
            Err(error) => ExitCode::from(u8::try_from(error.exit_code()).unwrap()),
        }
    }

    #[test]
    fn the_command_line_exit_statuses() {
        let usage = ExitCode::from(2);
        assert_eq!(exit(&[]), usage, "no command");
        assert_eq!(exit(&["frobnicate"]), usage);
        assert_eq!(exit(&["help"]), ExitCode::SUCCESS);
        for args in [
            &["sync", "--frobnicate"][..],
            &["sync", "--specifications"],
            &["sentinel-attack", "--frobnicate"],
            &["sentinel-attack", "--stix-dir"],
            &["diff"],
            &["ingest", "--check", "--apply"],
            &["ingest", "--frobnicate"],
            &["ingest", "--misp-url"],
            &["malapi", "--check", "--apply"],
            &["malapi", "--delay", "soon"],
            &["malapi", "--html-dir"],
        ] {
            assert_eq!(exit(args), usage, "{args:?}");
        }
    }

    #[test]
    fn the_sync_check_without_a_checkout_compares_the_lockfile_with_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("specifications");
        assert!(run_sync(true, Some(absent.clone())).unwrap());
        assert_eq!(
            exit(&[
                "sync",
                "--check",
                "--specifications",
                &absent.to_string_lossy()
            ]),
            ExitCode::SUCCESS
        );
        assert!(!absent.exists(), "a check writes nothing");
    }

    #[test]
    fn the_sentinel_check_needs_the_stix_bundles() {
        let empty = tempfile::tempdir().unwrap();
        let output = repo_root()
            .unwrap()
            .join("src/opentide/data/sentinel/attack-v18.json");
        let before = std::fs::read(&output).unwrap();
        assert_eq!(
            exit(&[
                "sentinel-attack",
                "--check",
                "--stix-dir",
                &empty.path().to_string_lossy()
            ]),
            ExitCode::from(2)
        );
        assert_eq!(std::fs::read(&output).unwrap(), before);
    }

    #[test]
    fn the_repository_root_holds_xtask() {
        assert!(repo_root().unwrap().join("xtask/Cargo.toml").is_file());
    }
}
