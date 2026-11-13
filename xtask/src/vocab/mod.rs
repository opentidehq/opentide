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
  ingest [--check|--apply] [--no-fetch] [--stix-dir DIR] [--misp-url URL]
         [--specifications DIR] [--now TIMESTAMP]
                 fetch the latest MITRE ATT&CK STIX release (into DIR, else
                 $OPENTIDE_ATTACK_STIX_DIR, else a scratch directory; --no-fetch
                 reads DIR) and the MISP threat-actor galaxy (URL, else the
                 bundled resources.toml's; file:// reads a file), and merge them
                 into the specifications checkout's att&ck, att&ck.groups,
                 mitigations, datasources and actors vocabularies with per-key
                 versions; --apply writes them and syncs the bundle, otherwise
                 it exits 1 when they would change. Schema pins never move.
                 --now fixes the timestamps it writes, for a reproducible run
  malapi [--check|--apply] [--specifications DIR] [--html-dir DIR]
         [--delay SECS] [--now TIMESTAMP]
                 scrape malapi.io's attack categories and API pages (or read
                 saved pages: DIR/index.html, DIR/winapi/<API>.html) and merge
                 them into the specifications checkout's malapi vocabulary
                 with per-key versions; --apply writes it and syncs the bundle,
                 otherwise it exits 1 when it would change. Pages are fetched
                 one at a time, SECS apart (default 60: the site serves about
                 a page a minute). A run the site stops part-way keeps the
                 keys it did not reach; --apply writes it, unsynced, and exits 1.
                 --now fixes source_fetched_at, for a reproducible run
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
        "ingest" => ingest::parse(rest).and_then(|options| ingest::run(&repo_root()?, &options)),
        "malapi" => malapi::parse(rest).and_then(|options| malapi::run(&repo_root()?, &options)),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn words(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn the_command_line_exit_statuses() {
        let usage = ExitCode::from(2);
        assert_eq!(main(&[]), usage, "no command");
        assert_eq!(main(&words(&["frobnicate"])), usage);
        assert_eq!(main(&words(&["help"])), ExitCode::SUCCESS);
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
            assert_eq!(main(&words(args)), usage, "{args:?}");
        }
    }

    #[test]
    fn the_sync_check_without_a_checkout_compares_the_lockfile_with_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("specifications");
        assert!(
            run_sync(&words(&[
                "--check",
                "--specifications",
                &absent.to_string_lossy()
            ]))
            .unwrap()
        );
        assert_eq!(
            main(&words(&[
                "sync",
                "--check",
                "--specifications",
                &absent.to_string_lossy()
            ])),
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
            main(&words(&[
                "sentinel-attack",
                "--check",
                "--stix-dir",
                &empty.path().to_string_lossy()
            ])),
            ExitCode::from(2)
        );
        assert_eq!(std::fs::read(&output).unwrap(), before);
    }

    #[test]
    fn the_repository_root_holds_xtask() {
        assert!(repo_root().unwrap().join("xtask/Cargo.toml").is_file());
    }
}
