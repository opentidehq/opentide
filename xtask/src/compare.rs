//! `cargo xtask compare`: the differential comparator (`opentide-compare`)
//! over runs on disk, and the check of the approved-diffs ledger.
//!
//! A run on disk is a folder:
//!
//! | Path | Holds |
//! |------|-------|
//! | `exit_code` | the exit code, in decimal |
//! | `stdout`, `stderr` | the bytes of each stream |
//! | `files/<path>` | each file the command created or changed, with its mode |
//! | `deleted` | the files it deleted, one relative path per line (optional) |
//!
//! `golden check --engine compare` (UC-0.5, #803) reads its recordings
//! instead, and compares them with the same library.

use anyhow::{Context, Result, bail};
use opentide_compare::ledger::Ledger;
use opentide_compare::{FileState, Run};
use std::collections::BTreeMap;
use std::path::Path;

/// The ledger's place in the repository.
pub const LEDGER: &str = "tests/golden/APPROVED_DIFFS.toml";

/// Reads the run in the folder `dir`.
pub fn read_run(dir: &Path) -> Result<Run> {
    let exit_text = std::fs::read_to_string(dir.join("exit_code"))
        .with_context(|| format!("read {}", dir.join("exit_code").display()))?;
    let exit_code = exit_text.trim().parse().with_context(|| {
        format!(
            "{}: not an exit code: {exit_text:?}",
            dir.join("exit_code").display()
        )
    })?;
    let stream = |name: &str| -> Result<Vec<u8>> {
        let path = dir.join(name);
        std::fs::read(&path).with_context(|| format!("read {}", path.display()))
    };
    let mut files = BTreeMap::new();
    let written = dir.join("files");
    if written.is_dir() {
        collect_files(&written, &written, &mut files)?;
    }
    let deleted = dir.join("deleted");
    if deleted.is_file() {
        let text = std::fs::read_to_string(&deleted)
            .with_context(|| format!("read {}", deleted.display()))?;
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if files.insert(line.to_owned(), FileState::Deleted).is_some() {
                bail!("{}: {line} is both written and deleted", dir.display());
            }
        }
    }
    Ok(Run {
        exit_code,
        stdout: stream("stdout")?,
        stderr: stream("stderr")?,
        files,
    })
}

fn collect_files(root: &Path, dir: &Path, files: &mut BTreeMap<String, FileState>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("read {}", dir.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = entry
            .file_type()
            .with_context(|| format!("stat {}", path.display()))?;
        if kind.is_dir() {
            collect_files(root, &path, files)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
        let name = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        files.insert(
            name,
            FileState::Written {
                mode: mode(
                    &entry
                        .metadata()
                        .with_context(|| format!("stat {}", path.display()))?,
                ),
                bytes,
            },
        );
    }
    Ok(())
}

#[cfg(unix)]
fn mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode(metadata: &std::fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

/// Reads and checks the ledger at `path`, and that `changelog` (the text of
/// `CHANGELOG.md`) holds every entry's changelog reference.
pub fn read_ledger(path: &Path, changelog: &str) -> Result<Ledger> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let ledger =
        Ledger::parse(&text).map_err(|error| anyhow::anyhow!("{}:\n{error}", path.display()))?;
    let missing = ledger.missing_changelog(changelog);
    if !missing.is_empty() {
        bail!("{}:\n{}", path.display(), missing.join("\n"));
    }
    Ok(ledger)
}

/// The candidate of `golden check --engine compare`: this repository's CLI
/// (`.venv`, from `uv sync --group dev`) with `OPENTIDE_ENGINE=rust`, which
/// runs a command's Rust implementation or refuses with `engine_not_ported`.
pub fn candidate(repo: &Path) -> Result<crate::golden::run::Engine> {
    let install_dir = repo.join(".venv");
    let bin_dir = install_dir.join("bin");
    if !bin_dir.join("opentide").is_file() {
        bail!(
            "{} is missing: run `uv sync --group dev` first",
            bin_dir.join("opentide").display()
        );
    }
    Ok(crate::golden::run::Engine {
        name: "rust".into(),
        bin_dir,
        install_dir,
        env: BTreeMap::from([("OPENTIDE_ENGINE".to_owned(), "rust".to_owned())]),
        host_paths: Vec::new(),
        known_uuids: std::sync::Arc::new(package_uuids(repo)?),
    })
}

/// The version the candidate reports (`opentide --version` prints
/// `opentide <version>`): this repository's build, compared against the
/// oracle's release version as [`opentide_compare::normalise::OPENTIDE_VERSION`].
pub fn candidate_version(repo: &Path) -> Result<String> {
    let opentide = repo.join(".venv").join("bin").join("opentide");
    let output = std::process::Command::new(&opentide)
        .arg("--version")
        .env("NO_COLOR", "1")
        .output()
        .with_context(|| format!("run {} --version (uv sync --group dev)", opentide.display()))?;
    let printed = String::from_utf8_lossy(&output.stdout);
    version_of(&printed)
        .with_context(|| format!("read the candidate's version from `{}`", printed.trim()))
}

/// The version in `opentide --version`'s output, `opentide <version>`.
fn version_of(printed: &str) -> Option<String> {
    let version = printed.trim().strip_prefix("opentide ")?.trim();
    (!version.is_empty() && !version.contains(char::is_whitespace)).then(|| version.to_owned())
}

/// The UUIDs in this repository's package (`src/opentide`: its bundled
/// vocabularies and data), which the editable install in `.venv` runs from;
/// the oracle's are those of its installed wheel.
fn package_uuids(repo: &Path) -> Result<std::collections::BTreeSet<String>> {
    let mut out = std::collections::BTreeSet::new();
    let package = repo.join("src").join("opentide");
    if package.is_dir() {
        crate::golden::oracle::collect_uuids(&package, &mut out)?;
    }
    Ok(out)
}

/// Which runs of a command its Rust implementation covers
/// (`RustCommand.requires` and `RustCommand.refuses`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Coverage {
    /// Flags of which a run must carry one (none: every run).
    #[serde(default)]
    pub requires: Vec<String>,
    /// Flags a run must carry none of (`validate query --live`).
    #[serde(default)]
    pub refuses: Vec<String>,
}

/// The command paths with a Rust implementation: the CLI's dispatch table,
/// `opentide.cli.engines.RUST_COMMANDS`, read through this repository's
/// `.venv`, each with the runs it covers ([`Coverage`]).
pub fn rust_commands(repo: &Path) -> Result<BTreeMap<String, Coverage>> {
    let python = repo.join(".venv").join("bin").join("python");
    let output = std::process::Command::new(&python)
        .args([
            "-I",
            "-c",
            "import json; from opentide.cli.engines import RUST_COMMANDS; \
             print(json.dumps({' '.join(path): {'requires': list(command.requires), \
             'refuses': list(getattr(command, 'refuses', ()))} \
             for path, command in RUST_COMMANDS.items()}))",
        ])
        .output()
        .with_context(|| format!("run {} (uv sync --group dev)", python.display()))?;
    if !output.status.success() {
        bail!(
            "read the dispatch table: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).context("parse the dispatch table")
}

/// Whether the Rust implementation covers a case of `command` run with
/// `argv`: its command is in `table`, and the arguments before `--` carry
/// one of the flags it requires, if it requires any, and none it refuses.
pub fn covers(table: &BTreeMap<String, Coverage>, command: &str, argv: &[String]) -> bool {
    let Some(coverage) = table.get(command) else {
        return false;
    };
    let options = argv
        .iter()
        .position(|arg| arg == "--")
        .map_or(argv, |end| &argv[..end]);
    !coverage.refuses.iter().any(|flag| options.contains(flag))
        && (coverage.requires.is_empty()
            || coverage.requires.iter().any(|flag| options.contains(flag)))
}

/// What the CLI prints when `OPENTIDE_ENGINE=rust` names a command with no
/// Rust implementation (`opentide.cli.engines`), in every output mode.
pub const NO_RUST: &str = "has no Rust implementation yet";

/// Whether the candidate refused the case: its command has no Rust implementation.
pub fn refused(run: &crate::golden::recording::Recording) -> bool {
    let has = |bytes: &[u8]| {
        bytes
            .windows(NO_RUST.len())
            .any(|w| w == NO_RUST.as_bytes())
    };
    run.exit_code == 2 && (has(&run.stdout) || has(&run.stderr))
}

/// A recording as the comparator's run: a link is its target with `S_IFLNK`
/// in its mode, a folder its mode with `S_IFDIR` and no bytes.
pub fn run_of(recording: &crate::golden::recording::Recording) -> Run {
    use crate::golden::snapshot::{ChangeKind, Kind};
    let files = recording
        .files
        .iter()
        .map(|file| {
            let mode = file
                .mode
                .as_deref()
                .and_then(|mode| u32::from_str_radix(mode, 8).ok())
                .unwrap_or(0);
            let state = match (file.change, file.kind) {
                (ChangeKind::Deleted, _) => FileState::Deleted,
                (_, Kind::Symlink) => FileState::Written {
                    mode: 0o120_777,
                    bytes: [
                        b"symlink:".as_slice(),
                        file.target.as_deref().unwrap_or("").as_bytes(),
                    ]
                    .concat(),
                },
                (_, Kind::Dir) => FileState::Written {
                    mode: 0o040_000 | mode,
                    bytes: Vec::new(),
                },
                (_, Kind::File) => FileState::Written {
                    mode,
                    bytes: file.contents.clone().unwrap_or_default(),
                },
            };
            (file.path.clone(), state)
        })
        .collect();
    Run {
        exit_code: recording.exit_code,
        stdout: recording.stdout.clone(),
        stderr: recording.stderr.clone(),
        files,
    }
}

/// `golden check --engine compare`: every case the candidate ran (not
/// refused) against its recording, through the comparator and the ledger;
/// a stale ledger entry fails the run. Whether it passed.
#[expect(
    clippy::too_many_arguments,
    reason = "the run's paths, results and counts, each read by `golden check` once"
)]
pub fn golden(
    repo: &Path,
    cases: &Path,
    blobs: &Path,
    results: &[Result<crate::golden::recording::Recording>],
    python_only: usize,
    complete: bool,
    report_path: Option<&Path>,
    full: bool,
    (oracle_version, candidate_version): (&str, &str),
) -> Result<bool> {
    use opentide_compare::ledger::Usage;
    use opentide_compare::normalise::opentide_version_in_run;
    let changelog = std::fs::read_to_string(repo.join("CHANGELOG.md"))
        .with_context(|| format!("read {}", repo.join("CHANGELOG.md").display()))?;
    let ledger = match read_ledger(&repo.join(LEDGER), &changelog) {
        Ok(ledger) => ledger,
        Err(error) => {
            eprintln!("error: {error:#}");
            return Ok(false);
        }
    };
    let mut usage = Usage::default();
    let mut reports = Vec::new();
    let mut failed = 0usize;
    for result in results {
        let actual = match result {
            Ok(actual) => actual,
            Err(error) => {
                failed += 1;
                eprintln!("error: {error:#}");
                continue;
            }
        };
        if refused(actual) {
            // The dispatch table names the command, yet the CLI refused it.
            failed += 1;
            eprintln!(
                "{}: the CLI has no Rust implementation of `{}`",
                actual.case.id, actual.case.command
            );
            continue;
        }
        let dir = cases.join(&actual.case.id);
        let recorded = crate::golden::recording::Recording::read(&dir, blobs)
            .with_context(|| format!("{}: not recorded", actual.case.id))?;
        // Each side's own version, the exact string it reports, is not behaviour.
        let mut oracle_run = run_of(&recorded);
        opentide_version_in_run(&mut oracle_run, oracle_version);
        let mut candidate_run = run_of(actual);
        opentide_version_in_run(&mut candidate_run, candidate_version);
        let report = opentide_compare::compare(
            opentide_compare::Case {
                command: &actual.case.command,
                id: &actual.case.id,
            },
            &oracle_run,
            &candidate_run,
            &ledger,
            &mut usage,
        );
        if !report.equal {
            eprintln!("{}: differs from the oracle's recording", actual.case.id);
            let shown = if full { usize::MAX } else { 10 };
            for difference in report.differences.iter().take(shown) {
                let at = difference
                    .pointer
                    .as_deref()
                    .or(difference.at.as_deref())
                    .unwrap_or("");
                eprintln!(
                    "  {} {} {at}\n    oracle:    {}\n    candidate: {}",
                    difference.target,
                    difference.kind.as_str(),
                    difference.oracle,
                    difference.candidate
                );
            }
        }
        reports.push(report);
    }
    // The recorded MCP sessions' entries are `cargo xtask mcp replay`'s to
    // apply, and to find stale.
    for (index, entry) in ledger.entries.iter().enumerate() {
        if crate::mcp::owns(entry) {
            usage.mark(index);
        }
    }
    // A ledger entry is stale only when it applied nowhere in a complete run.
    let report = if complete && failed == 0 {
        opentide_compare::RunReport::new(reports, &ledger, &usage)
    } else {
        opentide_compare::RunReport::partial(reports)
    };
    for stale in &report.stale {
        eprintln!(
            "error: {} entry {} ({} {} {} {}) applied to no case: it is stale, remove it",
            LEDGER, stale.entry, stale.command, stale.case, stale.target, stale.rule
        );
    }
    if let Some(path) = report_path {
        let text = serde_json::to_string_pretty(&report).context("serialise the report")?;
        std::fs::write(path, text + "\n").with_context(|| format!("write {}", path.display()))?;
    }
    let different = report.cases.iter().filter(|case| !case.equal).count();
    let passed = report.equal && failed == 0;
    let line = format!(
        "golden compare: {} case(s) compared, {python_only} Python only, {different} differ, \
         {} stale ledger entr{}, {failed} failed to run",
        report.cases.len(),
        report.stale.len(),
        if report.stale.len() == 1 { "y" } else { "ies" }
    );
    if passed {
        println!("{line}");
    } else {
        eprintln!("{line}");
    }
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::version_of;

    #[test]
    fn a_command_covers_the_runs_with_a_flag_it_requires_and_none_it_refuses() {
        use std::collections::BTreeMap;
        let argv =
            |args: &[&str]| -> Vec<String> { args.iter().map(|arg| (*arg).to_owned()).collect() };
        let table = BTreeMap::from([
            ("info".to_owned(), super::Coverage::default()),
            (
                "deploy".to_owned(),
                super::Coverage {
                    requires: vec!["--dry-run".to_owned()],
                    refuses: Vec::new(),
                },
            ),
            (
                "validate query".to_owned(),
                super::Coverage {
                    requires: Vec::new(),
                    refuses: vec!["--live".to_owned()],
                },
            ),
        ]);
        assert!(super::covers(
            &table,
            "validate query",
            &argv(&["opentide", "validate", "query", "--file", "x.kql"])
        ));
        assert!(!super::covers(
            &table,
            "validate query",
            &argv(&[
                "opentide",
                "validate",
                "query",
                "--live",
                "--platform",
                "elastic"
            ])
        ));
        assert!(super::covers(
            &table,
            "validate query",
            &argv(&["opentide", "validate", "query", "--", "--live"])
        ));
        assert!(super::covers(&table, "info", &argv(&["opentide", "info"])));
        assert!(super::covers(
            &table,
            "deploy",
            &argv(&["opentide", "deploy", "--dry-run", "--all"])
        ));
        assert!(!super::covers(
            &table,
            "deploy",
            &argv(&["opentide", "deploy", "--all"])
        ));
        assert!(!super::covers(
            &table,
            "deploy",
            &argv(&["opentide", "deploy", "--", "--dry-run"])
        ));
        assert!(!super::covers(&table, "lint", &argv(&["opentide", "lint"])));
    }

    #[test]
    fn reads_the_version_opentide_prints() {
        assert_eq!(
            version_of("opentide 0.23.1.dev719+g1f903689.d20261110\n").as_deref(),
            Some("0.23.1.dev719+g1f903689.d20261110")
        );
        assert_eq!(version_of("opentide \n"), None);
        assert_eq!(version_of("usage: opentide\n"), None);
        assert_eq!(version_of("opentide 1 2\n"), None);
    }
}
