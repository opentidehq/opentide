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
/// runs a command's Rust implementation or refuses with `engine_unavailable`.
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
    })
}

/// The command paths with a Rust implementation: the CLI's dispatch table,
/// `opentide.cli.engines.RUST_COMMANDS`, read through this repository's `.venv`.
pub fn rust_commands(repo: &Path) -> Result<std::collections::BTreeSet<String>> {
    let python = repo.join(".venv").join("bin").join("python");
    let output = std::process::Command::new(&python)
        .args([
            "-I",
            "-c",
            "import json; from opentide.cli.engines import RUST_COMMANDS; \
             print(json.dumps([' '.join(path) for path in RUST_COMMANDS]))",
        ])
        .output()
        .with_context(|| format!("run {} (uv sync --group dev)", python.display()))?;
    if !output.status.success() {
        bail!(
            "read the dispatch table: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let paths: Vec<String> =
        serde_json::from_slice(&output.stdout).context("parse the dispatch table")?;
    Ok(paths.into_iter().collect())
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
pub fn golden(
    repo: &Path,
    cases: &Path,
    blobs: &Path,
    results: &[Result<crate::golden::recording::Recording>],
    python_only: usize,
    report_path: Option<&Path>,
    full: bool,
) -> Result<bool> {
    use opentide_compare::ledger::Usage;
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
        let report = opentide_compare::compare(
            opentide_compare::Case {
                command: &actual.case.command,
                id: &actual.case.id,
            },
            &run_of(&recorded),
            &run_of(actual),
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
    let report = opentide_compare::RunReport::new(reports, &ledger, &usage);
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
