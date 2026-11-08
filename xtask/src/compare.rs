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
