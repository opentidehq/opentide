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
//! `golden check --engine rust` (UC-0.5, #803) reads its recordings
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

/// The candidate of `golden check --engine rust`: this repository's CLI
/// (`.venv`, from `uv sync --group dev`), the console script that runs the
/// Rust core in process. `target` is the Cargo target directory, where the
/// build of its native module left its dep-info ([`native_freshness`]).
pub fn candidate(repo: &Path, target: &Path) -> Result<crate::golden::run::Engine> {
    let install_dir = repo.join(".venv");
    let bin_dir = install_dir.join("bin");
    if !bin_dir.join("opentide").is_file() {
        bail!(
            "{} is missing: run `uv sync --group dev` first",
            bin_dir.join("opentide").display()
        );
    }
    native_freshness(repo, target)?;
    Ok(crate::golden::run::Engine {
        name: "rust".into(),
        bin_dir,
        install_dir,
        host_paths: Vec::new(),
        known_uuids: std::sync::Arc::new(package_uuids(repo)?),
    })
}

/// The command that rebuilds the console script's native module.
pub const REBUILD_NATIVE: &str = "uv sync --group dev --reinstall-package opentide";

/// Fails when the console script's native module (`src/opentide/_native.*`,
/// which `uv sync` builds once and does not rebuild when the Rust sources
/// change) is older than a file it is built from: the CLI would run the Rust
/// code of an earlier checkout, and every case would compare that.
///
/// The files are those cargo's dep-info lists for the last build of the
/// module (`<target>/develop/lib_native.d`: every source, `include_str!` file
/// and manifest), or, without one, the tracked Rust sources and manifests of
/// `crates/` and `bindings/python/`. Times are modification times: a file
/// touched without a change also counts, and the rebuild settles it.
pub fn native_freshness(repo: &Path, target: &Path) -> Result<()> {
    let Some(module) = native_module(repo) else {
        // Not an editable install of this checkout: nothing to compare.
        return Ok(());
    };
    let built = mtime(&module)?;
    let inputs = match dep_info(target) {
        Some(text) => parse_dep_info(&text),
        None => tracked_rust_inputs(repo)?,
    };
    if let Some((input, _)) = newest_after(&inputs, built) {
        bail!(
            "the console script's native module {} is older than {}, one of the files it is \
             built from: it runs the Rust code of an earlier checkout, and every case would \
             compare that. Rebuild it: `{REBUILD_NATIVE}`",
            module.display(),
            input.display()
        );
    }
    Ok(())
}

/// The native module of an editable install: `src/opentide/_native.<suffix>`.
fn native_module(repo: &Path) -> Option<std::path::PathBuf> {
    let dir = repo.join("src/opentide");
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.is_file()
                && path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with("_native.")
                        && [".so", ".pyd", ".dylib"]
                            .iter()
                            .any(|ext| name.ends_with(ext))
                })
        })
        .collect();
    found.sort();
    found.pop()
}

/// The dep-info cargo wrote for the module's last build, in the `develop`
/// profile `uv sync` builds.
fn dep_info(target: &Path) -> Option<String> {
    ["lib_native.d", "_native.d"]
        .iter()
        .find_map(|name| std::fs::read_to_string(target.join("develop").join(name)).ok())
}

/// The inputs of a dep-info file (`out: in in\ with\ spaces …`).
pub fn parse_dep_info(text: &str) -> Vec<std::path::PathBuf> {
    let mut inputs = Vec::new();
    for line in text.lines() {
        // `: ` ends the output: a Windows path has `C:\` but never `: `.
        let Some((_, deps)) = line.split_once(": ") else {
            continue;
        };
        let mut current = String::new();
        let mut chars = deps.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' if chars.peek() == Some(&' ') => {
                    current.push(' ');
                    chars.next();
                }
                ' ' => {
                    if !current.is_empty() {
                        inputs.push(std::path::PathBuf::from(std::mem::take(&mut current)));
                    }
                }
                other => current.push(other),
            }
        }
        if !current.is_empty() {
            inputs.push(std::path::PathBuf::from(current));
        }
    }
    inputs
}

/// The tracked Rust sources and manifests the module could be built from,
/// when no dep-info names them (tests, benches and examples are not).
fn tracked_rust_inputs(repo: &Path) -> Result<Vec<std::path::PathBuf>> {
    let output = std::process::Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--",
            "crates",
            "bindings/python",
            "Cargo.toml",
            "Cargo.lock",
        ])
        .current_dir(repo)
        .output()
        .context("run git ls-files")?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    Ok(output
        .stdout
        .split(|b| *b == 0)
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .filter(|path| {
            [".rs", ".toml", ".lock"]
                .iter()
                .any(|ext| path.ends_with(ext))
                && !["/tests/", "/benches/", "/examples/"]
                    .iter()
                    .any(|part| path.contains(part))
        })
        .map(|path| repo.join(path))
        .collect())
}

/// The most recently modified of `inputs` modified after `built`; missing files
/// (a dep-info entry since deleted) do not count.
fn newest_after(
    inputs: &[std::path::PathBuf],
    built: std::time::SystemTime,
) -> Option<(std::path::PathBuf, std::time::SystemTime)> {
    inputs
        .iter()
        .filter_map(|path| mtime(path).ok().map(|time| (path.clone(), time)))
        .filter(|(_, time)| *time > built)
        .max_by_key(|(_, time)| *time)
}

fn mtime(path: &Path) -> Result<std::time::SystemTime> {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .with_context(|| format!("stat {}", path.display()))
}

/// The version a candidate reports (`opentide --version` prints
/// `opentide <version>`): this repository's build, compared against the
/// oracle's release version as [`opentide_compare::normalise::OPENTIDE_VERSION`].
/// `opentide` is the candidate's executable.
pub fn candidate_version(opentide: &Path) -> Result<String> {
    let output = std::process::Command::new(opentide)
        .arg("--version")
        .env("NO_COLOR", "1")
        .output()
        .with_context(|| format!("run {} --version", opentide.display()))?;
    let printed = String::from_utf8_lossy(&output.stdout);
    version_of(&printed)
        .with_context(|| format!("read the candidate's version from `{}`", printed.trim()))
}

/// The candidate of `golden check --runner node` (UC-5.3, #838): the npm
/// package's `opentide` bin, `bindings/node/cli.js`, which calls the same
/// `main(argv)` as the console script in Node's process. It needs the addon
/// `npm run build` writes beside it. The cases run it through a launcher in
/// `target/golden-node/` that execs the `node` found on `PATH` now (a case's
/// `PATH` is the harness's own).
#[cfg(unix)]
pub fn node_candidate(repo: &Path, target: &Path) -> Result<crate::golden::run::Engine> {
    use std::os::unix::fs::PermissionsExt;
    let package = repo.join("bindings").join("node");
    let cli = package.join("cli.js");
    let built = std::fs::read_dir(&package)
        .with_context(|| format!("read {}", package.display()))?
        .filter_map(std::result::Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().ends_with(".node"));
    if !cli.is_file() || !built {
        bail!(
            "{} has no addon: run `npm ci && npm run build` there first",
            package.display()
        );
    }
    let node = std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join("node"))
        .find(|path| path.is_file())
        .context("no `node` on PATH")?;
    let quoted = |path: &Path| -> Result<String> {
        let text = path.to_string_lossy();
        if text.contains('\'') {
            bail!("{text}: a path with a quote cannot go in the launcher");
        }
        Ok(format!("'{text}'"))
    };
    let bin_dir = target.join("golden-node");
    std::fs::create_dir_all(&bin_dir).with_context(|| format!("create {}", bin_dir.display()))?;
    let launcher = bin_dir.join("opentide");
    std::fs::write(
        &launcher,
        format!(
            "#!/bin/sh\nexec {} {} \"$@\"\n",
            quoted(&node)?,
            quoted(&cli)?
        ),
    )
    .with_context(|| format!("write {}", launcher.display()))?;
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("make {} executable", launcher.display()))?;
    Ok(crate::golden::run::Engine {
        name: "node".into(),
        bin_dir,
        install_dir: package,
        host_paths: Vec::new(),
        known_uuids: std::sync::Arc::new(package_uuids(repo)?),
    })
}

/// The Node runner launches through a shell script: Unix only, as the
/// goldens are recorded.
#[cfg(not(unix))]
pub fn node_candidate(_repo: &Path, _target: &Path) -> Result<crate::golden::run::Engine> {
    bail!("--runner node runs on Unix only")
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

/// `golden check --engine rust`: every case the candidate ran against its
/// recording, through the comparator and the ledger;
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
    // Each case is read and compared on its own, on every core (#841); the
    // messages, the reports and the ledger's usage follow the cases' order.
    let compared = crate::parallel::in_order(results, |result| {
        let actual = match result {
            Ok(actual) => actual,
            Err(error) => return Ok(Err(format!("error: {error:#}"))),
        };
        let dir = cases.join(&actual.case.id);
        // A case with no recording fails on its own: a preview's recordings
        // (`golden record --out`) may lack the cases the oracle could not run.
        if !dir.join("case.toml").is_file() {
            return Ok(Err(format!(
                "{}: not recorded in {}",
                actual.case.id,
                cases.display()
            )));
        }
        let recorded = crate::golden::recording::Recording::read(&dir, blobs)
            .with_context(|| format!("{}: not recorded", actual.case.id))?;
        // Each side's own version, the exact string it reports, is not behaviour.
        let mut oracle_run = run_of(&recorded);
        opentide_version_in_run(&mut oracle_run, oracle_version);
        let mut candidate_run = run_of(actual);
        opentide_version_in_run(&mut candidate_run, candidate_version);
        let mut usage = Usage::default();
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
        Ok::<_, anyhow::Error>(Ok((report, usage)))
    });
    let mut usage = Usage::default();
    let mut reports = Vec::new();
    let mut failed = 0usize;
    for outcome in compared {
        let (report, case_usage) = match outcome? {
            Ok(compared) => compared,
            Err(message) => {
                failed += 1;
                eprintln!("{message}");
                continue;
            }
        };
        for index in 0..ledger.entries.len() {
            if case_usage.is_used(index) {
                usage.mark(index);
            }
        }
        if !report.equal {
            eprintln!("{}: differs from the oracle's recording", report.case);
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
        if crate::mcp::owns(entry) || on_a_cassette(entry) {
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
        "golden rust: {} case(s) compared, {different} differ, \
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

/// Whether a ledger entry is a cassette test's (case `cassette:<scenario>`):
/// a command no golden case can replay, compared against its connector's
/// cassette by an integration test of its own, which applies the entry and
/// finds it stale (`generate extract sentinel`:
/// `crates/opentide-cli/tests/extract_sentinel.rs`).
pub fn on_a_cassette(entry: &opentide_compare::Entry) -> bool {
    entry.case.starts_with("cassette:")
}

#[cfg(test)]
mod tests {
    use super::version_of;

    #[test]
    fn a_cassette_tests_entries_are_its_own() {
        let ledger = opentide_compare::ledger::Ledger::parse(
            r#"
[[diff]]
command = "generate extract sentinel"
case = "cassette:sentinel/extract"
target = "stdout"
rule = "text"
oracle = "a"
candidate = "b"
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/834"
changelog = "**c**"

[[diff]]
command = "generate extract sentinel"
case = "generate.extract.sentinel/plain/none/default"
target = "stdout"
rule = "text"
oracle = "a"
candidate = "b"
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/834"
changelog = "**c**"
"#,
        )
        .unwrap();
        let owned: Vec<bool> = ledger.entries.iter().map(super::on_a_cassette).collect();
        assert_eq!(owned, [true, false]);
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
