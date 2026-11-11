//! Fixture workspaces: how each one is laid out in a case's `ws/` directory.
//!
//! A fixture is materialised afresh for every case, so no case sees another's
//! writes. The kinds:
//!
//! - `copy`: a directory of the repository, copied as it is.
//! - `tide-corpus`: `tests/fixtures/tide_corpus/current`, copied and moved to
//!   the `.opentide/` layout the way the Python suite does it
//!   (`tests/corpus_support.py`, `materialise_corpus`).
//! - `skeleton`: empty directories only (`dirs`); none at all is "no workspace".
//! - `generated`: a generator command writes the workspace (`argv`, where
//!   `{out}` is the directory to fill). UC-0.6's corpus generator plugs in here:
//!   the workspace is generated at record and check time from a seed, never
//!   committed. A `cargo xtask corpus ...` generator runs in-process, in this
//!   program, rather than as a spawned cargo (#948).

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A fixture's entry in `cases.toml` (`[fixtures.<name>]`).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FixtureSpec {
    /// How the workspace is made.
    pub kind: FixtureKind,
    /// The source directory, relative to the repository root (`copy`, `tide-corpus`).
    #[serde(default)]
    pub source: Option<String>,
    /// Directories to create, relative to the workspace (`skeleton`).
    #[serde(default)]
    pub dirs: Vec<String>,
    /// The generator's argv (`generated`); `{out}` is the workspace directory,
    /// and it runs in the repository root (`cargo xtask corpus ...` runs
    /// in-process).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Values a case's arguments use as `{name}`.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// Where the fixture comes from, for the coverage report.
    #[serde(default)]
    pub about: String,
    /// Text edits applied once the workspace is laid out, each to exactly one
    /// place: a reviewed variation of a fixture (a typo `--fix` repairs).
    #[serde(default)]
    pub edits: Vec<Edit>,
}

/// One edit of a fixture file: `find` occurs exactly once and becomes `replace`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    /// The file, relative to the workspace.
    pub path: String,
    /// The text to replace; it must occur once.
    pub find: String,
    /// What it becomes.
    pub replace: String,
}

/// The kinds of fixture.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureKind {
    /// Copy `source`.
    Copy,
    /// Copy `source` and move it to the `.opentide/` layout (`materialise_corpus`).
    TideCorpus,
    /// Create `dirs`, nothing else.
    Skeleton,
    /// Run `argv` to write the workspace.
    Generated,
}

impl FixtureSpec {
    /// Writes the workspace into `dest`, which exists and is empty. Its
    /// permissions are then set the same on every host (see [`fix_modes`]).
    pub fn materialise(&self, repo: &Path, dest: &Path) -> Result<()> {
        self.lay_out(repo, dest)?;
        for edit in &self.edits {
            let path = dest.join(&edit.path);
            let text =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            ensure!(
                text.matches(edit.find.as_str()).count() == 1,
                "fixture edit: `{}` must occur exactly once in {}",
                edit.find,
                edit.path
            );
            fs::write(&path, text.replacen(edit.find.as_str(), &edit.replace, 1))
                .with_context(|| format!("write {}", path.display()))?;
        }
        fix_modes(dest)
    }

    fn lay_out(&self, repo: &Path, dest: &Path) -> Result<()> {
        match self.kind {
            FixtureKind::Copy => copy_tree(&self.source_dir(repo)?, dest),
            FixtureKind::TideCorpus => {
                copy_tree(&self.source_dir(repo)?, dest)?;
                migrate_tide_corpus_layout(dest)
            }
            FixtureKind::Skeleton => {
                for dir in &self.dirs {
                    fs::create_dir_all(dest.join(dir))
                        .with_context(|| format!("create {}", dest.join(dir).display()))?;
                }
                Ok(())
            }
            FixtureKind::Generated => self.generate(repo, dest),
        }
    }

    fn source_dir(&self, repo: &Path) -> Result<PathBuf> {
        let source = self
            .source
            .as_deref()
            .context("this fixture kind needs `source`")?;
        let dir = repo.join(source);
        ensure!(
            dir.is_dir(),
            "fixture source {} is not a directory",
            dir.display()
        );
        Ok(dir)
    }

    fn generate(&self, repo: &Path, dest: &Path) -> Result<()> {
        let out = dest.to_str().context("the workspace path is not UTF-8")?;
        let command: Vec<String> = self
            .argv
            .iter()
            .map(|arg| arg.replace("{out}", out))
            .collect();
        if let Some(args) = this_xtask(&command, repo) {
            // The generator is this program's own `corpus` command: run it
            // here. A spawned `cargo xtask` builds xtask alone, with other
            // features than a workspace test build, so under `cargo nextest
            // run --workspace` it recompiled much of the workspace and held
            // three corpus tests for minutes (#948).
            let code = crate::corpus::cli::run(args)
                .with_context(|| format!("the fixture generator `{}`", command.join(" ")))?;
            ensure!(
                code == 0,
                "the fixture generator `{}` failed (exit status {code})",
                command.join(" ")
            );
            return Ok(());
        }
        let Some((program, args)) = command.split_first() else {
            bail!("a generated fixture needs `argv`");
        };
        let output = Command::new(program)
            .args(args)
            .current_dir(repo)
            .output()
            .with_context(|| format!("run the fixture generator {program}"))?;
        ensure!(
            output.status.success(),
            "the fixture generator `{}` failed ({}): {}",
            command.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }
}

/// The `corpus` arguments of a generator `argv` that is `cargo xtask corpus
/// ...` run in this repository (`repo` is the workspace this xtask belongs
/// to), which [`FixtureSpec::materialise`] runs in-process; `None` for any
/// other command, which it spawns. The corpus command reads its inputs from
/// the repository root, never the working directory, so where it runs
/// changes nothing.
fn this_xtask<'a>(argv: &'a [String], repo: &Path) -> Option<&'a [String]> {
    let [cargo, xtask, corpus, rest @ ..] = argv else {
        return None;
    };
    if (cargo.as_str(), xtask.as_str(), corpus.as_str()) != ("cargo", "xtask", "corpus") {
        return None;
    }
    let same = |a: &Path, b: &Path| match (dunce::canonicalize(a), dunce::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    same(repo, &crate::corpus::cli::repo_root()).then_some(rest)
}

/// Sets every directory to `0755` and every regular file to `0644`, or
/// `0755` when any execute bit is set: a checkout's modes follow the umask
/// of whoever cloned, and a recording names the mode of each file it changes.
#[cfg(unix)]
pub fn fix_modes(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let path = entry.path();
        let meta =
            fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        let mode = if meta.is_dir() {
            fix_modes(&path)?;
            0o755
        } else if meta.is_file() {
            if meta.permissions().mode() & 0o111 == 0 {
                0o644
            } else {
                0o755
            }
        } else {
            continue;
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

/// Without Unix permission bits there is nothing to set.
#[cfg(not(unix))]
pub fn fix_modes(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Copies a directory tree: regular files with their permissions, directories,
/// and symbolic links as links.
pub fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to).with_context(|| format!("create {}", to.display()))?;
    let mut entries: Vec<_> = fs::read_dir(from)
        .with_context(|| format!("read {}", from.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("read {}", from.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let source = entry.path();
        let target = to.join(entry.file_name());
        let kind = entry
            .file_type()
            .with_context(|| format!("stat {}", source.display()))?;
        if kind.is_dir() {
            copy_tree(&source, &target)?;
        } else if kind.is_symlink() {
            let link = fs::read_link(&source)
                .with_context(|| format!("read link {}", source.display()))?;
            symlink_dir(&link, &target)?;
        } else {
            fs::copy(&source, &target)
                .with_context(|| format!("copy {} to {}", source.display(), target.display()))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn symlink_dir(link: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(link, target)
        .with_context(|| format!("link {} to {}", target.display(), link.display()))
}

/// Windows creates a directory symbolic link; that needs Developer Mode or
/// an elevated shell, which GitHub's Windows runners have.
#[cfg(windows)]
pub(crate) fn symlink_dir(link: &Path, target: &Path) -> Result<()> {
    std::os::windows::fs::symlink_dir(link, target).with_context(|| {
        format!(
            "link {} to {} (directory symbolic links on Windows need Developer Mode or an elevated shell)",
            target.display(),
            link.display()
        )
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn symlink_dir(_link: &Path, target: &Path) -> Result<()> {
    bail!(
        "{}: golden fixtures with symbolic links need a Unix or Windows host",
        target.display()
    )
}

/// `migrate_tide_corpus_layout` of `tests/corpus_support.py`: configurations
/// copied to `.opentide/configurations`, `objects/<family>` linked to the
/// legacy folders, and the `.opentide/` folders a workspace has.
fn migrate_tide_corpus_layout(dest: &Path) -> Result<()> {
    let opentide = dest.join(".opentide");
    fs::create_dir_all(&opentide).with_context(|| format!("create {}", opentide.display()))?;
    let legacy = dest.join("Configurations");
    if legacy.is_dir() {
        copy_tree(&legacy, &opentide.join("configurations"))?;
    }
    fs::create_dir_all(dest.join("objects")).context("create objects/")?;
    for (family, legacy) in [
        ("threats", "Objects/Threat Vectors"),
        ("objectives", "Objects/Detection Objectives"),
        ("rules", "Objects/Detection Rules"),
    ] {
        let link = dest.join("objects").join(family);
        if link.exists() || link.is_symlink() {
            continue;
        }
        // One component at a time: Windows does not resolve a link whose
        // target is spelled with `/`, so `..\Objects/Detection Rules` would
        // dangle there.
        let target: PathBuf = std::iter::once("..").chain(legacy.split('/')).collect();
        symlink_dir(&target, &link)?;
    }
    for dir in ["schemas", "templates", "exports", "inflight"] {
        fs::create_dir_all(opentide.join(dir))
            .with_context(|| format!("create .opentide/{dir}"))?;
    }
    Ok(())
}

/// Tests that run on every host, Windows included.
#[cfg(test)]
mod portable_tests {
    use super::*;

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    /// Only `cargo xtask corpus ...` in this repository runs in-process.
    #[test]
    fn only_this_repositorys_corpus_command_runs_in_process() {
        let repo = crate::corpus::cli::repo_root();
        let argv = strings(&["cargo", "xtask", "corpus", "faults", "--out", "/w"]);
        assert_eq!(
            this_xtask(&argv, &repo),
            Some(&strings(&["faults", "--out", "/w"])[..])
        );
        let elsewhere = tempfile::tempdir().unwrap();
        assert_eq!(this_xtask(&argv, elsewhere.path()), None);
        assert_eq!(this_xtask(&argv, &repo.join("no-such-dir")), None);
        for other in [
            &["cargo", "xtask", "golden", "record"][..],
            &["cargo", "run", "corpus", "generate"],
            &["cargo2", "xtask", "corpus", "generate"],
            &["cargo", "xtask"],
            &["sh", "-c", "true"],
            &[],
        ] {
            assert_eq!(this_xtask(&strings(other), &repo), None, "{other:?}");
        }
    }

    fn files_of(root: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let name = path.strip_prefix(root).unwrap().to_string_lossy();
                    files.insert(name.replace('\\', "/"), fs::read(&path).unwrap());
                }
            }
        }
        files
    }

    /// The generated fixture run in-process writes what the corpus
    /// generator writes, file for file, without spawning cargo (#948).
    #[test]
    fn a_generated_fixture_of_this_xtask_is_the_generators_workspace() {
        let repo = crate::corpus::cli::repo_root();
        let size = [
            "--seed",
            "3",
            "--threats",
            "2",
            "--objectives",
            "2",
            "--rules",
            "3",
        ];
        let fixture = FixtureSpec {
            kind: FixtureKind::Generated,
            source: None,
            dirs: Vec::new(),
            argv: strings(&["cargo", "xtask", "corpus", "generate"])
                .into_iter()
                .chain(strings(&size))
                .chain(strings(&["--out", "{out}"]))
                .collect(),
            vars: BTreeMap::new(),
            about: String::new(),
            edits: Vec::new(),
        };
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        fixture.materialise(&repo, &ws).unwrap();
        let direct = dir.path().join("direct");
        let args: Vec<String> = strings(&["generate"])
            .into_iter()
            .chain(strings(&size))
            .chain(["--out".to_owned(), direct.to_string_lossy().into_owned()])
            .collect();
        assert_eq!(crate::corpus::cli::run(&args).unwrap(), 0);
        fix_modes(&direct).unwrap();
        let written = files_of(&ws);
        assert!(written.len() > 5, "{:?}", written.keys());
        assert_eq!(written, files_of(&direct));

        let refused = FixtureSpec {
            argv: strings(&["cargo", "xtask", "corpus", "generate", "--nope", "{out}"]),
            ..fixture
        };
        let ws = dir.path().join("refused");
        fs::create_dir_all(&ws).unwrap();
        assert!(refused.materialise(&repo, &ws).is_err());
    }

    /// Every fixture copied from the repository is checked out with the
    /// bytes it was recorded from: no end-of-line conversion (a Windows
    /// checkout with `core.autocrlf` would otherwise hold CRLF, and the
    /// fixture edits and the bytes `--fix` writes would differ).
    #[test]
    fn every_fixture_source_is_checked_out_byte_for_byte() {
        let repo = crate::corpus::cli::repo_root();
        let text = fs::read_to_string(repo.join("tests/golden/cases.toml")).unwrap();
        let spec = crate::golden::case::Spec::parse(&text).unwrap();
        let sources: Vec<&str> = spec
            .fixtures
            .values()
            .filter_map(|fixture| fixture.source.as_deref())
            .collect();
        assert!(!sources.is_empty());
        for source in sources {
            let output = Command::new("git")
                .args(["ls-files", "--eol", "--", source])
                .current_dir(&repo)
                .output()
                .unwrap();
            assert!(output.status.success(), "git ls-files {source}");
            let listing = String::from_utf8(output.stdout).unwrap();
            assert!(!listing.is_empty(), "{source} holds no tracked file");
            for line in listing.lines() {
                // `i/lf w/lf attr/-text\tpath`: the attribute column.
                let attr = line.split_whitespace().nth(2).unwrap_or_default();
                assert_eq!(attr, "attr/-text", "{line}");
            }
        }
    }

    #[test]
    fn tide_corpus_links_resolve_on_every_host() {
        let repo = tempfile::tempdir().unwrap();
        let rules = repo.path().join("corpus/Objects/Detection Rules");
        fs::create_dir_all(&rules).unwrap();
        fs::write(rules.join("r.yaml"), "name: r\n").unwrap();
        let dest = tempfile::tempdir().unwrap();
        let fixture = FixtureSpec {
            kind: FixtureKind::TideCorpus,
            source: Some("corpus".into()),
            dirs: Vec::new(),
            argv: Vec::new(),
            vars: BTreeMap::new(),
            about: String::new(),
            edits: Vec::new(),
        };
        fixture.materialise(repo.path(), dest.path()).unwrap();
        let link = dest.path().join("objects").join("rules");
        assert!(link.is_symlink());
        // The link is followed: a folder, and its file is read through it.
        assert!(fs::metadata(&link).unwrap().is_dir());
        assert_eq!(
            fs::read_to_string(link.join("r.yaml")).unwrap(),
            "name: r\n"
        );
        let names: Vec<String> = fs::read_dir(&link)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["r.yaml"]);
        // The target names its components with the host's separator.
        let target = fs::read_link(&link).unwrap();
        let parts: Vec<String> = target
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        assert_eq!(parts, ["..", "Objects", "Detection Rules"]);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn spec(kind: FixtureKind) -> FixtureSpec {
        FixtureSpec {
            kind,
            source: None,
            dirs: Vec::new(),
            argv: Vec::new(),
            vars: BTreeMap::new(),
            about: String::new(),
            edits: Vec::new(),
        }
    }

    #[test]
    fn tide_corpus_gets_the_opentide_layout() {
        let repo = tempfile::tempdir().unwrap();
        let source = repo.path().join("corpus");
        fs::create_dir_all(source.join("Objects/Detection Rules")).unwrap();
        fs::write(source.join("Objects/Detection Rules/r.yaml"), "name: r\n").unwrap();
        fs::create_dir_all(source.join("Configurations/platforms")).unwrap();
        fs::write(source.join("Configurations/platforms/s.toml"), "x = 1\n").unwrap();
        let dest = tempfile::tempdir().unwrap();
        let fixture = FixtureSpec {
            source: Some("corpus".into()),
            ..spec(FixtureKind::TideCorpus)
        };
        fixture.materialise(repo.path(), dest.path()).unwrap();
        let ws = dest.path();
        assert_eq!(
            fs::read_link(ws.join("objects/rules")).unwrap(),
            Path::new("../Objects/Detection Rules")
        );
        assert_eq!(
            fs::read_to_string(ws.join("objects/rules/r.yaml")).unwrap(),
            "name: r\n"
        );
        assert!(
            ws.join(".opentide/configurations/platforms/s.toml")
                .is_file()
        );
        for dir in ["schemas", "templates", "exports", "inflight"] {
            assert!(ws.join(".opentide").join(dir).is_dir(), "{dir}");
        }
        // Dangling links for families the corpus lacks, as Python leaves them.
        assert!(ws.join("objects/threats").is_symlink());
    }

    #[test]
    fn modes_are_the_same_on_every_host() {
        use std::os::unix::fs::PermissionsExt;
        let repo = tempfile::tempdir().unwrap();
        let source = repo.path().join("src");
        fs::create_dir_all(source.join("sub")).unwrap();
        fs::write(source.join("sub/a.yaml"), "a").unwrap();
        fs::write(source.join("run.sh"), "x").unwrap();
        fs::set_permissions(source.join("sub/a.yaml"), fs::Permissions::from_mode(0o664)).unwrap();
        fs::set_permissions(source.join("run.sh"), fs::Permissions::from_mode(0o775)).unwrap();
        fs::set_permissions(source.join("sub"), fs::Permissions::from_mode(0o775)).unwrap();
        let dest = tempfile::tempdir().unwrap();
        let fixture = FixtureSpec {
            source: Some("src".into()),
            ..spec(FixtureKind::Copy)
        };
        fixture.materialise(repo.path(), dest.path()).unwrap();
        let mode = |p: &str| {
            fs::metadata(dest.path().join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("sub/a.yaml"), 0o644);
        assert_eq!(mode("run.sh"), 0o755);
        assert_eq!(mode("sub"), 0o755);
    }

    #[test]
    fn edits_apply_once_or_fail() {
        let repo = tempfile::tempdir().unwrap();
        fs::create_dir_all(repo.path().join("src")).unwrap();
        fs::write(
            repo.path().join("src/r.yaml"),
            "severity: High\nalert: High\n",
        )
        .unwrap();
        let edit = |find: &str| Edit {
            path: "r.yaml".into(),
            find: find.into(),
            replace: "severity: high".into(),
        };
        let fixture = FixtureSpec {
            source: Some("src".into()),
            edits: vec![edit("severity: High")],
            ..spec(FixtureKind::Copy)
        };
        let dest = tempfile::tempdir().unwrap();
        fixture.materialise(repo.path(), dest.path()).unwrap();
        assert_eq!(
            fs::read_to_string(dest.path().join("r.yaml")).unwrap(),
            "severity: high\nalert: High\n"
        );
        // Twice, or not at all: the edit is ambiguous or stale.
        for find in ["High", "nowhere"] {
            let fixture = FixtureSpec {
                source: Some("src".into()),
                edits: vec![edit(find)],
                ..spec(FixtureKind::Copy)
            };
            let dest = tempfile::tempdir().unwrap();
            assert!(
                fixture.materialise(repo.path(), dest.path()).is_err(),
                "{find}"
            );
        }
    }

    #[test]
    fn skeleton_and_generated() {
        let dest = tempfile::tempdir().unwrap();
        let skeleton = FixtureSpec {
            dirs: vec![".opentide".into()],
            ..spec(FixtureKind::Skeleton)
        };
        skeleton.materialise(Path::new("."), dest.path()).unwrap();
        assert!(dest.path().join(".opentide").is_dir());

        let generated = tempfile::tempdir().unwrap();
        let fixture = FixtureSpec {
            argv: vec![
                "sh".into(),
                "-c".into(),
                "echo seed > \"$0/w.txt\"".into(),
                "{out}".into(),
            ],
            ..spec(FixtureKind::Generated)
        };
        fixture
            .materialise(Path::new("."), generated.path())
            .unwrap();
        assert_eq!(
            fs::read_to_string(generated.path().join("w.txt")).unwrap(),
            "seed\n"
        );

        let failing = FixtureSpec {
            argv: vec!["false".into()],
            ..spec(FixtureKind::Generated)
        };
        assert!(
            failing
                .materialise(Path::new("."), generated.path())
                .is_err()
        );
    }
}
