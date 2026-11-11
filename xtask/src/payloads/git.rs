//! `cargo xtask payloads git --against python`: the changed rule files of a
//! scripted git history, read by the oracle (`git_probe.py`) and by
//! `opentide_compile::git` (gix), compared state by state.
//!
//! The history, on the tide-corpus fixture: the first commit (nothing
//! changed), an edit with a new rule whose name is not ASCII and a rule in a
//! subfolder, a rename and a delete, a detached HEAD, a merge commit, a
//! shallow clone whose parent is missing, a checkout with no commit, a
//! workspace in a subfolder of its checkout, and a folder with no checkout.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, ensure};
use opentide_compile::dry_run;
use serde_json::{Value, json};

/// The probe the oracle runs.
const PROBE: &str = include_str!("git_probe.py");

/// Configuration every git call of the scripted history and the oracle runs
/// with, as command-line scoped configuration (`GIT_CONFIG_COUNT`), so no
/// call can miss it: no automatic maintenance and no automatic garbage
/// collection. Either one runs in the background after a commit or a merge
/// and creates and deletes files under `.git` (`objects/maintenance.lock`)
/// while a state is being copied (#934).
pub const QUIET_GIT: [(&str, &str); 5] = [
    ("GIT_CONFIG_COUNT", "2"),
    ("GIT_CONFIG_KEY_0", "maintenance.auto"),
    ("GIT_CONFIG_VALUE_0", "false"),
    ("GIT_CONFIG_KEY_1", "gc.auto"),
    ("GIT_CONFIG_VALUE_1", "0"),
];

/// A git call of the scripted history: no inherited environment, `home` as
/// `HOME`, fixed identities and dates, and [`QUIET_GIT`].
fn git_command(dir: &Path, home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .envs(QUIET_GIT)
        .env("GIT_AUTHOR_NAME", "golden")
        .env("GIT_AUTHOR_EMAIL", "golden@example.invalid")
        .env("GIT_COMMITTER_NAME", "golden")
        .env("GIT_COMMITTER_EMAIL", "golden@example.invalid")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z");
    command
}

fn git(dir: &Path, home: &Path, args: &[&str]) -> Result<()> {
    let status = git_command(dir, home, args)
        .status()
        .with_context(|| format!("run git {args:?}"))?;
    ensure!(status.success(), "git {args:?} failed in {}", dir.display());
    Ok(())
}

/// The first rule files of the corpus, by name.
fn rules(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = fs::read_dir(dir.join("objects/rules"))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    found.sort();
    Ok(found)
}

fn touch(path: &Path) -> Result<()> {
    let mut text = fs::read_to_string(path)?;
    text.push_str("# edited\n");
    fs::write(path, text)?;
    Ok(())
}

/// The oracle's answer for the checkout at `repo`.
fn oracle(python: &Path, probe: &Path, repo: &Path, home: &Path) -> Result<Value> {
    let result = home.join("git-result.json");
    let _ = fs::remove_file(&result);
    let status = Command::new(python)
        .arg("-I")
        .arg(probe)
        .arg(repo)
        .arg(&result)
        .env_clear()
        .env(
            "PATH",
            python.parent().map(Path::as_os_str).unwrap_or_default(),
        )
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .env("OPENTIDE_NO_UPDATE_CHECK", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .envs(QUIET_GIT)
        .status()
        .with_context(|| format!("run {}", python.display()))?;
    ensure!(
        status.success(),
        "the oracle's git probe failed on {}",
        repo.display()
    );
    Ok(serde_json::from_str(&fs::read_to_string(&result)?)?)
}

/// opentide-compile's answer for the checkout at `repo`.
fn candidate(repo: &Path) -> Value {
    let env = |_: &str| None::<String>;
    let rules = repo.join("objects/rules");
    match dry_run::git_scope(repo, repo, &env, &rules, "objects/rules") {
        Ok((scope, _)) => {
            let mut files: Vec<String> = scope
                .files
                .iter()
                .filter_map(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .collect();
            files.sort();
            json!({"files": files, "nested": scope.nested})
        }
        Err(message) => json!({"error": message}),
    }
}

/// Runs the scripted history. Whether every state agrees.
pub fn run(python: &Path) -> Result<bool> {
    let (repo_root, _) = crate::vocab::diff::workspace()?;
    let scratch = tempfile::tempdir()?;
    let root = dunce::canonicalize(scratch.path())?;
    let home = root.join("home");
    fs::create_dir_all(&home)?;
    let probe = root.join("git_probe.py");
    fs::write(&probe, PROBE)?;
    let states = history(&repo_root, &root, &home)?;
    let mut passed = true;
    for (name, dir) in &states {
        let expected = oracle(python, &probe, dir, &home)?;
        let got = candidate(dir);
        if expected == got {
            println!("{name}: agrees ({expected})");
        } else {
            passed = false;
            println!("{name}: DIFFERS\n  oracle:    {expected}\n  candidate: {got}");
        }
    }
    Ok(passed)
}

/// Copies the checkout at `from` (its `.git` included) to `to`: files,
/// folders and symbolic links. A state never depends on git's transient
/// files: a lock file (`*.lock`) under `.git` belongs to a git process at
/// work, and is left out, as is an entry that disappears while the copy reads
/// its folder. Any other failure is an error, never a state left out.
fn copy_state(from: &Path, to: &Path) -> Result<()> {
    copy_checkout(from, to, false)
}

fn copy_checkout(from: &Path, to: &Path, in_git: bool) -> Result<()> {
    fs::create_dir_all(to).with_context(|| format!("create {}", to.display()))?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(from).with_context(|| format!("read {}", from.display()))? {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", from.display()));
            }
        }
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let source = entry.path();
        let target = to.join(&name);
        let in_git = in_git || name == ".git";
        if in_git
            && Path::new(&name)
                .extension()
                .is_some_and(|ext| ext == "lock")
        {
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("stat {}", source.display()));
            }
        };
        let copied = if kind.is_dir() {
            copy_checkout(&source, &target, in_git)
        } else if kind.is_symlink() {
            fs::read_link(&source)
                .with_context(|| format!("read link {}", source.display()))
                .and_then(|link| crate::golden::fixture::symlink_dir(&link, &target))
        } else {
            fs::copy(&source, &target)
                .map(drop)
                .with_context(|| format!("copy {} to {}", source.display(), target.display()))
        };
        if let Err(error) = copied {
            let vanished = error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            });
            // Only an entry that is gone from `from` now is a transient one.
            if !(vanished && fs::symlink_metadata(&source).is_err()) {
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Replaces the fixture's `objects/` links with real folders, and drops its
/// legacy `Objects/` tree. git would track a link alone, and on a
/// case-insensitive file system (macOS) `objects` and `Objects` are one
/// folder, which git indexes as `Objects/`: `git mv objects/rules/...` would
/// then name a path the index does not have.
fn flatten_objects(repo: &Path) -> Result<()> {
    let staged = repo.join("objects-staged");
    fs::create_dir_all(&staged)?;
    for family in ["threats", "objectives", "rules"] {
        let link = repo.join("objects").join(family);
        if fs::symlink_metadata(&link).is_err() {
            continue;
        }
        let target = dunce::canonicalize(&link)?;
        fs::rename(&target, staged.join(family))?;
    }
    for old in ["objects", "Objects"] {
        let old = repo.join(old);
        if fs::symlink_metadata(&old).is_ok() {
            fs::remove_dir_all(&old)?;
        }
    }
    fs::rename(&staged, repo.join("objects"))?;
    Ok(())
}

/// Builds the scripted history under `root` (git's `HOME` is `home`): each
/// state, named, with the directory the baseline reads it in.
pub fn history(repo_root: &Path, root: &Path, home: &Path) -> Result<Vec<(String, PathBuf)>> {
    let golden = repo_root.join("tests/golden");
    let spec = crate::golden::case::Spec::parse(&fs::read_to_string(golden.join("cases.toml"))?)?;
    let repo = root.join("repo");
    fs::create_dir_all(&repo)?;
    spec.fixtures
        .get("tide-corpus")
        .context("cases.toml has no fixture tide-corpus")?
        .materialise(repo_root, &repo)?;
    flatten_objects(&repo)?;
    let mut states: Vec<(String, PathBuf)> = Vec::new();
    let check = |name: &str, dir: &Path, states: &mut Vec<(String, PathBuf)>| -> Result<()> {
        // Each state is copied, so later commits do not change it.
        let copy = root.join(format!("state-{}", states.len()));
        copy_state(dir, &copy).with_context(|| format!("copy the state {name:?}"))?;
        states.push((name.to_owned(), copy));
        Ok(())
    };
    git(&repo, home, &["init", "-q", "-b", "main"])?;
    check("no commit yet", &repo, &mut states)?;
    git(&repo, home, &["add", "-A", "--force"])?;
    git(&repo, home, &["commit", "-q", "-m", "first"])?;
    check("the first commit", &repo, &mut states)?;
    let files = rules(&repo)?;
    ensure!(files.len() >= 5, "tide-corpus has fewer than five rules");
    touch(&files[0])?;
    fs::copy(&files[1], repo.join("objects/rules/règle-détection-é.yaml"))?;
    fs::create_dir_all(repo.join("objects/rules/sub"))?;
    fs::copy(&files[2], repo.join("objects/rules/sub/nested-rule.yaml"))?;
    git(&repo, home, &["add", "-A", "--force"])?;
    git(
        &repo,
        home,
        &["commit", "-q", "-m", "edit, non-ASCII, nested"],
    )?;
    check(
        "an edit, a non-ASCII name and a nested rule",
        &repo,
        &mut states,
    )?;
    let renamed = repo.join("objects/rules/renamed-rule.yaml");
    let relative = |path: &Path| {
        path.strip_prefix(&repo)
            .map(|p| p.to_string_lossy().into_owned())
    };
    git(
        &repo,
        home,
        &[
            "mv",
            &relative(&files[3])?,
            "objects/rules/renamed-rule.yaml",
        ],
    )?;
    git(&repo, home, &["rm", "-q", &relative(&files[4])?])?;
    git(&repo, home, &["commit", "-q", "-m", "rename and delete"])?;
    check("a rename and a delete", &repo, &mut states)?;
    git(&repo, home, &["checkout", "-q", "--detach", "HEAD~1"])?;
    check("a detached HEAD", &repo, &mut states)?;
    git(&repo, home, &["checkout", "-q", "main"])?;
    git(&repo, home, &["checkout", "-q", "-b", "feature"])?;
    touch(&files[0])?;
    git(&repo, home, &["commit", "-q", "-am", "feature edit"])?;
    git(&repo, home, &["checkout", "-q", "main"])?;
    touch(&renamed)?;
    git(&repo, home, &["commit", "-q", "-am", "main edit"])?;
    git(
        &repo,
        home,
        &["merge", "-q", "--no-ff", "-m", "merge feature", "feature"],
    )?;
    check("a merge commit", &repo, &mut states)?;
    let shallow = root.join("shallow");
    let url = format!("file://{}", repo.display());
    git(
        root,
        home,
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &url,
            &shallow.to_string_lossy(),
        ],
    )?;
    check("a shallow clone", &shallow, &mut states)?;
    // A workspace in a subfolder of its checkout: paths come from the top level.
    let outer = root.join("outer");
    let inner = outer.join("detections");
    fs::create_dir_all(&outer)?;
    copy_state(&states[1].1, &inner).context("copy the workspace into a subfolder")?;
    let _ = fs::remove_dir_all(inner.join(".git"));
    git(&outer, home, &["init", "-q", "-b", "main"])?;
    git(&outer, home, &["add", "-A", "--force"])?;
    git(&outer, home, &["commit", "-q", "-m", "first"])?;
    touch(&rules(&inner)?[0])?;
    git(
        &outer,
        home,
        &["commit", "-q", "-am", "edit below the top level"],
    )?;
    states.push(("a workspace below the git top level".to_owned(), inner));
    let bare = root.join("no-checkout");
    fs::create_dir_all(&bare)?;
    spec.fixtures
        .get("tide-corpus")
        .context("cases.toml has no fixture tide-corpus")?
        .materialise(repo_root, &bare)?;
    let _ = fs::remove_dir_all(bare.join(".git"));
    check("no checkout", &bare, &mut states)?;
    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_history_lays_out_real_lowercase_object_folders() {
        // On a case-insensitive file system `objects` is the fixture's
        // `Objects`, which git indexes by that name; no legacy tree and no
        // link may be left for git to index.
        let (repo_root, _) = crate::vocab::diff::workspace().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let repo = dunce::canonicalize(scratch.path()).unwrap().join("repo");
        let golden = repo_root.join("tests/golden");
        let spec = crate::golden::case::Spec::parse(
            &fs::read_to_string(golden.join("cases.toml")).unwrap(),
        )
        .unwrap();
        spec.fixtures["tide-corpus"]
            .materialise(&repo_root, &repo)
            .unwrap();
        flatten_objects(&repo).unwrap();
        let mut top: Vec<String> = fs::read_dir(&repo)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        top.sort();
        assert!(!top.contains(&"Objects".to_owned()), "{top:?}");
        assert!(top.contains(&"objects".to_owned()), "{top:?}");
        for family in ["threats", "objectives", "rules"] {
            let meta = fs::symlink_metadata(repo.join("objects").join(family)).unwrap();
            assert!(meta.is_dir(), "objects/{family} is a real folder");
        }
        assert!(rules(&repo).unwrap().len() >= 5);
    }

    /// The scripted environment turns automatic maintenance and garbage
    /// collection off for every git call (#934): git reads both settings
    /// back, whatever the host's git version defaults to.
    #[test]
    fn the_scripted_git_runs_without_maintenance_or_gc() {
        let scratch = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(scratch.path()).unwrap();
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        git(&root, &home, &["init", "-q", "-b", "main"]).unwrap();
        for (key, expected) in [("maintenance.auto", "false"), ("gc.auto", "0")] {
            let output = git_command(&root, &home, &["config", "--get", key])
                .output()
                .unwrap();
            assert!(output.status.success(), "git config --get {key} is unset");
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), expected);
        }
    }

    /// A state's copy never holds git's lock files, which a git process
    /// creates and deletes while it works; everything else is copied.
    #[test]
    fn a_state_copy_leaves_git_lock_files_out() {
        let scratch = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(scratch.path()).unwrap();
        let from = root.join("from");
        fs::create_dir_all(from.join(".git/objects/ab")).unwrap();
        fs::write(from.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(from.join(".git/objects/ab/cdef"), "object").unwrap();
        fs::write(from.join(".git/objects/maintenance.lock"), "").unwrap();
        fs::write(from.join(".git/index.lock"), "").unwrap();
        fs::write(from.join("rule.lock"), "a workspace file").unwrap();
        let to = root.join("to");
        copy_state(&from, &to).unwrap();
        assert!(to.join(".git/HEAD").is_file());
        assert_eq!(
            fs::read_to_string(to.join(".git/objects/ab/cdef")).unwrap(),
            "object"
        );
        assert!(!to.join(".git/objects/maintenance.lock").exists());
        assert!(!to.join(".git/index.lock").exists());
        assert!(
            to.join("rule.lock").is_file(),
            "only git's lock files are left out"
        );
    }

    /// A copy that fails is an error, never a state left out.
    #[test]
    fn a_state_copy_that_fails_is_an_error() {
        let scratch = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(scratch.path()).unwrap();
        assert!(copy_state(&root.join("missing"), &root.join("to")).is_err());
    }

    #[test]
    fn the_scripted_history_reads_each_state() {
        let (repo_root, _) = crate::vocab::diff::workspace().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(scratch.path()).unwrap();
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let states = history(&repo_root, &root, &home).unwrap();
        let read = |name: &str| {
            let (_, dir) = states.iter().find(|(known, _)| known == name).unwrap();
            candidate(dir)
        };
        assert_eq!(states.len(), 9, "{states:?}");
        assert_eq!(read("the first commit")["files"], json!([]));
        let edited = read("an edit, a non-ASCII name and a nested rule");
        assert!(
            edited["files"]
                .as_array()
                .unwrap()
                .contains(&json!("règle-détection-é.yaml")),
            "{edited}"
        );
        assert_eq!(
            edited["nested"],
            json!(["objects/rules/sub/nested-rule.yaml"])
        );
        assert!(read("no checkout").get("error").is_some());
        assert_eq!(
            read("a rename and a delete")["files"],
            json!(["renamed-rule.yaml"])
        );
        assert_eq!(read("a detached HEAD")["files"], edited["files"]);
        assert_eq!(
            read("a merge commit")["files"].as_array().map(Vec::len),
            Some(1)
        );
        assert!(read("a shallow clone").get("error").is_some());
        assert_eq!(
            read("a workspace below the git top level")["files"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }
}
