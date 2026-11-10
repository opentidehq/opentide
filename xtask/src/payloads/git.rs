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

fn git(dir: &Path, home: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "golden")
        .env("GIT_AUTHOR_EMAIL", "golden@example.invalid")
        .env("GIT_COMMITTER_NAME", "golden")
        .env("GIT_COMMITTER_EMAIL", "golden@example.invalid")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
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
    let root = scratch.path().canonicalize()?;
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
    // The fixture links objects/rules to its folder; git would track the link
    // alone, so the rules move into a real folder.
    let link = repo.join("objects/rules");
    if fs::symlink_metadata(&link).is_ok_and(|meta| meta.file_type().is_symlink()) {
        let target = fs::canonicalize(&link)?;
        fs::remove_file(&link)?;
        fs::rename(&target, &link)?;
    }
    let mut states: Vec<(String, PathBuf)> = Vec::new();
    let check = |name: &str, dir: &Path, states: &mut Vec<(String, PathBuf)>| {
        // Each state is copied, so later commits do not change it.
        let copy = root.join(format!("state-{}", states.len()));
        let copied = Command::new("cp").arg("-a").arg(dir).arg(&copy).status();
        if copied.is_ok_and(|copied| copied.success()) {
            states.push((name.to_owned(), copy));
        }
    };
    git(&repo, home, &["init", "-q", "-b", "main"])?;
    check("no commit yet", &repo, &mut states);
    git(&repo, home, &["add", "-A", "--force"])?;
    git(&repo, home, &["commit", "-q", "-m", "first"])?;
    check("the first commit", &repo, &mut states);
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
    );
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
    check("a rename and a delete", &repo, &mut states);
    git(&repo, home, &["checkout", "-q", "--detach", "HEAD~1"])?;
    check("a detached HEAD", &repo, &mut states);
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
    check("a merge commit", &repo, &mut states);
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
    check("a shallow clone", &shallow, &mut states);
    // A workspace in a subfolder of its checkout: paths come from the top level.
    let outer = root.join("outer");
    let inner = outer.join("detections");
    fs::create_dir_all(&outer)?;
    let copied = Command::new("cp")
        .arg("-a")
        .arg(&states[1].1)
        .arg(&inner)
        .status()?;
    ensure!(copied.success(), "copy the workspace into a subfolder");
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
    check("no checkout", &bare, &mut states);
    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scripted_history_reads_each_state() {
        let (repo_root, _) = crate::vocab::diff::workspace().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().canonicalize().unwrap();
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
