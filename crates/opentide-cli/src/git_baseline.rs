//! "What changed against the default branch" (`core/git_baseline.py`), for
//! `generate inflight` outside CI: the merge base with the first default
//! branch that resolves, then the paths changed in the work tree against it
//! and the untracked ones, read with the `git` program as the oracle reads
//! them. The working tree's changes and untracked files need git's index
//! and ignore rules, which the gix crates `opentide-compile` reads commits
//! with do not cover. `setup ci` asks git for the default branch the same
//! way (`cli/services/setup/ci.py`).
//!
//! git runs with the run's environment ([`Env`]), as the oracle's
//! subprocesses inherit its own.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::env::Env;

/// Default-branch names probed as `origin/<name>`, then `<name>`.
pub const DEFAULT_BRANCH_NAMES: [&str; 3] = ["development", "main", "master"];

/// Why there is no baseline.
pub const NO_GIT_MESSAGE: &str =
    "changed-object discovery requires a git repository with at least one commit";

/// Runs git in `dir` with `env`: its stdout when it succeeded, as bytes.
fn git(env: &Env, dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .envs(env.iter())
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout)
}

/// Git's trimmed stdout as text, when it succeeded.
pub fn stdout(env: &Env, dir: &Path, args: &[&str]) -> Option<String> {
    git(env, dir, args).map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
}

/// Whether `root` is in a work tree with at least one commit.
fn has_head(env: &Env, root: &Path) -> bool {
    stdout(env, root, &["rev-parse", "--is-inside-work-tree"]).as_deref() == Some("true")
        && stdout(env, root, &["rev-parse", "--verify", "HEAD"]).is_some()
}

/// The checked-out branch, `None` on a detached HEAD.
fn current_branch(env: &Env, root: &Path) -> Option<String> {
    stdout(env, root, &["symbolic-ref", "--quiet", "HEAD"])
        .and_then(|reference| reference.strip_prefix("refs/heads/").map(str::to_owned))
}

/// The branch `origin/HEAD` points at.
fn remote_default(env: &Env, root: &Path) -> Option<String> {
    stdout(
        env,
        root,
        &["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
    )
    .and_then(|reference| {
        reference
            .strip_prefix("refs/remotes/origin/")
            .map(str::to_owned)
    })
}

/// The baseline refs to try, most specific first (`candidate_refs`).
fn candidates(env: &Env, root: &Path) -> Vec<String> {
    let head = current_branch(env, root);
    let upstream = stdout(
        env,
        root,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    )
    .filter(|upstream| !upstream.is_empty());
    let remote = remote_default(env, root);
    let mut found: Vec<String> = Vec::new();
    let mut last_resort = None;
    match (&upstream, &head) {
        (Some(upstream), Some(branch))
            if stdout(
                env,
                root,
                &["config", "--get", &format!("branch.{branch}.merge")],
            ) == Some(format!("refs/heads/{branch}")) =>
        {
            let is_default = match &remote {
                Some(remote) => branch == remote,
                None => DEFAULT_BRANCH_NAMES.contains(&branch.as_str()),
            };
            if is_default {
                found.push(upstream.clone());
            } else {
                last_resort = Some(upstream.clone());
            }
        }
        (Some(upstream), _) => found.push(upstream.clone()),
        _ => {}
    }
    if let Some(remote) = &remote {
        found.push(format!("origin/{remote}"));
    }
    found.extend(
        DEFAULT_BRANCH_NAMES
            .iter()
            .map(|name| format!("origin/{name}")),
    );
    found.extend(DEFAULT_BRANCH_NAMES.iter().map(|name| (*name).to_owned()));
    found.extend(last_resort);
    let mut ordered: Vec<String> = Vec::new();
    for candidate in found {
        if Some(&candidate) == head.as_ref() || ordered.contains(&candidate) {
            continue;
        }
        ordered.push(candidate);
    }
    ordered
}

/// The commit to diff against (`resolve_baseline`): the merge base with the
/// first candidate that has one, else HEAD.
///
/// # Errors
///
/// No work tree, or no commit: [`NO_GIT_MESSAGE`].
pub fn resolve(env: &Env, root: &Path) -> Result<String, String> {
    if !has_head(env, root) {
        return Err(NO_GIT_MESSAGE.to_owned());
    }
    for candidate in candidates(env, root) {
        if let Some(commit) = stdout(env, root, &["merge-base", "HEAD", &candidate])
            .filter(|commit| !commit.is_empty())
        {
            return Ok(commit);
        }
    }
    stdout(env, root, &["rev-parse", "HEAD"])
        .filter(|commit| !commit.is_empty())
        .ok_or_else(|| NO_GIT_MESSAGE.to_owned())
}

/// The work tree's top level, which git's paths are relative to.
pub fn toplevel(env: &Env, root: &Path) -> PathBuf {
    stdout(env, root, &["rev-parse", "--show-toplevel"])
        .filter(|top| !top.is_empty())
        .map_or_else(|| root.to_path_buf(), PathBuf::from)
}

/// The paths changed against `baseline` (deleted ones included) and the
/// untracked ones, relative to the top level, each once
/// (`changed_paths`). A path that is not UTF-8 is left out with a warning.
pub fn changed(env: &Env, root: &Path, baseline: &str, pathspec: &str) -> Vec<String> {
    let top = toplevel(env, root);
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let runs: [&[&str]; 2] = [
        &[
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACMRD",
            baseline,
            "--",
            pathspec,
        ],
        &[
            "ls-files",
            "-z",
            "--others",
            "--exclude-standard",
            "--full-name",
            "--",
            pathspec,
        ],
    ];
    for args in runs {
        if let Some(out) = git(env, &top, args) {
            lines.extend(out.split(|byte| *byte == 0).map(<[u8]>::to_vec));
        }
    }
    let mut paths: Vec<String> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Ok(path) = String::from_utf8(line) else {
            tracing::warn!("git_path_not_utf8");
            continue;
        };
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env::from_pairs([
            ("PATH", std::env::var("PATH").unwrap_or_default()),
            ("GIT_CONFIG_NOSYSTEM", "1".into()),
            ("GIT_CONFIG_GLOBAL", "/dev/null".into()),
        ])
    }

    fn run(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    #[test]
    fn a_feature_branch_diffs_against_its_default_branch() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let env = env();
        assert_eq!(resolve(&env, root).unwrap_err(), NO_GIT_MESSAGE);
        run(root, &["init", "-q", "-b", "master"]);
        std::fs::create_dir_all(root.join("objects/rules")).unwrap();
        std::fs::write(root.join("objects/rules/a.yaml"), "a: 1\n").unwrap();
        std::fs::write(root.join("objects/rules/b.yaml"), "b: 1\n").unwrap();
        run(root, &["add", "."]);
        run(root, &["commit", "-q", "-m", "one"]);
        let base = stdout(&env, root, &["rev-parse", "HEAD"]).unwrap();
        // On the default branch with nothing else: HEAD.
        assert_eq!(resolve(&env, root).unwrap(), base);
        run(root, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(root.join("objects/rules/a.yaml"), "a: 2\n").unwrap();
        run(root, &["commit", "-q", "-am", "two"]);
        std::fs::remove_file(root.join("objects/rules/b.yaml")).unwrap();
        std::fs::write(root.join("objects/rules/c.yaml"), "c: 1\n").unwrap();
        std::fs::write(root.join("other.yaml"), "x: 1\n").unwrap();
        assert_eq!(resolve(&env, root).unwrap(), base);
        assert_eq!(
            changed(&env, root, &base, "objects/"),
            [
                "objects/rules/a.yaml",
                "objects/rules/b.yaml",
                "objects/rules/c.yaml"
            ]
        );
    }
}
