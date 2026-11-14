//! The `opentide` binary on real folders and git repositories (#1139): the
//! workspace each command finds from where it starts (#294), the changed
//! objects `generate docs --changed` and `generate inflight` read from git
//! (#241, #251, #268), and the chain a first user runs. Each test starts the
//! binary as a person's shell does, with no `OPENTIDE_*`, CI or agent
//! variable but those it sets.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a folder, a git command or a run that fails is a failure"
)]

#[path = "common/tutorial.rs"]
mod tutorial;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The variables a test's own environment could leak into a run.
const LEAKED: [&str; 9] = [
    "DEPLOYMENT_PLAN",
    "CI",
    "GITHUB_ACTIONS",
    "TF_BUILD",
    "INFLIGHT_PATHS",
    "CLAUDECODE",
    "AI_AGENT",
    "NO_COLOR",
    "CLAUDE_PROJECT_DIR",
];

/// What a run printed and how it ended.
#[derive(Debug)]
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    /// The JSON document on stdout.
    fn document(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|error| panic!("{error}: {self:?}"))
    }

    /// The document of a run that succeeded (exit 0, and `ok` when it says).
    fn ok(&self) -> Value {
        assert_eq!(self.code, Some(0), "{self:?}");
        assert!(!self.stderr.contains("panicked"), "{self:?}");
        let document = self.document();
        if let Some(ok) = document.get("ok") {
            assert_eq!(ok, true, "{self:?}");
        }
        document
    }
}

/// `opentide --json <args>` in `cwd`, with the variables `env` added.
fn opentide(cwd: &Path, args: &[&str], env: &[(&str, &Path)]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
    command.arg("--json").args(args).current_dir(cwd);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OPENTIDE_") {
            command.env_remove(name);
        }
    }
    for name in LEAKED {
        command.env_remove(name);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// `git <args>` in `dir`, which must succeed.
fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(["-c", "user.email=e2e@opentide.test", "-c", "user.name=e2e"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
}

/// A fresh folder, its path canonical (macOS's `/var` is `/private/var`).
fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

/// `opentide setup --yes` for Sentinel at `workspace`, run from its parent,
/// then the tutorial's three objects written into it.
fn scaffold(workspace: &Path) {
    let parent = workspace.parent().unwrap();
    std::fs::create_dir_all(parent).unwrap();
    let path = workspace.to_str().unwrap();
    let setup = ["setup", "--yes", "--name", "Baseline", "--platform"];
    opentide(
        parent,
        &[&setup[..], &["sentinel", "--path", path]].concat(),
        &[],
    )
    .ok();
    tutorial::write_objects(workspace);
}

/// `opentide --json --repo <ws> <args>` in `ws`, the workspace variables
/// naming it too.
fn in_workspace(ws: &Path, args: &[&str]) -> Run {
    let repo = ["--repo", ws.to_str().unwrap()];
    let env = [("OPENTIDE_REPO_ROOT", ws), ("OPENTIDE_TIDE_WORKSPACE", ws)];
    opentide(ws, &[&repo[..], args].concat(), &env)
}

/// [`scaffold`], then `generate`: the catalogue a pull request changes.
fn catalogue(ws: &Path) {
    scaffold(ws);
    in_workspace(ws, &["generate"]).ok();
}

/// `checkout` made a git repository on `branch`, everything committed, and
/// a `feature` branch checked out.
fn on_a_feature_branch(checkout: &Path, branch: &str) {
    git(checkout, &["init", "-q", "-b", branch, "."]);
    git(checkout, &["add", "-A"]);
    git(checkout, &["commit", "-qm", "initial catalogue"]);
    git(checkout, &["checkout", "-qb", "feature"]);
}

/// The tutorial rule's version raised: a change to it.
fn bump_rule(ws: &Path) {
    tutorial::edit(ws, tutorial::RULE_FILE, "version: 1", "version: 2");
}

/// The tutorial rule copied to `objects/rules/<name>` as another rule.
fn copy_rule(ws: &Path, name: &std::ffi::OsStr, uuid: &str) -> std::io::Result<()> {
    let text = std::fs::read_to_string(ws.join(tutorial::RULE_FILE)).unwrap();
    let text = text
        .replace(tutorial::RULE, uuid)
        .replace("Sentinel KQL Rule", "Another Sentinel Rule");
    std::fs::write(ws.join("objects/rules").join(name), text)
}

fn changed_paths(document: &Value) -> Vec<&str> {
    let paths = document["changed_paths"].as_array().expect("changed_paths");
    paths.iter().map(|path| path.as_str().unwrap()).collect()
}

/// The inflight shards `generate inflight` wrote, by file name.
fn shards(ws: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(ws.join(".opentide/inflight")) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "json"))
        .collect();
    names.sort();
    names
}

fn the_rule_shard() -> Vec<String> {
    vec![format!("{}.json", tutorial::RULE)]
}

#[test]
fn docs_changed_without_git_is_a_structured_failure() {
    let (_dir, root) = scratch();
    let ws = root.join("no-git");
    catalogue(&ws);
    let run = in_workspace(&ws, &["generate", "docs", "--changed"]);
    assert_eq!(run.code, Some(1), "{run:?}");
    assert!(!run.stderr.contains("panicked"), "{run:?}");
    let document = run.document();
    assert_eq!(document["ok"], false, "{run:?}");
    assert_eq!(document["status"], "failed", "{run:?}");
    let message = document["message"].as_str().unwrap();
    assert!(message.contains("git repository"), "{message}");
}

#[test]
fn inflight_without_git_succeeds() {
    let (_dir, root) = scratch();
    let ws = root.join("no-git-inflight");
    catalogue(&ws);
    let document = in_workspace(&ws, &["generate", "inflight"]).ok();
    assert_eq!(document["phase"], "inflight", "{document}");
}

/// A feature branch off `master`: docs and inflight see the committed diff.
#[test]
fn changed_objects_resolve_against_a_master_default_branch() {
    let (_dir, root) = scratch();
    let ws = root.join("master-repo");
    catalogue(&ws);
    on_a_feature_branch(&ws, "master");
    bump_rule(&ws);
    git(&ws, &["commit", "-qam", "bump rule version"]);

    let docs = in_workspace(&ws, &["generate", "docs", "--changed"]).ok();
    assert_eq!(changed_paths(&docs), [tutorial::RULE_FILE], "{docs}");
    assert!(docs["counts"]["rules"].as_u64() >= Some(1), "{docs}");
    in_workspace(&ws, &["generate", "inflight"]).ok();
    assert_eq!(shards(&ws), the_rule_shard());
}

#[test]
fn an_untracked_object_counts_as_changed() {
    let (_dir, root) = scratch();
    let ws = root.join("untracked-repo");
    catalogue(&ws);
    on_a_feature_branch(&ws, "development");
    let uuid = "00000000-0000-4000-8003-000000000099";
    copy_rule(&ws, "second-rule.yaml".as_ref(), uuid).unwrap();

    let docs = in_workspace(&ws, &["generate", "docs", "--changed"]).ok();
    assert!(
        changed_paths(&docs).contains(&"objects/rules/second-rule.yaml"),
        "{docs}"
    );
}

/// git prints `detections/objects/...` for a workspace kept in a folder of
/// the checkout: joined onto the workspace, or matched against `^objects/`,
/// every change was lost.
#[test]
fn a_workspace_nested_in_the_checkout_still_sees_its_changes() {
    let (_dir, root) = scratch();
    let checkout = root.join("checkout");
    let ws = checkout.join("detections");
    catalogue(&ws);
    on_a_feature_branch(&checkout, "main");
    bump_rule(&ws);

    let docs = in_workspace(&ws, &["generate", "docs", "--changed"]).ok();
    assert!(docs["counts"]["rules"].as_u64() >= Some(1), "{docs}");
    let names: Vec<_> = changed_paths(&docs)
        .into_iter()
        .map(|path| path.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(names, ["sentinel-kql-rule.yaml"], "{docs}");
    in_workspace(&ws, &["generate", "inflight"]).ok();
    assert_eq!(shards(&ws), the_rule_shard());
}

/// #294: with no `--repo` or `OPENTIDE_*`, the checkout's root won over the
/// workspace in it.
#[test]
fn a_nested_workspace_is_found_from_the_cwd_for_changed_objects() {
    for start in ["detections", "detections/objects/rules"] {
        let (_dir, root) = scratch();
        let checkout = root.join("checkout");
        let ws = checkout.join("detections");
        catalogue(&ws);
        on_a_feature_branch(&checkout, "main");
        bump_rule(&ws);
        git(&checkout, &["commit", "-qam", "bump rule version"]);

        let cwd = checkout.join(start);
        let docs = opentide(&cwd, &["generate", "docs", "--changed"], &[]).ok();
        let changed = format!("detections/{}", tutorial::RULE_FILE);
        assert_eq!(changed_paths(&docs), [changed.as_str()], "{start}: {docs}");
        assert!(docs["counts"]["rules"].as_u64() >= Some(1), "{docs}");
        assert_eq!(Path::new(docs["output"].as_str().unwrap()), ws.join("docs"));
        opentide(&cwd, &["generate", "inflight"], &[]).ok();
        assert_eq!(shards(&ws), the_rule_shard(), "{start}");
    }
}

/// A repository whose `feature` branch is pushed with `-u`, so that it
/// tracks itself: the bare origin and the clone.
fn published_feature_branch(root: &Path) -> (PathBuf, PathBuf) {
    let origin = root.join("origin.git");
    git(root, &["init", "-q", "--bare", "-b", "main", "origin.git"]);
    let ws = root.join("pushed");
    catalogue(&ws);
    git(&ws, &["init", "-q", "-b", "main", "."]);
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-qm", "initial catalogue"]);
    git(&ws, &["remote", "add", "origin", origin.to_str().unwrap()]);
    git(&ws, &["push", "-q", "-u", "origin", "main"]);
    git(&ws, &["checkout", "-qb", "feature"]);
    bump_rule(&ws);
    git(&ws, &["commit", "-qam", "bump rule version"]);
    git(&ws, &["push", "-q", "-u", "origin", "feature"]);
    (origin, ws)
}

/// After `push -u` the upstream is the branch itself: `merge-base HEAD
/// origin/feature` is `HEAD`, and every committed change vanished.
#[test]
fn a_pushed_feature_branch_still_compares_against_the_default_branch() {
    let (_dir, root) = scratch();
    let (_, ws) = published_feature_branch(&root);
    let docs = in_workspace(&ws, &["generate", "docs", "--changed"]).ok();
    assert_eq!(changed_paths(&docs), [tutorial::RULE_FILE], "{docs}");
    in_workspace(&ws, &["generate", "inflight"]).ok();
    assert_eq!(shards(&ws), the_rule_shard());
}

/// `actions/checkout` runs `checkout -B <branch> refs/remotes/origin/<branch>`,
/// which sets the branch's upstream to its own remote copy.
#[test]
fn a_ci_checkout_of_the_pr_branch_finds_its_changes() {
    let (_dir, root) = scratch();
    let (origin, _) = published_feature_branch(&root);
    let ci = root.join("ci");
    std::fs::create_dir(&ci).unwrap();
    git(&ci, &["init", "-q", "."]);
    git(&ci, &["remote", "add", "origin", origin.to_str().unwrap()]);
    let refspec = "+refs/heads/*:refs/remotes/origin/*";
    git(&ci, &["fetch", "-q", "origin", refspec]);
    let remote = "refs/remotes/origin/feature";
    git(&ci, &["checkout", "-q", "--force", "-B", "feature", remote]);

    in_workspace(&ci, &["generate", "inflight"]).ok();
    assert_eq!(shards(&ci), the_rule_shard(), "the PR job found no changes");
}

/// git C-quotes a path that is not ASCII (`"d\303\251tection.yaml"`) unless
/// asked not to.
#[test]
fn non_ascii_object_file_names_are_kept() {
    let (_dir, root) = scratch();
    let ws = root.join("unicode-repo");
    catalogue(&ws);
    on_a_feature_branch(&ws, "main");
    let uuid = "00000000-0000-4000-8003-000000000077";
    copy_rule(&ws, "détection-règle.yaml".as_ref(), uuid).unwrap();

    let docs = in_workspace(&ws, &["generate", "docs", "--changed"]).ok();
    assert_eq!(
        changed_paths(&docs),
        ["objects/rules/détection-règle.yaml"],
        "{docs}"
    );
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-qm", "add a rule with a French name"]);
    in_workspace(&ws, &["generate", "inflight"]).ok();
    assert!(
        shards(&ws).contains(&format!("{uuid}.json")),
        "{:?}",
        shards(&ws)
    );
}

/// A Latin-1 file name is no UTF-8: it is reported and left out, and the
/// JSON document still prints.
#[cfg(unix)]
#[test]
fn a_non_utf8_object_file_name_does_not_break_json_output() {
    use std::os::unix::ffi::OsStrExt as _;
    let (_dir, root) = scratch();
    let ws = root.join("latin1-repo");
    catalogue(&ws);
    on_a_feature_branch(&ws, "main");
    let name = std::ffi::OsStr::from_bytes(b"r\xe8gle.yaml");
    let uuid = "00000000-0000-4000-8003-000000000066";
    if copy_rule(&ws, name, uuid).is_err() {
        // macOS (APFS) refuses a file name that is not UTF-8.
        return;
    }
    bump_rule(&ws);

    let run = in_workspace(&ws, &["generate", "docs", "--changed"]);
    let docs = run.ok();
    assert_eq!(changed_paths(&docs), [tutorial::RULE_FILE], "{docs}");
    assert!(run.stderr.contains("git_path_not_utf8"), "{run:?}");
}
