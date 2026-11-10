//! The git baseline on repositories the `git` program builds: each CI diff
//! source, and the failures a run reports. The local diff is compared with
//! the oracle by `cargo xtask payloads git --against python`.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers: git builds every repository here"
)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use opentide_compile::git::{self, DiffSource, GitError};

fn git_cmd(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn write(dir: &Path, path: &str, text: &str) {
    let path = dir.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn commit(dir: &Path, message: &str) -> String {
    git_cmd(dir, &["add", "-A"]);
    git_cmd(dir, &["commit", "-q", "-m", message]);
    git_cmd(dir, &["rev-parse", "HEAD"])
}

/// main: a (first), b (edits r1); feature from a: c (adds r2); merge of
/// feature into main (m).
struct History {
    _dir: tempfile::TempDir,
    root: PathBuf,
    a: String,
    b: String,
    c: String,
    m: String,
}

fn history() -> History {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "objects/rules/r1.yaml", "a: 1\n");
    let a = commit(&root, "a");
    git_cmd(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, "objects/rules/r2.yaml", "b: 1\n");
    let c = commit(&root, "c");
    git_cmd(&root, &["checkout", "-q", "main"]);
    write(&root, "objects/rules/r1.yaml", "a: 2\n");
    let b = commit(&root, "b");
    git_cmd(&root, &["merge", "-q", "--no-ff", "-m", "m", "feature"]);
    let m = git_cmd(&root, &["rev-parse", "HEAD"]);
    History {
        _dir: dir,
        root,
        a,
        b,
        c,
        m,
    }
}

fn changed(root: &Path, pairs: &[(&str, &str)]) -> Result<Vec<String>, GitError> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let env = move |name: &str| map.get(name).cloned();
    let source = git::diff_source(&env);
    git::changed_paths(root, root, &env, source)
}

#[test]
fn outside_ci_the_last_commit_is_read() {
    let h = history();
    // HEAD is the merge: its first parent is b, so the feature's file changed.
    assert_eq!(changed(&h.root, &[]).unwrap(), ["objects/rules/r2.yaml"]);
}

#[test]
fn a_github_push_reads_from_the_events_before() {
    let h = history();
    let event = h.root.join("event.json");
    std::fs::write(&event, format!("{{\"before\": \"{}\"}}", h.a)).unwrap();
    let event = event.to_string_lossy().into_owned();
    let got = changed(
        &h.root,
        &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", &h.m),
            ("GITHUB_EVENT_PATH", &event),
        ],
    )
    .unwrap();
    assert_eq!(got, ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]);
    // Without a usable before, HEAD's first parent.
    let got = changed(&h.root, &[("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", &h.m)]).unwrap();
    assert_eq!(got, ["objects/rules/r2.yaml"]);
    let missing = changed(&h.root, &[("GITHUB_ACTIONS", "true")]).unwrap_err();
    assert_eq!(
        missing,
        GitError::Failed("GITHUB_SHA is required to compute the changed rules".into())
    );
}

#[test]
fn a_github_pull_request_diffs_its_merge_commit_from_the_first_parent() {
    let h = history();
    let base = [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_HEAD_REF", "feature"),
        ("GITHUB_BASE_REF", "main"),
    ];
    let mut pairs = base.to_vec();
    pairs.push(("GITHUB_SHA", &h.m));
    assert_eq!(changed(&h.root, &pairs).unwrap(), ["objects/rules/r2.yaml"]);
    // Not a merge commit: the request's branches, as origin holds them.
    git_cmd(&h.root, &["update-ref", "refs/remotes/origin/main", &h.b]);
    git_cmd(
        &h.root,
        &["update-ref", "refs/remotes/origin/feature", &h.c],
    );
    let mut pairs = base.to_vec();
    pairs.push(("GITHUB_SHA", &h.c));
    assert_eq!(changed(&h.root, &pairs).unwrap(), ["objects/rules/r2.yaml"]);
    let refused = changed(
        &h.root,
        &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "pull_request"),
        ],
    )
    .unwrap_err();
    assert!(
        matches!(refused, GitError::Failed(message) if message.starts_with("Expected to find GITHUB_HEAD_REF"))
    );
}

#[test]
fn a_pull_request_target_run_reads_the_events_commits() {
    let h = history();
    let event = h.root.join("event.json");
    std::fs::write(
        &event,
        format!(
            "{{\"pull_request\": {{\"base\": {{\"sha\": \"{}\"}}, \"head\": {{\"sha\": \"{}\"}}}}}}",
            h.b, h.c
        ),
    )
    .unwrap();
    let event = event.to_string_lossy().into_owned();
    let got = changed(
        &h.root,
        &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "pull_request_target"),
            ("GITHUB_HEAD_REF", "feature"),
            ("GITHUB_BASE_REF", "main"),
            ("GITHUB_SHA", &h.b),
            ("GITHUB_EVENT_PATH", &event),
        ],
    )
    .unwrap();
    assert_eq!(got, ["objects/rules/r2.yaml"]);
}

#[test]
fn gitlab_reads_the_before_sha_and_the_merged_result() {
    let h = history();
    let push = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_COMMIT_SHA", &h.m),
            ("CI_COMMIT_BEFORE_SHA", &h.a),
        ],
    )
    .unwrap();
    assert_eq!(push, ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]);
    let first = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_COMMIT_SHA", &h.m),
            (
                "CI_COMMIT_BEFORE_SHA",
                "0000000000000000000000000000000000000000",
            ),
        ],
    )
    .unwrap();
    assert_eq!(first, ["objects/rules/r2.yaml"]);
    let merged = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_PIPELINE_SOURCE", "merge_request_event"),
            ("CI_MERGE_REQUEST_EVENT_TYPE", "merged_result"),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", &h.c),
            ("CI_MERGE_REQUEST_DIFF_BASE_SHA", &h.a),
            ("CI_COMMIT_SHA", &h.m),
        ],
    )
    .unwrap();
    assert_eq!(merged, ["objects/rules/r2.yaml"]);
    let detached = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_PIPELINE_SOURCE", "merge_request_event"),
            ("CI_MERGE_REQUEST_DIFF_BASE_SHA", &h.a),
            ("CI_COMMIT_SHA", &h.c),
        ],
    )
    .unwrap();
    assert_eq!(detached, ["objects/rules/r2.yaml"]);
}

#[test]
fn azure_reads_the_first_parent_and_the_pull_requests_merge() {
    let h = history();
    let push = changed(
        &h.root,
        &[("TF_BUILD", "True"), ("BUILD_SOURCEVERSION", &h.m)],
    )
    .unwrap();
    assert_eq!(push, ["objects/rules/r2.yaml"]);
    let request = changed(
        &h.root,
        &[
            ("TF_BUILD", "True"),
            ("BUILD_REASON", "PullRequest"),
            ("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature"),
            ("SYSTEM_PULLREQUEST_TARGETBRANCHNAME", "main"),
            ("SYSTEM_PULLREQUEST_SOURCECOMMITID", &h.c),
            ("BUILD_SOURCEVERSION", &h.m),
        ],
    )
    .unwrap();
    assert_eq!(request, ["objects/rules/r2.yaml"]);
    let unknown = changed(
        &h.root,
        &[
            ("TF_BUILD", "True"),
            ("BUILD_REASON", "PullRequest"),
            ("SYSTEM_PULLREQUEST_SOURCEBRANCH", "gone"),
            ("SYSTEM_PULLREQUEST_TARGETBRANCHNAME", "main"),
            ("BUILD_SOURCEVERSION", &h.c),
        ],
    )
    .unwrap_err();
    assert_eq!(
        unknown,
        GitError::Failed("Could not find git ref origin/main".into())
    );
}

#[test]
fn a_merge_whose_second_parent_is_not_the_requests_head_reads_the_origin_branches() {
    let h = history();
    // origin's branches put the request at b on top of a: the diff a..b
    // edits r1, where the merge's first parent (b) would give r2.
    git_cmd(&h.root, &["update-ref", "refs/remotes/origin/main", &h.a]);
    git_cmd(
        &h.root,
        &["update-ref", "refs/remotes/origin/feature", &h.b],
    );
    let azure = changed(
        &h.root,
        &[
            ("TF_BUILD", "True"),
            ("BUILD_REASON", "PullRequest"),
            ("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature"),
            ("SYSTEM_PULLREQUEST_TARGETBRANCHNAME", "main"),
            ("SYSTEM_PULLREQUEST_SOURCECOMMITID", &h.b),
            ("BUILD_SOURCEVERSION", &h.m),
        ],
    )
    .unwrap();
    assert_eq!(azure, ["objects/rules/r1.yaml"]);
    // GitLab: the source head is read instead, from the diff base.
    let gitlab = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_PIPELINE_SOURCE", "merge_request_event"),
            ("CI_MERGE_REQUEST_EVENT_TYPE", "merged_result"),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", &h.b),
            ("CI_MERGE_REQUEST_DIFF_BASE_SHA", &h.a),
            ("CI_COMMIT_SHA", &h.m),
        ],
    )
    .unwrap();
    assert_eq!(gitlab, ["objects/rules/r1.yaml"]);
}

#[test]
fn a_shallow_clone_names_the_parent_it_does_not_hold() {
    let h = history();
    let dir = tempfile::tempdir().unwrap();
    let shallow = dunce::canonicalize(dir.path()).unwrap().join("shallow");
    let path = h.root.to_string_lossy().replace('\\', "/");
    let url = format!("file:///{}", path.trim_start_matches('/'));
    git_cmd(
        dir.path(),
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &url,
            &shallow.to_string_lossy(),
        ],
    );
    // HEAD is the merge; its first parent, b, is not in the clone.
    assert_eq!(
        changed(&shallow, &[]).unwrap_err(),
        GitError::Failed(format!("Could not find git commit {}", h.b))
    );
}

#[test]
fn a_ci_run_without_a_checkout_names_where_it_looked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let error = changed(&root, &[("CI", "true")]).unwrap_err();
    assert_eq!(error, GitError::MissingCheckout(root.clone()));
    let env = |_: &str| None::<String>;
    assert!(git::no_commits_warning(&root, &env, "x").is_none());
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    assert_eq!(
        git::no_commits_warning(&root, &env, "commit them").as_deref(),
        Some(
            "HEAD names no commit yet (a new repository or an orphan branch), so no file has changed: commit them"
        )
    );
    assert_eq!(
        git::changed_paths(&root, &root, &env, DiffSource::ChangeRequest).unwrap_err(),
        GitError::Failed("A pull or merge request diff needs a CI run".into())
    );
}

#[test]
fn a_linked_worktree_reads_the_common_repository() {
    let h = history();
    let linked = h.root.join("linked");
    git_cmd(
        &h.root,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            linked.to_str().unwrap(),
            &h.m,
        ],
    );
    let env = |_: &str| None::<String>;
    let got = git::changed_paths(&linked, &linked, &env, DiffSource::LastCommit).unwrap();
    assert_eq!(got, ["objects/rules/r2.yaml"]);
}

#[test]
fn the_dry_run_reads_the_changed_rules_from_the_rules_folder() {
    let h = history();
    let env = |_: &str| None::<String>;
    let rules = h.root.join("objects/rules");
    let (scope, warning) =
        opentide_compile::dry_run::git_scope(&h.root, &h.root, &env, &rules, "objects/rules")
            .unwrap();
    assert_eq!(scope.files, [rules.join("r2.yaml")]);
    assert!(scope.nested.is_empty());
    assert_eq!(warning, None);
    // A repository without a commit has changed nothing, and says why.
    let empty = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(empty.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    let (scope, warning) = opentide_compile::dry_run::git_scope(
        &root,
        &root,
        &env,
        &root.join("objects/rules"),
        "objects/rules",
    )
    .unwrap();
    assert!(scope.files.is_empty());
    assert!(
        warning.is_some_and(|warning| warning.starts_with("HEAD names no commit yet")
            && warning.ends_with("commit the rules, or pass --all to read every rule file"))
    );
    // Outside a checkout, the error says what to do.
    let bare = tempfile::tempdir().unwrap();
    assert!(
        opentide_compile::dry_run::git_scope(bare.path(), bare.path(), &env, bare.path(), "x")
            .is_err()
    );
}
