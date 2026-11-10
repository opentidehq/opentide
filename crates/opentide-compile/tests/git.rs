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

#[test]
fn revisions_are_read_as_git_rev_parse_reads_them() {
    let h = history();
    // A short id, and a parent step from HEAD (the merge's second parent, c).
    let short = &h.a[..12];
    let got = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_COMMIT_BEFORE_SHA", short),
            ("CI_COMMIT_SHA", "HEAD^2"),
        ],
    );
    assert_eq!(got.unwrap(), ["objects/rules/r2.yaml"]);
    // An annotated tag is peeled to its commit; a branch is a partial name.
    git_cmd(&h.root, &["tag", "-a", "-m", "first", "v1", &h.a]);
    let got = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_COMMIT_BEFORE_SHA", "v1"),
            ("CI_COMMIT_SHA", "feature"),
        ],
    );
    assert_eq!(got.unwrap(), ["objects/rules/r2.yaml"]);
    // HEAD~1 is the merge's first parent, b.
    let got = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_COMMIT_BEFORE_SHA", "HEAD~1"),
            ("CI_COMMIT_SHA", &h.m),
        ],
    );
    assert_eq!(got.unwrap(), ["objects/rules/r2.yaml"]);
    // A reflog entry names no commit a run diffs.
    let got = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_COMMIT_BEFORE_SHA", "HEAD@{1}"),
            ("CI_COMMIT_SHA", &h.m),
        ],
    );
    assert_eq!(got, Err(GitError::Failed("No Source Commit Found".into())));
    // An unknown tip is named.
    let got = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_COMMIT_BEFORE_SHA", &h.b),
            ("CI_COMMIT_SHA", "no-such-branch"),
        ],
    );
    assert_eq!(
        got,
        Err(GitError::Failed(
            "Could not find git commit no-such-branch".into()
        ))
    );
}

#[test]
fn the_checkout_is_found_from_a_subfolder_and_a_bare_repository_is_none() {
    let h = history();
    let below = h.root.join("objects/rules");
    let env = |_: &str| None::<String>;
    let got = git::changed_paths(&below, &below, &env, DiffSource::LastCommit).unwrap();
    assert_eq!(got, ["objects/rules/r2.yaml"]);
    assert_eq!(git::worktree(&below), Some(h.root.clone()));
    let bare = h.root.join("bare.git");
    git_cmd(
        &h.root,
        &["clone", "-q", "--bare", ".", bare.to_str().unwrap()],
    );
    let inside = bare.join("refs");
    // The bare repository sits inside the checkout: discovery passes it by
    // and finds the checkout above.
    assert_eq!(git::worktree(&inside), Some(h.root.clone()));
    let lone = tempfile::tempdir().unwrap();
    let lone_bare = dunce::canonicalize(lone.path()).unwrap().join("b.git");
    git_cmd(
        &h.root,
        &["clone", "-q", "--bare", ".", lone_bare.to_str().unwrap()],
    );
    assert_eq!(git::worktree(&lone_bare), None);
    assert_eq!(
        git::changed_paths(&lone_bare, &lone_bare, &env, DiffSource::LastCommit),
        Err(GitError::MissingCheckout(lone_bare.clone()))
    );
}

/// `generate docs --changed`: the object files that differ from the default
/// branch's merge base, committed on the branch, edited, added (untracked)
/// or deleted; files of other folders and nested files are not read.
#[test]
fn docs_read_the_object_files_changed_against_the_default_branch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "objects/rules/kept.yaml", "name: kept\n");
    write(&root, "objects/rules/edited.yaml", "name: edited\n");
    write(&root, "objects/rules/deleted.yaml", "name: deleted\n");
    write(&root, "objects/rules/committed.yaml", "name: committed\n");
    write(&root, "other/elsewhere.yaml", "name: elsewhere\n");
    commit(&root, "base");
    git_cmd(&root, &["checkout", "-q", "-b", "feature"]);
    write(
        &root,
        "objects/rules/committed.yaml",
        "name: committed on the branch\n",
    );
    commit(&root, "on the branch");
    write(
        &root,
        "objects/rules/edited.yaml",
        "name: edited in the work tree\n",
    );
    write(&root, "objects/rules/added.yaml", "name: added\n");
    write(&root, "objects/rules/notes.md", "not an object\n");
    write(&root, "objects/rules/sub/nested.yaml", "name: nested\n");
    write(&root, "other/elsewhere.yaml", "name: changed elsewhere\n");
    std::fs::remove_file(root.join("objects/rules/deleted.yaml")).unwrap();
    let keep = |name: &str| {
        std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext == "yaml")
    };
    let changed = git::changed_in_folders(&root, &[root.join("objects/rules")], &keep).unwrap();
    let found: Vec<(&str, Option<&[u8]>)> = changed
        .iter()
        .map(|file| (file.relative.as_str(), file.baseline.as_deref()))
        .collect();
    assert_eq!(
        found,
        [
            ("objects/rules/added.yaml", None),
            (
                "objects/rules/committed.yaml",
                Some(b"name: committed\n".as_slice())
            ),
            (
                "objects/rules/deleted.yaml",
                Some(b"name: deleted\n".as_slice())
            ),
            (
                "objects/rules/edited.yaml",
                Some(b"name: edited\n".as_slice())
            ),
        ]
    );
    assert_eq!(changed[0].absolute, root.join("objects/rules/added.yaml"));
}

/// On the default branch with nothing else to compare with, the baseline is
/// HEAD: only work not committed yet counts.
#[test]
fn docs_on_a_lone_branch_compare_with_head() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "trunk"]);
    write(&root, "rules/a.yaml", "a: 1\n");
    commit(&root, "a");
    write(&root, "rules/b.yaml", "b: 1\n");
    commit(&root, "b");
    let keep = |_: &str| true;
    assert!(
        git::changed_in_folders(&root, &[root.join("rules")], &keep)
            .unwrap()
            .is_empty()
    );
    write(&root, "rules/b.yaml", "b: 2\n");
    let changed = git::changed_in_folders(&root, &[root.join("rules")], &keep).unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].relative, "rules/b.yaml");
}

/// No commit, or no checkout: the run says what it needs.
#[test]
fn docs_changes_need_a_commit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let keep = |_: &str| true;
    let error = git::changed_in_folders(&root, std::slice::from_ref(&root), &keep).unwrap_err();
    assert_eq!(error.message(), git::NO_GIT_MESSAGE);
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    let error = git::changed_in_folders(&root, std::slice::from_ref(&root), &keep).unwrap_err();
    assert_eq!(error.message(), git::NO_GIT_MESSAGE);
}

/// The `origin` remote's URL picks the Markdown flavour of a local run.
#[test]
fn the_origin_url_is_read_from_the_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    assert_eq!(git::origin_url(&root), None);
    git_cmd(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "git@gitlab.example.org:team/detections.git",
        ],
    );
    std::fs::create_dir_all(root.join("nested")).unwrap();
    assert_eq!(
        git::origin_url(&root.join("nested")).as_deref(),
        Some("git@gitlab.example.org:team/detections.git")
    );
}

/// A feature branch tracking its own remote copy still compares with the
/// default branch, not with what it already pushed.
#[test]
fn docs_on_a_pushed_feature_branch_compare_with_the_default_branch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "rules/a.yaml", "a: 1\n");
    commit(&root, "a");
    git_cmd(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, "rules/a.yaml", "a: 2\n");
    let head = commit(&root, "on the branch");
    git_cmd(
        &root,
        &["update-ref", "refs/remotes/origin/feature", head.as_str()],
    );
    git_cmd(&root, &["config", "branch.feature.remote", "origin"]);
    git_cmd(
        &root,
        &["config", "branch.feature.merge", "refs/heads/feature"],
    );
    let keep = |_: &str| true;
    let changed = git::changed_in_folders(&root, &[root.join("rules")], &keep).unwrap();
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert_eq!(changed[0].baseline.as_deref(), Some(b"a: 1\n".as_slice()));
}

fn yaml(name: &str) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "yaml")
}

fn changed_names(root: &Path, folder: &str) -> Vec<String> {
    git::changed_in_folders(root, &[root.join(folder)], &yaml)
        .unwrap()
        .into_iter()
        .map(|file| file.relative)
        .collect()
}

/// What git itself reports for `folder` against `base`: `git diff
/// --name-only` and `git ls-files --others --exclude-standard`, the oracle's
/// two commands.
fn git_reports(root: &Path, base: &str, folder: &str) -> Vec<String> {
    let mut names: Vec<String> = git_cmd(
        root,
        &[
            "diff",
            "--name-only",
            "--diff-filter=ACMRD",
            base,
            "--",
            folder,
        ],
    )
    .lines()
    .chain(
        git_cmd(
            root,
            &[
                "ls-files",
                "--others",
                "--exclude-standard",
                "--full-name",
                "--",
                folder,
            ],
        )
        .lines(),
    )
    .filter(|line| yaml(line) && !line[folder.len() + 1..].contains('/'))
    .map(str::to_owned)
    .collect();
    names.sort();
    names.dedup();
    names
}

/// An untracked file an exclude file ignores (`.gitignore`, a nested one,
/// `.git/info/exclude`) is no change, as `git ls-files --exclude-standard`
/// skips it; a tracked file stays read even when a pattern matches it.
#[test]
fn docs_changes_skip_ignored_untracked_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "objects/rules/tracked.yaml", "name: tracked\n");
    commit(&root, "tracked");
    write(&root, ".gitignore", "*.local.yaml\ntracked.yaml\n");
    write(&root, "objects/rules/.gitignore", "scratch-*.yaml\n");
    commit(&root, "base");
    write(&root, "objects/rules/draft.local.yaml", "name: draft\n");
    write(&root, "objects/rules/scratch-1.yaml", "name: scratch\n");
    write(&root, "objects/rules/excluded.yaml", "name: excluded\n");
    write(&root, ".git/info/exclude", "excluded.yaml\n");
    write(&root, "objects/rules/new.yaml", "name: new\n");
    write(
        &root,
        "objects/rules/tracked.yaml",
        "name: tracked, edited\n",
    );
    let expected = ["objects/rules/new.yaml", "objects/rules/tracked.yaml"];
    assert_eq!(git_reports(&root, "HEAD", "objects/rules"), expected);
    assert_eq!(changed_names(&root, "objects/rules"), expected);
}

/// A checkout with `core.autocrlf` (or a `text eol=crlf` attribute) has
/// CRLF files whose stored content is the baseline's: they are not changed,
/// as `git diff` compares a file through its clean filter.
#[test]
fn docs_changes_compare_files_through_the_clean_filters() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    git_cmd(&root, &["config", "core.autocrlf", "false"]);
    write(&root, "rules/a.yaml", "name: a\nlevel: 1\n");
    write(&root, "rules/b.yaml", "name: b\n");
    write(&root, "attributed/c.yaml", "name: c\n");
    write(&root, "attributed/.gitattributes", "*.yaml text eol=crlf\n");
    commit(&root, "base");
    // What a Windows checkout with autocrlf writes.
    git_cmd(&root, &["config", "core.autocrlf", "true"]);
    write(&root, "rules/a.yaml", "name: a\r\nlevel: 1\r\n");
    write(&root, "rules/b.yaml", "name: b, edited\r\n");
    write(&root, "attributed/c.yaml", "name: c\r\n");
    assert_eq!(git_reports(&root, "HEAD", "rules"), ["rules/b.yaml"]);
    assert_eq!(changed_names(&root, "rules"), ["rules/b.yaml"]);
    assert!(git_reports(&root, "HEAD", "attributed").is_empty());
    assert!(changed_names(&root, "attributed").is_empty());
    // Without the conversion, the CRLF bytes are a change.
    git_cmd(&root, &["config", "core.autocrlf", "false"]);
    assert_eq!(
        changed_names(&root, "rules"),
        ["rules/a.yaml", "rules/b.yaml"]
    );
}

/// A file removed from the index but left on disk reads as changed (`git
/// diff` reports the baseline's as deleted), even when it is ignored.
#[test]
fn docs_changes_report_a_file_no_longer_tracked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "rules/a.yaml", "name: a\n");
    write(&root, "rules/b.yaml", "name: b\n");
    commit(&root, "base");
    git_cmd(&root, &["rm", "-q", "--cached", "rules/a.yaml"]);
    write(&root, ".gitignore", "a.yaml\n");
    assert_eq!(git_reports(&root, "HEAD", "rules"), ["rules/a.yaml"]);
    assert_eq!(changed_names(&root, "rules"), ["rules/a.yaml"]);
}

/// The baseline is the merge base with the default branch, not its tip: a
/// commit the default branch gained after the work branched off is no
/// change of the work.
#[test]
fn docs_compare_with_the_merge_base_of_an_advanced_default_branch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "rules/a.yaml", "a: 1\n");
    write(&root, "rules/b.yaml", "b: 1\n");
    let fork = commit(&root, "base");
    git_cmd(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, "rules/a.yaml", "a: 2\n");
    commit(&root, "on the branch");
    git_cmd(&root, &["checkout", "-q", "main"]);
    write(&root, "rules/b.yaml", "b: 2\n");
    write(&root, "rules/c.yaml", "c: 1\n");
    commit(&root, "on main");
    git_cmd(&root, &["checkout", "-q", "feature"]);
    let changed = git::changed_in_folders(&root, &[root.join("rules")], &yaml).unwrap();
    let found: Vec<(&str, Option<&[u8]>)> = changed
        .iter()
        .map(|file| (file.relative.as_str(), file.baseline.as_deref()))
        .collect();
    assert_eq!(found, [("rules/a.yaml", Some(b"a: 1\n".as_slice()))]);
    assert_eq!(git_reports(&root, &fork, "rules"), ["rules/a.yaml"]);
}

/// main: base; `release` from base: r (edits a); `feature` from release: f
/// (edits b).
fn release_history() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "rules/a.yaml", "a: 1\n");
    write(&root, "rules/b.yaml", "b: 1\n");
    commit(&root, "base");
    git_cmd(&root, &["checkout", "-q", "-b", "release"]);
    write(&root, "rules/a.yaml", "a: 2\n");
    commit(&root, "r");
    git_cmd(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, "rules/b.yaml", "b: 2\n");
    commit(&root, "f");
    (dir, root)
}

/// A branch tracking another remote branch than its own copy compares with
/// that upstream, ahead of the default branch.
#[test]
fn docs_compare_with_a_tracked_upstream_that_is_not_the_branch_itself() {
    let (_dir, root) = release_history();
    assert_eq!(
        changed_names(&root, "rules"),
        ["rules/a.yaml", "rules/b.yaml"]
    );
    let release = git_cmd(&root, &["rev-parse", "release"]);
    git_cmd(
        &root,
        &[
            "update-ref",
            "refs/remotes/origin/release",
            release.as_str(),
        ],
    );
    git_cmd(&root, &["config", "branch.feature.remote", "origin"]);
    git_cmd(
        &root,
        &["config", "branch.feature.merge", "refs/heads/release"],
    );
    assert_eq!(changed_names(&root, "rules"), ["rules/b.yaml"]);
}

/// A branch tracking a local branch (`remote = .`) compares with that
/// branch.
#[test]
fn docs_compare_with_a_tracked_local_branch() {
    let (_dir, root) = release_history();
    git_cmd(&root, &["config", "branch.feature.remote", "."]);
    git_cmd(
        &root,
        &["config", "branch.feature.merge", "refs/heads/release"],
    );
    assert_eq!(changed_names(&root, "rules"), ["rules/b.yaml"]);
}

/// `origin/HEAD` names the default branch when it has none of the usual
/// names.
#[test]
fn docs_compare_with_the_default_branch_origin_head_names() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "trunk"]);
    write(&root, "rules/a.yaml", "a: 1\n");
    let base = commit(&root, "base");
    git_cmd(&root, &["checkout", "-q", "-b", "feature"]);
    write(&root, "rules/a.yaml", "a: 2\n");
    commit(&root, "on the branch");
    git_cmd(&root, &["branch", "-q", "-D", "trunk"]);
    git_cmd(
        &root,
        &["update-ref", "refs/remotes/origin/trunk", base.as_str()],
    );
    // Without origin/HEAD nothing names the default branch: the baseline is
    // HEAD, and the committed edit is no change.
    assert!(changed_names(&root, "rules").is_empty());
    git_cmd(
        &root,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/trunk",
        ],
    );
    assert_eq!(changed_names(&root, "rules"), ["rules/a.yaml"]);
}
