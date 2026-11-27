//! The git baseline on repositories the `git` program builds: each CI diff
//! source, and the failures a run reports.
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
        // No automatic maintenance or gc: either works in `.git` in the
        // background after a commit, while the test reads the repository (#934).
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "maintenance.auto")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "gc.auto")
        .env("GIT_CONFIG_VALUE_1", "0")
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
    // An all-zero before: the push created the branch, so every file is new (#1683).
    assert_eq!(first, ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]);
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
    // HEAD is the merge; its first parent, b, is not in the clone, and the
    // error says why and what to fetch.
    let hint = "the checkout is shallow, so it does not hold the commits the diff needs. \
                Check out the full history (`fetch-depth: 0` in GitHub Actions, \
                `GIT_DEPTH: \"0\"` on GitLab, `fetchDepth: 0` on Azure Pipelines)";
    assert_eq!(
        changed(&shallow, &[]).unwrap_err(),
        GitError::Failed(format!("Could not find git commit {}: {hint}", h.b))
    );
    // So does a CI push read from a depth-1 checkout: its event names a
    // `before` the clone does not hold (a push of several commits), and the
    // fallback to the pushed commit's parent finds none either.
    let events = tempfile::tempdir().unwrap();
    let event = events.path().join("event.json");
    std::fs::write(&event, format!("{{\"before\": \"{}\"}}", h.a)).unwrap();
    let event = event.to_string_lossy().into_owned();
    let pushed = changed(
        &shallow,
        &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", &h.m),
            ("GITHUB_EVENT_PATH", &event),
        ],
    )
    .unwrap_err();
    assert_eq!(
        pushed,
        GitError::Failed(format!("Could not find git commit {}: {hint}", h.b))
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
    // A reflog entry names no commit a run diffs: as a before the checkout
    // does not hold (#1683), the run reads the last commit, from HEAD's
    // first parent (b), and the dry run warns.
    let got = changed(
        &h.root,
        &[
            ("CI", "true"),
            ("CI_COMMIT_BEFORE_SHA", "HEAD@{1}"),
            ("CI_COMMIT_SHA", &h.m),
        ],
    );
    assert_eq!(got.unwrap(), ["objects/rules/r2.yaml"]);
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

fn through_head(
    root: &Path,
    pairs: &[(&str, &str)],
    since: Option<&str>,
) -> Result<Vec<String>, GitError> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let env = move |name: &str| map.get(name).cloned();
    git::changed_through_head(root, root, &env, since)
}

/// `share push --changed` (#834): the push's diff up to HEAD, from the
/// trigger's first parent, GitLab's before SHA, or `--since`.
#[test]
fn the_push_is_read_up_to_head_from_its_base() {
    let h = history();
    // A deploy's write-back after the push: HEAD moves past the trigger.
    write(&h.root, "objects/rules/r3.yaml", "c: 1\n");
    commit(&h.root, "write-back");
    let github = [("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", h.m.as_str())];
    assert_eq!(
        through_head(&h.root, &github, None).unwrap(),
        ["objects/rules/r2.yaml", "objects/rules/r3.yaml"]
    );
    // The event's `before` is not read: the trigger's first parent is the base.
    let event = h.root.join("event.json");
    std::fs::write(&event, format!("{{\"before\": \"{}\"}}", h.a)).unwrap();
    let event = event.to_string_lossy().into_owned();
    let with_event = [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_SHA", h.m.as_str()),
        ("GITHUB_EVENT_PATH", event.as_str()),
    ];
    assert_eq!(
        through_head(&h.root, &with_event, None).unwrap(),
        ["objects/rules/r2.yaml", "objects/rules/r3.yaml"]
    );
    // GitLab's before SHA, unless all zeros.
    let gitlab = [
        ("CI", "true"),
        ("CI_COMMIT_SHA", h.m.as_str()),
        ("CI_COMMIT_BEFORE_SHA", h.c.as_str()),
    ];
    assert_eq!(
        through_head(&h.root, &gitlab, None).unwrap(),
        ["objects/rules/r1.yaml", "objects/rules/r3.yaml"]
    );
    let zeros = [
        ("CI", "true"),
        ("CI_COMMIT_SHA", h.m.as_str()),
        (
            "CI_COMMIT_BEFORE_SHA",
            "0000000000000000000000000000000000000000",
        ),
    ];
    assert_eq!(
        through_head(&h.root, &zeros, None).unwrap(),
        ["objects/rules/r2.yaml", "objects/rules/r3.yaml"]
    );
    // Azure: the trigger's first parent.
    let azure = [("TF_BUILD", "True"), ("BUILD_SOURCEVERSION", "HEAD")];
    assert_eq!(
        through_head(&h.root, &azure, None).unwrap(),
        ["objects/rules/r3.yaml"]
    );
    // A push of the first commit started from nothing: every file up to
    // HEAD is new (smoke E9/D10).
    let every: Vec<String> = git_cmd(&h.root, &["ls-files"])
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        through_head(
            &h.root,
            &[("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", &h.a)],
            None
        )
        .unwrap(),
        every
    );
}

#[test]
fn a_push_without_its_trigger_or_with_an_unknown_one_fails() {
    let h = history();
    assert_eq!(
        through_head(&h.root, &[("GITHUB_ACTIONS", "true")], None).unwrap_err(),
        GitError::Failed("GITHUB_SHA is required to compute the changed objects".into())
    );
    assert_eq!(
        through_head(&h.root, &[("CI", "true"), ("CI_COMMIT_SHA", "")], None).unwrap_err(),
        GitError::Failed("CI_COMMIT_SHA is required to compute the changed objects".into())
    );
    let unknown = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(
        through_head(
            &h.root,
            &[("TF_BUILD", "True"), ("BUILD_SOURCEVERSION", unknown)],
            None
        )
        .unwrap_err(),
        GitError::Failed(format!("Could not find git commit {unknown}"))
    );
    // A tree is no commit.
    let tree = git_cmd(&h.root, &["rev-parse", "HEAD^{tree}"]);
    assert_eq!(
        through_head(
            &h.root,
            &[("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", &tree)],
            None
        )
        .unwrap_err(),
        GitError::Failed(format!("Object {tree} is not a commit"))
    );
}

/// `--since` names a commit as the oracle read it: a full id, a branch,
/// `origin/<branch>`, `refs/...` (an annotated tag peeled); never a short id
/// or a revision expression.
#[test]
fn since_names_a_commit_as_the_oracle_read_it() {
    let h = history();
    let local = |since: &str| through_head(&h.root, &[], Some(since));
    assert_eq!(local(&h.b).unwrap(), ["objects/rules/r2.yaml"]);
    assert_eq!(
        local(&h.a).unwrap(),
        ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]
    );
    assert!(local("main").unwrap().is_empty());
    assert!(local("HEAD").unwrap().is_empty());
    assert_eq!(local("feature").unwrap(), ["objects/rules/r1.yaml"]);
    assert_eq!(
        local("refs/heads/feature").unwrap(),
        ["objects/rules/r1.yaml"]
    );
    git_cmd(&h.root, &["update-ref", "refs/remotes/origin/main", &h.b]);
    assert_eq!(local("origin/main").unwrap(), ["objects/rules/r2.yaml"]);
    git_cmd(&h.root, &["tag", "-a", "-m", "release", "v1", &h.a]);
    assert_eq!(
        local("refs/tags/v1").unwrap(),
        ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]
    );
    for refused in ["v1", "HEAD~1", "HEAD^", &h.a[..12], "nope"] {
        assert_eq!(
            local(refused).unwrap_err(),
            GitError::Failed(format!("Could not find git commit {refused}")),
            "{refused}"
        );
    }
    // A CI run takes --since in place of the push's base.
    assert_eq!(
        through_head(&h.root, &[("GITHUB_ACTIONS", "true")], Some(&h.a)).unwrap(),
        ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]
    );
}

#[test]
fn outside_ci_the_diff_needs_since_and_a_checkout_with_a_commit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    assert_eq!(
        through_head(&root, &[], None).unwrap_err(),
        GitError::Failed("Outside CI, --since must name the commit to diff from".into())
    );
    assert_eq!(
        through_head(&root, &[], Some("HEAD")).unwrap_err(),
        GitError::MissingCheckout(root.clone())
    );
    assert_eq!(
        through_head(&root, &[("GITHUB_ACTIONS", "true")], None).unwrap_err(),
        GitError::MissingCheckout(root.clone())
    );
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    assert_eq!(
        through_head(&root, &[], Some("HEAD")).unwrap_err(),
        GitError::Failed(format!(
            "The git repository at {} has no commits yet",
            root.display()
        ))
    );
}

/// `git::checkout` says what `git` itself says of a checkout (`opentide
/// doctor` under WASI, which cannot run git): its top level, origin's
/// default branch when origin/HEAD is set, and the current branch.
#[test]
fn a_checkout_is_read_as_git_reads_it() {
    let history = history();
    let root = &history.root;
    let nested = root.join("objects/rules");
    let found = git::checkout(&nested).unwrap();
    assert_eq!(found.top, *root);
    assert_eq!(
        (
            found.default_branch.as_deref(),
            found.has_origin,
            found.current_branch.as_deref()
        ),
        (None, false, Some("main"))
    );
    git_cmd(
        root,
        &["remote", "add", "origin", "https://example.invalid/r.git"],
    );
    git_cmd(
        root,
        &["update-ref", "refs/remotes/origin/main", &history.m],
    );
    let found = git::checkout(root).unwrap();
    assert_eq!((found.default_branch, found.has_origin), (None, true));
    git_cmd(
        root,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );
    assert_eq!(
        git::checkout(root).unwrap().default_branch.as_deref(),
        Some("main")
    );
    git_cmd(root, &["checkout", "-q", "--detach", "HEAD"]);
    assert_eq!(git::checkout(root).unwrap().current_branch, None);
    let outside = tempfile::tempdir().unwrap();
    assert_eq!(git::checkout(outside.path()), None);
}

/// A repository's first commit has no parent: it added every file it holds,
/// so a run on it reads them all (smoke E9/D10, the first push of a new
/// detection repository), outside CI, on a CI push and up to HEAD.
#[test]
fn the_first_commit_added_every_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "objects/rules/r1.yaml", "a: 1\n");
    write(&root, "objects/rules/sub/r2.yaml", "b: 1\n");
    let first = commit(&root, "first");
    let every = ["objects/rules/r1.yaml", "objects/rules/sub/r2.yaml"];
    assert_eq!(changed(&root, &[]).unwrap(), every);
    // GitHub's first push names an all-zero `before` (the event file sits
    // outside the checkout, as the runner's does).
    let events = tempfile::tempdir().unwrap();
    let event = events.path().join("event.json");
    std::fs::write(&event, format!("{{\"before\": \"{}\"}}", "0".repeat(40))).unwrap();
    let event = event.to_string_lossy().into_owned();
    let github = [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_SHA", first.as_str()),
        ("GITHUB_EVENT_PATH", event.as_str()),
    ];
    assert_eq!(changed(&root, &github).unwrap(), every);
    let gitlab = [
        ("CI", "true"),
        ("CI_COMMIT_SHA", first.as_str()),
        (
            "CI_COMMIT_BEFORE_SHA",
            "0000000000000000000000000000000000000000",
        ),
    ];
    assert_eq!(changed(&root, &gitlab).unwrap(), every);
    let azure = [
        ("TF_BUILD", "True"),
        ("BUILD_SOURCEVERSION", first.as_str()),
    ];
    assert_eq!(changed(&root, &azure).unwrap(), every);
    assert_eq!(through_head(&root, &github, None).unwrap(), every);
    // The run's commit decides, not HEAD: a push of the second commit, read
    // from a checkout of the first, diffs it from its own parent.
    write(&root, "objects/rules/r3.yaml", "c: 1\n");
    let second = commit(&root, "second");
    git_cmd(&root, &["checkout", "-q", "--detach", &first]);
    let pushed = [("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", second.as_str())];
    assert_eq!(changed(&root, &pushed).unwrap(), ["objects/rules/r3.yaml"]);
}

/// A CI push from a checkout whose HEAD names no commit fails with the
/// documented message, not with the run's commit that is not there.
#[test]
fn a_ci_push_without_a_commit_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    let sha = "1".repeat(40);
    for env in [
        vec![("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", sha.as_str())],
        vec![("CI", "true"), ("CI_COMMIT_SHA", sha.as_str())],
        vec![("TF_BUILD", "True"), ("BUILD_SOURCEVERSION", sha.as_str())],
    ] {
        assert_eq!(
            changed(&root, &env).unwrap_err(),
            GitError::Failed(format!(
                "The git repository at {} has no commits yet",
                root.display()
            )),
            "{env:?}"
        );
    }
}

/// #1683: the first push of a new repository often holds several commits.
/// The diff starts where the branch was before the push (all zeros: every
/// file), not at the last commit's parent; where the platform names no such
/// commit, the dry run's scope says that only the last commit was read.
#[test]
fn a_push_of_several_commits_reads_from_before_the_push() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "objects/rules/r1.yaml", "a: 1\n");
    let a = commit(&root, "a");
    write(&root, "objects/rules/r2.yaml", "b: 1\n");
    commit(&root, "b");
    write(&root, "objects/rules/r3.yaml", "c: 1\n");
    let c = commit(&root, "c");
    let every = [
        "objects/rules/r1.yaml",
        "objects/rules/r2.yaml",
        "objects/rules/r3.yaml",
    ];
    let zeros = "0".repeat(40);
    let events = tempfile::tempdir().unwrap();
    let event = |before: &str| {
        let path = events.path().join(format!("{before}.json"));
        std::fs::write(&path, format!("{{\"before\": \"{before}\"}}")).unwrap();
        path.to_string_lossy().into_owned()
    };
    // GitHub: the first push (a, b and c at once) names an all-zero before.
    let created = event(&zeros);
    fn github<'a>(sha: &'a str, path: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", sha),
            ("GITHUB_EVENT_PATH", path),
        ]
    }
    assert_eq!(changed(&root, &github(&c, &created)).unwrap(), every);
    // A later push of b and c names a.
    let later = event(&a);
    assert_eq!(
        changed(&root, &github(&c, &later)).unwrap(),
        ["objects/rules/r2.yaml", "objects/rules/r3.yaml"]
    );
    // GitLab: the same first push.
    let gitlab = [
        ("CI", "true"),
        ("CI_COMMIT_SHA", c.as_str()),
        ("CI_COMMIT_BEFORE_SHA", zeros.as_str()),
    ];
    assert_eq!(changed(&root, &gitlab).unwrap(), every);
    let pushed = [gitlab.as_slice(), &[("CI_PIPELINE_SOURCE", "push")]].concat();
    assert_eq!(changed(&root, &pushed).unwrap(), every);
    // A scheduled or manual pipeline sends all zeros too, but created no
    // branch: it reads the last commit.
    let scheduled = [gitlab.as_slice(), &[("CI_PIPELINE_SOURCE", "schedule")]].concat();
    assert_eq!(
        changed(&root, &scheduled).unwrap(),
        ["objects/rules/r3.yaml"]
    );

    let rules = root.join("objects/rules");
    let scope = |pairs: &[(&str, &str)]| {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let env = move |name: &str| map.get(name).cloned();
        opentide_compile::dry_run::git_scope(&root, &root, &env, &rules, "objects/rules").unwrap()
    };
    // A push that names where the branch was says nothing more.
    let (read, warning) = scope(&github(&c, &created));
    assert_eq!(read.files.len(), 3);
    assert_eq!(warning, None);
    // Azure names no such commit: the last commit is read, and the run says so.
    let (read, warning) = scope(&[("TF_BUILD", "True"), ("BUILD_SOURCEVERSION", c.as_str())]);
    assert_eq!(read.files, [rules.join("r3.yaml")]);
    let warning = warning.unwrap();
    assert!(
        warning
            .contains("Azure Pipelines does not name the commit the branch held before the push")
            && warning.ends_with("pass --all to deploy every rule file"),
        "{warning}"
    );
    // So does a GitHub run with no push event, and one whose before is not
    // in the checkout (a force push), and GitLab without its variable or
    // with a before the checkout does not hold.
    let gone = event(&"1".repeat(40));
    let missing = "1".repeat(40);
    for pairs in [
        vec![("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", c.as_str())],
        github(&c, &gone),
        vec![("CI", "true"), ("CI_COMMIT_SHA", c.as_str())],
        vec![
            ("CI", "true"),
            ("CI_COMMIT_SHA", c.as_str()),
            ("CI_COMMIT_BEFORE_SHA", missing.as_str()),
        ],
        scheduled.clone(),
    ] {
        let (read, warning) = scope(&pairs);
        assert_eq!(read.files, [rules.join("r3.yaml")], "{pairs:?}");
        assert!(
            warning.is_some_and(|warning| warning.contains("pass --all")),
            "{pairs:?}"
        );
    }
}

fn noted(root: &Path, pairs: &[(&str, &str)]) -> Result<(Vec<String>, Option<String>), GitError> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let env = move |name: &str| map.get(name).cloned();
    let source = git::diff_source(&env);
    git::changed_paths_noted(root, root, &env, source)
}

/// An Azure push names no commit before it, and a merge commit's first parent
/// is the previous tip only for a merge made on the target branch: the run
/// warns for every such push, merge commits included.
#[test]
fn an_azure_push_warns_even_when_head_is_a_merge_commit() {
    let h = history();
    let azure = |sha: &str, more: &[(&str, &str)]| {
        let mut pairs = vec![("TF_BUILD", "True"), ("BUILD_SOURCEVERSION", sha)];
        pairs.extend_from_slice(more);
        noted(&h.root, &pairs).unwrap()
    };
    let warns = |note: Option<String>| {
        note.is_some_and(|note| {
            note.starts_with(git::LAST_COMMIT_ONLY_PREFIX) && note.contains("OPENTIDE_PUSH_BASE")
        })
    };
    // A pull request completed on the target branch: exact, and still warned.
    let (paths, note) = azure(&h.m, &[]);
    assert_eq!(paths, ["objects/rules/r2.yaml"]);
    assert!(warns(note));
    // `git pull` (a merge of main into the branch) and a direct push of
    // three commits: the first parent is the branch's own last commit, so the
    // two commits before it are not in the diff.
    git_cmd(&h.root, &["checkout", "-q", "-b", "topic", &h.a]);
    write(&h.root, "objects/rules/t1.yaml", "t: 1\n");
    commit(&h.root, "t1");
    write(&h.root, "objects/rules/t2.yaml", "t: 2\n");
    commit(&h.root, "t2");
    git_cmd(&h.root, &["merge", "-q", "--no-ff", "-m", "pull", &h.b]);
    let pulled = git_cmd(&h.root, &["rev-parse", "HEAD"]);
    let (paths, note) = azure(&pulled, &[]);
    assert_eq!(paths, ["objects/rules/r1.yaml"], "t1 and t2 are missed");
    assert!(warns(note));
    // The override reads the whole push and drops the warning.
    let (paths, note) = azure(&pulled, &[("OPENTIDE_PUSH_BASE", &h.a)]);
    assert_eq!(
        paths,
        [
            "objects/rules/r1.yaml",
            "objects/rules/t1.yaml",
            "objects/rules/t2.yaml"
        ]
    );
    assert_eq!(note, None);
    // A plain commit warns as before.
    git_cmd(&h.root, &["checkout", "-q", &h.b]);
    assert!(warns(azure(&h.b, &[]).1));
}

#[test]
fn opentide_push_base_starts_a_pushs_diff_on_any_provider() {
    let h = history();
    let base = [("OPENTIDE_PUSH_BASE", h.a.as_str())];
    let azure = [
        &[("TF_BUILD", "True"), ("BUILD_SOURCEVERSION", h.m.as_str())][..],
        &base,
    ]
    .concat();
    let (paths, note) = noted(&h.root, &azure).unwrap();
    assert_eq!(paths, ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]);
    assert_eq!(note, None);
    // GitHub with no push event: the override replaces the note's fallback.
    let github = [
        &[("GITHUB_ACTIONS", "true"), ("GITHUB_SHA", h.m.as_str())][..],
        &base,
    ]
    .concat();
    let (paths, note) = noted(&h.root, &github).unwrap();
    assert_eq!(paths, ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]);
    assert_eq!(note, None);
    // `share push --changed` reads the same base.
    let map: HashMap<String, String> = azure
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let env = move |name: &str| map.get(name).cloned();
    assert_eq!(
        git::changed_through_head(&h.root, &h.root, &env, None).unwrap(),
        ["objects/rules/r1.yaml", "objects/rules/r2.yaml"]
    );
}

#[test]
fn opentide_push_base_must_be_an_ancestor_of_head() {
    let h = history();
    // c is on the feature branch: not an ancestor of b.
    git_cmd(&h.root, &["checkout", "-q", &h.b]);
    let azure = |base: &str| {
        noted(
            &h.root,
            &[
                ("TF_BUILD", "True"),
                ("BUILD_SOURCEVERSION", h.b.as_str()),
                ("OPENTIDE_PUSH_BASE", base),
            ],
        )
    };
    let error = azure(&h.c).unwrap_err();
    assert_eq!(error.exit_code(), 2);
    let GitError::PushBase(message) = error else {
        panic!("a usage failure");
    };
    assert!(
        message.contains("OPENTIDE_PUSH_BASE") && message.contains("not an ancestor of HEAD"),
        "{message}"
    );
    let error = azure(&"1".repeat(40)).unwrap_err();
    assert_eq!(error.exit_code(), 2);
    let GitError::PushBase(message) = error else {
        panic!("a usage failure");
    };
    assert!(
        message.contains("is not a commit of this checkout"),
        "{message}"
    );
    // A valid ancestor works.
    assert_eq!(azure(&h.a).unwrap().0, ["objects/rules/r1.yaml"]);
}

/// F-05: outside CI the scope is the last commit, and the commands read files
/// from disk: object files that are edited, staged or new and that the scope
/// does not name are left out of the run, and the run says so.
#[test]
fn uncommitted_object_files_the_scope_leaves_out_are_noted_outside_ci() {
    let h = history();
    let rules = h.root.join("objects/rules");
    let objects = [rules.clone(), h.root.join("objects/threats")];
    let no_env = |_: &str| None::<String>;
    let note = |recursive: bool, in_scope: &[PathBuf]| {
        git::uncommitted_warning(&h.root, &no_env, &objects, recursive, in_scope)
    };
    assert_eq!(note(true, &[]), None, "a clean tree says nothing");
    // r1 edited, r2 (the file the last commit changed, so in scope) staged,
    // a new rule below the rules folder, and a file that is no object.
    write(&h.root, "objects/rules/r1.yaml", "a: 3\n");
    write(&h.root, "objects/rules/r2.yaml", "b: 2\n");
    git_cmd(&h.root, &["add", "objects/rules/r2.yaml"]);
    write(&h.root, "objects/rules/nested/r4.yaml", "d: 1\n");
    write(&h.root, "objects/rules/notes.txt", "x\n");
    let r2 = [rules.join("r2.yaml")];
    // A file the scope names is read from disk as it is: not in the note.
    assert_eq!(
        note(true, &r2).as_deref(),
        Some(
            "2 uncommitted object files are not in scope (objects/rules/nested/r4.yaml, \
             objects/rules/r1.yaml); commit them or pass --file"
        )
    );
    // Only the rules folder's own files can be in a deploy's scope.
    assert_eq!(
        note(false, &r2).as_deref(),
        Some(
            "1 uncommitted object file is not in scope (objects/rules/r1.yaml); commit them or \
             pass --file"
        )
    );
    // With nothing in scope, all three; a fourth, in another folder, is counted.
    assert!(note(true, &[]).is_some_and(|text| text.starts_with("3 uncommitted object files")));
    write(&h.root, "objects/threats/t1.yaml", "t: 1\n");
    let four = note(true, &[]).unwrap();
    assert!(
        four.starts_with("4 uncommitted object files are not in scope (")
            && four.contains(" and 1 more)"),
        "{four}"
    );
    // The dry run's scope is unchanged (the last commit), and its warning
    // names the one rules-folder file it leaves out.
    let (scope, warning) =
        opentide_compile::dry_run::git_scope(&h.root, &h.root, &no_env, &rules, "objects/rules")
            .unwrap();
    assert_eq!(scope.files, [rules.join("r2.yaml")]);
    assert_eq!(
        warning.as_deref(),
        Some(
            "1 uncommitted object file is not in scope (objects/rules/r1.yaml); commit them or \
             pass --file"
        )
    );
    // A file deleted from disk cannot be passed to `--file`: not named.
    std::fs::remove_file(rules.join("r1.yaml")).unwrap();
    assert!(note(false, &[]).is_some_and(|text| !text.contains("r1.yaml")));
    // Committing them clears it; CI never says it.
    commit(&h.root, "all");
    assert_eq!(note(true, &[]), None);
    write(&h.root, "objects/rules/r2.yaml", "b: 4\n");
    assert!(note(true, &[]).is_some());
    let ci = |name: &str| (name == "GITHUB_ACTIONS").then(|| "true".to_owned());
    assert_eq!(
        git::uncommitted_warning(&h.root, &ci, &objects, true, &[]),
        None
    );
}

fn deleted(root: &Path, pairs: &[(&str, &str)]) -> Result<Vec<(String, String)>, GitError> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let env = move |name: &str| map.get(name).cloned();
    let source = git::diff_source(&env);
    git::deleted_paths(root, root, &env, source).map(|files| {
        files
            .into_iter()
            .map(|file| (file.path, String::from_utf8(file.content).unwrap()))
            .collect()
    })
}

/// The files a diff deleted, with what its base held (#1713): the push's
/// range, not only its last commit; a file deleted and a modified one in
/// the same range are told apart.
#[test]
fn the_files_a_diff_deleted_come_with_their_last_content() {
    let h = history();
    // Outside CI, the last commit: the merge deleted nothing.
    assert_eq!(deleted(&h.root, &[]).unwrap(), Vec::new());
    std::fs::remove_file(h.root.join("objects/rules/r1.yaml")).unwrap();
    let d = commit(&h.root, "d");
    assert_eq!(
        deleted(&h.root, &[]).unwrap(),
        [("objects/rules/r1.yaml".to_owned(), "a: 2\n".to_owned())]
    );
    // A push from a: r1 was there at a (as `a: 1`), and is gone at d.
    let event = h.root.join("event.json");
    std::fs::write(&event, format!("{{\"before\": \"{}\"}}", h.a)).unwrap();
    let event = event.to_string_lossy().into_owned();
    let pushed = deleted(
        &h.root,
        &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", &d),
            ("GITHUB_EVENT_PATH", &event),
        ],
    )
    .unwrap();
    assert_eq!(
        pushed,
        [("objects/rules/r1.yaml".to_owned(), "a: 1\n".to_owned())]
    );
    // A push that created its branch has no base: nothing was deleted.
    std::fs::write(
        h.root.join("event.json"),
        "{\"before\": \"0000000000000000000000000000000000000000\"}",
    )
    .unwrap();
    let created = deleted(
        &h.root,
        &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", &d),
            ("GITHUB_EVENT_PATH", &event),
        ],
    )
    .unwrap();
    assert_eq!(created, Vec::new());
}

/// A shallow checkout's deletions are its diff's failure, never an empty
/// list a deploy would read as "nothing deleted" (#1713).
#[test]
fn a_shallow_clone_cannot_list_what_it_deleted() {
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
    assert!(matches!(
        deleted(&shallow, &[]).unwrap_err(),
        GitError::Failed(message) if message.contains("the checkout is shallow")
    ));
}

/// The loose object file of `id`, made unreadable by git: its bytes no
/// longer inflate.
fn corrupt_object(root: &Path, id: &str) {
    let path = root.join(".git/objects").join(&id[..2]).join(&id[2..]);
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    #[expect(
        clippy::permissions_set_readonly_false,
        reason = "git writes loose objects read-only; the test overwrites one"
    )]
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).unwrap();
    std::fs::write(&path, b"not a zlib stream").unwrap();
}

/// A baseline object that cannot be read is the run's failure, never an
/// empty folder or a file without its committed text (#1931): the baseline
/// decides which rules a run reads and retires.
#[test]
fn docs_changes_fail_on_a_baseline_object_that_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    git_cmd(&root, &["init", "-q", "-b", "main"]);
    write(&root, "rules/kept é.yaml", "name: kept 😀\n");
    write(&root, "rules/edited.yaml", "name: edited\n");
    commit(&root, "base");
    write(
        &root,
        "rules/edited.yaml",
        "name: edited in the work tree\n",
    );
    let keep = |_: &str| true;
    // The edited file's committed text cannot be read: not an added file.
    let blob = git_cmd(&root, &["rev-parse", "HEAD:rules/edited.yaml"]);
    corrupt_object(&root, &blob);
    let error = git::changed_in_folders(&root, &[root.join("rules")], &keep).unwrap_err();
    assert!(
        matches!(&error, GitError::Failed(message) if message.starts_with(&format!("Could not find git object {blob}"))),
        "{error:?}"
    );
    // The folder's tree cannot be read: not an empty folder whose files are all new.
    let tree = git_cmd(&root, &["rev-parse", "HEAD:rules"]);
    corrupt_object(&root, &tree);
    let error = git::changed_in_folders(&root, &[root.join("rules")], &keep).unwrap_err();
    assert!(
        matches!(&error, GitError::Failed(message) if message.starts_with(&format!("Could not find git object {tree}"))),
        "{error:?}"
    );
}

/// A shallow clone that does not hold the merge base with the default
/// branch says to fetch more history, not compare with HEAD or an empty
/// tree (#1931).
#[test]
fn docs_changes_in_a_shallow_clone_without_the_merge_base_say_to_fetch_history() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let origin = root.join("origin");
    std::fs::create_dir_all(&origin).unwrap();
    git_cmd(&origin, &["init", "-q", "-b", "main"]);
    write(&origin, "rules/a.yaml", "a: 1\n");
    commit(&origin, "a");
    git_cmd(&origin, &["checkout", "-q", "-b", "feature"]);
    write(&origin, "rules/b.yaml", "b: 1\n");
    commit(&origin, "on the branch");
    git_cmd(&origin, &["checkout", "-q", "main"]);
    write(&origin, "rules/a.yaml", "a: 2\n");
    commit(&origin, "main moves on");
    let path = origin.to_string_lossy().replace('\\', "/");
    let url = format!("file:///{}", path.trim_start_matches('/'));
    let shallow = root.join("shallow");
    git_cmd(
        &root,
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            "--no-single-branch",
            "--branch",
            "feature",
            &url,
            &shallow.to_string_lossy(),
        ],
    );
    let keep = |_: &str| true;
    let error = git::changed_in_folders(&shallow, &[shallow.join("rules")], &keep).unwrap_err();
    assert!(
        matches!(&error, GitError::Failed(message) if message.contains("the checkout is shallow") && message.contains("fetch-depth: 0")),
        "{error:?}"
    );
}
