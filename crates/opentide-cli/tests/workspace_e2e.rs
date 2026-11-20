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
    isolate_git(&mut command);
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
    let mut command = Command::new("git");
    command
        .args(["-c", "user.email=e2e@opentide.test", "-c", "user.name=e2e"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir);
    isolate_git(&mut command);
    let output = command.output().unwrap();
    assert!(output.status.success(), "git {args:?}: {output:?}");
}

/// Keeps git, run by a test or by the binary, to the scratch folders: no
/// repository above the temporary directory (a checkout the tests run in),
/// no system configuration, and none of the variables that point git at
/// another repository (a hook running the tests sets them).
fn isolate_git(command: &mut Command) {
    let temp = dunce::canonicalize(std::env::temp_dir()).unwrap();
    command.env("GIT_CEILING_DIRECTORIES", temp);
    command.env("GIT_CONFIG_NOSYSTEM", "1");
    // Nor the person's own configuration: a global `core.hooksPath` or
    // `init.templateDir` would change what a commit runs.
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
        command.env_remove(name);
    }
}

/// A fresh folder, its path canonical (macOS's `/var` is `/private/var`)
/// and, on Windows, without the `\\?\` prefix `std::fs::canonicalize` adds:
/// git and the binary print the plain form, and the paths are compared.
fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
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
/// workspace in it. `start` is where the run starts, under the checkout.
fn nested_workspace_found_from(start: &str) {
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
    assert!(
        docs["counts"]["rules"].as_u64() >= Some(1),
        "{start}: {docs}"
    );
    let output = Path::new(docs["output"].as_str().unwrap());
    assert_eq!(output, ws.join("docs"), "{start}: {docs}");
    opentide(&cwd, &["generate", "inflight"], &[]).ok();
    assert_eq!(shards(&ws), the_rule_shard(), "{start}");
}

#[test]
fn a_nested_workspace_is_found_from_its_root_for_changed_objects() {
    nested_workspace_found_from("detections");
}

#[test]
fn a_nested_workspace_is_found_from_a_subfolder_for_changed_objects() {
    nested_workspace_found_from("detections/objects/rules");
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

// Workspace discovery (#294): no `OPENTIDE_*`, so the cwd alone decides.

/// The tutorial's objects, by family.
fn tutorial_counts() -> Value {
    serde_json::json!({"rules": 1, "threats": 1, "objectives": 1})
}

/// `(top, workspace)`: a scaffold of its own (`standalone`), or a
/// workspace in `detections/` of a git checkout that has a `tools/` too.
fn layout(root: &Path, kind: &str) -> (PathBuf, PathBuf) {
    if kind == "standalone" {
        let ws = root.join("scaffold");
        scaffold(&ws);
        return (ws.clone(), ws);
    }
    let checkout = root.join("monorepo");
    let ws = checkout.join("detections");
    scaffold(&ws);
    std::fs::create_dir(checkout.join("tools")).unwrap();
    git(&checkout, &["init", "-q", "-b", "main", "."]);
    (checkout, ws)
}

fn listing(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn path_of<'a>(document: &'a Value, key: &str) -> &'a Path {
    Path::new(
        document[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key}: {document}")),
    )
}

/// `info`, `validate`, `lint` and `generate` run from `start` under the top
/// of a `kind` layout ([`layout`]) all find its workspace, and write nothing
/// outside it.
fn first_commands_agree_from(kind: &str, start: &str) {
    let (_dir, root) = scratch();
    let (top, ws) = layout(&root, kind);
    let cwd = top.join(start);
    let mut bystanders = vec![(top.clone(), listing(&top))];
    bystanders.push((cwd.clone(), listing(&cwd)));
    bystanders.retain(|(path, _)| *path != ws);

    let info = opentide(&cwd, &["info"], &[]).ok();
    assert_eq!(path_of(&info, "repo"), ws, "{kind} {start}: {info}");
    assert_eq!(info["counts"], tutorial_counts(), "{kind} {start}: {info}");
    let enabled: Vec<&Value> = info["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|platform| platform["enabled"] == true)
        .map(|platform| &platform["name"])
        .collect();
    assert_eq!(enabled, ["sentinel"], "{kind} {start}: {info}");

    let validate = opentide(&cwd, &["validate", "--strict"], &[]).ok();
    assert_eq!(
        path_of(&validate, "workspace"),
        ws,
        "{kind} {start}: {validate}"
    );
    assert_eq!(
        validate["message"], "Validation passed",
        "{kind} {start}: {validate}"
    );
    let checked = &validate["report"]["stats"]["objects_checked"];
    assert_eq!(checked, 3, "{kind} {start}: {validate}");

    let lint = opentide(&cwd, &["lint", "--strict"], &[]).ok();
    assert_eq!(path_of(&lint, "path"), ws, "{kind} {start}: {lint}");
    assert_eq!(lint["count"], 0, "{kind} {start}: {lint}");

    let docs = opentide(&cwd, &["generate", "docs"], &[]).ok();
    assert_eq!(
        path_of(&docs, "output"),
        ws.join("docs"),
        "{kind} {start}: {docs}"
    );
    assert_eq!(docs["counts"], tutorial_counts(), "{kind} {start}: {docs}");

    opentide(&cwd, &["generate"], &[]).ok();
    let exported = ws.join(".opentide/exports/objects.export.json");
    let exported: Value =
        serde_json::from_str(&std::fs::read_to_string(exported).unwrap()).unwrap();
    assert_eq!(exported.as_array().map(Vec::len), Some(3), "{kind} {start}");
    let page = ws.join("docs/rules/sentinel-kql-rule.md");
    assert!(page.is_file(), "{kind} {start}: no {}", page.display());

    for (path, before) in bystanders {
        assert_eq!(
            listing(&path),
            before,
            "{kind} {start}: output leaked into {}",
            path.display()
        );
    }
}

#[test]
fn first_commands_agree_from_a_scaffold_root() {
    first_commands_agree_from("standalone", ".");
}

#[test]
fn first_commands_agree_from_a_scaffold_rules_folder() {
    first_commands_agree_from("standalone", "objects/rules");
}

#[test]
fn first_commands_agree_from_a_scaffold_configuration_folder() {
    first_commands_agree_from("standalone", ".opentide/configurations/platforms");
}

#[test]
fn first_commands_agree_from_a_nested_workspace_root() {
    first_commands_agree_from("nested", "detections");
}

#[test]
fn first_commands_agree_from_a_nested_workspace_rules_folder() {
    first_commands_agree_from("nested", "detections/objects/rules");
}

/// Above the workspace nothing is marked: the checkout stays the root, run
/// from `start` under it, which prints the checkout as `shown`.
fn the_git_root_is_kept_from(start: &str, shown: &str) {
    let (_dir, root) = scratch();
    let (checkout, _) = layout(&root, "nested");
    let cwd = checkout.join(start);

    let info = opentide(&cwd, &["info"], &[]).ok();
    assert_eq!(path_of(&info, "repo"), checkout, "{start}: {info}");
    let none = serde_json::json!({"rules": 0, "threats": 0, "objectives": 0});
    assert_eq!(info["counts"], none, "{start}: {info}");

    let validate = opentide(&cwd, &["validate"], &[]).ok();
    let checked = &validate["report"]["stats"]["objects_checked"];
    assert_eq!(checked, 0, "{start}: {validate}");
    assert_eq!(
        path_of(&validate, "workspace"),
        checkout,
        "{start}: {validate}"
    );
    // Relative to where it ran.
    let message = format!("Validation passed, but no detection objects were found under {shown}");
    assert_eq!(validate["message"], message, "{start}: {validate}");
    // `--strict` fails it, naming the same folder, and `--allow-empty` does
    // not pass a folder that is not a workspace.
    for args in [
        &["validate", "--strict"][..],
        &["validate", "--strict", "--allow-empty"],
    ] {
        let strict = opentide(&cwd, args, &[]);
        assert_eq!(strict.code, Some(1), "{start} {args:?}: {strict:?}");
        let document = strict.document();
        assert_eq!(document["failure"]["code"], "issues_found", "{document}");
        assert_eq!(path_of(&document, "workspace"), checkout, "{document}");
        let message = format!(
            "Validation failed: no detection objects were found under {shown}, and --strict \
             requires at least one"
        );
        assert_eq!(document["message"], message, "{start}: {document}");
    }
}

#[test]
fn a_checkout_without_markers_keeps_the_git_root_from_its_root() {
    the_git_root_is_kept_from(".", "./");
}

#[test]
fn a_checkout_without_markers_keeps_the_git_root_from_a_folder() {
    the_git_root_is_kept_from("tools", "../");
}

/// The workspace `how` names (`--repo` or a variable) wins over the one the
/// cwd is in.
fn an_explicit_workspace_beats_discovery(how: &str) {
    let (_dir, root) = scratch();
    let (_, ws) = layout(&root, "nested");
    // A workspace that holds a threat alone.
    let other = root.join("other");
    scaffold(&other);
    for family in ["rules", "objectives"] {
        for entry in std::fs::read_dir(other.join("objects").join(family)).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
    }
    let cwd = ws.join("objects/rules");
    let run = |args: &[&str]| {
        if how == "--repo" {
            let repo = ["--repo", other.to_str().unwrap()];
            opentide(&cwd, &[&repo[..], args].concat(), &[])
        } else {
            opentide(&cwd, args, &[(how, &other)])
        }
    };

    let info = run(&["info"]).ok();
    let threat = serde_json::json!({"rules": 0, "threats": 1, "objectives": 0});
    assert_eq!(info["counts"], threat, "{how}: {info}");
    let validate = run(&["validate", "--strict"]).ok();
    assert_eq!(path_of(&validate, "workspace"), other, "{how}: {validate}");
    let checked = &validate["report"]["stats"]["objects_checked"];
    assert_eq!(checked, 1, "{how}: {validate}");
}

#[test]
fn the_repo_flag_beats_discovery() {
    an_explicit_workspace_beats_discovery("--repo");
}

#[test]
fn opentide_repo_root_beats_discovery() {
    an_explicit_workspace_beats_discovery("OPENTIDE_REPO_ROOT");
}

#[test]
fn opentide_tide_workspace_beats_discovery() {
    an_explicit_workspace_beats_discovery("OPENTIDE_TIDE_WORKSPACE");
}

/// The published first-user path, each step through the binary: setup,
/// generate on the empty repository, the tutorial's objects, then generate,
/// validate, lint and info, every one of them passing.
#[test]
fn the_first_user_workflow_passes_end_to_end() {
    let (_dir, root) = scratch();
    let parent = root.join("workspace");
    std::fs::create_dir(&parent).unwrap();
    let fresh = parent.join("tutorial-detections");
    let (repo, path) = (parent.to_str().unwrap(), fresh.to_str().unwrap());
    let env = [
        ("OPENTIDE_REPO_ROOT", &*parent),
        ("OPENTIDE_TIDE_WORKSPACE", &*parent),
    ];
    let args = [
        "--repo",
        repo,
        "setup",
        "--yes",
        "--name",
        "Tutorial Detections",
    ];
    let more = [
        "--org",
        "Example Corp",
        "--platform",
        "sentinel",
        "--path",
        path,
    ];
    opentide(&parent, &[&args[..], &more[..]].concat(), &env).ok();
    assert!(fresh.join("objects/threats").is_dir());
    let sentinel = fresh.join(".opentide/configurations/platforms/sentinel.toml");
    assert!(
        std::fs::read_to_string(sentinel)
            .unwrap()
            .contains("enabled = true")
    );

    in_workspace(&fresh, &["generate"]).ok();
    assert!(
        fresh
            .join(".opentide/schemas/rule.1.0.schema.json")
            .is_file()
    );
    let template = fresh.join(".opentide/templates/rule.1.0.template.yaml");
    let template = std::fs::read_to_string(template).unwrap();
    assert!(!template.contains("configurations: {}"), "{template}");
    assert!(template.contains("#sentinel:"), "{template}");
    assert!(!template.contains("null"), "{template}");

    tutorial::write_objects(&fresh);
    let threat = fresh.join("objects/threats/simulated-actor.yaml");
    assert!(
        std::fs::read_to_string(threat)
            .unwrap()
            .contains("name: att&ck::G0006")
    );

    in_workspace(&fresh, &["generate"]).ok();
    let validate = in_workspace(&fresh, &["validate", "--strict"]).ok();
    assert_eq!(validate["report"]["ok"], true, "{validate}");
    let lint = in_workspace(&fresh, &["lint", "--strict"]).ok();
    assert_eq!(lint["count"], 0, "{lint}");
    let info = in_workspace(&fresh, &["info"]).ok();
    assert_eq!(info["counts"], tutorial_counts(), "{info}");
    let coverage = in_workspace(&fresh, &["info", "--technique", "T1059", "coverage"]).ok();
    assert!(
        coverage["coverage"]["count"].as_u64() >= Some(1),
        "{coverage}"
    );
}

/// `setup --org` reaches `new` (#1670, smoke B17): a threat, an objective and
/// a rule written after `opentide setup --org "Example Corp"` carry
/// `metadata.organisation` and no warning about it, on a catalogue that has
/// no object to copy it from. Rerunning `setup` without `--org` keeps it, the
/// same `--org` keeps its uuid, and what `new` wrote still validates, and
/// passes the `metadata` lint (the placeholders it holds fail the others).
#[test]
fn setup_org_fills_metadata_organisation_of_new_objects() {
    let (_dir, root) = scratch();
    let fresh = root.join("detections");
    let path = fresh.to_str().unwrap();
    let setup = |extra: &[&str]| {
        let base = ["setup", "--yes", "--platform", "sentinel", "--path", path];
        opentide(&root, &[&base[..], extra].concat(), &[]).ok()
    };
    setup(&["--org", "Example Corp"]);
    let configured =
        std::fs::read_to_string(fresh.join(".opentide/configurations/organisation.toml")).unwrap();
    let uuid = configured
        .lines()
        .find_map(|line| line.strip_prefix("uuid = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("no uuid in {configured}"))
        .to_owned();
    in_workspace(&fresh, &["generate"]).ok();

    let new_objects = |suffix: &str| {
        let threat = in_workspace(
            &fresh,
            &["new", "threat", "--name", &format!("Threat {suffix}")],
        )
        .ok();
        let objective = in_workspace(
            &fresh,
            &["new", "objective", "--name", &format!("Objective {suffix}")],
        )
        .ok();
        let rule = in_workspace(
            &fresh,
            &[
                "new",
                "rule",
                "--name",
                &format!("Rule {suffix}"),
                "--platform",
                "sentinel",
            ],
        )
        .ok();
        [threat, objective, rule]
    };
    let check = |documents: &[Value; 3]| {
        for document in documents {
            assert_eq!(
                document["organisation"],
                serde_json::json!({"uuid": uuid, "name": "Example Corp"}),
                "{document}"
            );
            let warnings = document["warnings"].to_string();
            assert!(!warnings.contains("organisation"), "{warnings}");
            let file = std::fs::read_to_string(document["file_path"].as_str().unwrap()).unwrap();
            assert!(file.contains(&format!("uuid: {uuid}")), "{file}");
            assert!(file.contains("name: Example Corp"), "{file}");
        }
    };
    check(&new_objects("one"));

    // A rerun without `--org` keeps the file; the same `--org` keeps its uuid.
    setup(&[]);
    assert_eq!(
        std::fs::read_to_string(fresh.join(".opentide/configurations/organisation.toml")).unwrap(),
        configured
    );
    setup(&["--org", "Example Corp"]);
    assert_eq!(
        std::fs::read_to_string(fresh.join(".opentide/configurations/organisation.toml")).unwrap(),
        configured
    );
    check(&new_objects("two"));

    in_workspace(&fresh, &["generate"]).ok();
    let validate = in_workspace(&fresh, &["validate", "--strict"]).ok();
    assert_eq!(validate["report"]["ok"], true, "{validate}");
    in_workspace(&fresh, &["lint", "--strict", "--check", "metadata"]).ok();
}

/// The organisation comes from `organisation.toml` only (#1670, smoke B17):
/// objects already in the catalogue never supply it. With no file `new`
/// leaves `metadata.organisation` out and says to run `setup --org`; with
/// one it writes it, and a uuid edited in the file, or another `--org`,
/// reaches the next `new`.
#[test]
fn the_organisation_comes_from_organisation_toml_only() {
    let (_dir, root) = scratch();
    let fresh = root.join("detections");
    let path = fresh.to_str().unwrap();
    let setup = |extra: &[&str]| {
        let base = ["setup", "--yes", "--path", path];
        opentide(&root, &[&base[..], extra].concat(), &[]).ok()
    };
    setup(&[]);
    let file = fresh.join(".opentide/configurations/organisation.toml");
    assert!(!file.exists());
    in_workspace(&fresh, &["generate"]).ok();
    // A catalogue object that names an organisation, and no configured one.
    std::fs::write(
        fresh.join("objects/threats/other.yaml"),
        "name: Other\nmetadata:\n  uuid: 00000000-0000-4000-8001-000000000042\n  organisation:\n    \
         uuid: 00000000-0000-4000-8000-000000000099\n    name: Other Corp\n",
    )
    .unwrap();

    let new_threat = |name: &str| in_workspace(&fresh, &["new", "threat", "--name", name]).ok();
    let organisation = |document: &Value| document["organisation"].clone();
    let file_of = |document: &Value| {
        std::fs::read_to_string(document["file_path"].as_str().unwrap()).unwrap()
    };

    // No organisation configured: none is written, whatever the catalogue
    // holds, and the warning says what to do.
    let none = new_threat("None");
    assert_eq!(organisation(&none), Value::Null, "{none}");
    let warnings = none["warnings"].to_string();
    assert!(
        warnings.contains("no organisation is configured")
            && warnings.contains("opentide setup --org"),
        "{warnings}"
    );
    assert!(!warnings.contains("catalogue"), "{warnings}");
    assert!(!file_of(&none).contains("Other Corp"), "{}", file_of(&none));

    // `setup --org` configures it: `new` writes it, not the catalogue's.
    setup(&["--org", "Example Corp"]);
    let configured = std::fs::read_to_string(&file).unwrap();
    let uuid = configured
        .lines()
        .find_map(|line| line.strip_prefix("uuid = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("no uuid in {configured}"))
        .to_owned();
    let first = new_threat("First");
    assert_eq!(
        organisation(&first),
        serde_json::json!({"uuid": uuid, "name": "Example Corp"}),
        "{first}"
    );
    assert!(!first["warnings"].to_string().contains("organisation"));

    // Editing the uuid in the file reaches the next object, though the
    // first one is now in the catalogue with the old one.
    let edited = "11111111-2222-4333-8444-555555555555";
    std::fs::write(&file, configured.replace(&uuid, edited)).unwrap();
    let second = new_threat("Second");
    assert_eq!(
        organisation(&second),
        serde_json::json!({"uuid": edited, "name": "Example Corp"}),
        "{second}"
    );
    // So does another `--org`, which keeps the uuid.
    setup(&["--org", "Renamed Corp"]);
    let third = new_threat("Third");
    assert_eq!(
        organisation(&third),
        serde_json::json!({"uuid": edited, "name": "Renamed Corp"}),
        "{third}"
    );
    let text = file_of(&third);
    assert!(text.contains("name: Renamed Corp"), "{text}");

    // A file `new` cannot use is not worked around: no organisation, and the
    // warning says what is wrong with it.
    std::fs::write(&file, "name = \"Example Corp\"\n").unwrap();
    let unusable = new_threat("Fourth");
    assert_eq!(organisation(&unusable), Value::Null, "{unusable}");
    let warnings = unusable["warnings"].to_string();
    assert!(
        warnings.contains("organisation.toml is not usable: it has no uuid"),
        "{warnings}"
    );
    assert!(!warnings.contains("catalogue"), "{warnings}");
}

/// `opentide setup --hooks` then the first `git commit` of the scaffold:
/// the commit hook it installs runs `validate --strict --allow-empty`, so a
/// workspace with no detection object yet commits; `validate --strict`
/// alone, as the generated CI runs it, fails on the same scaffold.
#[cfg(unix)]
#[test]
fn the_first_commit_of_a_fresh_setup_passes_its_hook() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    opentide(&repo, &["setup", "--hooks", "--yes"], &[]).ok();
    // The hook runs `opentide` from PATH: this build.
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_opentide-cli"), bin.join("opentide")).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    git(&repo, &["add", "-A"]);
    let mut commit = Command::new("git");
    commit
        .args(["-c", "user.email=e2e@opentide.test", "-c", "user.name=e2e"])
        .args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "scaffold",
        ])
        .current_dir(&repo)
        .env("PATH", &path);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OPENTIDE_") {
            commit.env_remove(name);
        }
    }
    for name in LEAKED {
        commit.env_remove(name);
    }
    isolate_git(&mut commit);
    // The hook is installed, executable, and runs: it leaves a trace.
    let hook = repo.join(".git/hooks/pre-commit");
    let script = std::fs::read_to_string(&hook).unwrap();
    assert!(
        script.contains("validate --strict --allow-empty"),
        "{script}"
    );
    let traced = script.replacen(
        "set -e\n",
        &format!("set -e\ntouch {}\n", root.join("hook-ran").display()),
        1,
    );
    std::fs::write(&hook, traced).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_ne!(
            std::fs::metadata(&hook).unwrap().permissions().mode() & 0o111,
            0
        );
    }
    let output = commit.output().unwrap();
    assert!(
        output.status.success(),
        "the hook refused the scaffold: {output:?}"
    );
    assert!(
        root.join("hook-ran").exists(),
        "the commit did not run the hook"
    );
    // CI's `validate --strict` fails the same empty workspace.
    let strict = opentide(&repo, &["validate", "--strict"], &[]);
    assert_eq!(strict.code, Some(1), "{strict:?}");
    assert_eq!(strict.document()["failure"]["code"], "issues_found");
    let allowed = opentide(&repo, &["validate", "--strict", "--allow-empty"], &[]);
    assert_eq!(allowed.code, Some(0), "{allowed:?}");
}

/// `git commit` in `repo` with `opentide` on `PATH` (this build, linked
/// from `root/bin`), as a person's shell runs it.
#[cfg(unix)]
fn hooked_commit(root: &Path, repo: &Path, message: &str) -> std::process::Output {
    let bin = root.join("bin");
    if !bin.join("opentide").exists() {
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_opentide-cli"), bin.join("opentide"))
            .unwrap();
    }
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // The hook's copy of the index goes here, where the test can see it.
    let tmp = root.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    let mut commit = Command::new("git");
    commit
        .args(["-c", "user.email=e2e@opentide.test", "-c", "user.name=e2e"])
        .args(["-c", "commit.gpgsign=false", "commit", "-q", "-m", message])
        .current_dir(repo)
        .env("PATH", &path)
        .env("TMPDIR", &tmp);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OPENTIDE_") {
            commit.env_remove(name);
        }
    }
    for name in LEAKED {
        commit.env_remove(name);
    }
    isolate_git(&mut commit);
    commit.output().unwrap()
}

/// The commit hook validates what the commit holds, the staged files, not
/// the work tree (#1670, smoke A8): a broken rule staged, then fixed on disk
/// but not staged, is refused; a good rule staged, then broken on disk, is
/// committed.
#[cfg(unix)]
#[test]
fn the_commit_hook_validates_the_staged_files() {
    let (_dir, root) = scratch();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    opentide(
        &repo,
        &[
            "setup",
            "--hooks",
            "--yes",
            "--name",
            "Hooked",
            "--platform",
            "sentinel",
        ],
        &[],
    )
    .ok();
    tutorial::write_objects(&repo);
    git(&repo, &["add", "-A"]);
    let first = hooked_commit(&root, &repo, "objects");
    assert!(
        first.status.success(),
        "the hook refused good objects: {first:?}"
    );

    // Broken in the index, good on disk: refused.
    tutorial::break_tlp(&repo);
    git(&repo, &["add", "-A"]);
    tutorial::write_objects(&repo);
    let broken = hooked_commit(&root, &repo, "broken");
    assert!(
        !broken.status.success(),
        "the hook let a broken staged rule through: {broken:?}"
    );
    let stderr = String::from_utf8_lossy(&broken.stderr);
    let stdout = String::from_utf8_lossy(&broken.stdout);
    assert!(
        format!("{stdout}{stderr}").contains("clearr"),
        "{stdout}{stderr}"
    );

    // Good in the index, broken on disk: committed, and the hook's copy of
    // the index is gone.
    std::fs::write(repo.join("notes.txt"), "a change to commit\n").unwrap();
    git(&repo, &["add", "-A"]);
    tutorial::break_tlp(&repo);
    let good = hooked_commit(&root, &repo, "good");
    assert!(
        good.status.success(),
        "the hook validated the work tree, not the staged rule: {good:?}"
    );
    let left: Vec<_> = std::fs::read_dir(root.join("tmp")).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

/// One hook for a repository's root workspace and a workspace nested in it
/// (#1670 review): each is validated from a copy of its own staged files.
/// One shared copy refused every commit, the nested files being there
/// already when its turn came.
#[cfg(unix)]
#[test]
fn the_commit_hook_validates_a_root_and_a_nested_workspace() {
    let (_dir, root) = scratch();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    let setup = ["setup", "--hooks", "--yes", "--platform", "sentinel"];
    opentide(&repo, &[&setup[..], &["--name", "Root"]].concat(), &[]).ok();
    opentide(
        &repo,
        &[&setup[..], &["--name", "Kept", "--path", "kept"]].concat(),
        &[],
    )
    .ok();
    let script = std::fs::read_to_string(repo.join(".git/hooks/pre-commit")).unwrap();
    assert!(
        script.contains("for OPENTIDE_HOOK_WORKSPACE in . kept; do"),
        "{script}"
    );
    tutorial::write_objects(&repo);
    tutorial::write_objects(&repo.join("kept"));
    git(&repo, &["add", "-A"]);
    let both = hooked_commit(&root, &repo, "both");
    assert!(
        both.status.success(),
        "the hook refused two good workspaces: {both:?}"
    );

    // A broken rule staged in the nested workspace alone is refused, and the
    // hook says how to see where the staged files differ, without changing them.
    tutorial::break_tlp(&repo.join("kept"));
    git(&repo, &["add", "-A"]);
    let broken = hooked_commit(&root, &repo, "broken");
    assert!(!broken.status.success(), "{broken:?}");
    let stderr = String::from_utf8_lossy(&broken.stderr);
    assert!(
        stderr.contains("See how with: git diff -- ") && !stderr.contains("git stash"),
        "{stderr}"
    );
    assert!(!stderr.contains("opentide-hook."), "{stderr}");
}
