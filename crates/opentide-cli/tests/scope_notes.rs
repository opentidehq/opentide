//! The notes about what `--changed` and deploy's default scope read, end to
//! end on a git repository through [`opentide_cli::run`]: the uncommitted
//! object files a scope leaves out (F-05), the Azure push that reads only its
//! last commit (OT-12) and the `OPENTIDE_PUSH_BASE` override.
#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here is written to a fresh folder"
)]

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Ran {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

impl Ran {
    fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

const SYSDIG: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"one\"\n\
    description = \"d\"\n[tenants.setup]\nssl = true\nurl = \"https://s.example.org\"\n\
    api_token = \"$SYSDIG_TOKEN\"\n";

const KEPT: &str = "00000000-0000-4000-8000-0000000000a1";
const EDITED: &str = "00000000-0000-4000-8000-0000000000a2";

fn rule(uuid: &str, condition: &str) -> String {
    format!(
        "name: Rule {}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\ndescription: d\n\
         configurations:\n  sysdig:\n    status: STAGING\n    condition: {condition}\n",
        &uuid[uuid.len() - 2..]
    )
}

fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// A repository on disk, removed when dropped.
struct Repo {
    _dir: tempfile::TempDir,
    root: PathBuf,
    /// The first of its two commits.
    first: String,
}

/// A Sysdig workspace that is a git checkout of two commits: the first holds
/// `kept.yaml` and `edited.yaml`, the second changes `edited.yaml`, so the
/// last commit's scope is that one file. Returns the root and the first commit.
fn repository() -> Repo {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    write(
        &root,
        ".opentide/configurations/platforms/sysdig.toml",
        SYSDIG,
    );
    write(
        &root,
        "objects/rules/kept.yaml",
        &rule(KEPT, "proc.name = a"),
    );
    write(
        &root,
        "objects/rules/edited.yaml",
        &rule(EDITED, "proc.name = b"),
    );
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "base"]);
    let first = git(&root, &["rev-parse", "HEAD"]);
    write(
        &root,
        "objects/rules/edited.yaml",
        &rule(EDITED, "proc.name = c"),
    );
    git(&root, &["commit", "-q", "-a", "-m", "change"]);
    Repo {
        _dir: dir,
        root,
        first,
    }
}

fn opentide(ws: &Path, args: &[&str], env: &[(&str, String)]) -> Ran {
    let words: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let mut pairs: Vec<(String, String)> = vec![(
        "GIT_CEILING_DIRECTORIES".into(),
        ws.parent().unwrap().to_string_lossy().into_owned(),
    )];
    pairs.extend(env.iter().map(|(k, v)| ((*k).to_owned(), v.clone())));
    let env = Env::from_pairs(pairs);
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "1.0.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let exit_code = run(&words, &env, &host, &mut out, &mut err);
    let stderr = String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap();
    Ran {
        exit_code,
        stdout: String::from_utf8(out).unwrap(),
        stderr,
    }
}

const LEFT_OUT: &str = "1 uncommitted object file is not in scope (objects/rules/kept.yaml); commit them or pass --file";

/// `kept.yaml` edited and `edited.yaml` (the last commit's file) edited again,
/// and a new rule: the scope is `edited.yaml`, which is read from disk as it
/// is now, so only the other two files are left out.
fn dirty(root: &Path) {
    write(
        root,
        "objects/rules/kept.yaml",
        &rule(KEPT, "proc.name = z"),
    );
    write(
        root,
        "objects/rules/edited.yaml",
        &rule(EDITED, "proc.name = y"),
    );
}

#[test]
fn a_local_deploy_names_the_uncommitted_rule_its_scope_leaves_out() {
    let repo = repository();
    let ws = repo.root.clone();
    dirty(&ws);
    let args = ["deploy", "--dry-run", "--strategy", "PREVIEW"];
    let ran = opentide(&ws, &args, &[]);
    assert_eq!(ran.exit_code, 0, "{}", ran.all());
    assert!(
        ran.stderr.contains(&format!("warning: {LEFT_OUT}")),
        "{}",
        ran.all()
    );
    // The rule in scope is read from disk, so it is not in the note; and in
    // the machine mode the note is one of the document's warnings.
    assert!(!ran.stderr.contains("edited.yaml"), "{}", ran.stderr);
    let json = opentide(
        &ws,
        &["--json", "deploy", "--dry-run", "--strategy", "PREVIEW"],
        &[],
    );
    assert_eq!(json.exit_code, 0, "{}", json.all());
    assert!(json.stdout.contains(LEFT_OUT), "{}", json.stdout);
    // Committed, there is nothing to say.
    git(&ws, &["commit", "-q", "-a", "-m", "all"]);
    let clean = opentide(&ws, &args, &[]);
    assert!(!clean.all().contains("uncommitted"), "{}", clean.all());
}

#[test]
fn lint_and_validate_query_name_what_changed_leaves_out() {
    let repo = repository();
    let ws = repo.root.clone();
    dirty(&ws);
    // A rule that is not a rules-folder file is no scope for validate query,
    // but lint reads every object folder: a new object there is named too.
    write(&ws, "objects/threats/t.yaml", "name: T\n");
    let lint = opentide(&ws, &["lint", "--changed"], &[]);
    assert!(
        lint.all()
            .contains("uncommitted object files are not in scope")
            && lint.all().contains("objects/rules/kept.yaml"),
        "{}",
        lint.all()
    );
    assert!(
        !lint.all().contains("1 uncommitted object file is"),
        "{}",
        lint.all()
    );
    let query = opentide(&ws, &["validate", "query", "--changed"], &[]);
    assert!(query.all().contains(LEFT_OUT), "{}", query.all());
}

/// The environment of an Azure Pipelines push build of `ws`'s HEAD, with the
/// push's base when one is named.
fn azure(ws: &Path, base: Option<String>) -> Vec<(&'static str, String)> {
    let mut env = vec![
        ("TF_BUILD", "True".to_owned()),
        ("BUILD_SOURCEVERSION", git(ws, &["rev-parse", "HEAD"])),
        ("BUILD_SOURCESDIRECTORY", ws.to_string_lossy().into_owned()),
    ];
    env.extend(base.map(|base| ("OPENTIDE_PUSH_BASE", base)));
    env
}

#[test]
fn an_azure_push_without_a_base_warns_in_the_build_summary_and_not_in_json() {
    let repo = repository();
    let ws = repo.root.clone();
    let first = repo.first.clone();
    let args = ["deploy", "--dry-run", "--strategy", "PREVIEW"];
    let ran = opentide(&ws, &args, &azure(&ws, None));
    assert_eq!(ran.exit_code, 0, "{}", ran.all());
    assert!(
        ran.stdout.contains(
            "##vso[task.logissue type=warning;]This push's diff starts at its last commit's parent"
        ),
        "{}",
        ran.stdout
    );
    assert!(
        ran.stderr.contains("warning: This push's diff starts at"),
        "{}",
        ran.stderr
    );
    let json = opentide(
        &ws,
        &["--json", "deploy", "--dry-run", "--strategy", "PREVIEW"],
        &azure(&ws, None),
    );
    assert!(!json.stdout.contains("##vso"), "{}", json.stdout);
    assert!(
        json.stdout.contains("This push's diff starts at"),
        "{}",
        json.stdout
    );
    // validate query and lint show the note too.
    for command in [
        ["validate", "query", "--changed"],
        ["lint", "--changed", "--strict"],
    ] {
        let ran = opentide(&ws, &command, &azure(&ws, None));
        assert!(
            ran.all()
                .contains("This push's diff starts at its last commit's parent"),
            "{command:?}: {}",
            ran.all()
        );
    }
    // With the push's base named there is no note, and the diff starts there.
    let based = azure(&ws, Some(first));
    let ran = opentide(&ws, &args, &based);
    assert_eq!(ran.exit_code, 0, "{}", ran.all());
    assert!(!ran.all().contains("This push's diff"), "{}", ran.all());
    assert!(!ran.all().contains("task.logissue"), "{}", ran.all());
}

#[test]
fn a_wrong_push_base_is_a_usage_error_in_deploy_lint_and_validate_query() {
    let repo = repository();
    let ws = repo.root.clone();
    // Not in the checkout, and a commit that is not an ancestor of HEAD.
    git(&ws, &["checkout", "-q", "-b", "other", "HEAD~1"]);
    write(
        &ws,
        "objects/rules/other.yaml",
        &rule("00000000-0000-4000-8000-0000000000a3", "proc.name = o"),
    );
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-q", "-m", "other"]);
    let other = git(&ws, &["rev-parse", "HEAD"]);
    git(&ws, &["checkout", "-q", "main"]);
    for base in ["1".repeat(40), other] {
        let env = azure(&ws, Some(base));
        for command in [
            vec!["deploy", "--dry-run", "--strategy", "PREVIEW"],
            vec!["deploy", "--strategy", "PREVIEW"],
            vec!["lint", "--changed"],
            vec!["validate", "query", "--changed"],
            vec![
                "validate",
                "query",
                "--live",
                "--changed",
                "--platform",
                "sentinel",
            ],
        ] {
            let ran = opentide(&ws, &command, &env);
            assert_eq!(ran.exit_code, 2, "{command:?}: {}", ran.all());
            assert!(
                ran.all().contains("OPENTIDE_PUSH_BASE"),
                "{command:?}: {}",
                ran.all()
            );
        }
    }
}
