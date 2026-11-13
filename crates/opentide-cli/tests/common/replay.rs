//! Replaying the oracle's recordings in-process (UC-3.2, UC-3.5): each
//! recorded case run through [`opentide_cli::run`] on a fresh copy of its
//! fixture, with the goldens' normalisation (`opentide-compare`), compared
//! with the recording by the goldens' comparator (`opentide_compare::compare`,
//! as `cargo xtask golden check --engine compare` compares them) under
//! `APPROVED_DIFFS.toml`: exit code, stdout, stderr, and every file written.
//!
//! The fixtures laid out here are the static ones of `tests/golden/cases.toml`
//! (`none`, `empty`, `tide-corpus`, `tide-corpus-typo`, `vscode`, `tenants`); the
//! generated ones (`fault`, `heavy-small`) are `cargo xtask golden check
//! --engine compare`'s.

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};
use opentide_compare::ledger::{Ledger, Usage};
use opentide_compare::normalise::{Normaliser, Rule, Volatile};
use opentide_compare::{FileState, Run};

/// Whether `case` records a refused connection, whose text carries the
/// host's errno (`[Errno 111]` in the recording, `os error 111` from the Rust
/// connectors on Linux, 61 on macOS): its `unreachable` variants (UC-4.2,
/// #832; UC-4.4, #834) are recorded and compared on Linux, by `cargo xtask
/// golden check`, and replayed here only there.
pub fn host_errno(case: &str) -> bool {
    !cfg!(target_os = "linux")
        && case
            .rsplit('/')
            .next()
            .is_some_and(|variant| variant.contains("unreachable"))
}

/// A generated fixture laid out already (`cargo xtask corpus faults --out
/// DIR`, `cargo xtask corpus generate --seed 1 ... --out DIR`), named in
/// `OPENTIDE_REPLAY_FIXTURES` as `fault=DIR,heavy-small=DIR`.
pub fn generated(name: &str) -> Option<PathBuf> {
    let listed = std::env::var("OPENTIDE_REPLAY_FIXTURES").ok()?;
    listed.split(',').find_map(|pair| {
        let (key, dir) = pair.split_once('=')?;
        (key == name).then(|| PathBuf::from(dir))
    })
}

/// A case's root directory, named and placed as `cargo xtask golden check`
/// places it (`xtask/src/golden/run.rs`: `/tmp/golden-XXXXXX` on Unix,
/// whatever `TMPDIR` says). Paths in a frame or a message wrap by their
/// length, so a root of another length (`tempfile::tempdir()`'s
/// `.tmpXXXXXX`, or a `TMPDIR` elsewhere) wraps lines the real compare does
/// not, and a ledger entry drafted from this replay would not apply there.
///
/// The replay reads the root by its canonical path, so where `/tmp` is a
/// link (macOS: `/private/tmp`) the name is shortened to keep the canonical
/// root as long as the recordings' `/tmp/golden-XXXXXX`.
pub fn case_root() -> tempfile::TempDir {
    let parent = if Path::new("/tmp").is_dir() {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let (prefix, random) = root_name(&std::fs::canonicalize(&parent).unwrap_or(parent.clone()));
    tempfile::Builder::new()
        .prefix(prefix)
        .rand_bytes(random)
        .tempdir_in(parent)
        .unwrap()
}

/// The prefix and the count of random characters of a case root's name in
/// *parent* (canonical): `golden-` and six, as `cargo xtask golden check`
/// names it, cut to keep the root `/tmp/golden-XXXXXX`'s length when
/// *parent* is longer than `/tmp` and leaves room for three random ones.
pub fn root_name(parent: &Path) -> (&'static str, usize) {
    const PREFIX: &str = "golden-";
    const RECORDED: usize = "/tmp/golden-XXXXXX".len();
    let name = RECORDED.saturating_sub(parent.as_os_str().len() + 1);
    if name < 3 {
        return (PREFIX, 6);
    }
    let prefix = (name - 3).min(PREFIX.len());
    (&PREFIX[..prefix], name - prefix)
}

/// The fixtures this module lays out.
pub const FIXTURES: &[&str] = &[
    "none",
    "empty",
    "tide-corpus",
    "tide-corpus-typo",
    "tide-corpus-cve",
    "tide-corpus-legacy-ids",
    "tide-corpus-legacy-id-error",
    "tide-corpus-compile-missing-field",
    "tide-corpus-compile-invalid-value",
    "tide-corpus-compile-empty-block",
    "tide-corpus-compile-invalid-rule",
    "tide-corpus-compile-elastic-severity",
    "tide-corpus-compile-hidden",
    "vscode",
    "setup-merge",
    "skills-merge",
    "vscode-docs-folder",
    "tenants",
    "live-tenants",
    "deploy-tenants",
    "deploy-tenants-sysdig",
    "deploy-push",
    "deploy-push-production",
    "deploy-push-anchor",
    "deploy-push-no-target",
    "deploy-push-key",
    "deploy-push-unreadable",
    "share-misp",
    "share-misp-broken",
    "share-misp-push",
    "share-misp-push-config",
];

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[derive(Clone, Default)]
pub struct Buffer(pub Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// The fixture as `cargo xtask golden record` lays it out (`xtask/src/golden/fixture.rs`).
pub fn fixture(name: &str, ws: &Path) {
    if let Some(dir) = generated(name) {
        copy_tree(&dir, ws);
        return;
    }
    match name {
        "none" => {}
        "empty" => std::fs::create_dir_all(ws.join(".opentide")).unwrap(),
        "tide-corpus-typo" => {
            fixture("tide-corpus", ws);
            let path = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(text.matches("\nseverity: High\n").count(), 1);
            std::fs::write(
                &path,
                text.replace("\nseverity: High\n", "\nseverity: high\n"),
            )
            .unwrap();
        }
        "tide-corpus" => {
            copy_tree(&repo().join("tests/fixtures/tide_corpus/current"), ws);
            copy_tree(
                &ws.join("Configurations"),
                &ws.join(".opentide/configurations"),
            );
            std::fs::create_dir_all(ws.join("objects")).unwrap();
            for (family, legacy) in [
                ("threats", "../Objects/Threat Vectors"),
                ("objectives", "../Objects/Detection Objectives"),
                ("rules", "../Objects/Detection Rules"),
            ] {
                std::os::unix::fs::symlink(legacy, ws.join("objects").join(family)).unwrap();
            }
            for dir in ["schemas", "templates", "exports", "inflight"] {
                std::fs::create_dir_all(ws.join(".opentide").join(dir)).unwrap();
            }
        }
        "vscode" => copy_tree(&repo().join("tests/golden/fixtures/vscode-workspace"), ws),
        "setup-merge" => copy_tree(&repo().join("tests/golden/fixtures/setup-merge"), ws),
        "skills-merge" => copy_tree(&repo().join("tests/golden/fixtures/skills-merge"), ws),
        // The stand-in tenants of the cassette cases (UC-4.2c): `query`'s.
        "tenants" => copy_tree(&repo().join("tests/golden/fixtures/tenants"), ws),
        "live-tenants" => copy_tree(&repo().join("tests/golden/fixtures/live-tenants"), ws),
        "deploy-tenants" => copy_tree(&repo().join("tests/golden/fixtures/deploy-tenants"), ws),
        // Every platform but Sysdig disabled (UC-4.4c): a deploy without
        // --platform sends to Sysdig's stand-in alone.
        "deploy-tenants-sysdig" => {
            fixture("deploy-tenants", ws);
            for platform in [
                "carbon_black_cloud",
                "crowdstrike",
                "defender_for_endpoint",
                "elastic",
                "harfanglab",
                "sentinel",
                "sentinel_one",
                "splunk",
            ] {
                let path = ws.join(format!(
                    ".opentide/configurations/platforms/{platform}.toml"
                ));
                let text = std::fs::read_to_string(&path).unwrap();
                let (on, off) = (
                    "[platform]\nenabled = true\n",
                    "[platform]\nenabled = false\n",
                );
                assert_eq!(text.matches(on).count(), 1, "{platform}");
                std::fs::write(&path, text.replace(on, off)).unwrap();
            }
        }
        // A push of one edit on `deploy-tenants` (UC-4.6c): two commits.
        "deploy-push" => pushed(
            ws,
            "objects/rules/splunk-a-create.yaml",
            "description: A rule the splunk",
            "description: A changed rule the splunk",
        ),
        "deploy-push-production" => pushed(
            ws,
            "objects/rules/crowdstrike-b-update.yaml",
            "description: A rule the crowdstrike",
            "description: A changed rule the crowdstrike",
        ),
        "deploy-push-anchor" => pushed(
            ws,
            "objects/rules/splunk-a-create.yaml",
            "    status: STAGING\n",
            "    status: &status STAGING\n",
        ),
        // UC-4.4b (#834): the MISP destinations of `share`'s cases.
        "share-misp" => copy_tree(&repo().join("tests/golden/fixtures/share-misp"), ws),
        "share-misp-broken" => {
            fixture("share-misp", ws);
            apply_edits(name, ws);
        }
        // UC-4.4e (#834): `share-misp` as a checkout whose last commit is a push.
        "share-misp-push" | "share-misp-push-config" => pushed_from_cases(name, ws),
        // UC-6.2e: pushes the status promotion fails the run on.
        "deploy-push-no-target" | "deploy-push-key" | "deploy-push-unreadable" => {
            pushed_from_cases(name, ws);
        }
        "vscode-docs-folder" => {
            fixture("vscode", ws);
            let path = ws.join(".opentide/configurations/paths.toml");
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(text.matches("[paths.objects]\n").count(), 1);
            std::fs::write(
                &path,
                text.replace(
                    "[paths.objects]\n",
                    "[paths.core]\ndocs_folder = \"site\"\n\n[paths.objects]\n",
                ),
            )
            .unwrap();
        }
        // UC-4.4 (#834), UC-2.2 (#817): tide-corpus with the edits
        // cases.toml declares.
        "tide-corpus-cve"
        | "tide-corpus-legacy-ids"
        | "tide-corpus-legacy-id-error"
        | "tide-corpus-compile-missing-field"
        | "tide-corpus-compile-invalid-value"
        | "tide-corpus-compile-empty-block"
        | "tide-corpus-compile-invalid-rule"
        | "tide-corpus-compile-elastic-severity"
        | "tide-corpus-compile-hidden" => {
            fixture("tide-corpus", ws);
            apply_edits(name, ws);
        }
        other => panic!("{other}: a fixture this test does not lay out"),
    }
}

/// The `edits` of fixture `name` in `tests/golden/cases.toml`, each `find`
/// found once and replaced, or, with an empty `find`, a new file written
/// (`xtask/src/golden/fixture.rs`).
fn apply_edits(name: &str, ws: &Path) {
    let text = std::fs::read_to_string(repo().join("tests/golden/cases.toml")).unwrap();
    let spec: toml::Table = toml::from_str(&text).unwrap();
    let edits = spec["fixtures"][name]
        .get("edits")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    for edit in edits {
        let path = ws.join(edit["path"].as_str().unwrap());
        let (find, replace) = (
            edit["find"].as_str().unwrap(),
            edit["replace"].as_str().unwrap(),
        );
        if find.is_empty() {
            assert!(!path.exists(), "{name}: {}", path.display());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, replace).unwrap();
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches(find).count(), 1, "{name}: {}", path.display());
        std::fs::write(&path, text.replacen(find, replace, 1)).unwrap();
    }
}

/// `deploy-tenants` as a git checkout of two commits, the fixture and then
/// one edit (`pushed` in `cases.toml`, laid out by `xtask/src/golden/fixture.rs`).
fn pushed(ws: &Path, path: &str, find: &str, replace: &str) {
    copy_tree(&repo().join("tests/golden/fixtures/deploy-tenants"), ws);
    fix_modes(ws);
    commit_push(
        ws,
        &[(path.to_owned(), find.to_owned(), replace.to_owned())],
    );
}

/// The copy fixture `name` of `tests/golden/cases.toml` as a git checkout of
/// two commits: its `source` with its `edits`, then its `pushed` edits.
fn pushed_from_cases(name: &str, ws: &Path) {
    let text = std::fs::read_to_string(repo().join("tests/golden/cases.toml")).unwrap();
    let spec: toml::Table = toml::from_str(&text).unwrap();
    let fixture = &spec["fixtures"][name];
    copy_tree(&repo().join(fixture["source"].as_str().unwrap()), ws);
    apply_edits(name, ws);
    fix_modes(ws);
    let edits: Vec<(String, String, String)> = fixture["pushed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edit| {
            let field = |key: &str| edit[key].as_str().unwrap().to_owned();
            (field("path"), field("find"), field("replace"))
        })
        .collect();
    commit_push(ws, &edits);
}

/// Sets every folder to 0755 and every file to 0644, or 0755 when any
/// execute bit is set, before the fixture is committed, as
/// `xtask/src/golden/fixture.rs`'s `fix_modes` does: a checkout's modes follow
/// the umask of whoever cloned, and status promotion keeps a rule file's mode
/// (#987), which the recordings name.
fn fix_modes(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let mode = if meta.is_dir() {
            fix_modes(&path);
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
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// Commits `ws` as it is, then `edits` (path, find, replace) as a second
/// commit, with the fixed author and time of `xtask/src/golden/fixture.rs`.
fn commit_push(ws: &Path, edits: &[(String, String, String)]) {
    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "init.defaultBranch=main",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(["-c", "core.autocrlf=false"])
            // No detached auto-maintenance: its `.git/objects/maintenance.lock`
            // would outlive the commit and land in the snapshot taken before
            // the run.
            .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
            .args(args)
            .current_dir(ws)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .envs([
                ("GIT_AUTHOR_NAME", "opentide golden"),
                ("GIT_AUTHOR_EMAIL", "golden@opentide.invalid"),
                ("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z"),
                ("GIT_COMMITTER_NAME", "opentide golden"),
                ("GIT_COMMITTER_EMAIL", "golden@opentide.invalid"),
                ("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z"),
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}: {output:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "--no-verify", "-m", "The fixture"]);
    for (path, find, replace) in edits {
        let file = ws.join(path);
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(text.matches(find.as_str()).count(), 1);
        std::fs::write(&file, text.replacen(find.as_str(), replace, 1)).unwrap();
    }
    git(&["commit", "-q", "--no-verify", "-a", "-m", "A push"]);
}

/// Every file under `root` (links not followed), by relative path.
pub fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(relative, std::fs::read(entry.path()).unwrap());
            }
        }
    }
    out
}

/// Every folder under `root` (links not followed), by relative path.
pub fn dirs(root: &Path) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(relative);
                pending.push(entry.path());
            }
        }
    }
    out
}

/// What the recording says the case wrote, by its path in the recording
/// (`ws/...`).
pub fn recorded_files(dir: &Path, outcome: &toml::Table) -> BTreeMap<String, FileState> {
    let mut out = BTreeMap::new();
    for entry in outcome
        .get("files")
        .and_then(|files| files.as_array())
        .into_iter()
        .flatten()
    {
        let path = entry["path"].as_str().unwrap();
        if entry["change"].as_str() == Some("deleted") {
            out.insert(path.to_owned(), FileState::Deleted);
            continue;
        }
        let mode = u32::from_str_radix(entry["mode"].as_str().unwrap(), 8).unwrap();
        // As `cargo xtask golden check` reads a recording (`xtask/src/compare.rs` `run_of`).
        let state = match entry["kind"].as_str() {
            Some("dir") => FileState::Written {
                mode: 0o040_000 | mode,
                bytes: Vec::new(),
            },
            Some("file") => FileState::Written {
                mode,
                bytes: match entry.get("blob").and_then(|blob| blob.as_str()) {
                    Some(blob) => {
                        std::fs::read(repo().join("tests/golden/blobs").join(blob)).unwrap()
                    }
                    None => std::fs::read(dir.join("files").join(escape(path))).unwrap(),
                },
            },
            other => panic!("{path}: a recorded {other:?} this test does not read"),
        };
        out.insert(path.to_owned(), state);
    }
    out
}

/// A recorded file's path under `files/`, as `cargo xtask golden record`
/// escapes it (`xtask/src/golden/recording.rs` `escape`): a component that
/// starts with `.git` or `~` gets a `~` before it. The other escapes (`%XX`,
/// Windows' reserved names) name no file the replayed commands write.
fn escape(path: &str) -> PathBuf {
    path.split('/')
        .map(|part| {
            if part.starts_with(".git") || part.starts_with('~') {
                format!("~{part}")
            } else {
                part.to_owned()
            }
        })
        .collect()
}

/// The ledger, as `cargo xtask golden check` reads it.
pub fn ledger() -> Ledger {
    Ledger::parse(
        &std::fs::read_to_string(repo().join("tests/golden/APPROVED_DIFFS.toml")).unwrap(),
    )
    .unwrap()
}

/// The UUIDs in the package's data (`src/opentide`), which no run mints:
/// `cargo xtask compare`'s `package_uuids`.
fn package_uuids() -> &'static std::collections::BTreeSet<String> {
    static CELL: std::sync::OnceLock<std::collections::BTreeSet<String>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        fn walk(dir: &Path, out: &mut std::collections::BTreeSet<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(text) = std::fs::read_to_string(&path) {
                    out.extend(opentide_compare::normalise::uuids_in(&text));
                }
            }
        }
        let mut out = std::collections::BTreeSet::new();
        walk(&repo().join("src/opentide"), &mut out);
        out
    })
}

thread_local! {
    static LAST_FILES: std::cell::RefCell<BTreeMap<String, FileState>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
}

/// The files the last case [`replay`]ed on this thread wrote, normalised, by
/// their recorded paths (`ws/...`): for a test that checks them beyond the
/// comparison, such as loading them as data.
pub fn last_files() -> BTreeMap<String, FileState> {
    LAST_FILES.with(|last| last.borrow().clone())
}

/// Replays the recording in `dir`; the differences found, if any.
pub fn replay(id: &str, dir: &Path, ledger: &Ledger, usage: &mut Usage) -> Vec<String> {
    let case: toml::Table = std::fs::read_to_string(dir.join("case.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let outcome: toml::Table = std::fs::read_to_string(dir.join("outcome.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let argv: Vec<String> = case["argv"]
        .as_array()
        .unwrap()
        .iter()
        .skip(1)
        .map(|arg| arg.as_str().unwrap().to_owned())
        .collect();
    let mode = case["mode"].as_str().unwrap();
    let scratch = case_root();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    let (home, tmp, ws) = (root.join("home"), root.join("tmp"), root.join("ws"));
    for folder in [&home, &tmp, &ws] {
        std::fs::create_dir_all(folder).unwrap();
    }
    fixture(case["fixture"].as_str().unwrap(), &ws);
    // Every folder a recording names files under: the workspace, the
    // temporary directory (CI summaries), home (the state directory).
    // A recording's `tmp/` is `$TMPDIR`, `<TMP>/tmp`.
    std::fs::create_dir_all(tmp.join("tmp")).unwrap();
    let roots = [
        ("ws", ws.clone()),
        ("tmp", tmp.join("tmp")),
        ("home", home.clone()),
    ];
    let before: Vec<_> = roots
        .iter()
        .map(|(_, root)| (files(root), dirs(root)))
        .collect();
    // A cassette case (UC-4.1): the network is the replaying proxy, its CA
    // where the case's CA bundle variables point.
    let proxy = case
        .get("cassette")
        .and_then(|name| name.as_str())
        .map(|name| {
            let text = std::fs::read_to_string(repo().join(format!("tests/cassettes/{name}.json")))
                .unwrap();
            let proxy = opentide_cassette::Proxy::start(
                opentide_cassette::Mode::Replay {
                    cassette: opentide_cassette::Cassette::parse(&text).unwrap(),
                },
                opentide_cassette::Redaction::default(),
            )
            .unwrap();
            std::fs::write(tmp.join("cassette-ca.pem"), proxy.ca_pem()).unwrap();
            proxy
        });
    let proxy_url = proxy.as_ref().map_or_else(
        || "http://127.0.0.1:9".to_owned(),
        opentide_cassette::Proxy::url,
    );
    let env = Env::from_pairs(case["env"].as_table().unwrap().iter().map(|(key, value)| {
        let value = value
            .as_str()
            .unwrap()
            .replace("<CASSETTE_PROXY>", &proxy_url)
            .replace("<HOME>", &home.display().to_string())
            .replace("<TMP>", &tmp.display().to_string())
            .replace("<WS>", &ws.display().to_string());
        (key.clone(), value)
    }));
    let terminal = mode == "human";
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let cwd = match case.get("cwd").and_then(|cwd| cwd.as_str()) {
        None | Some(".") => ws.clone(),
        Some(sub) => ws.join(sub),
    };
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: terminal,
        stderr_tty: terminal,
        log_sink: sink,
        cwd: Some(cwd),
        width: terminal.then_some(100),
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    let today = opentide_compare::normalise::utc_date(std::time::SystemTime::now());
    // The case's opt-in rules (`fresh-uuids` for a command that mints
    // identifiers), with the UUIDs that are not fresh as the golden check
    // knows them: the fixture's, the case's argv and the package's data.
    let rules: Vec<Rule> = case
        .get("normalise")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .filter_map(|rule| rule.as_str())
                .filter_map(|rule| {
                    serde_json::from_value(serde_json::Value::String(rule.to_owned())).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    let mut known_uuids = std::collections::BTreeSet::new();
    if rules.contains(&Rule::FreshUuids) {
        for arg in &argv {
            known_uuids.extend(opentide_compare::normalise::uuids_in(arg));
        }
        known_uuids.extend(package_uuids().iter().cloned());
    }
    let fixture_text: Vec<String> = before
        .iter()
        .flat_map(|(files, _)| files.values())
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect();
    let mut normaliser = Normaliser::new(
        &Volatile {
            literals: vec![
                (ws.display().to_string(), "<WS>".into()),
                (home.display().to_string(), "<HOME>".into()),
                (tmp.display().to_string(), "<TMP>".into()),
            ],
            dates: vec![today],
            // A default window reaches back from now (`query` starts 24
            // hours ago), as `cargo xtask golden check` counts back.
            recent_dates: (1..=7)
                .map(|days| {
                    opentide_compare::normalise::utc_date(
                        std::time::SystemTime::now()
                            - std::time::Duration::from_secs(days * 86_400),
                    )
                })
                .collect(),
            known_uuids,
            ..Volatile::default()
        },
        &rules,
        fixture_text.iter().map(String::as_str),
    );
    let stdout = normaliser.text(&String::from_utf8(out).unwrap());
    let stderr = normaliser.text(&String::from_utf8(stderr.0.lock().unwrap().clone()).unwrap());
    let mut problems = Vec::new();
    if let Some(proxy) = &proxy {
        for mismatch in proxy.verify() {
            problems.push(format!("{id}: not the cassette's requests: {mismatch}"));
        }
    }
    // `generate` prints its checklist once the work is done: no live display.
    if mode == "human" && id.starts_with("generate") && stderr.contains("\x1b[?25l") {
        problems.push(format!(
            "{id}: stderr draws a live display after the work is done"
        ));
    }
    let mut written = BTreeMap::new();
    for ((prefix, root), (files_before, folders_before)) in roots.iter().zip(&before) {
        use std::os::unix::fs::PermissionsExt;
        let after = files(root);
        for (path, bytes) in &after {
            if files_before.get(path) == Some(bytes) {
                continue;
            }
            let mode = std::fs::metadata(root.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            let bytes = normaliser
                .text(&String::from_utf8_lossy(bytes))
                .into_bytes();
            written.insert(
                format!("{prefix}/{path}"),
                FileState::Written { mode, bytes },
            );
        }
        for path in files_before.keys() {
            if !after.contains_key(path) {
                written.insert(format!("{prefix}/{path}"), FileState::Deleted);
            }
        }
        let folders_after = dirs(root);
        // A folder the run removed (a skill's tree replaced whole), as the
        // recording lists it.
        for folder in folders_before.difference(&folders_after) {
            written.insert(format!("{prefix}/{folder}"), FileState::Deleted);
        }
        for folder in folders_after.difference(folders_before) {
            let mode = std::fs::metadata(root.join(folder))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            written.insert(
                format!("{prefix}/{folder}"),
                FileState::Written {
                    mode: 0o040_000 | mode,
                    bytes: Vec::new(),
                },
            );
        }
    }
    let oracle = Run {
        exit_code: i32::try_from(outcome["exit_code"].as_integer().unwrap()).unwrap(),
        stdout: std::fs::read(dir.join("stdout")).unwrap(),
        stderr: std::fs::read(dir.join("stderr")).unwrap(),
        files: recorded_files(dir, &outcome),
    };
    let candidate = Run {
        exit_code,
        stdout: stdout.into_bytes(),
        stderr: stderr.into_bytes(),
        files: written,
    };
    LAST_FILES.with(|last| *last.borrow_mut() = candidate.files.clone());
    let command = case["command"].as_str().unwrap();
    if let Ok(dump) = std::env::var("OPENTIDE_REPLAY_DUMP") {
        // The candidate's run, for `scripts/golden/ledger_entries.py`.
        let out = Path::new(&dump).join(id);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("stdout"), &candidate.stdout).unwrap();
        std::fs::write(out.join("stderr"), &candidate.stderr).unwrap();
        std::fs::write(out.join("exit_code"), candidate.exit_code.to_string()).unwrap();
        for (path, state) in &candidate.files {
            if let FileState::Written { mode, bytes } = state
                && mode & 0o040_000 == 0
            {
                let target = out.join("files").join(path);
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(target, bytes).unwrap();
            }
        }
    }
    let report = opentide_compare::compare(
        opentide_compare::Case { command, id },
        &oracle,
        &candidate,
        ledger,
        usage,
    );
    for difference in &report.differences {
        problems.push(format!(
            "{id}: {} {} {}\n--- oracle\n{}\n--- rust\n{}",
            difference.target,
            difference.kind.as_str(),
            difference
                .pointer
                .as_deref()
                .or(difference.at.as_deref())
                .unwrap_or_default(),
            difference.oracle,
            difference.candidate
        ));
    }
    problems
}

/// Replays every recorded case of `commands` (`_root` for the root's) on the
/// fixtures this module lays out, `--help` included (clap's help, held to
/// the oracle's by content: the ledger's `help` entries); the problems, and
/// how many cases ran. A ledger entry of these commands that applied to
/// nothing is a problem when `complete`.
pub fn replay_commands(commands: &[&str], complete: bool) -> (Vec<String>, usize) {
    let cases = repo().join("tests/golden/cases");
    let ledger = ledger();
    let mut usage = Usage::default();
    let mut problems = Vec::new();
    let mut ran = 0;
    let filter = std::env::var("OPENTIDE_REPLAY_FILTER").unwrap_or_default();
    for command in commands {
        for mode in ["human", "plain", "json", "agent"] {
            let extra: Vec<&str> = ["fault", "heavy-small"]
                .into_iter()
                .filter(|name| generated(name).is_some())
                .collect();
            for fixture in FIXTURES.iter().chain(&extra) {
                let fixture_dir = cases.join(command).join(mode).join(fixture);
                let Ok(variants) = std::fs::read_dir(&fixture_dir) else {
                    continue;
                };
                let mut variants: Vec<PathBuf> =
                    variants.map(|entry| entry.unwrap().path()).collect();
                variants.sort();
                for dir in variants {
                    let id = format!(
                        "{command}/{mode}/{fixture}/{}",
                        dir.file_name().unwrap().to_string_lossy()
                    );
                    if !id.contains(&filter) || host_errno(&id) {
                        continue;
                    }
                    problems.extend(replay(&id, &dir, &ledger, &mut usage));
                    ran += 1;
                }
            }
        }
    }
    if complete && filter.is_empty() {
        for (index, entry) in ledger.entries.iter().enumerate() {
            let elsewhere = ["fault", "heavy-small"].iter().any(|fixture| {
                entry.case.contains(&format!("/{fixture}/")) && generated(fixture).is_none()
            })
                // A cassette test's (`tests/extract_sentinel.rs`), not a golden case's.
                || entry.case.starts_with("cassette:")
                || host_errno(&entry.case);
            // The root's cases are recorded under `_root`.
            let dir = if entry.command.is_empty() {
                "_root".to_owned()
            } else {
                entry.command.replace(' ', ".")
            };
            if commands.contains(&dir.as_str()) && !elsewhere && !usage.is_used(index) {
                problems.push(format!(
                    "APPROVED_DIFFS.toml entry {} ({} {}) applied to no case: it is stale",
                    index + 1,
                    entry.command,
                    entry.case
                ));
            }
        }
    }
    (problems, ran)
}

/// Replays the `variant` case (`help`) of every command path in every mode
/// and fixture; the problems, and how many cases ran. A ledger entry for
/// those cases that applied to nothing is a problem.
pub fn replay_variant(variant: &str) -> (Vec<String>, usize) {
    let cases = repo().join("tests/golden/cases");
    let ledger = ledger();
    let mut usage = Usage::default();
    let mut problems = Vec::new();
    let mut ran = 0;
    let mut commands: Vec<PathBuf> = std::fs::read_dir(&cases)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    commands.sort();
    for command in commands {
        for mode in ["human", "plain", "json", "agent"] {
            for fixture in FIXTURES {
                let dir = command.join(mode).join(fixture).join(variant);
                if !dir.is_dir() {
                    continue;
                }
                let id = format!(
                    "{}/{mode}/{fixture}/{variant}",
                    command.file_name().unwrap().to_string_lossy()
                );
                problems.extend(replay(&id, &dir, &ledger, &mut usage));
                ran += 1;
            }
        }
    }
    let suffix = format!("/{variant}");
    for (index, entry) in ledger.entries.iter().enumerate() {
        if entry.case.ends_with(&suffix) && !usage.is_used(index) {
            problems.push(format!(
                "APPROVED_DIFFS.toml entry {} ({} {}) applied to no case: it is stale",
                index + 1,
                entry.command,
                entry.case
            ));
        }
    }
    (problems, ran)
}
