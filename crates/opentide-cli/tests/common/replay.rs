//! What the in-process CLI tests share: the fixtures of
//! `tests/golden/cases.toml` laid out in a case's folder (`none`, `empty`,
//! `tide-corpus` and its variants, `vscode`, `tenants`, ...), the case root,
//! and small file helpers. The snapshot suite (`snapshot.rs`) runs the cases;
//! the generated fixtures (`fault`, `fault-lint`, `heavy-small`) are named in
//! `OPENTIDE_REPLAY_FIXTURES` ([`generated`]).

#![allow(dead_code, reason = "each test binary uses part of the helpers")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A generated fixture laid out already (`cargo xtask corpus faults --out
/// DIR`, `cargo xtask corpus generate --seed 1 ... --out DIR`), named in
/// `OPENTIDE_REPLAY_FIXTURES` as `fault=DIR,heavy-small=DIR` (`fault-lint`
/// is `fault` with lint's recommended check off, as `tests/golden/cases.toml`
/// lays it out).
pub fn generated(name: &str) -> Option<PathBuf> {
    let listed = std::env::var("OPENTIDE_REPLAY_FIXTURES").ok()?;
    listed.split(',').find_map(|pair| {
        let (key, dir) = pair.split_once('=')?;
        (key == name).then(|| PathBuf::from(dir))
    })
}

/// A case's root directory, named and placed as the retired `cargo xtask
/// golden check` placed it (`/tmp/golden-XXXXXX` on Unix,
/// whatever `TMPDIR` says). Paths in a frame or a message wrap by their
/// length, so a root of another length (`tempfile::tempdir()`'s
/// `.tmpXXXXXX`, or a `TMPDIR` elsewhere) wraps lines the real compare does
/// not, and a ledger entry drafted from this replay would not apply there.
///
/// The replay reads the root by its canonical path, so where `/tmp` is a
/// link (macOS: `/private/tmp`) the name is shortened to keep the canonical
/// root as long as the recordings' `/tmp/golden-XXXXXX`.
///
/// `OPENTIDE_CASE_ROOT` names another folder to put the roots in, for a
/// host whose `/tmp` is case-insensitive (macOS): the `tide-corpus` fixtures
/// hold `Objects/` and `objects/` side by side, which are one folder there
/// (the snapshot harness refuses to record on one). A short mount point
/// keeps the root's length (a long one is cut as above, to the room it
/// leaves); see tests/golden/README.md, "Snapshots".
pub fn case_root() -> tempfile::TempDir {
    let parent = case_root_parent();
    let (prefix, random) = root_name(&std::fs::canonicalize(&parent).unwrap_or(parent.clone()));
    tempfile::Builder::new()
        .prefix(prefix)
        .rand_bytes(random)
        .tempdir_in(parent)
        .unwrap()
}

/// The folder the case roots are made in: `OPENTIDE_CASE_ROOT`, else `/tmp`
/// (the recordings' place), else the host's temporary directory.
pub fn case_root_parent() -> PathBuf {
    if let Some(dir) = std::env::var_os("OPENTIDE_CASE_ROOT").filter(|dir| !dir.is_empty()) {
        return PathBuf::from(dir);
    }
    if Path::new("/tmp").is_dir() {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    }
}

/// The prefix and the count of random characters of a case root's name in
/// *parent* (canonical): `golden-` and six, as the retired `cargo xtask
/// golden check` named it, cut to keep the root `/tmp/golden-XXXXXX`'s length when
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
    "tide-corpus-folders",
    "tide-corpus-typo",
    "tide-corpus-cve",
    "tide-corpus-legacy-ids",
    "tide-corpus-legacy-id-error",
    "tide-corpus-splunk-advanced",
    "tide-corpus-legacy-text-id",
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

/// The fixture as the retired `cargo xtask golden record` laid it out.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
pub fn fixture(name: &str, ws: &Path) {
    if let Some(dir) = generated(name) {
        copy_tree(&dir, ws);
        return;
    }
    match name {
        "none" => {}
        "empty" => std::fs::create_dir_all(ws.join(".opentide")).unwrap(),
        // `fault` with lint's recommended check off (`cases.toml`).
        "fault-lint" => {
            fixture("fault", ws);
            apply_edits(name, ws);
        }
        // `objects/<family>` as real folders: a walk of `objects/` enters
        // no link to a folder (`migrate vocab-scope`'s does not).
        "tide-corpus-folders" => {
            fixture("tide-corpus", ws);
            for (family, legacy) in [
                ("threats", "Objects/Threat Vectors"),
                ("objectives", "Objects/Detection Objectives"),
                ("rules", "Objects/Detection Rules"),
            ] {
                let folder = ws.join("objects").join(family);
                std::fs::remove_file(&folder).unwrap();
                copy_tree(&ws.join(legacy), &folder);
            }
        }
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
        // #1139: the vscode workspace with the edits cases.toml declares.
        "vscode-unscoped" | "vscode-ambiguous" | "vscode-folded-comment" => {
            fixture("vscode", ws);
            apply_edits(name, ws);
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
        | "tide-corpus-splunk-advanced"
        | "tide-corpus-legacy-text-id"
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
/// (as the retired `xtask/src/golden/fixture.rs` did).
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
/// one edit (`pushed` in `cases.toml`, laid out by the retired `xtask/src/golden/fixture.rs`).
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
/// the retired `xtask/src/golden/fixture.rs`'s `fix_modes` does: a checkout's modes follow
/// the umask of whoever cloned, and status promotion keeps a rule file's mode
/// (#987), which the recordings name.
pub fn fix_modes(dir: &Path) {
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
/// commit, with the fixed author and time of the retired `xtask/src/golden/fixture.rs`.
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
