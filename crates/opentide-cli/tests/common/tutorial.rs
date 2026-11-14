//! The repository `docs/usage/tutorial.md` builds (one threat, objective
//! and rule), made by the Rust `opentide setup` and the tutorial's own YAML:
//! what `tests/test_cli/test_tui.py` drives the Python UI against.
#![allow(dead_code, reason = "each test file uses part of the helpers")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const THREAT: &str = "00000000-0000-4000-8001-000000000001";
pub const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000001";
pub const RULE: &str = "00000000-0000-4000-8003-000000000001";
pub const RULE_FILE: &str = "objects/rules/sentinel-kql-rule.yaml";

const FILES: [(&str, &str); 3] = [
    (
        "objects/threats/simulated-actor.yaml",
        "Create `objects/threats/simulated-actor.yaml`:",
    ),
    (
        "objects/objectives/credential-access-objective.yaml",
        "Create `objects/objectives/credential-access-objective.yaml`:",
    ),
    (RULE_FILE, "Create `objects/rules/sentinel-kql-rule.yaml`:"),
];

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

/// The YAML fence after `heading`, every line ending a `\n`: a checkout
/// with `core.autocrlf` (Windows) has the tutorial with `\r\n`.
fn yaml_after(markdown: &str, heading: &str) -> String {
    let markdown = markdown.replace("\r\n", "\n");
    let at = markdown.find(heading).unwrap();
    let start = markdown[at..].find("```yaml").unwrap() + at + 7;
    let end = markdown[start..].find("```").unwrap() + start;
    markdown[start..end].trim_start_matches('\n').to_owned()
}

/// A fresh tutorial repository under a temporary folder: the folder, and
/// the repository in it (`tutorial-detections`).
pub fn tutorial() -> (tempfile::TempDir, PathBuf) {
    let base = tempfile::tempdir().unwrap();
    let repo = base.path().join("tutorial-detections");
    let argv: Vec<String> = [
        "setup",
        "--yes",
        "--name",
        "Tutorial Detections",
        "--org",
        "Example Corp",
        "--platform",
        "sentinel",
        "--path",
    ]
    .iter()
    .map(|word| (*word).to_owned())
    .chain(std::iter::once(repo.display().to_string()))
    .collect();
    let err = Buffer::default();
    let host = opentide_cli::Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: Arc::new(Mutex::new(err.clone())),
        cwd: Some(base.path().to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let env = opentide_cli::env::Env::from_pairs([("HOME", base.path().display().to_string())]);
    let mut out = Vec::new();
    let code = opentide_cli::run(&argv, &env, &host, &mut out, &mut err.clone());
    assert_eq!(
        code,
        0,
        "{}{}",
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&err.0.lock().unwrap())
    );
    let markdown = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/usage/tutorial.md"),
    )
    .unwrap();
    for (path, heading) in FILES {
        let path = repo.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, yaml_after(&markdown, heading)).unwrap();
    }
    (base, repo)
}

/// Rewrites `path` under `repo` with `from` replaced by `to`, once.
pub fn edit(repo: &Path, path: &str, from: &str, to: &str) {
    let path = repo.join(path);
    // Compared with `\n` line endings, whatever the file was written with.
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\r\n", "\n");
    assert!(text.contains(from), "{from} not in {}", path.display());
    std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
}

/// The rule's TLP made a value its vocabulary does not have (`clearr`).
pub fn break_tlp(repo: &Path) {
    edit(repo, RULE_FILE, "tlp: clear\n", "tlp: clearr\n");
}

#[test]
fn the_tutorial_reads_the_same_with_windows_line_endings() {
    let markdown = "Intro\r\nCreate `x.yaml`:\r\n\r\n```yaml\r\nname: A\r\nmetadata:\r\n  tlp: clear\r\n```\r\n";
    assert_eq!(
        yaml_after(markdown, "Create `x.yaml`:"),
        "name: A\nmetadata:\n  tlp: clear\n"
    );
}
