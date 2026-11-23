//! `opentide validate` against the language server (#678, #1139): the
//! findings the command line reports on an object, the editor shows on the
//! same file with the same code and on the same line.
//!
//! `cargo xtask lsp parity --corpus faults` compares the two on every fault
//! kind through the engine; this one runs the binary, as a person does, on
//! a workspace with one fault in each of four files (a value outside its
//! vocabulary, a malformed UUID, an unknown key, a missing required field),
//! and reads the server's side as `opentide tui` does
//! ([`opentide_lsp::ObjectFindings`]).

#![expect(
    clippy::unwrap_used,
    reason = "a test: a workspace that does not lay out is a failure"
)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

const CORPUS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tide_corpus/current"
);

fn copy_tree(from: &Path, to: &Path) {
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

/// Every `.yaml` file under `dir`.
fn yaml_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(yaml_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "yaml") {
            out.push(path);
        }
    }
    out
}

/// `find` replaced by `replace` in `file`, once.
fn edit(file: &Path, find: &str, replace: &str) {
    let text = std::fs::read_to_string(file).unwrap();
    assert_eq!(text.matches(find).count(), 1, "{}", file.display());
    std::fs::write(file, text.replacen(find, replace, 1)).unwrap();
}

#[test]
fn validate_and_the_language_server_report_the_same_codes_on_the_same_lines() {
    let dir = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(dir.path()).unwrap();
    let corpus = Path::new(CORPUS);
    copy_tree(
        &corpus.join("Configurations"),
        &ws.join(".opentide/configurations"),
    );
    for (family, legacy) in [
        ("threats", "Threat Vectors"),
        ("objectives", "Detection Objectives"),
        ("rules", "Detection Rules"),
    ] {
        copy_tree(
            &corpus.join("Objects").join(legacy),
            &ws.join("objects").join(family),
        );
    }
    let rules = ws.join("objects/rules");
    edit(
        &rules.join("rule-0001-sentinel-kql.yaml"),
        "\nseverity: High\n",
        "\nseverity: high\n",
    );
    edit(
        &rules.join("rule-0002-defender-kql.yaml"),
        "uuid: 00000000-0000-4000-8003-000000000002",
        "uuid: not-a-uuid",
    );
    edit(
        &rules.join("rule-0003-splunk-spl.yaml"),
        "\nstatus: STAGING\n",
        "\nstatus: STAGING\nbogus_key: 1\n",
    );
    edit(
        &ws.join("objects/threats/threat-0001-simulated-actor.yaml"),
        "name: Simulated Actor\n",
        "",
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OPENTIDE_") {
            command.env_remove(name);
        }
    }
    let output = command
        .args(["--json", "--no-color", "validate", "--queries", "off"])
        .current_dir(&ws)
        .env("GIT_CEILING_DIRECTORIES", &ws)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();

    // What the command line reports: (code, 1-based line) per file.
    let mut command_line: BTreeMap<String, Vec<(String, u64)>> = BTreeMap::new();
    for issue in document["report"]["issues"].as_array().unwrap() {
        // `ws` is canonical (`\\?\C:\...` on Windows); so is the file.
        let file = std::fs::canonicalize(issue["file_path"].as_str().unwrap()).unwrap();
        let file = file.strip_prefix(&ws).unwrap();
        command_line
            .entry(file.display().to_string())
            .or_default()
            .push((
                issue["code"].as_str().unwrap().to_owned(),
                issue["line"].as_u64().expect("an issue carries its line"),
            ));
    }

    // What the editor shows on every file of `objects/`.
    let findings = opentide_lsp::ObjectFindings::validate(&ws);
    let mut editor: BTreeMap<String, Vec<(String, u64)>> = BTreeMap::new();
    for file in yaml_files(&ws.join("objects")) {
        let text = std::fs::read_to_string(&file).unwrap();
        let path = file.strip_prefix(&ws).unwrap().display().to_string();
        // The editor adds lint's file name and metadata findings
        // (docs/engine/EDITORS.md): `validate` does not report them.
        let found: Vec<_> = findings
            .for_file(&file, &text)
            .into_iter()
            .filter(|finding| {
                !matches!(
                    finding.code.as_str(),
                    "filename_mismatch" | "metadata_recommended" | "reviewed_before_modified"
                )
            })
            .collect();
        if found.is_empty() {
            continue;
        }
        editor.insert(
            path,
            found
                .into_iter()
                .map(|finding| (finding.code, u64::from(finding.range.start.line) + 1))
                .collect(),
        );
    }

    for list in command_line.values_mut().chain(editor.values_mut()) {
        list.sort();
    }
    assert_eq!(
        command_line.len(),
        4,
        "one file for each fault: {command_line:#?}"
    );
    assert_eq!(command_line, editor);
}
