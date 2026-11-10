//! `validate --fix --dry-run`'s diff against the oracle's
//! (`cli/ui/fixes.py` `FixPlan.diff`: CPython's `difflib.unified_diff` over
//! the lines as YAML breaks them), on generated files and the in-place
//! value edits `--fix` makes (UC-2.3, #818).
//!
//! The Rust diff is the `similar` crate's (patience) in its unified format; the
//! user's rule is a crate, never a port of difflib. Its text is the oracle's
//! byte for byte, but where a changed line is next to an identical line the
//! two algorithms may align the edit to a different one of them
//! (`tests/golden/APPROVED_DIFFS.toml`, `fix-diff-alignment`): both diffs
//! then apply to the same file, and this test checks that they do.
//!
//! Needs a Python 3: `OPENTIDE_PYTHON`, or this checkout's `.venv`
//! (`uv sync --group dev`). The fast nextest profile leaves `external_*`
//! binaries out.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "a test: a failure is the report"
)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use opentide_workspace::fix::{split_keeping_breaks, unified_diff};
use proptest::prelude::*;
use proptest::strategy::ValueTree as _;
use proptest::test_runner::TestRunner;

/// The oracle's `FixPlan.diff`, as `cli/ui/fixes.py` writes it.
const ORACLE: &str = r#"
import difflib, json, re, sys
_LINE_END = re.compile(r"(?<=\r\n)|(?<=\r)(?!\n)|(?<=\n)")
def _diff_lines(text):
    lines = [line for line in _LINE_END.split(text) if line]
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += "\n\\ No newline at end of file\n"
    return lines
out = []
for path, before, after in json.load(sys.stdin):
    out.append("".join(difflib.unified_diff(
        _diff_lines(before), _diff_lines(after), f"a/{path}", f"b/{path}")))
json.dump(out, sys.stdout)
"#;

fn python() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let python = std::env::var_os("OPENTIDE_PYTHON").map_or_else(
        || {
            if cfg!(windows) {
                root.join(".venv").join("Scripts").join("python.exe")
            } else {
                root.join(".venv").join("bin").join("python")
            }
        },
        PathBuf::from,
    );
    assert!(
        python.is_file() || python.components().count() == 1,
        "no Python at {}: run `uv sync --group dev` (or set OPENTIDE_PYTHON)",
        python.display()
    );
    python
}

fn oracle_diffs(cases: &[(String, String, String)]) -> Vec<String> {
    let mut child = Command::new(python())
        .args(["-I", "-X", "utf8", "-c", ORACLE])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("python starts");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(cases).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "the oracle failed");
    serde_json::from_slice(&output.stdout).unwrap()
}

/// A file of YAML-like lines (repeats included, so alignment choices
/// arise), its line breaks, and the lines whose `high` an edit capitalises.
fn file() -> impl Strategy<Value = (String, String)> {
    let line = prop_oneof![
        Just("severity: high"),
        Just("  - high"),
        Just("tlp: amber"),
        Just("  - T1059"),
        Just("description: |"),
        Just(""),
        Just("# comment"),
        Just("name: high high"),
    ];
    let lines = prop::collection::vec(
        (
            line,
            prop_oneof![Just("\n"), Just("\r\n"), Just("\r")],
            any::<bool>(),
        ),
        1..40,
    );
    (lines, any::<bool>()).prop_map(|(lines, final_break)| {
        let mut before = String::new();
        let mut after = String::new();
        let count = lines.len();
        for (index, (text, end, edit)) in lines.into_iter().enumerate() {
            let end = if index + 1 == count && !final_break {
                ""
            } else {
                end
            };
            before.push_str(text);
            before.push_str(end);
            // An in-place edit of one value, as `--fix` makes.
            if edit && text.contains("high") {
                after.push_str(&text.replacen("high", "High", 1));
            } else {
                after.push_str(text);
            }
            after.push_str(end);
        }
        (before, after)
    })
}

/// `before` with the unified diff `diff` applied, hunk by hunk.
fn patch(before: &str, diff: &str) -> String {
    let old = split_keeping_breaks(before);
    let mut out = String::new();
    let mut next = 0;
    // The two header lines, then the hunks.
    let body = diff
        .splitn(3, '\n')
        .nth(2)
        .filter(|_| diff.starts_with("--- "))
        .unwrap_or(diff);
    let mut rest = body;
    while !rest.is_empty() {
        let header_end = rest.find('\n').unwrap() + 1;
        let header = &rest[..header_end];
        assert!(header.starts_with("@@ -"), "{header:?}");
        let start: usize = header[4..]
            .split([',', ' '])
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let first = if start == 0 { 0 } else { start - 1 };
        for line in &old[next..first] {
            out.push_str(line);
        }
        next = first;
        rest = &rest[header_end..];
        while !rest.is_empty() && !rest.starts_with("@@ -") {
            let tag = &rest[..1];
            let line = split_keeping_breaks(&rest[1..])[0];
            let mut consumed = 1 + line.len();
            let text = line;
            // `\ No newline at end of file` follows a line written without
            // its break, after the `\n` the format adds.
            let marker = "\\ No newline at end of file\n";
            let missing = rest[consumed..].starts_with(marker);
            let text = if missing {
                consumed += marker.len();
                text.strip_suffix('\n').unwrap()
            } else {
                text
            };
            match tag {
                " " => {
                    assert_eq!(old[next], text);
                    out.push_str(text);
                    next += 1;
                }
                "-" => {
                    assert_eq!(old[next], text);
                    next += 1;
                }
                "+" => out.push_str(text),
                other => panic!("unexpected line tag {other:?}"),
            }
            rest = &rest[consumed..];
        }
    }
    for line in &old[next..] {
        out.push_str(line);
    }
    out
}

#[test]
fn the_diff_is_difflibs_text_or_an_equivalent_alignment() {
    let mut runner = TestRunner::deterministic();
    let strategy = file();
    let cases: Vec<(String, String, String)> = (0..3000)
        .map(|index| {
            let (before, after) = strategy.new_tree(&mut runner).unwrap().current();
            (format!("objects/rules/r{index}.yaml"), before, after)
        })
        .collect();
    let oracle = oracle_diffs(&cases);
    let mut identical = 0;
    let mut realigned = Vec::new();
    for ((path, before, after), expected) in cases.iter().zip(&oracle) {
        let ours = unified_diff(path, before, after);
        if &ours == expected {
            identical += 1;
            continue;
        }
        // Only where a change sits among identical lines may differ, and
        // both diffs patch `before` into `after`.
        assert_eq!(
            patch(before, &ours),
            *after,
            "{path}: ours does not apply\n{ours}"
        );
        assert_eq!(
            patch(before, expected),
            *after,
            "{path}: the oracle's does not apply\n{expected}"
        );
        realigned.push(path.clone());
    }
    eprintln!(
        "{identical} of {} diffs identical; {} realigned",
        cases.len(),
        realigned.len()
    );
    // Most edits sit among distinct lines, where the two agree byte for
    // byte: 2877 of these 3000 files, made to repeat lines far more than an
    // object file does.
    assert!(identical * 100 >= cases.len() * 95, "{identical} identical");
}

#[test]
fn every_recorded_dry_run_diff_is_the_oracles() {
    // tests/golden/cases/validate/*/tide-corpus-typo/fix-typo-dry-run: the
    // file the typo fixture edits, and the diff the oracle printed for it.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let before = std::fs::read_to_string(root.join(
        "tests/fixtures/tide_corpus/current/Objects/Detection Rules/rule-0001-sentinel-kql.yaml",
    ))
    .unwrap()
    .replace("\nseverity: High\n", "\nseverity: high\n");
    let after = before.replace("\nseverity: high\n", "\nseverity: High\n");
    let path = "Objects/Detection Rules/rule-0001-sentinel-kql.yaml";
    let recorded: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            root.join("tests/golden/cases/validate/json/tide-corpus-typo/fix-typo-dry-run/stdout"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(unified_diff(path, &before, &after), recorded["diff"]);
    let oracle = oracle_diffs(&[(path.to_owned(), before.clone(), after.clone())]);
    assert_eq!(unified_diff(path, &before, &after), oracle[0]);
}
