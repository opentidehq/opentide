//! `validate`'s compile check (#660; UC-2.2, #817): what a deploy would
//! compile must compile. The tide corpus, in today's layout, with one change
//! each; the codes, paths and lines are the oracle's (0.23.0,
//! `tests/golden/cases/validate/*/tide-corpus-compile-*`).
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the corpus reads and every workspace here opens"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::validate::Compilers;
use opentide_workspace::diagnostic::ContextValue;
use opentide_workspace::validate::{Check, Options as ValidateOptions, Validation};
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

const SENTINEL_RULE: &str = "/ws/objects/rules/rule-0001-sentinel-kql.yaml";
const SENTINEL_UUID: &str = "00000000-0000-4000-8003-000000000001";

/// Every file under `dir`, by its path from `dir`.
fn files(dir: &Path, prefix: &Path, out: &mut Vec<(PathBuf, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let relative = prefix.join(path.file_name().unwrap());
        if path.is_dir() {
            files(&path, &relative, out);
        } else {
            out.push((relative, std::fs::read_to_string(&path).unwrap()));
        }
    }
}

/// The tide corpus in today's layout under `/ws`, with `edits` (a file's
/// path under `/ws`, the text to find once, its replacement) applied.
fn corpus(edits: &[(&str, &str, &str)]) -> Workspace {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tide_corpus/current");
    let fs = Arc::new(MemoryFs::new());
    for (legacy, today) in [
        ("Configurations", ".opentide/configurations"),
        ("Objects/Threat Vectors", "objects/threats"),
        ("Objects/Detection Objectives", "objects/objectives"),
        ("Objects/Detection Rules", "objects/rules"),
    ] {
        let mut found = Vec::new();
        files(&source.join(legacy), Path::new(""), &mut found);
        let base = Path::new("/ws").join(today);
        fs.create_dir(&base);
        for (relative, mut text) in found {
            let path = base.join(relative);
            for (file, find, replace) in edits {
                if path == Path::new(file) {
                    assert_eq!(text.matches(find).count(), 1, "{find:?} in {file}");
                    text = text.replace(find, replace);
                }
            }
            if let Some(parent) = path.parent() {
                fs.create_dir(parent);
            }
            fs.write(&path, text);
        }
    }
    Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .unwrap()
}

fn validate(ws: &Workspace, check: Option<Check>) -> Validation {
    ws.validate(&ValidateOptions {
        check,
        compile_check: Some(&Compilers),
        ..ValidateOptions::default()
    })
}

fn codes(validation: &Validation) -> Vec<&str> {
    validation
        .report
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect()
}

const NO_GROUPING: (&str, &str, &str) = (
    SENTINEL_RULE,
    "\n      alert:\n        enabled: false\n",
    "\n",
);

#[test]
fn the_corpus_compiles() {
    let validation = validate(&corpus(&[]), None);
    assert!(validation.report.ok, "{:?}", codes(&validation));
}

#[test]
fn a_rule_sentinel_cannot_compile_fails_validate() {
    let ws = corpus(&[NO_GROUPING]);
    let validation = validate(&ws, None);
    assert_eq!(codes(&validation), ["compile_missing_field"]);
    assert_eq!(validation.exit_code(), 1);
    let issue = &validation.report.issues[0];
    assert_eq!(issue.object_uuid, SENTINEL_UUID);
    assert_eq!(issue.object_type, "rule");
    assert_eq!(issue.file_path.as_deref(), Some(Path::new(SENTINEL_RULE)));
    assert_eq!(
        issue.field_path,
        ["configurations", "sentinel", "grouping", "alert"]
    );
    assert_eq!(
        issue.message,
        "configurations.sentinel.grouping.alert is missing"
    );
    assert_eq!(
        issue.suggestion.as_deref(),
        Some("Sentinel deploy requires incident grouping (grouping.alert.enabled)")
    );
    assert_eq!(
        issue.context.get("platform").and_then(ContextValue::as_str),
        Some("sentinel")
    );
    // The deepest key the file has: `grouping`, line 37 (36 from 0).
    assert_eq!(issue.yaml_line, Some(36));
    assert_eq!((issue.line, issue.column), (Some(37), Some(5)));
    // The oracle's checks: the compile codes are no check's own.
    assert!(
        validation
            .checks
            .iter()
            .all(|(_, status)| *status == "passed")
    );
}

#[test]
fn the_codes_are_the_compilers() {
    for (edit, code, field_path) in [
        (
            (
                SENTINEL_RULE,
                "      suppression: false\n",
                "      suppression: true\n",
            ),
            "compile_invalid_value",
            &["configurations", "sentinel", "alert", "suppression"][..],
        ),
        (
            (
                SENTINEL_RULE,
                "\nresponse:\n  alert_severity: High\n",
                "\nresponse:\n",
            ),
            "compile_empty_block",
            &["response"][..],
        ),
    ] {
        let validation = validate(&corpus(&[edit]), None);
        assert_eq!(codes(&validation), [code]);
        assert_eq!(validation.report.issues[0].field_path, field_path);
    }
}

#[test]
fn only_a_clean_run_compiles() {
    // KG-10: an unrelated error elsewhere hides every compile finding.
    let ws = corpus(&[
        NO_GROUPING,
        (
            "/ws/objects/rules/rule-0002-defender-kql.yaml",
            "  tlp: clear\n",
            "  tlp: clearr\n",
        ),
    ]);
    assert_eq!(codes(&validate(&ws, None)), ["vocab_unknown"]);
}

#[test]
fn only_what_a_deploy_compiles_is_compiled() {
    // An inert status, a disabled platform, a run without the schema check
    // and a host without the compilers compile nothing.
    let design = (
        SENTINEL_RULE,
        "    status: STAGING\n",
        "    status: DESIGN\n",
    );
    assert!(validate(&corpus(&[NO_GROUPING, design]), None).report.ok);
    let disabled = (
        "/ws/.opentide/configurations/platforms/sentinel.toml",
        "enabled = true",
        "enabled = false",
    );
    let validation = validate(&corpus(&[NO_GROUPING, disabled]), None);
    assert!(
        !codes(&validation).contains(&"compile_missing_field"),
        "{:?}",
        codes(&validation)
    );
    let ws = corpus(&[NO_GROUPING]);
    assert!(validate(&ws, Some(Check::Queries)).report.ok);
    assert_eq!(
        codes(&validate(&ws, Some(Check::Schema))),
        ["compile_missing_field"]
    );
    assert!(ws.validate(&ValidateOptions::default()).report.ok);
}
