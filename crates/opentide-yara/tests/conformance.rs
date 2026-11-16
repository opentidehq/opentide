//! The engine against YARA-X 1.x on YARA-X's and libyara's own test cases
//! (`crates/testdata/conformance/yara/cases.json`, written by
//! `scripts/engine/sync_yara_conformance.py` with each engine's live verdict).
//!
//! YARA-X is the language (#1225): a case YARA-X refuses must get an error,
//! and a case it compiles must get none. Under a refusing profile, the
//! portability check (`yara_x_only_syntax`) refuses no case libyara compiles
//! too. Every difference is a `[[yara]]` entry of
//! `crates/testdata/oracles/exceptions.toml`, which
//! `scripts/engine/oracles/yara/oracle.py` shares; an entry for a case that
//! agrees fails.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::Severity;
use opentide_yara::{Context, YaraXSyntax, analyze_with};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Case {
    origin: String,
    source: String,
    libyara: String,
    yara_x: String,
    #[serde(default)]
    yara_x_message: String,
}

#[derive(Deserialize)]
struct Cases {
    cases: Vec<Case>,
}

fn cases() -> Vec<Case> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/conformance/yara/cases.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str::<Cases>(&text)
        .expect("cases.json")
        .cases
}

/// Whether the engine reports an error where `yara_x_syntax` says.
fn error(source: &str, yara_x_syntax: YaraXSyntax) -> bool {
    let ctx = Context {
        profile: None,
        yara_x_syntax,
    };
    // `yara_empty_signature` is the spec's rule for a signature, not a
    // compile error: YARA-X compiles a file of private rules.
    analyze_with(source, &ctx)
        .diagnostics
        .iter()
        .any(|d| d.severity == Severity::Error && d.code != "yara_empty_signature")
}

fn shown(case: &Case) -> String {
    format!(
        "{} [{}]: {}",
        case.origin,
        case.yara_x_message,
        case.source
            .replace('\n', " ")
            .chars()
            .take(160)
            .collect::<String>()
    )
}

/// Cases where the engine and a reference differ by design: the `[[yara]]`
/// entries of `crates/testdata/oracles/exceptions.toml` whose paths name a case
/// (`cases.json#<origin>`), as (origin, check, id). The check is `yara_x`
/// (the verdict against YARA-X's) or `portable` (the refusing context
/// against a case both engines compile).
fn differences() -> Vec<(String, String, String)> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/oracles/exceptions.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: toml::Value = toml::from_str(&text).expect("exceptions.toml");
    let mut out = Vec::new();
    for entry in doc
        .get("yara")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let field = |k: &str| {
            entry
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        let (id, check) = (field("id"), field("check"));
        assert!(
            matches!(check.as_str(), "yara_x" | "portable") && !field("reason").is_empty(),
            "[[yara]] {id}: needs a reason and check = yara_x or portable"
        );
        for p in entry
            .get("paths")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(origin) = p
                .as_str()
                .and_then(|p| p.strip_prefix("crates/testdata/conformance/yara/cases.json#"))
            {
                out.push((origin.to_string(), check.clone(), id.clone()));
            }
        }
    }
    assert!(!out.is_empty(), "no [[yara]] case in exceptions.toml");
    out
}

/// The ledger entry excusing `origin` for a check, if any.
fn excused(differences: &[(String, String, String)], origin: &str, check: &str) -> bool {
    differences
        .iter()
        .any(|(o, c, _)| o == origin && c == check)
}

/// One check against the verdicts: an error exactly where `refuses` says
/// the case must get one, over the cases `applies` keeps.
fn agree(
    check: &str,
    yara_x_syntax: YaraXSyntax,
    applies: &dyn Fn(&Case) -> bool,
    refuses: &dyn Fn(&Case) -> bool,
) -> (usize, Vec<String>) {
    let differences = differences();
    let mut wrong = Vec::new();
    let mut checked = 0;
    for case in cases().iter().filter(|c| applies(c)) {
        checked += 1;
        let want = refuses(case);
        let got = error(&case.source, yara_x_syntax);
        let listed = excused(&differences, &case.origin, check);
        if got != want && !listed {
            let kind = if want { "missed error" } else { "false error" };
            wrong.push(format!("{kind}: {}", shown(case)));
        } else if got == want && listed {
            wrong.push(format!("listed but agrees: {}", case.origin));
        }
    }
    (checked, wrong)
}

#[test]
fn agrees_with_yara_x() {
    let (checked, wrong) = agree(
        "yara_x",
        YaraXSyntax::Allowed,
        &|c| matches!(c.yara_x.as_str(), "ok" | "error"),
        &|c| c.yara_x == "error",
    );
    assert!(checked > 1700, "{checked} cases");
    assert!(
        wrong.is_empty(),
        "{} case(s):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The portability check refuses no case both engines compile: what a
/// platform profile reports beyond YARA-X's verdict is YARA-X-only syntax.
#[test]
fn the_portability_check_takes_what_both_engines_compile() {
    let (checked, wrong) = agree(
        "portable",
        YaraXSyntax::Refused,
        &|c| matches!(c.libyara.as_str(), "ok" | "warning") && c.yara_x == "ok",
        &|_| false,
    );
    assert!(checked > 900, "{checked} cases");
    assert!(
        wrong.is_empty(),
        "{} case(s):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
