//! The engine against libyara 4.5 on YARA-X's and libyara's own test cases
//! (`crates/testdata/conformance/yara/cases.json`, written by
//! `scripts/engine/sync_yara_conformance.py` with each engine's live verdict).
//!
//! Under the libyara dialect, a case libyara refuses must get an error, and
//! a case it compiles must get none. A libyara compile warning must get a
//! warning. Under the YARA-X dialect, a case YARA-X refuses must get an
//! error. Every difference is a `[[yara]]` entry of
//! `crates/testdata/oracles/exceptions.toml`, which `scripts/engine/oracles/yara/oracle.py`
//! shares; an entry for a case that agrees fails.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::Severity;
use opentide_yara::{Context, Dialect, analyze_with};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Case {
    origin: String,
    source: String,
    libyara: String,
    yara_x: String,
    #[serde(default)]
    libyara_message: String,
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

/// `(error, warning)` the engine reports under a dialect.
fn verdict(source: &str, dialect: Dialect) -> (bool, bool) {
    let ctx = Context {
        dialect,
        profile: None,
    };
    let d = analyze_with(source, &ctx).diagnostics;
    // `yara_empty_signature` is the spec's rule for a signature, not a
    // compile error: libyara compiles a file of private rules.
    let errors = d
        .iter()
        .any(|d| d.severity == Severity::Error && d.code != "yara_empty_signature");
    (errors, d.iter().any(|d| d.severity == Severity::Warning))
}

/// Cases where the engine and a reference differ by design: the `[[yara]]`
/// entries of `crates/testdata/oracles/exceptions.toml` whose paths name a case
/// (`cases.json#<origin>`), as (origin, check, id). The check is `libyara`
/// (the libyara verdict), `yara_x` (`yara_x_incompatible` against YARA-X's
/// verdict) or `both`.
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
            matches!(check.as_str(), "libyara" | "yara_x" | "both") && !field("reason").is_empty(),
            "[[yara]] {id}: needs a reason and check = libyara, yara_x or both"
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
        .any(|(o, c, _)| o == origin && (c == check || c == "both"))
}

#[test]
fn libyara_dialect_agrees_with_libyara() {
    let differences = differences();
    let mut wrong: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut checked = 0;
    for case in cases() {
        if !matches!(case.libyara.as_str(), "ok" | "warning" | "error") {
            continue;
        }
        checked += 1;
        let (error, warning) = verdict(&case.source, Dialect::Libyara4);
        let want_error = case.libyara == "error";
        let excused = excused(&differences, &case.origin, "libyara");
        let kind = if error != want_error {
            Some(if want_error {
                "missed error"
            } else {
                "false error"
            })
        } else if !want_error && case.libyara == "warning" && !warning {
            Some("missed warning")
        } else {
            None
        };
        if kind.is_none()
            && excused
            && differences
                .iter()
                .any(|(o, c, _)| *o == case.origin && c == "libyara")
        {
            wrong
                .entry("listed but agrees".into())
                .or_default()
                .push(case.origin.clone());
        }
        if let Some(kind) = kind
            && !excused
        {
            wrong.entry(kind.to_string()).or_default().push(format!(
                "{} [{}]: {}",
                case.origin,
                case.libyara_message,
                case.source
                    .replace('\n', " ")
                    .chars()
                    .take(160)
                    .collect::<String>()
            ));
        }
    }
    assert!(checked > 1500, "{checked} cases");
    let report: Vec<String> = wrong
        .iter()
        .map(|(k, v)| format!("{k} ({}):\n  {}", v.len(), v.join("\n  ")))
        .collect();
    assert!(wrong.is_empty(), "{}", report.join("\n"));
}

/// yara-1.0: "libyara compiles it and YARA-X 1.x refuses it" is the
/// warning `yara_x_incompatible`. Every such case gets it (or
/// `yara_entrypoint_deprecated`, which names the same refusal).
#[test]
fn yara_x_refusals_are_yara_x_incompatible() {
    let differences = differences();
    let mut wrong = Vec::new();
    let mut checked = 0;
    for case in cases() {
        if !(matches!(case.libyara.as_str(), "ok" | "warning") && case.yara_x == "error") {
            continue;
        }
        checked += 1;
        let ctx = Context::default();
        let codes: Vec<String> = analyze_with(&case.source, &ctx)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect();
        let flagged = codes
            .iter()
            .any(|c| c == "yara_x_incompatible" || c == "yara_entrypoint_deprecated");
        let excused = excused(&differences, &case.origin, "yara_x");
        if flagged
            && differences
                .iter()
                .any(|(o, c, _)| *o == case.origin && c == "yara_x")
        {
            wrong.push(format!("{}: listed but agrees", case.origin));
        }
        if !flagged && !excused {
            wrong.push(format!(
                "{} [{}]: {}",
                case.origin,
                case.yara_x_message,
                case.source
                    .replace('\n', " ")
                    .chars()
                    .take(160)
                    .collect::<String>()
            ));
        }
    }
    assert!(checked >= 30, "{checked} cases");
    assert!(
        wrong.is_empty(),
        "{} case(s):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The converse: a case both engines compile gets no `yara_x_incompatible`.
#[test]
fn yara_x_incompatible_only_where_yara_x_refuses() {
    let differences = differences();
    let mut wrong = Vec::new();
    let mut checked = 0;
    for case in cases() {
        if !(matches!(case.libyara.as_str(), "ok" | "warning") && case.yara_x == "ok") {
            continue;
        }
        checked += 1;
        let diagnostics = analyze_with(&case.source, &Context::default()).diagnostics;
        let excused = excused(&differences, &case.origin, "yara_x");
        if let Some(d) = diagnostics.iter().find(|d| d.code == "yara_x_incompatible")
            && !excused
        {
            wrong.push(format!(
                "{} [{}]: {}",
                case.origin,
                d.message,
                case.source
                    .replace('\n', " ")
                    .chars()
                    .take(160)
                    .collect::<String>()
            ));
        }
    }
    assert!(checked > 900, "{checked} cases");
    assert!(
        wrong.is_empty(),
        "{} case(s):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
