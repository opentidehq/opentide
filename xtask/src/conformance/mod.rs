//! `cargo xtask conformance` (UC-5.4, #839): the cross-SDK conformance suite.
//!
//! The Rust, Python and Node SDKs are one implementation (the `opentide`
//! facade) behind three bindings. Each SDK's runner runs every operation of
//! `tests/conformance/manifest.json` on every corpus and writes a normalised
//! JSON document per operation and corpus; this module holds the manifest,
//! the documents each runner must write, and the comparator, which requires
//! them byte-identical and names the first difference by its JSON pointer.
//!
//! This module computes; [`cli`] lays the corpora out, runs the runners and
//! prints.

pub mod cli;

use anyhow::{Context, Result, bail};
use opentide_compare::json::{self, JsonDifference};
use serde::Deserialize;

/// The runners, in the order a run lists them by default.
pub const RUNNERS: [&str; 3] = ["rust", "python", "node"];

/// The members a runner writes as null, as JSON pointers from a document's
/// root: a run's own clock (its wall time, the time it ran), the values two
/// runs of one operation differ in. Each runner holds the same list
/// (`tests/conformance/README.md`); nothing else is normalised.
pub const VOLATILE: [&str; 3] = ["/duration_ms", "/evaluated_at", "/report/stats/wall_ms"];

/// `tests/conformance/manifest.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    /// The corpora, in the order the report lists them.
    pub corpora: Vec<Corpus>,
    /// The stand-in tenants a run starts once, for every runner.
    #[serde(default)]
    pub stand_ins: Vec<StandIn>,
    /// The tenants the tenant operations connect to.
    #[serde(default)]
    pub tenants: Vec<Tenant>,
    /// The operations each runner runs on each corpus.
    pub operations: Vec<Operation>,
}

/// A stand-in tenant of the manifest: `tests/cassettes/<name>/tenant.py`, on
/// loopback, which prints its port on its first line.
#[derive(Debug, Clone, Deserialize)]
pub struct StandIn {
    /// Its folder under `tests/cassettes/`, and the `{<name>}` a tenant's
    /// setup names its URL by.
    pub name: String,
    /// The variables it is started with (the credential it accepts).
    #[serde(default)]
    pub environment: std::collections::BTreeMap<String, String>,
}

/// A tenant of the manifest. The runners read the rest of its fields
/// (`platform`, `setup`, `environment`).
#[derive(Debug, Clone, Deserialize)]
pub struct Tenant {
    /// Its name, which a tenant operation's `tenant` names.
    pub name: String,
    /// Its setup: a `{<stand-in>}` in a value is that stand-in's URL.
    pub setup: std::collections::BTreeMap<String, String>,
}

/// A corpus of the manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct Corpus {
    /// Its name: the folder of its documents.
    pub name: String,
    /// `tide_corpus`, `heavy`, `faults` or `configuration_faults`.
    pub kind: String,
    /// The heavy workspace's seed.
    #[serde(default)]
    pub seed: Option<u64>,
}

/// An operation of the manifest. The runners read the rest of its fields
/// (`options`, `argv`, `technique`, `open`, `repo`).
#[derive(Debug, Clone, Deserialize)]
pub struct Operation {
    /// Its name: the document's file name, without `.json`.
    pub name: String,
    /// The SDK call: `validate`, `lint`, `info`, `catalog`, `rules`,
    /// `objectives`, `threats`, `coverage`, `deploy_plan` or `run_json`.
    pub call: String,
    /// The corpora it runs on, by the manifest's names; all when absent.
    #[serde(default)]
    pub corpora: Option<Vec<String>>,
    /// The tenant a tenant operation runs on, by the manifest's name.
    #[serde(default)]
    pub tenant: Option<String>,
}

/// The calls a runner knows.
pub const CALLS: [&str; 15] = [
    "validate",
    "lint",
    "info",
    "catalog",
    "rules",
    "objectives",
    "threats",
    "coverage",
    "deploy_plan",
    "run_json",
    "tenants",
    "connectors",
    "query",
    "validate_query",
    "deploy",
];

/// The calls on a tenant (a `Connection`), each with its `tenant`.
pub const TENANT_CALLS: [&str; 3] = ["query", "validate_query", "deploy"];

impl Manifest {
    /// Parses and checks the manifest: unique names, known kinds and calls,
    /// operations restricted to corpora the manifest has, tenant operations
    /// on tenants it has, tenants on stand-ins it has.
    ///
    /// # Errors
    ///
    /// When the text is not the manifest, or names something unknown.
    pub fn parse(text: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(text).context("not the conformance manifest")?;
        let mut corpora = std::collections::BTreeSet::new();
        for corpus in &manifest.corpora {
            if !corpora.insert(corpus.name.as_str()) {
                bail!("corpus `{}` is listed twice", corpus.name);
            }
            match corpus.kind.as_str() {
                "tide_corpus" | "faults" | "configuration_faults" => {}
                "heavy" if corpus.seed.is_some() => {}
                "heavy" => bail!("corpus `{}`: a heavy workspace needs a seed", corpus.name),
                other => bail!("corpus `{}`: unknown kind `{other}`", corpus.name),
            }
        }
        let mut stand_ins = std::collections::BTreeSet::new();
        for stand_in in &manifest.stand_ins {
            if !stand_ins.insert(stand_in.name.as_str()) {
                bail!("stand-in `{}` is listed twice", stand_in.name);
            }
        }
        let mut tenants = std::collections::BTreeSet::new();
        for tenant in &manifest.tenants {
            if !tenants.insert(tenant.name.as_str()) {
                bail!("tenant `{}` is listed twice", tenant.name);
            }
            for value in tenant.setup.values() {
                for named in placeholders(value) {
                    if !stand_ins.contains(named) {
                        bail!(
                            "tenant `{}` names stand-in `{named}`, which the manifest has not",
                            tenant.name
                        );
                    }
                }
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for operation in &manifest.operations {
            if !names.insert(operation.name.as_str()) {
                bail!("operation `{}` is listed twice", operation.name);
            }
            if !CALLS.contains(&operation.call.as_str()) {
                bail!(
                    "operation `{}`: unknown call `{}`",
                    operation.name,
                    operation.call
                );
            }
            let on_tenant = TENANT_CALLS.contains(&operation.call.as_str());
            match (&operation.tenant, on_tenant) {
                (Some(tenant), true) if !tenants.contains(tenant.as_str()) => bail!(
                    "operation `{}` names tenant `{tenant}`, which the manifest has not",
                    operation.name
                ),
                (None, true) => bail!(
                    "operation `{}`: a tenant call needs its tenant",
                    operation.name
                ),
                (Some(_), false) => bail!(
                    "operation `{}`: only a tenant call ({}) names a tenant",
                    operation.name,
                    TENANT_CALLS.join(", ")
                ),
                _ => {}
            }
            for corpus in operation.corpora.iter().flatten() {
                if !corpora.contains(corpus.as_str()) {
                    bail!(
                        "operation `{}` names corpus `{corpus}`, which the manifest has not",
                        operation.name
                    );
                }
            }
        }
        Ok(manifest)
    }
}

/// The stand-ins `value` names, each `{<name>}` in it.
pub fn placeholders(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        out.push(&rest[open + 1..open + close]);
        rest = &rest[open + close + 1..];
    }
    out
}

/// The documents a runner writes for the corpora laid out (each a manifest
/// corpus's name, or `<name>/<part>` for a corpus of several workspaces), as
/// paths under its output folder, in the plan's order.
pub fn documents(operations: &[Operation], laid_out: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for corpus in laid_out {
        let family = corpus.split('/').next().unwrap_or(corpus);
        for operation in operations {
            if operation
                .corpora
                .as_ref()
                .is_some_and(|only| !only.iter().any(|name| name == family))
            {
                continue;
            }
            out.push(format!("{corpus}/{}.json", operation.name));
        }
    }
    out
}

/// Where two documents first differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    /// The JSON pointer (RFC 6901) of the value or object that differs; `""`
    /// is the whole document.
    pub pointer: String,
    /// What differs there.
    pub detail: String,
}

/// A value for a report line: compact, at most 160 characters.
fn shown(value: Option<&json::Json>) -> String {
    let Some(value) = value else {
        return "(absent)".to_owned();
    };
    let text = json::compact(value);
    if text.chars().count() > 160 {
        let cut: String = text.chars().take(157).collect();
        format!("{cut}...")
    } else {
        text
    }
}

/// The first difference between the `reference` runner's document and a
/// `candidate`'s, or `None` when they are byte-identical. The data is
/// compared first (the first value that differs, in document order), then
/// the order of each object's keys, then the bytes.
pub fn first_difference(reference: &[u8], candidate: &[u8]) -> Option<Difference> {
    if reference == candidate {
        return None;
    }
    let (Some(left), Some(right)) = (json::parse(reference), json::parse(candidate)) else {
        let which = match (
            json::parse(reference).is_some(),
            json::parse(candidate).is_some(),
        ) {
            (true, false) => "the candidate's document is not JSON",
            (false, true) => "the reference's document is not JSON",
            _ => "neither document is JSON",
        };
        return Some(Difference {
            pointer: String::new(),
            detail: which.to_owned(),
        });
    };
    if let Some(first) = json::value_differences(&left, &right).into_iter().next() {
        return Some(describe(first));
    }
    if let Some(first) = json::key_order_differences(&left, &right)
        .into_iter()
        .next()
    {
        return Some(describe(first));
    }
    let offset = reference
        .iter()
        .zip(candidate)
        .position(|(a, b)| a != b)
        .unwrap_or(reference.len().min(candidate.len()));
    Some(Difference {
        pointer: String::new(),
        detail: format!("the same data and key order, other bytes from byte {offset}"),
    })
}

fn describe(difference: JsonDifference) -> Difference {
    match difference {
        JsonDifference::Value {
            pointer,
            oracle,
            candidate,
        } => Difference {
            pointer: json::format_pointer(&pointer),
            detail: format!(
                "reference {}, candidate {}",
                shown(oracle.as_ref()),
                shown(candidate.as_ref())
            ),
        },
        JsonDifference::KeyOrder {
            pointer,
            oracle,
            candidate,
        } => Difference {
            pointer: json::format_pointer(&pointer),
            detail: format!("keys in another order: reference {oracle:?}, candidate {candidate:?}"),
        },
    }
}

/// One document of one runner that is not the reference runner's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// The document: `<corpus>/<operation>.json`.
    pub document: String,
    /// The runner whose document differs from the reference's.
    pub runner: String,
    /// Where, or `None` when the runner wrote no such document.
    pub difference: Option<Difference>,
}

/// A difference between the SDKs that is known and cannot be fixed in a
/// binding, listed in `tests/conformance/known_differences.json` with its
/// reason: one value, at one pointer, of one runner's document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Known {
    /// The document: `<corpus>/<operation>.json`.
    pub document: String,
    /// The runner whose document differs from the reference's.
    pub runner: String,
    /// The JSON pointer of the value.
    pub pointer: String,
    /// The reference's value, as compact JSON.
    pub reference: String,
    /// The runner's value, as compact JSON.
    pub candidate: String,
    /// Why no binding can make the two the same.
    pub reason: String,
    /// The issue that tracks it.
    pub issue: String,
}

#[derive(Deserialize)]
struct KnownFile {
    differences: Vec<Known>,
}

/// Parses `tests/conformance/known_differences.json`.
///
/// # Errors
///
/// When the text is not that file, or an entry has no reason or issue.
pub fn parse_known(text: &str) -> Result<Vec<Known>> {
    let file: KnownFile = serde_json::from_str(text).context("not the known differences")?;
    for known in &file.differences {
        if known.reason.trim().is_empty() || known.issue.trim().is_empty() {
            bail!(
                "{} {} {}: a known difference needs its reason and its issue",
                known.document,
                known.runner,
                known.pointer
            );
        }
    }
    Ok(file.differences)
}

/// The entries of `known` that explain every difference between `reference`
/// and `candidate` (`runner`'s `document`), or `None` when one is not
/// explained: a value no entry names with both its values, the order of an
/// object's keys, or a document that is not JSON. Only a difference in the
/// data can be known; the bytes then follow from it.
pub fn explained(
    reference: &[u8],
    candidate: &[u8],
    document: &str,
    runner: &str,
    known: &[Known],
) -> Option<Vec<usize>> {
    let (left, right) = (json::parse(reference)?, json::parse(candidate)?);
    if !json::key_order_differences(&left, &right).is_empty() {
        return None;
    }
    let mut used = Vec::new();
    for difference in json::value_differences(&left, &right) {
        let JsonDifference::Value {
            pointer,
            oracle,
            candidate,
        } = difference
        else {
            return None;
        };
        let pointer = json::format_pointer(&pointer);
        let values = (
            oracle.as_ref().map(json::compact),
            candidate.as_ref().map(json::compact),
        );
        let index = known.iter().position(|k| {
            k.document == document
                && k.runner == runner
                && k.pointer == pointer
                && values.0.as_deref() == Some(k.reference.as_str())
                && values.1.as_deref() == Some(k.candidate.as_str())
        })?;
        used.push(index);
    }
    // A layout difference alone is never known.
    (!used.is_empty()).then_some(used)
}

/// Whether a run passed: every document identical, or, with `diverge`
/// (`--diverge <runner>`, the suite's own test), at least one mismatch and
/// every mismatch the diverging runner's.
pub fn passed(mismatches: &[Mismatch], diverge: Option<&str>) -> bool {
    match diverge {
        None => mismatches.is_empty(),
        Some(runner) => {
            !mismatches.is_empty()
                && mismatches
                    .iter()
                    .all(|m| m.runner == runner && m.difference.is_some())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{
        "corpora": [
            {"name": "small", "kind": "tide_corpus"},
            {"name": "configuration", "kind": "configuration_faults"}
        ],
        "operations": [
            {"name": "validate", "call": "validate"},
            {"name": "commands", "call": "run_json", "argv": ["commands"], "corpora": ["small"]}
        ]
    }"#;

    #[test]
    fn the_manifest_parses_and_names_each_document() {
        let manifest = Manifest::parse(MANIFEST).unwrap();
        let laid_out = vec![
            "small".to_owned(),
            "configuration/a".to_owned(),
            "configuration/b".to_owned(),
        ];
        assert_eq!(
            documents(&manifest.operations, &laid_out),
            [
                "small/validate.json",
                "small/commands.json",
                "configuration/a/validate.json",
                "configuration/b/validate.json",
            ]
        );
    }

    #[test]
    fn the_repository_manifest_parses() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/conformance/manifest.json"),
        )
        .unwrap();
        let manifest = Manifest::parse(&text).unwrap();
        for call in CALLS {
            assert!(
                manifest.operations.iter().any(|op| op.call == call),
                "no operation calls {call}"
            );
        }
    }

    #[test]
    fn a_manifest_that_names_the_unknown_is_refused() {
        for (text, message) in [
            (
                r#"{"corpora": [{"name": "a", "kind": "x"}], "operations": []}"#,
                "unknown kind",
            ),
            (
                r#"{"corpora": [{"name": "a", "kind": "heavy"}], "operations": []}"#,
                "needs a seed",
            ),
            (
                r#"{"corpora": [], "operations": [{"name": "a", "call": "explode"}]}"#,
                "unknown call",
            ),
            (
                r#"{"corpora": [], "operations": [{"name": "a", "call": "info", "corpora": ["b"]}]}"#,
                "which the manifest has not",
            ),
            (
                r#"{"corpora": [], "operations": [{"name": "a", "call": "info"}, {"name": "a", "call": "lint"}]}"#,
                "listed twice",
            ),
            (
                r#"{"corpora": [], "operations": [{"name": "a", "call": "query"}]}"#,
                "needs its tenant",
            ),
            (
                r#"{"corpora": [], "operations": [{"name": "a", "call": "query", "tenant": "t"}]}"#,
                "names tenant `t`",
            ),
            (
                r#"{"corpora": [], "tenants": [{"name": "t", "setup": {}}], "operations": [{"name": "a", "call": "info", "tenant": "t"}]}"#,
                "only a tenant call",
            ),
            (
                r#"{"corpora": [], "tenants": [{"name": "t", "setup": {"url": "{s1}"}}], "operations": []}"#,
                "names stand-in `s1`",
            ),
            (
                r#"{"corpora": [], "stand_ins": [{"name": "s"}, {"name": "s"}], "operations": []}"#,
                "stand-in `s` is listed twice",
            ),
            (
                r#"{"corpora": [], "tenants": [{"name": "t", "setup": {}}, {"name": "t", "setup": {}}], "operations": []}"#,
                "tenant `t` is listed twice",
            ),
        ] {
            let error = Manifest::parse(text).unwrap_err();
            assert!(format!("{error:#}").contains(message), "{error:#}");
        }
    }

    #[test]
    fn a_setup_names_its_stand_ins_by_placeholder() {
        assert_eq!(placeholders("{sentinel_one}/web"), ["sentinel_one"]);
        assert_eq!(placeholders("{a}:{b}"), ["a", "b"]);
        assert!(placeholders("$S1_API_TOKEN").is_empty());
        assert!(placeholders("{unclosed").is_empty());
    }

    #[test]
    fn identical_documents_have_no_difference() {
        assert_eq!(first_difference(b"{\"a\": 1}\n", b"{\"a\": 1}\n"), None);
    }

    #[test]
    fn a_value_is_named_by_its_pointer() {
        let difference = first_difference(
            br#"{"report": {"issues": [{"code": "a/b"}, {"code": "x"}]}}"#,
            br#"{"report": {"issues": [{"code": "a/b"}, {"code": "y"}]}}"#,
        )
        .unwrap();
        assert_eq!(difference.pointer, "/report/issues/1/code");
        assert_eq!(difference.detail, r#"reference "x", candidate "y""#);
    }

    #[test]
    fn a_member_one_side_lacks_is_named() {
        let difference = first_difference(br#"{"a/b": {"c~": 1}}"#, br#"{"a/b": {}}"#).unwrap();
        assert_eq!(difference.pointer, "/a~1b/c~0");
        assert_eq!(difference.detail, "reference 1, candidate (absent)");
    }

    #[test]
    fn an_integer_and_a_float_differ() {
        let difference =
            first_difference(br#"{"default": 120.0}"#, br#"{"default": 120}"#).unwrap();
        assert_eq!(difference.pointer, "/default");
        assert_eq!(difference.detail, "reference 120.0, candidate 120");
    }

    /// The divergence the runners' test-only flag makes: the same data, its
    /// keys sorted, as a binding that went through a sorted map would write it.
    #[test]
    fn keys_in_another_order_are_caught() {
        let difference = first_difference(
            b"{\n  \"checks\": {},\n  \"report\": {},\n  \"exit_code\": 0\n}\n",
            b"{\n  \"checks\": {},\n  \"exit_code\": 0,\n  \"report\": {}\n}\n",
        )
        .unwrap();
        assert_eq!(difference.pointer, "");
        assert!(
            difference.detail.starts_with("keys in another order"),
            "{difference:?}"
        );
        assert!(
            difference
                .detail
                .contains(r#"["checks", "report", "exit_code"]"#)
        );
    }

    #[test]
    fn layout_alone_is_a_difference() {
        let difference = first_difference(b"{\"a\": 1}\n", b"{\"a\":1}\n").unwrap();
        assert_eq!(difference.pointer, "");
        assert_eq!(
            difference.detail,
            "the same data and key order, other bytes from byte 5"
        );
    }

    #[test]
    fn a_document_that_is_not_json_is_a_difference() {
        let difference = first_difference(b"{}", b"{").unwrap();
        assert_eq!(difference.detail, "the candidate's document is not JSON");
    }

    #[test]
    fn a_long_value_is_shortened() {
        let long = format!(r#"{{"a": "{}"}}"#, "x".repeat(400));
        let difference = first_difference(long.as_bytes(), br#"{"a": "y"}"#).unwrap();
        assert!(difference.detail.len() < 200, "{}", difference.detail);
        assert!(difference.detail.contains("..."));
    }

    fn known(pointer: &str, reference: &str, candidate: &str) -> Known {
        Known {
            document: "small/commands.json".to_owned(),
            runner: "node".to_owned(),
            pointer: pointer.to_owned(),
            reference: reference.to_owned(),
            candidate: candidate.to_owned(),
            reason: "JavaScript has one number type".to_owned(),
            issue: "#839".to_owned(),
        }
    }

    #[test]
    fn a_known_difference_explains_exactly_its_value() {
        let entries = [known("/default", "120.0", "120")];
        let (reference, candidate) = (br#"{"default": 120.0}"#, br#"{"default": 120}"#);
        let explain = |r: &[u8], c: &[u8], document: &str, runner: &str| {
            explained(r, c, document, runner, &entries)
        };
        assert_eq!(
            explain(reference, candidate, "small/commands.json", "node"),
            Some(vec![0])
        );
        // Another runner, document, value or pointer is not explained.
        assert_eq!(
            explain(reference, candidate, "small/commands.json", "python"),
            None
        );
        assert_eq!(
            explain(reference, candidate, "small/other.json", "node"),
            None
        );
        assert_eq!(
            explain(
                reference,
                br#"{"default": 121}"#,
                "small/commands.json",
                "node"
            ),
            None
        );
        assert_eq!(
            explain(
                br#"{"x": 120.0}"#,
                br#"{"x": 120}"#,
                "small/commands.json",
                "node"
            ),
            None
        );
        // A second difference beside the known one is not explained.
        assert_eq!(
            explain(
                br#"{"default": 120.0, "a": 1}"#,
                br#"{"default": 120, "a": 2}"#,
                "small/commands.json",
                "node"
            ),
            None
        );
        // Nor keys in another order, nor layout alone.
        assert_eq!(
            explain(
                br#"{"default": 120.0, "a": 1}"#,
                br#"{"a": 1, "default": 120}"#,
                "small/commands.json",
                "node"
            ),
            None
        );
        assert_eq!(
            explain(b"{\"a\": 1}", b"{\"a\":1}", "small/commands.json", "node"),
            None
        );
    }

    #[test]
    fn a_known_difference_needs_its_reason_and_issue() {
        let text = r##"{"differences": [{"document": "a.json", "runner": "node", "pointer": "/a",
            "reference": "1.0", "candidate": "1", "reason": " ", "issue": "#1"}]}"##;
        assert!(parse_known(text).is_err());
        let repository = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/conformance/known_differences.json"),
        )
        .unwrap();
        parse_known(&repository).unwrap();
    }

    #[test]
    fn a_run_passes_on_no_mismatch_and_a_divergence_run_on_the_diverging_runner_alone() {
        let mismatch = |runner: &str| Mismatch {
            document: "small/validate.json".to_owned(),
            runner: runner.to_owned(),
            difference: Some(Difference {
                pointer: String::new(),
                detail: "keys".to_owned(),
            }),
        };
        assert!(passed(&[], None));
        assert!(!passed(&[mismatch("python")], None));
        assert!(passed(&[mismatch("python")], Some("python")));
        // Nothing caught: the divergence went unnoticed.
        assert!(!passed(&[], Some("python")));
        // Another runner differs too: that is a real difference.
        assert!(!passed(
            &[mismatch("python"), mismatch("node")],
            Some("python")
        ));
        // A missing document is not the divergence.
        let missing = Mismatch {
            difference: None,
            ..mismatch("python")
        };
        assert!(!passed(&[missing], Some("python")));
    }
}
