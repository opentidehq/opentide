//! `corpus faults --check --engine rust --only queries` (UC-2.5, #820): the
//! fault kinds `validate` reports query findings for, each workspace
//! validated by `opentide-workspace` with the queries check on the query
//! engines (`opentide_cli::queries::EngineQueries`), and every finding of
//! the queries check (`context.source` `engine`, in `issues` and `warnings`)
//! compared with the oracle's, every key of it, with the number of queries
//! checked. A difference fails the kind unless an approved rule explains it:
//! `xtask validate diff`'s, or one of [`APPROVED`], which only the kinds reach.
//!
//! The kinds `opentide lint` reports from its queries check (`command =
//! ["lint"]`, UC-3.5b): each workspace linted by `opentide-workspace` with
//! the query engines (`opentide_cli::queries::EngineLintQueries`, the
//! editor's analysis of the whole object), and every finding of the
//! `queries` check compared with the oracle's `lint --json`, every key of it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use opentide_workspace::validate::{Options, QueryCheck, QueryFindings, QueryObject};
use opentide_workspace::{OsFs, RootOptions, Workspace};
use serde_json::{Value as Json, json};

use super::faults::{Catalogue, Kind};
use crate::validate::Approved;

/// The queries check on the engines, counting the CrowdStrike queries and
/// HarfangLab YARA rules it checked (the oracle checked neither). The counts are the last check's: a
/// `validate --fix` that writes validates twice, and its report is the second
/// run's.
#[derive(Default)]
pub struct CountingQueries {
    crowdstrike: std::sync::atomic::AtomicUsize,
    yara: std::sync::atomic::AtomicUsize,
    /// The other queries checked, by file.
    others: std::sync::Mutex<BTreeMap<PathBuf, usize>>,
}

impl CountingQueries {
    /// The CrowdStrike queries checked.
    pub fn crowdstrike(&self) -> usize {
        self.crowdstrike.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The YARA rules checked (HarfangLab's `yara` block).
    pub fn yara(&self) -> usize {
        self.yara.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The queries other than CrowdStrike's and YARA's checked in the files
    /// `files` names.
    pub fn others_in(&self, files: &std::collections::BTreeSet<PathBuf>) -> usize {
        let others = self
            .others
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        files.iter().filter_map(|file| others.get(file)).sum()
    }
}

impl QueryCheck for CountingQueries {
    fn check(
        &self,
        ws: &Workspace,
        objects: &[QueryObject<'_>],
        as_warnings: bool,
    ) -> QueryFindings {
        let found = opentide_cli::queries::EngineQueries.check(ws, objects, as_warnings);
        let _engine = opentide_cli::queries::ENGINE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let profiles = opentide_cli::queries::Profiles::install(ws.fs().as_ref(), Some(ws.root()));
        let mut others = self
            .others
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        others.clear();
        self.crowdstrike
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.yara.store(0, std::sync::atomic::Ordering::Relaxed);
        for object in objects {
            let checked = profiles.check_object(object.source);
            let checked: Vec<_> = checked.iter().filter(|query| !query.placeholder).collect();
            let crowdstrike = checked
                .iter()
                .filter(|query| query.platform == "crowdstrike")
                .count();
            let yara = checked
                .iter()
                .filter(|query| query.language == "yara")
                .count();
            self.crowdstrike
                .fetch_add(crowdstrike, std::sync::atomic::Ordering::Relaxed);
            self.yara
                .fetch_add(yara, std::sync::atomic::Ordering::Relaxed);
            *others.entry(object.path.to_path_buf()).or_default() +=
                checked.len() - crowdstrike - yara;
        }
        found
    }
}

/// The group `--only` names.
pub const GROUP: &str = "queries";

/// Code prefixes of the query engines' findings.
const ENGINE_PREFIXES: [&str; 10] = [
    "kql_", "spl_", "esql_", "eql_", "kuery_", "lucene_", "ecs_", "falco_", "cql_", "yaral_",
];

/// The codes lint's queries check reports beside the engines' own: the
/// Elastic block advisories, Sysdig's self-referencing list and the
/// datasets `visibility.toml` does not declare.
const LINT_QUERY_CODES: [&str; 9] = [
    "lookback_zero",
    "lookback_long",
    "threshold_lookback",
    "risk_band",
    "technique_not_enterprise",
    "sysdig_list_self_reference",
    "kql_table_not_declared",
    "spl_dataset_not_declared",
    "elastic_dataset_not_declared",
];

/// Whether `kind` is one of the group: `validate` reports an engine code
/// for it, or `lint` reports one of its queries check's codes.
pub fn is_query_kind(kind: &Kind) -> bool {
    is_validate_kind(kind) || is_lint_kind(kind)
}

/// The YARA-L codes a Google SecOps block's own checks report on its YAML
/// (the section keys, `match` and `options`), which the queries check
/// leaves to them: a kind that writes a block and expects only these has no
/// engine finding to compare. A search (a hunt) reports `yaral_match_window`
/// and `yaral_option` from the engine.
const SECOPS_BLOCK_CODES: [&str; 7] = [
    "yaral_section_missing",
    "yaral_section_empty",
    "yaral_section_header",
    "yaral_section_alias",
    "yaral_match_shape",
    "yaral_match_window",
    "yaral_option",
];

/// A kind `validate` reports an engine code for.
pub fn is_validate_kind(kind: &Kind) -> bool {
    let hunt = kind.target.tags.iter().any(|tag| tag == "hunt");
    kind.command.first().map(String::as_str) == Some("validate")
        && kind.command.get(1).is_none_or(|word| word.starts_with('-'))
        && kind.codes.iter().any(|code| {
            is_engine_code(code) && (hunt || !SECOPS_BLOCK_CODES.contains(&code.as_str()))
        })
}

/// A kind `lint` reports from its queries check.
pub fn is_lint_kind(kind: &Kind) -> bool {
    kind.command.first().map(String::as_str) == Some("lint")
        && kind.codes.iter().any(|code| is_lint_query_code(code))
}

/// Whether lint's queries check reports `code`.
pub fn is_lint_query_code(code: &str) -> bool {
    is_engine_code(code) || LINT_QUERY_CODES.contains(&code)
}

/// Whether `code` is a query engine's.
pub fn is_engine_code(code: &str) -> bool {
    ENGINE_PREFIXES
        .iter()
        .any(|prefix| code.starts_with(prefix))
}

/// The group's kinds, in the catalogue's order.
pub fn kinds(catalogue: &Catalogue) -> Vec<String> {
    catalogue
        .kinds
        .iter()
        .filter(|kind| is_query_kind(kind))
        .map(|kind| kind.id.clone())
        .collect()
}

/// The queries check's findings in a `validate --json` document (or in a
/// report), then the number of queries it checked.
pub fn engine_findings(report: &Json) -> (Vec<Json>, Json) {
    let mut found = Vec::new();
    for list in ["issues", "warnings"] {
        for item in report[list].as_array().into_iter().flatten() {
            if item.pointer("/context/source").and_then(Json::as_str) == Some("engine") {
                found.push(item.clone());
            }
        }
    }
    (found, report["stats"]["queries_checked"].clone())
}

/// What the Rust `validate` reports for `command` in the workspace at `dir`:
/// its report, as `validate --json` writes it, and how many CrowdStrike
/// queries and HarfangLab YARA rules it checked.
///
/// # Errors
///
/// The command holds options `validate` on the Rust engine does not take, or
/// the workspace does not open.
pub fn rust_report(dir: &Path, command: &[String]) -> Result<(Json, usize, usize)> {
    let args = crate::validate::parse_args(command)
        .filter(|args| args.fix.is_none())
        .ok_or_else(|| anyhow!("`{}` is not a checking validate", command.join(" ")))?;
    let workspace = Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options {
            roots: RootOptions {
                repo: Some(dir.to_path_buf()),
                repo_root_env: None,
                tide_workspace_env: None,
                cwd: dir.to_path_buf(),
            },
        },
    )
    .map_err(|error| anyhow!("{}: open: {error}", dir.display()))?;
    let counting = CountingQueries::default();
    let validation = workspace.validate(&Options {
        check: args.check,
        selection: Some(&args.selection),
        strict: args.strict,
        queries: args.queries,
        query_check: Some(&counting),
        cve_check: None,
        platform_configurations: None,
        compile_check: None,
    });
    Ok((
        serde_json::to_value(&validation.report)?,
        counting.crowdstrike(),
        counting.yara(),
    ))
}

/// The findings of lint's queries check in a `lint --json` document.
pub fn lint_findings(document: &Json) -> Vec<Json> {
    document["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item["check"] == "queries")
        .cloned()
        .collect()
}

/// What the Rust `lint` reports for `command` in the workspace at `dir`:
/// its findings, as `lint --json` lists them.
///
/// # Errors
///
/// The command is not a plain `lint`, or the workspace does not open.
pub fn rust_lint(dir: &Path, command: &[String]) -> Result<Vec<Json>> {
    if command.len() != 1 || command[0] != "lint" {
        return Err(anyhow!("`{}` is not a plain lint", command.join(" ")));
    }
    let workspace = Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options {
            roots: RootOptions {
                repo: Some(dir.to_path_buf()),
                repo_root_env: None,
                tide_workspace_env: None,
                cwd: dir.to_path_buf(),
            },
        },
    )
    .map_err(|error| anyhow!("{}: open: {error}", dir.display()))?;
    let _engine = opentide_cli::queries::ENGINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let queries = opentide_cli::queries::EngineLintQueries::install(&OsFs, workspace.root());
    let report = workspace.lint(
        None,
        &opentide_workspace::lint::LintOptions {
            checks: Vec::new(),
            fix: false,
            strict: false,
            files: Vec::new(),
            changed: None,
            cwd: dir.to_path_buf(),
            query_check: Some(&queries),
        },
    );
    let document = json!({"findings": serde_json::to_value(&report.findings)?});
    Ok(lint_findings(&document))
}

/// The approved differences only the fault kinds reach: no recorded
/// `validate --json` case holds them, so `xtask validate diff` would find
/// them stale. A complete `--only queries` run fails on one that explains
/// nothing.
pub const APPROVED: &[Approved] = &[Approved {
    id: "hunt-platform",
    reason: "a response hunt's finding names the platform its `system` runs on as \
             `context.platform` (#696), where the oracle wrote `null` outside \
             `configurations`; the finding, its code, place and field path are the same",
    changelog: "**A hunt's findings name the platform it runs on**",
    applies: hunt_platform,
}];

/// The rule, of `xtask validate diff`'s `APPROVED` or of [`APPROVED`], that
/// explains this pair of findings.
pub fn approved(oracle: Option<&Json>, rust: Option<&Json>) -> Option<&'static str> {
    crate::validate::APPROVED
        .iter()
        .chain(APPROVED)
        .find(|rule| (rule.applies)(oracle, rust, &[]))
        .map(|rule| rule.id)
}

/// A hunt's finding with its `system` as `context.platform`, where the
/// oracle's is `null`, and nothing else different.
fn hunt_platform(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    let platform = |finding: &Json| finding.pointer("/context/platform").cloned();
    let mut same = rust.clone();
    if let Some(context) = same.get_mut("context").and_then(Json::as_object_mut) {
        context.insert("platform".to_owned(), Json::Null);
    }
    oracle.pointer("/context/source") == Some(&json!("engine"))
        && oracle.pointer("/field_path/0") == Some(&json!("response"))
        && platform(oracle) == Some(Json::Null)
        && platform(rust).is_some_and(|value| value.as_str().is_some_and(|s| !s.is_empty()))
        && same == *oracle
}

/// The differences between the oracle's findings and the Rust run's, each
/// with the finding on both sides (`null` when absent).
pub fn differences(oracle: &[Json], rust: &[Json]) -> Vec<Json> {
    let mut left: Vec<Option<&Json>> = rust.iter().map(Some).collect();
    let mut out = Vec::new();
    for item in oracle {
        if let Some(at) = left.iter().position(|candidate| *candidate == Some(item)) {
            left[at] = None;
        } else {
            let key = |found: &Json| (found["code"].clone(), found["file_path"].clone());
            let paired = left
                .iter()
                .position(|candidate| candidate.is_some_and(|found| key(found) == key(item)));
            let rust = paired.and_then(|at| left[at].take());
            out.push(json!({"oracle": item, "rust": rust}));
        }
    }
    out.extend(
        left.into_iter()
            .flatten()
            .map(|item| json!({"oracle": null, "rust": item})),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(command: &[&str], codes: &[&str]) -> Kind {
        let text = format!(
            "id = \"k\"\ncodes = {codes:?}\nseverity = \"error\"\ncommand = {command:?}\n\
             ops = []\n[target]\nfamily = \"rule\"\n"
        );
        toml::from_str(&text).unwrap()
    }

    #[test]
    fn the_counts_are_the_last_check_s() {
        use opentide_workspace::{FileSystem, MemoryFs};
        let text = "name: A\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  \
                    schema: rule::1.1\nconfigurations:\n  crowdstrike:\n    query: |\n      \
                    #event_simpleName=ProcessRollup2\n  sentinel:\n    query: |\n      \
                    SecurityEvent\n";
        let fs = Arc::new(MemoryFs::new());
        fs.create_dir("/ws/.opentide/configurations");
        fs.create_dir("/ws/objects/rules");
        fs.write("/ws/objects/rules/a.yaml", text);
        let ws = Workspace::open(
            fs as Arc<dyn FileSystem>,
            opentide_workspace::Options {
                roots: RootOptions {
                    repo: Some(PathBuf::from("/ws")),
                    cwd: PathBuf::from("/ws"),
                    ..RootOptions::default()
                },
            },
        )
        .unwrap();
        let path = PathBuf::from("/ws/objects/rules/a.yaml");
        let objects = [QueryObject {
            path: &path,
            uuid: "11111111-1111-4111-8111-111111111111",
            family: "rule",
            source: text,
        }];
        let counting = CountingQueries::default();
        let files = std::collections::BTreeSet::from([path.clone()]);
        for _ in 0..2 {
            counting.check(&ws, &objects, false);
            assert_eq!(counting.crowdstrike(), 1);
            assert_eq!(counting.others_in(&files), 1);
        }
    }

    #[test]
    fn the_group_is_validate_s_engine_codes_and_lint_s_queries_check() {
        assert!(is_query_kind(&kind(&["validate"], &["kql_parse_error"])));
        assert!(is_query_kind(&kind(
            &["validate", "--queries", "warn"],
            &["vocab_unknown", "falco_value_type"]
        )));
        assert!(is_query_kind(&kind(&["lint"], &["kql_unscoped_search"])));
        assert!(is_lint_kind(&kind(&["lint"], &["risk_band"])));
        assert!(is_lint_kind(&kind(
            &["lint"],
            &["elastic_dataset_not_declared"]
        )));
        assert!(!is_query_kind(&kind(&["lint"], &["filename_mismatch"])));
        assert!(!is_query_kind(&kind(&["lint"], &["placeholder"])));
        assert!(!is_validate_kind(&kind(
            &["lint"],
            &["kql_unscoped_search"]
        )));
        assert!(!is_query_kind(&kind(&["validate"], &["vocab_unknown"])));
        assert!(!is_query_kind(&kind(
            &["validate", "query"],
            &["kql_parse_error"]
        )));
    }

    #[test]
    fn yara_l_kinds_are_in_the_group_but_a_block_s_own_checks_are_not() {
        assert!(is_query_kind(&kind(
            &["validate"],
            &["yaral_undefined_variable"]
        )));
        assert!(is_query_kind(&kind(&["lint"], &["yaral_string_escape"])));
        // The block's checks report these on its YAML, not the engine.
        for code in SECOPS_BLOCK_CODES {
            assert!(!is_query_kind(&kind(&["validate"], &[code])), "{code}");
        }
        // A search's window is the engine's.
        let mut hunt = kind(&["validate"], &["yaral_match_window"]);
        hunt.target.tags.push("hunt".to_owned());
        assert!(is_query_kind(&hunt));
    }

    #[test]
    fn findings_are_paired_and_each_difference_is_named() {
        let a = json!({"code": "kql_parse_error", "file_path": "a", "line": 1});
        let b = json!({"code": "kql_parse_error", "file_path": "a", "line": 2});
        let c = json!({"code": "spl_parse_error", "file_path": "b", "line": 1});
        assert!(differences(&[a.clone(), c.clone()], &[c.clone(), a.clone()]).is_empty());
        let found = differences(&[a.clone(), c.clone()], std::slice::from_ref(&b));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0], json!({"oracle": a, "rust": b}));
        assert_eq!(found[1], json!({"oracle": c, "rust": null}));
        let extra = differences(&[], std::slice::from_ref(&a));
        assert_eq!(extra, vec![json!({"oracle": null, "rust": a})]);
    }

    #[test]
    fn a_hunt_s_platform_is_approved_and_nothing_else_with_it() {
        let oracle = json!({
            "code": "spl_empty_command", "line": 4,
            "field_path": ["response", "procedure", "searches", "1", "query"],
            "context": {"source": "engine", "language": "spl", "platform": null},
        });
        let mut rust = oracle.clone();
        rust["context"]["platform"] = json!("splunk");
        assert_eq!(approved(Some(&oracle), Some(&rust)), Some("hunt-platform"));
        // Another difference beside it is not this rule's.
        let mut moved = rust.clone();
        moved["line"] = json!(5);
        assert_eq!(approved(Some(&oracle), Some(&moved)), None);
        // A rule block's platform is never `null` in the oracle's report.
        let mut block = oracle.clone();
        block["field_path"] = json!(["configurations", "splunk", "query"]);
        let mut block_rust = rust.clone();
        block_rust["field_path"] = block["field_path"].clone();
        assert_eq!(approved(Some(&block), Some(&block_rust)), None);
        // A finding on one side only is not a platform that differs.
        assert_eq!(approved(None, Some(&rust)), None);
    }

    #[test]
    fn only_lint_s_queries_findings_are_read() {
        let document = json!({"findings": [
            {"check": "queries", "code": "kql_x"},
            {"check": "filenames", "code": "filename_mismatch"},
        ]});
        assert_eq!(
            lint_findings(&document),
            vec![json!({"check": "queries", "code": "kql_x"})]
        );
        assert!(lint_findings(&json!({})).is_empty());
    }

    #[test]
    fn the_catalogue_s_lint_query_kinds_are_in_the_group() {
        let catalogue = Catalogue::parse(
            &std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/corpora/faults.toml"),
            )
            .unwrap(),
        )
        .unwrap();
        let ids = kinds(&catalogue);
        let lint = catalogue
            .kinds
            .iter()
            .filter(|kind| ids.contains(&kind.id) && is_lint_kind(kind))
            .count();
        // Every lint kind whose code the queries check reports, none of the
        // file-name, metadata, placeholder or YAML kinds.
        assert_eq!(lint, 71);
        assert!(ids.iter().any(|id| id == "kql-deprecated-function"));
        assert!(!ids.iter().any(|id| id == "lint-filename-mismatch"));
    }

    #[test]
    fn only_the_engine_s_findings_are_read() {
        let report = json!({
            "issues": [
                {"code": "kql_parse_error", "context": {"source": "engine"}},
                {"code": "vocab_unknown", "context": {}},
            ],
            "warnings": [{"code": "esql_x", "context": {"source": "engine"}}],
            "stats": {"queries_checked": 3},
        });
        let (found, queries) = engine_findings(&report);
        assert_eq!(found.len(), 2);
        assert_eq!(queries, json!(3));
    }
}
