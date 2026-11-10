//! `corpus faults --check --engine rust --only queries` (UC-2.5, #820): the
//! fault kinds `validate` reports query findings for, each workspace
//! validated by `opentide-workspace` with the queries check on the query
//! engines (`opentide_cli::queries::EngineQueries`), and every finding of
//! the queries check (`context.source` `engine`, in `issues` and `warnings`)
//! compared with the oracle's, every key of it, with the number of queries
//! checked.
//!
//! The kinds `opentide lint` reports (`command = ["lint"]`) come with lint
//! on the Rust engine (UC-2.3): lint's queries check reads the editor's
//! analysis of the whole object, not this hook.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use opentide_workspace::validate::{Options, QueryCheck, QueryFindings, QueryObject};
use opentide_workspace::{OsFs, RootOptions, Workspace};
use serde_json::{Value as Json, json};

use super::faults::{Catalogue, Kind};

/// The queries check on the engines, counting the CrowdStrike queries it
/// checked (the oracle checked none).
#[derive(Default)]
pub struct CountingQueries {
    crowdstrike: std::sync::atomic::AtomicUsize,
    /// The other queries checked, by file.
    others: std::sync::Mutex<BTreeMap<PathBuf, usize>>,
}

impl CountingQueries {
    /// The CrowdStrike queries checked.
    pub fn crowdstrike(&self) -> usize {
        self.crowdstrike.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The queries other than CrowdStrike's checked in the files `files`
    /// names.
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
        for object in objects {
            let checked = profiles.check_object(object.source);
            let checked: Vec<_> = checked.iter().filter(|query| !query.placeholder).collect();
            let crowdstrike = checked
                .iter()
                .filter(|query| query.platform == "crowdstrike")
                .count();
            self.crowdstrike
                .fetch_add(crowdstrike, std::sync::atomic::Ordering::Relaxed);
            *others.entry(object.path.to_path_buf()).or_default() += checked.len() - crowdstrike;
        }
        found
    }
}

/// The group `--only` names.
pub const GROUP: &str = "queries";

/// Code prefixes of the query engines' findings.
const ENGINE_PREFIXES: [&str; 9] = [
    "kql_", "spl_", "esql_", "eql_", "kuery_", "lucene_", "ecs_", "falco_", "cql_",
];

/// Whether `kind` is one of the group: `validate` reports an engine code
/// for it.
pub fn is_query_kind(kind: &Kind) -> bool {
    kind.command.first().map(String::as_str) == Some("validate")
        && kind.command.get(1).is_none_or(|word| word.starts_with('-'))
        && kind.codes.iter().any(|code| is_engine_code(code))
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
/// queries it checked.
///
/// # Errors
///
/// The command holds options `validate` on the Rust engine does not take, or
/// the workspace does not open.
pub fn rust_report(dir: &Path, command: &[String]) -> Result<(Json, usize)> {
    let args = crate::validate::parse_args(command)
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
    });
    Ok((
        serde_json::to_value(&validation.report)?,
        counting.crowdstrike(),
    ))
}

/// Whether a validate diff rule (`xtask validate diff`'s `APPROVED`)
/// explains this pair of findings.
pub fn approved(oracle: Option<&Json>, rust: Option<&Json>) -> bool {
    crate::validate::APPROVED
        .iter()
        .any(|rule| (rule.applies)(oracle, rust, &[]))
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
    fn the_group_is_validate_s_engine_codes() {
        assert!(is_query_kind(&kind(&["validate"], &["kql_parse_error"])));
        assert!(is_query_kind(&kind(
            &["validate", "--queries", "warn"],
            &["vocab_unknown", "falco_value_type"]
        )));
        assert!(!is_query_kind(&kind(&["lint"], &["kql_unscoped_search"])));
        assert!(!is_query_kind(&kind(&["validate"], &["vocab_unknown"])));
        assert!(!is_query_kind(&kind(
            &["validate", "query"],
            &["kql_parse_error"]
        )));
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
