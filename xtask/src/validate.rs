//! `cargo xtask validate diff` (UC-2.2, #817): `opentide-workspace`'s
//! `validate` against the oracle's recordings of `opentide --json validate`
//! (`tests/golden/cases/validate/json/`), fixture by fixture and option by
//! option.
//!
//! Each recorded case whose arguments are only `validate`'s check and scope
//! options (`--check`, `--type`, `--uuid`, `--file`, `--strict`,
//! `--queries`) is run again: its fixture is laid out as the goldens lay it
//! out, the workspace is loaded and validated in-process, and the report's
//! `issues` and `warnings` (every key of every finding, in order), its
//! `stats.objects_checked`, the `checks` statuses, `ok` and the `summary` are
//! compared with the recording. The workspace's path reads `<WS>`, as the
//! recordings write it.
//!
//! The `--fix` and `--fix --dry-run` cases (UC-2.3, #818) run on a fresh
//! copy of their fixture through `Workspace::validate_fix`; their report is
//! compared as above (after the fixes, or the one that found them), and so
//! are `fixed` or `would_fix` (each value replaced), `diff` (the dry run's
//! unified diff, text for text), `summary.fixed`, and every file the run
//! changed, with its bytes.
//!
//! The queries check runs on the query engines (`opentide_cli::queries`,
//! UC-2.5, #820): its findings (`context.source` is `engine`), its status
//! and `stats.queries_checked` are compared like the others. Any difference
//! fails the run unless an approved rule ([`APPROVED`]) explains it; a rule
//! that explains nothing on the whole run is stale and fails it too.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde_json::{Value as Json, json};

use crate::corpus::cli::{Scratch, repo_root};
use crate::golden::case::{Case, Spec};
use crate::golden::recording::Recording;
use crate::golden::snapshot::{ChangeKind, Snapshot};
use opentide_workspace::fix::FixRun;
use opentide_workspace::validate::{Check, Options, QueriesMode, Selection};
use opentide_workspace::{OsFs, RootOptions, Workspace};

/// The usage of `cargo xtask validate`.
pub const USAGE: &str = "\
usage: cargo xtask validate diff [--filter GLOB] [--keep DIR] [--show-approved]

  run opentide-workspace's validate on every recorded `validate --json`
  case that checks or fixes (no --format, --watch) and compare its
  report, checks and summary with the oracle's recording; a --fix case
  also what it fixed, its diff and the files it wrote. GLOB filters
  the case ids (validate/json/<fixture>/<variant>). --show-approved
  prints each approved difference too.
";

/// An approved class of difference: where it applies, and why.
pub struct Approved {
    /// The rule's id.
    pub id: &'static str,
    /// Why the Rust result is right.
    pub reason: &'static str,
    /// The bold lead of its CHANGELOG.md entry.
    pub changelog: &'static str,
    /// Whether it explains this finding of the oracle (`None`: none) and
    /// this finding of the Rust run (`None`: none) as one difference; the
    /// last argument is the oracle's whole list (issues or warnings) in the
    /// same case.
    pub applies: fn(oracle: Option<&Json>, rust: Option<&Json>, oracle_list: &[Json]) -> bool,
}

/// The approved differences. A count or verdict that differs (`summary`,
/// `stats.objects_checked`) is approved as derived when every finding that
/// differs in its case is.
pub const APPROVED: &[Approved] = &[
    Approved {
        id: "suggestions",
        reason: "\"did you mean\" is opentide_core::suggest's one rule (the engines', the \
                 configuration's and the vocabularies'), not difflib's ratio: `Host::Gizmo` \
                 and `Big incident` suggest nothing, where the oracle offered unrelated words \
                 that share letters (`Host::File`, `Substantial incident`); the finding, its \
                 code and place are the same, with no suggestion, help or fix",
        changelog: "**\"Did you mean\" suggests what a typo meant, not a word that shares letters**",
        applies: suggestions,
    },
    Approved {
        id: "yaml-error-text",
        reason: "a file that is not YAML is reported in the words of the YAML 1.2 parser \
                 (saphyr), at the line and column the oracle names (one column later where \
                 saphyr names the tab it refuses); the code, the file and the help are the \
                 same (as in `cargo xtask registry diff`)",
        changelog: "**Tide objects are read as YAML 1.2**",
        applies: yaml_error_text,
    },
    Approved {
        id: "yaml-1-2-dates",
        reason: "an unquoted impossible date (`reviewed: 2026-02-30`) no longer stops the file \
                 from loading: the object is indexed and checked, and the field's own \
                 `schema_validation` reports the date, where the oracle refused the whole file \
                 as `yaml_parse` (UC-1.3, `yaml-1-2-dates`)",
        changelog: "**Tide objects are read as YAML 1.2**",
        applies: yaml_1_2_dates,
    },
    Approved {
        id: "invalid-uuid-every-file",
        reason: "KG-04: every file that writes an invalid UUID gets its `invalid_uuid`, also a \
                 file whose object a later file with the same UUID displaced from the index; \
                 the oracle reported it once per value, on another file, in the same words",
        changelog: "**Every file with an invalid UUID is reported**",
        applies: invalid_uuid_every_file,
    },
    Approved {
        id: "engine-suggestions",
        reason: "the query engines suggest by opentide_core::suggest's one rule (#812): a name \
                 far from every choice (ES|QL `::foo`) suggests nothing, where the oracle's \
                 engine offered an unrelated one (`bool`); the finding, its code and place are \
                 the same, and its help is the language reference",
        changelog: "**The query engines suggest by the same rule**",
        applies: engine_suggestions,
    },
    Approved {
        id: "crowdstrike-cql",
        reason: "CrowdStrike queries are checked as CQL (language-server 0.12.0): each one \
                 counts in `queries_checked`, and a query Next-Gen SIEM would refuse is a \
                 `cql_*` error the oracle, which never checked them, does not report; the \
                 count also holds the queries of a file the oracle could not read and the \
                 Rust run reads (`yaml-1-2-dates`), never otherwise",
        changelog: "**`opentide validate` checks CrowdStrike queries, and fails a rule whose \
                    query Next-Gen SIEM would refuse**",
        applies: crowdstrike_cql,
    },
];

/// The parts of a `--fix` case no approved finding explains.
const FIX_PARTS: [&str; 7] = [
    "summary (self)",
    "fixed",
    "would_fix",
    "diff",
    "unwritten",
    "files",
    "summary.fixed",
];

/// The difference in `stats.queries_checked`, as a rule reads it: the
/// oracle's count, and the Rust run's with how many of its queries were
/// CrowdStrike's.
/// CrowdStrike's, and how many were in files the oracle could not read
/// (`yaml-1-2-dates`).
fn queries_checked(
    oracle: &Json,
    rust: &Json,
    crowdstrike: usize,
    yaml_1_2: usize,
) -> (Json, Json) {
    (
        json!({"queries_checked": oracle}),
        json!({"queries_checked": rust, "crowdstrike": crowdstrike, "yaml_1_2": yaml_1_2}),
    )
}

fn engine_suggestions(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    let reference = opentide_cli::queries::engine_help(
        code(rust),
        rust["message"].as_str().unwrap_or(""),
        None,
    );
    oracle.pointer("/context/source") == Some(&json!("engine"))
        && !oracle["suggestion"].is_null()
        && rust["suggestion"].is_null()
        && rust["help"] == json!(reference)
        && without(oracle, &["suggestion", "help"]) == without(rust, &["suggestion", "help"])
}

pub(crate) fn crowdstrike_cql(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    match (oracle, rust) {
        // A CrowdStrike query's finding, which the oracle did not check.
        (None, Some(rust)) => {
            code(rust).starts_with("cql_")
                && rust.pointer("/context/source") == Some(&json!("engine"))
                && rust.pointer("/context/platform") == Some(&json!("crowdstrike"))
        }
        // The count: the oracle's, and the CrowdStrike queries.
        (Some(oracle), Some(rust)) => {
            let (Some(before), Some(after), Some(added), Some(read)) = (
                oracle["queries_checked"].as_u64(),
                rust["queries_checked"].as_u64(),
                rust["crowdstrike"].as_u64(),
                rust["yaml_1_2"].as_u64(),
            ) else {
                return false;
            };
            added > 0 && before + added + read == after
        }
        _ => false,
    }
}

/// `finding` without the keys `drop` names.
fn without(finding: &Json, drop: &[&str]) -> Json {
    let mut copy = finding.clone();
    if let Some(map) = copy.as_object_mut() {
        for key in drop {
            map.remove(*key);
        }
    }
    copy
}

fn code(finding: &Json) -> &str {
    finding["code"].as_str().unwrap_or("")
}

fn suggestions(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    const VALUE_CODES: [&str; 4] = [
        "vocab_unknown",
        "invalid_ref",
        "chaining_relation_unknown",
        "config_enum_unknown",
    ];
    VALUE_CODES.contains(&code(oracle))
        && !oracle["suggestion"].is_null()
        // Rust suggests nothing: a different suggestion is not this rule's.
        && rust["suggestion"].is_null()
        && rust["help"].is_null()
        && rust["fix"].is_null()
        && without(oracle, &["suggestion", "help", "fix"])
            == without(rust, &["suggestion", "help", "fix"])
}

fn yaml_error_text(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    let message = rust["message"].as_str().unwrap_or("");
    // The same column, or one later where saphyr names the tab it refuses
    // (the oracle placed the error at the tab's line start).
    let shift = |key: &str| {
        let (Some(o), Some(r)) = (oracle[key].as_u64(), rust[key].as_u64()) else {
            return None;
        };
        r.checked_sub(o)
    };
    let columns = match (shift("column"), shift("end_column")) {
        (Some(0), Some(0)) => true,
        (Some(1), Some(1)) => message.contains("tab"),
        _ => false,
    };
    code(oracle) == "yaml_parse"
        && code(rust) == "yaml_parse"
        && message.starts_with("Could not parse object YAML: ")
        && columns
        && without(oracle, &["message", "column", "end_column"])
            == without(rust, &["message", "column", "end_column"])
}

fn yaml_1_2_dates(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    match (oracle, rust) {
        (Some(oracle), None) => {
            code(oracle) == "yaml_parse"
                && oracle["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("is not a valid date"))
        }
        (None, Some(rust)) => {
            code(rust) == "schema_validation"
                && rust["field_path"] == json!(["metadata", "reviewed"])
                && rust["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("is not a valid date or time"))
        }
        _ => false,
    }
}

/// A Rust-only `invalid_uuid` whose value the oracle itself reported as
/// invalid, in the same words, on another file: the UUID is invalid and
/// shared, and only the file the index kept was reported.
fn invalid_uuid_every_file(
    oracle: Option<&Json>,
    rust: Option<&Json>,
    oracle_list: &[Json],
) -> bool {
    let (None, Some(rust)) = (oracle, rust) else {
        return false;
    };
    code(rust) == "invalid_uuid"
        && rust["object_uuid"].is_string()
        && oracle_list.iter().any(|reported| {
            code(reported) == "invalid_uuid"
                && reported["object_uuid"] == rust["object_uuid"]
                && reported["message"] == rust["message"]
                && reported["field_path"] == rust["field_path"]
                && reported["file_path"] != rust["file_path"]
        })
}

/// The arguments of a recorded case, as `validate` options.
#[derive(Debug, Default)]
pub(crate) struct Args {
    pub(crate) check: Option<Check>,
    pub(crate) selection: Selection,
    pub(crate) strict: bool,
    pub(crate) queries: QueriesMode,
    /// `--fix`: `Some(dry_run)`.
    pub(crate) fix: Option<bool>,
}

/// `argv`'s `validate` options; `None` when it holds another (`--format`,
/// `--watch`, ...) or no `validate`.
pub(crate) fn parse_args(argv: &[String]) -> Option<Args> {
    let rest = argv.iter().skip_while(|arg| *arg != "validate").skip(1);
    let mut parsed = Args::default();
    let mut rest = rest.peekable();
    while let Some(arg) = rest.next() {
        let mut value = || rest.next().cloned();
        match arg.as_str() {
            "--strict" => parsed.strict = true,
            "--fix" => parsed.fix = Some(parsed.fix.unwrap_or(false)),
            "--dry-run" => parsed.fix = Some(true),
            "--check" => parsed.check = Some(Check::parse(&value()?)?),
            "--type" => {
                // Another spelling is the command line's usage error (UC-3.5).
                let family = value()?;
                if !["rule", "threat", "objective"].contains(&family.as_str()) {
                    return None;
                }
                parsed.selection.types.push(family);
            }
            "--uuid" => parsed.selection.uuids.push(value()?),
            "--file" => parsed.selection.files.push(value()?),
            "--queries" => {
                parsed.queries = match value()?.as_str() {
                    "error" => QueriesMode::Error,
                    "warn" => QueriesMode::Warn,
                    "off" => QueriesMode::Off,
                    _ => return None,
                };
            }
            _ => return None,
        }
    }
    // `--dry-run` without `--fix` is the command line's usage error (UC-3.5).
    if parsed.fix == Some(true) && !argv.iter().any(|arg| arg == "--fix") {
        return None;
    }
    Some(parsed)
}

/// The difference in the number of queries checked.
const QUERIES_CHECKED: &str = "stats.queries_checked";

/// One difference between the two runs of a case.
#[derive(Debug)]
struct Difference {
    case: String,
    what: String,
    oracle: Option<Json>,
    rust: Option<Json>,
    /// The oracle's whole list the finding belongs to (empty for the
    /// counts, statuses and verdict).
    oracle_list: Arc<[Json]>,
}

/// The findings of one list that differ: unmatched on either side, paired
/// by `code`, file and field where they can be.
fn list_differences(
    case: &str,
    list: &str,
    oracle: &[Json],
    rust: &[Json],
    out: &mut Vec<Difference>,
) {
    let whole: Arc<[Json]> = oracle.into();
    let mut unmatched_rust: Vec<Option<&Json>> = rust.iter().map(Some).collect();
    let mut unmatched_oracle = Vec::new();
    for item in oracle {
        match unmatched_rust
            .iter()
            .position(|candidate| *candidate == Some(item))
        {
            Some(index) => unmatched_rust[index] = None,
            None => unmatched_oracle.push(item),
        }
    }
    let mut leftover: Vec<&Json> = unmatched_rust.into_iter().flatten().collect();
    let key = |item: &Json| {
        (
            item["code"].clone(),
            item["file_path"].clone(),
            item["field_path"].clone(),
        )
    };
    for item in unmatched_oracle {
        let paired = leftover
            .iter()
            .position(|candidate| key(candidate) == key(item));
        let rust = paired.map(|index| leftover.remove(index).clone());
        out.push(Difference {
            case: case.to_owned(),
            what: list.to_owned(),
            oracle: Some(item.clone()),
            rust,
            oracle_list: whole.clone(),
        });
    }
    for item in leftover {
        out.push(Difference {
            case: case.to_owned(),
            what: list.to_owned(),
            oracle: None,
            rust: Some(item.clone()),
            oracle_list: whole.clone(),
        });
    }
    if out.iter().all(|d| d.case != case || d.what != list) {
        let same_order = oracle.iter().zip(rust).all(|(a, b)| a == b);
        if !same_order {
            out.push(Difference {
                case: case.to_owned(),
                what: format!("{list} (order)"),
                oracle: Some(Json::Array(oracle.to_vec())),
                rust: Some(Json::Array(rust.to_vec())),
                oracle_list: whole.clone(),
            });
        }
    }
}

fn summary_of(issues: &[Json], warnings: &[Json]) -> Json {
    let files = |items: &[Json]| {
        items
            .iter()
            .filter_map(|item| item["path"].as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    };
    let fixable = issues
        .iter()
        .chain(warnings)
        .filter(|item| item.pointer("/fix/safe") == Some(&Json::Bool(true)))
        .count();
    json!({
        "errors": issues.len(),
        "warnings": warnings.len(),
        "files": files(issues),
        "warning_files": files(warnings),
        "fixable": fixable,
    })
}

/// The CVE lookup of a `--check cve` case (UC-4.4, #834): the command
/// line's, with the `[cve]` settings of the case's workspace, in the case's
/// own recorded environment and never this process's. The recordings send
/// every request to a proxy that refuses it (`127.0.0.1:9`), so the lookup
/// fails as the oracle's failed, with no network reached.
fn online_cve(
    case: &Case,
    args: &Args,
    workspace: &Workspace,
) -> Option<opentide_cli::commands::cve::OnlineCve> {
    use opentide_cli::commands::cve::{OnlineCve, Settings};
    (args.check == Some(Check::Cve)).then(|| {
        let settings =
            Settings::from_documentation(workspace.configuration().resolved.get("documentation"));
        let env = opentide_cli::env::Env::from_pairs(
            case.env
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        OnlineCve::new(&settings, &env, None, env!("CARGO_PKG_VERSION"))
    })
}

/// Runs one case; its differences.
fn run_case(
    case: &Case,
    ws: &Path,
    recorded: &Json,
    recording_files: &Json,
) -> Result<Vec<Difference>> {
    let Some(args) = parse_args(&case.argv) else {
        return Ok(Vec::new());
    };
    let cwd = ws.join(&case.cwd);
    let workspace = Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options {
            roots: RootOptions {
                repo: None,
                repo_root_env: None,
                tide_workspace_env: None,
                cwd,
            },
        },
    );
    let mut out = Vec::new();
    let Some(oracle_report) = recorded.get("report") else {
        // The run stopped before validating (a configuration file that does
        // not resolve, no workspace): the CLI's failure, UC-3.5's.
        if workspace.is_ok() {
            out.push(Difference {
                case: case.id.clone(),
                what: "report".to_owned(),
                oracle: None,
                rust: Some(json!("a report")),
                oracle_list: Arc::from(Vec::new()),
            });
        }
        return Ok(out);
    };
    let mut workspace = workspace.map_err(|error| anyhow::anyhow!("{}: open: {error}", case.id))?;
    let counting = crate::corpus::queries::CountingQueries::default();
    let cve = online_cve(case, &args, &workspace);
    let options = Options {
        check: args.check,
        selection: Some(&args.selection),
        strict: args.strict,
        queries: args.queries,
        query_check: Some(&counting),
        cve_check: cve
            .as_ref()
            .map(|cve| cve as &dyn opentide_workspace::validate::CveCheck),
    };
    let validation = match args.fix {
        None => workspace.validate(&options),
        Some(dry_run) => {
            let before = Snapshot::take(ws)?;
            let run = workspace
                .validate_fix(&OsFs, &options, dry_run)
                .map_err(|error| anyhow::anyhow!("{}: reload: {error}", case.id))?;
            let after = Snapshot::take(ws)?;
            compare_fix(
                case,
                recorded,
                recording_files,
                &run,
                dry_run,
                &before,
                &after,
                &mut out,
            )?;
            run.validation
        }
    };
    let root = ws.to_string_lossy().into_owned();
    let text = crate::payloads::placeholder(&serde_json::to_string(&validation.report)?, ws);
    let rust: Json = serde_json::from_str(&text)?;
    let list = |report: &Json, key: &str| -> Vec<Json> {
        report[key].as_array().cloned().unwrap_or_default()
    };
    let oracle_issues = list(oracle_report, "issues");
    let oracle_warnings = list(oracle_report, "warnings");
    let rust_issues = list(&rust, "issues");
    let rust_warnings = list(&rust, "warnings");
    list_differences(&case.id, "issues", &oracle_issues, &rust_issues, &mut out);
    list_differences(
        &case.id,
        "warnings",
        &oracle_warnings,
        &rust_warnings,
        &mut out,
    );
    let mut scalar = |what: &str, oracle: Json, rust: Json| {
        if oracle != rust {
            out.push(Difference {
                case: case.id.clone(),
                what: what.to_owned(),
                oracle: Some(oracle),
                rust: Some(rust),
                oracle_list: Arc::from(Vec::new()),
            });
        }
    };
    scalar(
        "stats.objects_checked",
        oracle_report["stats"]["objects_checked"].clone(),
        rust["stats"]["objects_checked"].clone(),
    );
    let oracle_queries = &oracle_report["stats"]["queries_checked"];
    let rust_queries = &rust["stats"]["queries_checked"];
    if oracle_queries != rust_queries {
        // Files the oracle could not read (YAML 1.1) and the Rust run read.
        let unread = |report: &Json| -> std::collections::BTreeSet<PathBuf> {
            report["issues"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|issue| code(issue) == "yaml_parse")
                .filter_map(|issue| issue["file_path"].as_str())
                .map(|file| PathBuf::from(file.replace("<WS>", &root)))
                .collect()
        };
        let read_here: std::collections::BTreeSet<PathBuf> = unread(oracle_report)
            .difference(&unread(&rust))
            .cloned()
            .collect();
        let (oracle, rust) = queries_checked(
            oracle_queries,
            rust_queries,
            counting.crowdstrike(),
            counting.others_in(&read_here),
        );
        scalar(QUERIES_CHECKED, oracle, rust);
    }
    scalar(
        "summary",
        summary_of(&oracle_issues, &oracle_warnings),
        serde_json::to_value(validation.summary).map(|summary| {
            json!({
                "errors": summary["errors"], "warnings": summary["warnings"],
                "files": summary["files"], "warning_files": summary["warning_files"],
                "fixable": summary["fixable"],
            })
        })?,
    );
    let own = summary_of(&rust_issues, &rust_warnings);
    let reported = serde_json::to_value(validation.summary)?;
    for key in ["errors", "warnings", "files", "warning_files", "fixable"] {
        if own[key] != reported[key] {
            scalar("summary (self)", own.clone(), reported.clone());
            break;
        }
    }
    scalar(
        "summary.objects",
        recorded["summary"]["objects"].clone(),
        json!(validation.summary.objects),
    );
    let mut oracle_checks = BTreeMap::new();
    if let Some(checks) = recorded["checks"].as_object() {
        for (name, check) in checks {
            oracle_checks.insert(name.clone(), check["status"].clone());
        }
    }
    let rust_checks: BTreeMap<String, Json> = validation
        .checks
        .iter()
        .map(|(check, status)| (check.name().to_owned(), json!(status)))
        .collect();
    scalar("checks", json!(oracle_checks), json!(rust_checks));
    let oracle_failed = !oracle_issues.is_empty()
        || (args.strict
            && oracle_warnings
                .iter()
                .any(|w| w["code"] != "platform_not_enabled"));
    scalar("failed", json!(oracle_failed), json!(validation.failed));
    Ok(out)
}

/// A recorded case: its case, its JSON, and the files it changed.
type RecordedCase = (Case, Json, Json);

fn recorded_cases(repo: &Path) -> Result<Vec<RecordedCase>> {
    let root = repo.join("tests/golden/cases/validate/json");
    let blobs = repo.join("tests/golden/blobs");
    let mut cases = Vec::new();
    for fixture in std::fs::read_dir(&root).with_context(|| format!("read {}", root.display()))? {
        let fixture = fixture?.path();
        for variant in std::fs::read_dir(&fixture)? {
            let dir = variant?.path();
            let case = Case::parse(&std::fs::read_to_string(dir.join("case.toml"))?)?;
            if parse_args(&case.argv).is_none() {
                continue;
            }
            let recording = Recording::read(&dir, &blobs)?;
            let recorded: Json = serde_json::from_slice(&recording.stdout)
                .with_context(|| format!("{}: stdout is not JSON", case.id))?;
            let files = files_of(&recording);
            cases.push((case, recorded, files));
        }
    }
    cases.sort_by(|a, b| a.0.id.cmp(&b.0.id));
    Ok(cases)
}

/// A recording's changes under the workspace: path, change and bytes.
pub(crate) fn files_of(recording: &Recording) -> Json {
    let mut out = BTreeMap::new();
    for file in &recording.files {
        let Some(path) = file.path.strip_prefix("ws/") else {
            continue;
        };
        let bytes = file
            .contents
            .as_ref()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        out.insert(
            path.to_owned(),
            json!({"change": change_name(file.change), "bytes": bytes}),
        );
    }
    json!(out)
}

fn change_name(change: ChangeKind) -> &'static str {
    match change {
        ChangeKind::Created => "created",
        ChangeKind::Modified => "modified",
        ChangeKind::Deleted => "deleted",
    }
}

/// What a run changed under the workspace, as [`files_of`] writes it.
pub(crate) fn files_changed(before: &Snapshot, after: &Snapshot) -> Json {
    let mut out = BTreeMap::new();
    for change in before.changes(after) {
        let bytes = (change.change != ChangeKind::Deleted)
            .then(|| String::from_utf8_lossy(&change.entry.bytes).into_owned());
        out.insert(
            change.path,
            json!({"change": change_name(change.change), "bytes": bytes}),
        );
    }
    json!(out)
}

/// `fixed` or `would_fix`, `diff`, `summary.fixed`, `summary.fixable` and the
/// files written, against the recording.
#[expect(clippy::too_many_arguments, reason = "one case's whole state")]
fn compare_fix(
    case: &Case,
    recorded: &Json,
    recording_files: &Json,
    run: &FixRun,
    dry_run: bool,
    before: &Snapshot,
    after: &Snapshot,
    out: &mut Vec<Difference>,
) -> Result<()> {
    let mut scalar = |what: &str, oracle: Json, rust: Json| {
        if oracle != rust {
            out.push(Difference {
                case: case.id.clone(),
                what: what.to_owned(),
                oracle: Some(oracle),
                rust: Some(rust),
                oracle_list: Arc::from(Vec::new()),
            });
        }
    };
    let key = if dry_run { "would_fix" } else { "fixed" };
    scalar(
        key,
        recorded[key].clone(),
        serde_json::to_value(&run.changes)?,
    );
    if dry_run {
        scalar("diff", recorded["diff"].clone(), json!(run.diff));
    } else {
        scalar(
            "summary.fixed",
            recorded["summary"]["fixed"].clone(),
            json!(run.changes.len()),
        );
    }
    scalar(
        "summary.fixable",
        recorded["summary"]["fixable"].clone(),
        json!(run.validation.summary.fixable),
    );
    scalar("unwritten", json!([]), json!(run.unwritten));
    scalar(
        "files",
        recording_files.clone(),
        files_changed(before, after),
    );
    Ok(())
}

fn show(value: Option<&Json>) -> String {
    value.map_or_else(
        || "(absent)".to_owned(),
        |value| serde_json::to_string(value).unwrap_or_default(),
    )
}

/// `cargo xtask validate diff`.
///
/// # Errors
///
/// A recording or the fixtures cannot be read.
pub fn run(args: &[String]) -> Result<u8> {
    let mut filter = None;
    let mut keep = None;
    let mut show_approved = false;
    let mut rest = args.iter();
    match rest.next().map(String::as_str) {
        Some("diff") => {}
        Some("help" | "--help") | None => {
            print!("{USAGE}");
            return Ok(0);
        }
        Some(other) => bail!("unknown subcommand `{other}`\n{USAGE}"),
    }
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--filter" => filter = Some(rest.next().context("--filter needs a glob")?.clone()),
            "--keep" => keep = Some(PathBuf::from(rest.next().context("--keep needs a dir")?)),
            "--show-approved" => show_approved = true,
            other => bail!("unknown option `{other}`\n{USAGE}"),
        }
    }
    let repo = repo_root();
    let spec = Spec::parse(&std::fs::read_to_string(
        repo.join("tests/golden/cases.toml"),
    )?)?;
    let pattern = filter
        .as_deref()
        .map(glob::Pattern::new)
        .transpose()
        .context("--filter")?;
    let cases: Vec<RecordedCase> = recorded_cases(&repo)?
        .into_iter()
        .filter(|(case, _, _)| pattern.as_ref().is_none_or(|p| p.matches(&case.id)))
        .collect();
    if cases.is_empty() {
        bail!("no recorded validate case matches");
    }
    let scratch = Scratch {
        path: keep.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("xtask-validate-{}", std::process::id()))
        }),
        keep: keep.is_some(),
    };
    std::fs::create_dir_all(&scratch.path)?;
    let mut laid_out: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut differences = Vec::new();
    for (number, (case, recorded, files)) in cases.iter().enumerate() {
        let ws = match laid_out.get(&case.fixture) {
            Some(ws) => ws.clone(),
            None => {
                let fixture = spec
                    .fixtures
                    .get(&case.fixture)
                    .with_context(|| format!("no fixture `{}`", case.fixture))?;
                let ws = scratch.path.join(&case.fixture).join("ws");
                std::fs::create_dir_all(&ws)?;
                fixture
                    .materialise(&repo, &ws)
                    .with_context(|| format!("lay out {}", case.fixture))?;
                let ws = dunce::canonicalize(&ws)?;
                laid_out.insert(case.fixture.clone(), ws.clone());
                ws
            }
        };
        // `--fix` writes: each such case on its own copy.
        let ws = if parse_args(&case.argv).is_some_and(|args| args.fix.is_some()) {
            let copy = scratch.path.join("fix").join(number.to_string()).join("ws");
            crate::golden::fixture::copy_tree(&ws, &copy)?;
            crate::golden::fixture::fix_modes(&copy)?;
            dunce::canonicalize(&copy)?
        } else {
            ws
        };
        differences.extend(run_case(case, &ws, recorded, files)?);
    }
    let mut used = vec![0usize; APPROVED.len()];
    let mut failures = 0;
    let is_list =
        |difference: &Difference| difference.what == "issues" || difference.what == "warnings";
    let rule_of = |difference: &Difference| {
        APPROVED.iter().position(|rule| {
            (rule.applies)(
                difference.oracle.as_ref(),
                difference.rust.as_ref(),
                &difference.oracle_list,
            )
        })
    };
    // A case whose differing findings are all approved: its counts and
    // verdict follow from them.
    let mut explained_cases: BTreeMap<&str, bool> = BTreeMap::new();
    for difference in differences.iter().filter(|d| is_list(d)) {
        let explained = rule_of(difference).is_some();
        *explained_cases
            .entry(difference.case.as_str())
            .or_insert(true) &= explained;
    }
    for difference in &differences {
        let rule = if is_list(difference) || difference.what == QUERIES_CHECKED {
            rule_of(difference)
        } else {
            None
        };
        // What --fix wrote, and the fixes it reports, never follow from an
        // approved finding: they are compared as they are.
        let derived = !is_list(difference)
            && !FIX_PARTS.contains(&difference.what.as_str())
            && difference.what != QUERIES_CHECKED
            && explained_cases.get(difference.case.as_str()) == Some(&true);
        if derived || rule.is_some() {
            let id = rule.map_or("derived", |index| {
                used[index] += 1;
                APPROVED[index].id
            });
            if !show_approved {
                continue;
            }
            println!("approved ({id}): {} {}", difference.case, difference.what);
        } else {
            failures += 1;
            println!("DIFF {} {}", difference.case, difference.what);
        }
        println!("  oracle: {}", show(difference.oracle.as_ref()));
        println!("  rust:   {}", show(difference.rust.as_ref()));
    }
    let complete = filter.is_none();
    let mut stale = 0;
    for (rule, count) in APPROVED.iter().zip(&used) {
        println!("{:>5}  {}  ({})", count, rule.id, rule.changelog);
        if complete && *count == 0 {
            println!(
                "       stale: the rule explains no difference ({})",
                rule.reason
            );
            stale += 1;
        }
    }
    println!(
        "{} cases, {} differences, {} unexplained, {} stale rules",
        cases.len(),
        differences.len(),
        failures,
        stale
    );
    Ok(u8::from(failures > 0 || stale > 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        ["opentide", "--json", "validate"]
            .iter()
            .chain(args)
            .map(|s| (*s).to_owned())
            .collect()
    }

    #[test]
    fn only_checking_cases_are_run() {
        let args = parse_args(&argv(&["--check", "schema", "--uuid", "u", "--strict"])).unwrap();
        assert_eq!(args.check, Some(Check::Schema));
        assert_eq!(args.selection.uuids, vec!["u".to_owned()]);
        assert!(args.strict);
        assert_eq!(parse_args(&argv(&["--fix"])).unwrap().fix, Some(false));
        assert_eq!(
            parse_args(&argv(&["--fix", "--dry-run"])).unwrap().fix,
            Some(true)
        );
        assert!(parse_args(&argv(&["--dry-run"])).is_none());
        assert!(parse_args(&argv(&["--format", "sarif"])).is_none());
        assert!(parse_args(&argv(&["--check", "nope"])).is_none());
    }

    #[test]
    fn a_moved_finding_is_one_difference_and_order_counts() {
        let a = json!({"code": "x", "file_path": "f", "field_path": [], "line": 1});
        let b = json!({"code": "x", "file_path": "f", "field_path": [], "line": 2});
        let c = json!({"code": "y", "file_path": "f", "field_path": [], "line": 2});
        let mut out = Vec::new();
        list_differences(
            "k",
            "issues",
            std::slice::from_ref(&a),
            std::slice::from_ref(&b),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].oracle, Some(a.clone()));
        assert_eq!(out[0].rust, Some(b));
        out.clear();
        list_differences("k", "issues", &[a.clone(), c.clone()], &[c, a], &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].what, "issues (order)");
    }

    fn uuid_finding(file: &str, value: &str) -> Json {
        json!({
            "code": "invalid_uuid",
            "file_path": file,
            "field_path": ["metadata", "uuid"],
            "object_uuid": value,
            "message": format!("UUID '{value}' is not a valid UUIDv4"),
        })
    }

    #[test]
    fn only_a_shared_invalid_uuid_the_oracle_reported_elsewhere_is_approved() {
        let kept = uuid_finding("a.yaml", "not-a-uuid");
        let displaced = uuid_finding("b.yaml", "not-a-uuid");
        let oracle = [kept.clone()];
        assert!(invalid_uuid_every_file(None, Some(&displaced), &oracle));
        // A spurious invalid_uuid: no file's value is reported by the oracle.
        let spurious = uuid_finding("c.yaml", "7b8864a9-890e-4e58-8a56-ae78cd82796b");
        assert!(!invalid_uuid_every_file(None, Some(&spurious), &oracle));
        assert!(!invalid_uuid_every_file(None, Some(&spurious), &[]));
        // The oracle's finding on the same file is not another file's.
        assert!(!invalid_uuid_every_file(None, Some(&kept), &oracle));
        // Other words for the same value are not the oracle's.
        let mut reworded = displaced.clone();
        reworded["message"] = json!("UUID 'not-a-uuid' is bad");
        assert!(!invalid_uuid_every_file(None, Some(&reworded), &oracle));
        // A finding the oracle has too is a different rule's business.
        assert!(!invalid_uuid_every_file(
            Some(&kept),
            Some(&displaced),
            &oracle
        ));
        let spurious_case = Difference {
            case: "k".to_owned(),
            what: "issues".to_owned(),
            oracle: None,
            rust: Some(spurious),
            oracle_list: Arc::from(oracle.to_vec()),
        };
        assert!(APPROVED.iter().all(|rule| !(rule.applies)(
            spurious_case.oracle.as_ref(),
            spurious_case.rust.as_ref(),
            &spurious_case.oracle_list,
        )));
    }

    fn vocab_finding(suggestion: Option<&str>) -> Json {
        json!({
            "code": "invalid_ref",
            "file_path": "a.yaml",
            "field_path": ["threat", "actors"],
            "message": "unknown",
            "suggestion": suggestion,
            "help": suggestion.map(|s| format!("did you mean '{s}'?")),
            "fix": suggestion.map(|s| json!({"edits": [{"replacement": s}], "safe": false})),
        })
    }

    #[test]
    fn only_a_lost_suggestion_is_approved() {
        let oracle = vocab_finding(Some("Host::File"));
        assert!(suggestions(Some(&oracle), Some(&vocab_finding(None)), &[]));
        // A different suggestion (another object's UUID) needs review.
        let other = vocab_finding(Some("e305cca1-c265-4ae9-a34e-2ffaee82a359"));
        assert!(!suggestions(Some(&oracle), Some(&other), &[]));
        // A help or fix left without a suggestion is not a lost suggestion.
        let mut stray = vocab_finding(None);
        stray["help"] = json!("did you mean 'Host::Gizmo'?");
        assert!(!suggestions(Some(&oracle), Some(&stray), &[]));
        let mut stray = vocab_finding(None);
        stray["fix"] = json!({"edits": [], "safe": false});
        assert!(!suggestions(Some(&oracle), Some(&stray), &[]));
    }

    fn yaml_finding(column: u64, message: &str) -> Json {
        json!({
            "code": "yaml_parse",
            "file_path": "a.yaml",
            "line": 68,
            "column": column,
            "end_column": column + 1,
            "message": format!("Could not parse object YAML: {message}"),
        })
    }

    #[test]
    fn a_yaml_error_keeps_its_column_but_for_a_tab() {
        let oracle = yaml_finding(1, "found character that cannot start any token");
        let same = yaml_finding(1, "while parsing a flow sequence, expected ',' or ']'");
        assert!(yaml_error_text(Some(&oracle), Some(&same), &[]));
        let tab = yaml_finding(2, "tabs disallowed within this context (block indentation)");
        assert!(yaml_error_text(Some(&oracle), Some(&tab), &[]));
        // One column later without a tab, or anywhere else on the line: no.
        let later = yaml_finding(2, "while parsing a flow sequence, expected ',' or ']'");
        assert!(!yaml_error_text(Some(&oracle), Some(&later), &[]));
        let far = yaml_finding(9, "tabs disallowed within this context (block indentation)");
        assert!(!yaml_error_text(Some(&oracle), Some(&far), &[]));
        let earlier = yaml_finding(1, "tab");
        assert!(!yaml_error_text(
            Some(&yaml_finding(2, "x")),
            Some(&earlier),
            &[]
        ));
    }

    /// `id`'s recorded case and a fresh copy of its fixture, as `run` lays a
    /// `--fix` case out.
    fn laid_out(id: &str, dir: &Path) -> (RecordedCase, PathBuf) {
        let repo = repo_root();
        let spec =
            Spec::parse(&std::fs::read_to_string(repo.join("tests/golden/cases.toml")).unwrap())
                .unwrap();
        let recorded = recorded_cases(&repo)
            .unwrap()
            .into_iter()
            .find(|(case, _, _)| case.id == id)
            .unwrap_or_else(|| panic!("no recorded case {id}"));
        let ws = dir.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        spec.fixtures[&recorded.0.fixture]
            .materialise(&repo, &ws)
            .unwrap();
        crate::golden::fixture::fix_modes(&ws).unwrap();
        (recorded, dunce::canonicalize(&ws).unwrap())
    }

    fn parts(differences: &[Difference]) -> std::collections::BTreeSet<&str> {
        differences.iter().map(|d| d.what.as_str()).collect()
    }

    #[test]
    fn a_fix_that_differs_from_its_recording_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let ((case, recorded, files), ws) =
            laid_out("validate/json/tide-corpus-typo/fix-typo", dir.path());
        assert_eq!(recorded["fixed"][0]["after"], json!("High"));
        // As recorded: the fix, the summary and the file written agree.
        let clean = run_case(&case, &ws, &recorded, &files).unwrap();
        assert!(
            parts(&clean).iter().all(|part| !FIX_PARTS.contains(part)),
            "{clean:?}"
        );
        let written =
            std::fs::read_to_string(ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml"))
                .unwrap();
        assert!(written.contains("severity: High\n"), "{written}");
        // Another fix, count and file on a fresh copy: each is reported.
        let ((case, mut recorded, _), ws) = laid_out(
            "validate/json/tide-corpus-typo/fix-typo",
            &dir.path().join("doctored"),
        );
        recorded["fixed"][0]["after"] = json!("Low");
        recorded["summary"]["fixed"] = json!(2);
        recorded["summary"]["fixable"] = json!(5);
        let differences = run_case(&case, &ws, &recorded, &json!({})).unwrap();
        let found = parts(&differences);
        for part in ["fixed", "summary.fixed", "summary.fixable", "files"] {
            assert!(found.contains(part), "{part} not reported: {found:?}");
        }
        assert!(!found.contains("diff") && !found.contains("would_fix"));
        let files = differences.iter().find(|d| d.what == "files").unwrap();
        assert_eq!(
            files.rust.as_ref().unwrap()["Objects/Detection Rules/rule-0001-sentinel-kql.yaml"]["change"],
            json!("modified")
        );
    }

    #[test]
    fn a_dry_run_writes_nothing_and_its_diff_is_compared() {
        let dir = tempfile::tempdir().unwrap();
        let ((case, mut recorded, files), ws) = laid_out(
            "validate/json/tide-corpus-typo/fix-typo-dry-run",
            dir.path(),
        );
        assert_eq!(files, json!({}));
        let clean = run_case(&case, &ws, &recorded, &files).unwrap();
        assert!(
            parts(&clean).iter().all(|part| !FIX_PARTS.contains(part)),
            "{clean:?}"
        );
        recorded["diff"] = json!("");
        recorded["would_fix"] = json!([]);
        let found_owned = run_case(&case, &ws, &recorded, &files).unwrap();
        let found = parts(&found_owned);
        assert!(
            found.contains("diff") && found.contains("would_fix"),
            "{found:?}"
        );
        assert!(
            !found.contains("files") && !found.contains("fixed"),
            "{found:?}"
        );
    }

    #[test]
    fn the_fix_cases_agree_with_their_recordings() {
        let args = ["diff", "--filter", "validate/json/*/fix*"].map(str::to_owned);
        assert_eq!(run(&args).unwrap(), 0);
    }
}
