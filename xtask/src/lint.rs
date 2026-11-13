//! `cargo xtask lint diff` (UC-2.3, #818): `opentide-workspace`'s `lint`
//! against the oracle's recordings of `opentide --json lint`
//! (`tests/golden/cases/lint/json/`), fixture by fixture and option by
//! option.
//!
//! Each recorded case whose arguments are `lint`'s check, scope and fix
//! options (`--check`, `--file`, `--changed`, `--strict`, `--fix`) is run
//! again on a fresh copy of its fixture, laid out as the goldens lay it out.
//! Compared with the recording: every finding (each key, value and the keys'
//! order), `checks`, `count`, `fixed`, `scope`, `unmatched`, the status, the
//! message, the exit code, the `summary`, the `next_actions` (the command as
//! a person types it: the recording's `--json` is the mode's), and every
//! file the run created, changed or deleted, with its bytes.
//!
//! The queries check is UC-2.5's (#820): the oracle's `queries` findings are
//! left out, and the counts, status and message are recomputed without them.
//! Any other difference fails the run unless an approved rule ([`APPROVED`])
//! explains it; a rule that explains nothing on a complete run is stale and
//! fails it too.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use serde_json::{Value as Json, json};

use crate::corpus::cli::{Scratch, repo_root};
use crate::golden::case::Spec;
use crate::golden::recording::Recording;
use crate::golden::snapshot::Snapshot;
use opentide_workspace::lint::{Changed, LintCheck, LintOptions, LintReport};
use opentide_workspace::{FileSystem as _, OsFs, RootOptions, Workspace};

/// The usage of `cargo xtask lint`.
pub const USAGE: &str = "\
usage: cargo xtask lint diff [--filter GLOB] [--keep DIR] [--show-approved]

  run opentide-workspace's lint on every recorded `lint --json` case
  (no --format) and compare its findings, counts, verdict, next steps
  and the files it renamed with the oracle's recording. GLOB filters the
  case ids (lint/json/<fixture>/<variant>). --show-approved prints each
  approved difference too.
";

/// An approved class of difference.
pub struct Approved {
    /// The rule's id.
    pub id: &'static str,
    /// Why the Rust result is right.
    pub reason: &'static str,
    /// The bold lead of its CHANGELOG.md entry.
    pub changelog: &'static str,
    /// Whether it explains this finding of the oracle and of the Rust run
    /// (either may be absent); the last argument is the oracle's whole list.
    pub applies: fn(oracle: Option<&Json>, rust: Option<&Json>, oracle_list: &[Json]) -> bool,
}

/// The approved differences. A count, verdict or next step that differs is
/// approved as derived when every finding that differs in its case is.
pub const APPROVED: &[Approved] = &[
    Approved {
        id: "yaml-error-text",
        reason: "a file that is not YAML is reported in the words of the YAML 1.2 parser \
                 (saphyr), at the line and column the oracle names (one column later where \
                 saphyr names the tab it refuses); the code, the file and the check are the \
                 same (as in `cargo xtask validate diff`)",
        changelog: "**Tide objects are read as YAML 1.2**",
        applies: yaml_error_text,
    },
    Approved {
        id: "yaml-1-2-dates",
        reason: "an unquoted impossible date (`reviewed: 2026-02-30`) no longer stops the file \
                 from loading: lint reads it like any other file (its date is validate's \
                 `schema_validation`), where the oracle reported `yaml_parse`; the findings \
                 lint then makes on that file are approved with it",
        changelog: "**Tide objects are read as YAML 1.2**",
        applies: yaml_1_2_dates,
    },
    Approved {
        id: "messages-quote-values",
        reason: "a message and its help quote a value in double quotes with Rust's escapes, \
                 where the oracle used Python's repr ('x', None, True): the finding is the \
                 same but for the quote characters around its values",
        changelog: "**Messages quote values the same way everywhere**",
        applies: quoting_only,
    },
];

/// `text` without quote characters and backslashes.
fn unquoted(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect()
}

/// A JSON value with every string [`unquoted`].
pub fn unquoted_json(value: &Json) -> Json {
    match value {
        Json::String(text) => Json::String(unquoted(text)),
        Json::Array(items) => Json::Array(items.iter().map(unquoted_json).collect()),
        Json::Object(map) => Json::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), unquoted_json(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `messages-quote-values`: the two findings differ only in the quote
/// characters of their strings.
pub fn quoting_only(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    oracle != rust && unquoted_json(oracle) == unquoted_json(rust)
}

fn code(finding: &Json) -> &str {
    finding["code"].as_str().unwrap_or("")
}

fn without(finding: &Json, drop: &[&str]) -> Json {
    let mut copy = finding.clone();
    if let Some(map) = copy.as_object_mut() {
        for key in drop {
            map.remove(*key);
        }
    }
    copy
}

fn yaml_error_text(oracle: Option<&Json>, rust: Option<&Json>, _: &[Json]) -> bool {
    let (Some(oracle), Some(rust)) = (oracle, rust) else {
        return false;
    };
    let message = rust["message"].as_str().unwrap_or("");
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

fn is_invalid_date(finding: &Json) -> bool {
    code(finding) == "yaml_parse"
        && finding["message"]
            .as_str()
            .is_some_and(|m| m.contains("is not a valid date"))
}

fn yaml_1_2_dates(oracle: Option<&Json>, rust: Option<&Json>, oracle_list: &[Json]) -> bool {
    match (oracle, rust) {
        (Some(oracle), None) => is_invalid_date(oracle),
        // A finding on a file the oracle could not read for its date.
        (None, Some(rust)) => oracle_list
            .iter()
            .any(|item| is_invalid_date(item) && item["path"] == rust["path"]),
        _ => false,
    }
}

/// The arguments of a recorded case.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    checks: Vec<LintCheck>,
    fix: bool,
    strict: bool,
    files: Vec<String>,
    changed: bool,
}

fn parse_args(argv: &[String]) -> Option<Args> {
    let mut rest = argv.iter().skip_while(|arg| *arg != "lint").skip(1);
    let mut parsed = Args::default();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--strict" => parsed.strict = true,
            "--fix" => parsed.fix = true,
            "--changed" => parsed.changed = true,
            // Another check name is the command line's usage error (UC-3.5).
            "--check" => parsed.checks.push(LintCheck::parse(rest.next()?)?),
            "--file" => parsed.files.push(rest.next()?.clone()),
            _ => return None,
        }
    }
    Some(parsed)
}

/// One difference.
#[derive(Debug)]
struct Difference {
    case: String,
    what: String,
    oracle: Option<Json>,
    rust: Option<Json>,
    oracle_list: Arc<[Json]>,
}

/// A finding: its JSON text (keys in order) and its value.
#[derive(Debug, Clone)]
struct Item {
    text: String,
    value: Json,
}

impl Item {
    fn new(map: &IndexMap<String, Json>) -> Self {
        Self {
            text: serde_json::to_string(map).unwrap_or_default(),
            value: serde_json::to_value(map).unwrap_or(Json::Null),
        }
    }
}

fn list_differences(case: &str, oracle: &[Item], rust: &[Item], out: &mut Vec<Difference>) {
    let whole: Arc<[Json]> = oracle.iter().map(|item| item.value.clone()).collect();
    let mut leftover: Vec<Option<&Item>> = rust.iter().map(Some).collect();
    let mut missing = Vec::new();
    for item in oracle {
        match leftover
            .iter()
            .position(|candidate| candidate.is_some_and(|c| c.text == item.text))
        {
            Some(index) => leftover[index] = None,
            None => missing.push(item),
        }
    }
    let mut leftover: Vec<&Item> = leftover.into_iter().flatten().collect();
    let key = |value: &Json| (value["code"].clone(), value["path"].clone());
    let before = out.len();
    for item in missing {
        let paired = leftover
            .iter()
            .position(|candidate| key(&candidate.value) == key(&item.value));
        let rust = paired.map(|index| leftover.remove(index).value.clone());
        out.push(Difference {
            case: case.to_owned(),
            what: "findings".to_owned(),
            oracle: Some(item.value.clone()),
            rust,
            oracle_list: whole.clone(),
        });
    }
    for item in leftover {
        out.push(Difference {
            case: case.to_owned(),
            what: "findings".to_owned(),
            oracle: None,
            rust: Some(item.value.clone()),
            oracle_list: whole.clone(),
        });
    }
    if out.len() == before && oracle.iter().zip(rust).any(|(a, b)| a.text != b.text) {
        out.push(Difference {
            case: case.to_owned(),
            what: "findings (order)".to_owned(),
            oracle: Some(Json::Array(
                oracle.iter().map(|i| i.value.clone()).collect(),
            )),
            rust: Some(Json::Array(rust.iter().map(|i| i.value.clone()).collect())),
            oracle_list: whole.clone(),
        });
    }
}

#[derive(serde::Deserialize)]
struct Recorded {
    #[serde(default)]
    checks: Vec<String>,
    #[serde(default)]
    findings: Vec<IndexMap<String, Json>>,
    #[serde(default)]
    fixed: usize,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    unmatched: Vec<String>,
    status: String,
    message: String,
    exit_code: i32,
    #[serde(default)]
    summary: Json,
    #[serde(default)]
    next_actions: Vec<Json>,
}

/// The status, message, exit code and summary the oracle's findings give
/// without its queries findings (`run_lint`'s verdict).
fn verdict(findings: &[Json], strict: bool, files: &Json) -> (String, String, i32, Json) {
    let left: Vec<&Json> = findings
        .iter()
        .filter(|f| f.get("fixed") != Some(&Json::Bool(true)))
        .collect();
    let status = if !left.is_empty() && strict {
        "failed"
    } else if !left.is_empty() {
        "issues"
    } else {
        "completed"
    };
    let message = if findings.is_empty() {
        "Catalogue lint passed"
    } else {
        "Catalogue lint found issues"
    };
    let count = |severity: &str| left.iter().filter(|f| f["severity"] == severity).count();
    let fixed = findings.len() - left.len();
    let summary = json!({
        "files": files,
        "findings": left.len(),
        "errors": count("error"),
        "warnings": count("warning"),
        "notes": count("info"),
        "fixed": fixed,
    });
    (
        status.to_owned(),
        message.to_owned(),
        i32::from(status == "failed"),
        summary,
    )
}

/// The command as a person types it: the recording's `--json` is the mode's.
fn typed(command: &str) -> String {
    command.replacen("opentide --json ", "opentide ", 1)
}

fn changed_for(ws: &Path) -> Changed {
    // The host's `--changed`: the goldens' workspaces are not git checkouts.
    let fs = OsFs;
    match opentide_workspace::root::git_root(&fs, ws) {
        None => Changed::Failed(format!(
            "--changed needs a git checkout; no .git was found from {}",
            ws.display()
        )),
        Some(_) => Changed::Files {
            files: Vec::new(),
            warning: None,
        },
    }
}

/// `text`, a plain string, with the workspace `ws` written `<WS>` and the
/// path that follows it with `/`, on every host ([`crate::payloads::placeholder`]).
fn masked(text: &str, ws: &Path) -> String {
    masked_for(text, &ws.to_string_lossy(), cfg!(windows))
}

/// [`masked`] for a workspace spelled `ws`, with Windows' separator when
/// `windows`.
fn masked_for(text: &str, ws: &str, windows: bool) -> String {
    let quoted = serde_json::to_string(text).unwrap_or_default();
    serde_json::from_str(&crate::payloads::placeholder_for(&quoted, ws, windows))
        .unwrap_or_else(|_| text.to_owned())
}

/// Runs one case on `ws`, a fresh copy of its fixture.
fn run_case(recording: &Recording, ws: &Path) -> Result<Vec<Difference>> {
    let case = &recording.case;
    let Some(args) = parse_args(&case.argv) else {
        return Ok(Vec::new());
    };
    let recorded: Recorded = serde_json::from_slice(&recording.stdout)
        .with_context(|| format!("{}: stdout is not lint's JSON", case.id))?;
    let cwd = ws.join(&case.cwd);
    let before = Snapshot::take(ws)?;
    let workspace = Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options {
            roots: RootOptions {
                repo: None,
                repo_root_env: None,
                tide_workspace_env: None,
                cwd: cwd.clone(),
            },
        },
    )
    .map_err(|error| anyhow::anyhow!("{}: open: {error}", case.id))?;
    let options = LintOptions {
        checks: args.checks.clone(),
        fix: args.fix,
        strict: args.strict,
        files: args.files.clone(),
        changed: args.changed.then(|| changed_for(&OsFs.resolve(ws))),
        cwd,
        query_check: None,
    };
    let report: LintReport = workspace.lint(Some(&OsFs), &options);
    let after = Snapshot::take(ws)?;
    let mut out = Vec::new();
    let oracle: Vec<Item> = recorded
        .findings
        .iter()
        .filter(|finding| finding.get("check") != Some(&json!("queries")))
        .map(Item::new)
        .collect();
    let rust: Vec<Item> = report
        .findings
        .iter()
        .map(|finding| {
            let text = serde_json::to_string(&finding.json).unwrap_or_default();
            let map: IndexMap<String, Json> =
                serde_json::from_str(&crate::payloads::placeholder(&text, ws)).unwrap_or_default();
            Item::new(&map)
        })
        .collect();
    list_differences(&case.id, &oracle, &rust, &mut out);
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
    let payload = report.payload();
    scalar(
        "path",
        json!("<WS>"),
        json!(masked(payload["path"].as_str().unwrap_or(""), ws)),
    );
    scalar("checks", json!(recorded.checks), payload["checks"].clone());
    scalar("count", json!(oracle.len()), payload["count"].clone());
    scalar("fixed", json!(recorded.fixed), payload["fixed"].clone());
    scalar("scope", json!(recorded.scope), json!(report.scope));
    scalar(
        "unmatched",
        json!(recorded.unmatched),
        json!(report.unmatched),
    );
    let refused = recorded
        .summary
        .as_object()
        .is_none_or(serde_json::Map::is_empty);
    let oracle_values: Vec<Json> = oracle.iter().map(|item| item.value.clone()).collect();
    let (status, message, exit_code, summary) = if refused {
        (
            recorded.status.clone(),
            recorded.message.clone(),
            recorded.exit_code,
            Json::Null,
        )
    } else {
        verdict(&oracle_values, args.strict, &recorded.summary["files"])
    };
    let rust_status = match report.status {
        opentide_workspace::lint::LintStatus::Completed => "completed",
        opentide_workspace::lint::LintStatus::Issues => "issues",
        opentide_workspace::lint::LintStatus::Failed => "failed",
    };
    scalar("status", json!(status), json!(rust_status));
    scalar(
        "message",
        json!(message),
        json!(masked(&report.message, ws)),
    );
    scalar("exit_code", json!(exit_code), json!(report.exit_code));
    scalar(
        "summary",
        summary,
        report
            .summary
            .map_or(Json::Null, |s| serde_json::to_value(s).unwrap_or_default()),
    );
    let oracle_actions: Vec<Json> = recorded
        .next_actions
        .iter()
        .map(|action| {
            json!({
                "command": typed(action["command"].as_str().unwrap_or("")),
                "reason": action["reason"],
            })
        })
        .collect();
    scalar(
        "next_actions",
        json!(oracle_actions),
        serde_json::to_value(&report.next_actions)?,
    );
    scalar(
        "files",
        crate::validate::files_of(recording),
        crate::validate::files_changed(&before, &after),
    );
    Ok(out)
}

fn recorded_cases(repo: &Path) -> Result<Vec<Recording>> {
    let root = repo.join("tests/golden/cases/lint/json");
    let blobs = repo.join("tests/golden/blobs");
    let mut cases = Vec::new();
    for fixture in std::fs::read_dir(&root).with_context(|| format!("read {}", root.display()))? {
        for variant in std::fs::read_dir(fixture?.path())? {
            let recording = Recording::read(&variant?.path(), &blobs)?;
            if parse_args(&recording.case.argv).is_some() {
                cases.push(recording);
            }
        }
    }
    cases.sort_by(|a, b| a.case.id.cmp(&b.case.id));
    Ok(cases)
}

fn show(value: Option<&Json>) -> String {
    value.map_or_else(
        || "(absent)".to_owned(),
        |value| serde_json::to_string(value).unwrap_or_default(),
    )
}

/// `cargo xtask lint diff`.
///
/// # Errors
///
/// A recording or a fixture cannot be read or laid out.
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
    let cases: Vec<Recording> = recorded_cases(&repo)?
        .into_iter()
        .filter(|recording| {
            pattern
                .as_ref()
                .is_none_or(|p| p.matches(&recording.case.id))
        })
        .collect();
    if cases.is_empty() {
        bail!("no recorded lint case matches");
    }
    let scratch = Scratch {
        path: keep.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("xtask-lint-{}", std::process::id()))
        }),
        keep: keep.is_some(),
    };
    std::fs::create_dir_all(&scratch.path)?;
    let mut pristine: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut differences = Vec::new();
    for (number, recording) in cases.iter().enumerate() {
        let case = &recording.case;
        let source = match pristine.get(&case.fixture) {
            Some(dir) => dir.clone(),
            None => {
                let fixture = spec
                    .fixtures
                    .get(&case.fixture)
                    .with_context(|| format!("no fixture `{}`", case.fixture))?;
                let dir = scratch.path.join("fixtures").join(&case.fixture);
                std::fs::create_dir_all(&dir)?;
                fixture
                    .materialise(&repo, &dir)
                    .with_context(|| format!("lay out {}", case.fixture))?;
                pristine.insert(case.fixture.clone(), dir.clone());
                dir
            }
        };
        // Each case on its own copy: `--fix` renames files.
        let ws = scratch
            .path
            .join("cases")
            .join(number.to_string())
            .join("ws");
        crate::golden::fixture::copy_tree(&source, &ws)?;
        crate::golden::fixture::fix_modes(&ws)?;
        let ws = dunce::canonicalize(&ws)?;
        differences.extend(run_case(recording, &ws)?);
    }
    let mut used = vec![0usize; APPROVED.len()];
    let mut failures = 0;
    let is_list = |difference: &Difference| difference.what == "findings";
    let rule_of = |difference: &Difference| {
        APPROVED.iter().position(|rule| {
            (rule.applies)(
                difference.oracle.as_ref(),
                difference.rust.as_ref(),
                &difference.oracle_list,
            )
        })
    };
    let mut explained: BTreeMap<&str, bool> = BTreeMap::new();
    for difference in differences.iter().filter(|d| is_list(d)) {
        *explained.entry(difference.case.as_str()).or_insert(true) &= rule_of(difference).is_some();
    }
    for difference in &differences {
        let rule = if is_list(difference) {
            rule_of(difference)
        } else {
            None
        };
        // Counts, verdicts and next steps follow from the findings; the files
        // a run writes never do.
        let derived = !is_list(difference)
            && difference.what != "files"
            && explained.get(difference.case.as_str()) == Some(&true);
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
        println!("{count:>5}  {}  ({})", rule.id, rule.changelog);
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
        ["opentide", "--json", "lint"]
            .iter()
            .chain(args)
            .map(|s| (*s).to_owned())
            .collect()
    }

    #[test]
    fn checking_scoping_and_fixing_cases_are_run() {
        let args = parse_args(&argv(&[
            "--check",
            "filenames",
            "--file",
            "x.yaml",
            "--fix",
        ]))
        .unwrap();
        assert_eq!(args.checks, vec![LintCheck::Filenames]);
        assert_eq!(args.files, vec!["x.yaml".to_owned()]);
        assert!(args.fix && !args.strict && !args.changed);
        assert!(parse_args(&argv(&["--format", "sarif"])).is_none());
        assert!(parse_args(&argv(&["--check", "filenamez"])).is_none());
        assert!(parse_args(&argv(&["--help"])).is_none());
    }

    #[test]
    fn the_json_mode_is_not_part_of_a_next_step() {
        assert_eq!(typed("opentide --json lint --fix"), "opentide lint --fix");
        assert_eq!(typed("opentide setup"), "opentide setup");
    }

    fn parse_error(path: &str, column: u64, message: &str) -> Json {
        json!({
            "check": "filenames", "path": path, "code": "yaml_parse",
            "line": 53, "column": column, "end_line": 53, "end_column": column + 1,
            "message": format!("Could not parse object YAML: {message}"),
        })
    }

    #[test]
    fn a_yaml_error_keeps_its_place_and_check() {
        let oracle = parse_error("a.yaml", 1, "did not find expected ',' or ']'");
        let same = parse_error(
            "a.yaml",
            1,
            "while parsing a flow sequence, expected ',' or ']'",
        );
        assert!(yaml_error_text(Some(&oracle), Some(&same), &[]));
        let moved = parse_error("a.yaml", 2, "while parsing a flow sequence");
        assert!(!yaml_error_text(Some(&oracle), Some(&moved), &[]));
        let mut other_check = same.clone();
        other_check["check"] = json!("metadata");
        assert!(!yaml_error_text(Some(&oracle), Some(&other_check), &[]));
    }

    #[test]
    fn only_findings_on_a_file_the_oracle_refused_for_its_date_are_approved() {
        let date = parse_error(
            "r.yaml",
            13,
            "'2026-02-30' is not a valid date (day is out of range for month) at line 9, column 13",
        );
        let list = [date.clone()];
        assert!(yaml_1_2_dates(Some(&date), None, &list));
        let on_it = json!({"code": "metadata_recommended", "path": "r.yaml"});
        assert!(yaml_1_2_dates(None, Some(&on_it), &list));
        let elsewhere = json!({"code": "metadata_recommended", "path": "s.yaml"});
        assert!(!yaml_1_2_dates(None, Some(&elsewhere), &list));
        let syntax = parse_error("r.yaml", 1, "did not find expected ','");
        assert!(!yaml_1_2_dates(
            Some(&syntax),
            None,
            std::slice::from_ref(&syntax)
        ));
    }

    #[test]
    fn a_moved_or_reordered_finding_is_a_difference() {
        let item = |path: &str, line: u64| {
            let mut map = IndexMap::new();
            map.insert("code".to_owned(), json!("x"));
            map.insert("path".to_owned(), json!(path));
            map.insert("line".to_owned(), json!(line));
            Item::new(&map)
        };
        let mut out = Vec::new();
        list_differences("k", &[item("a", 1)], &[item("a", 2)], &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].rust.is_some());
        out.clear();
        list_differences(
            "k",
            &[item("a", 1), item("b", 1)],
            &[item("b", 1), item("a", 1)],
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].what, "findings (order)");
        // The same keys in another order are another finding.
        let mut reordered = IndexMap::new();
        reordered.insert("path".to_owned(), json!("a"));
        reordered.insert("code".to_owned(), json!("x"));
        reordered.insert("line".to_owned(), json!(1));
        out.clear();
        list_differences("k", &[item("a", 1)], &[Item::new(&reordered)], &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn the_verdict_leaves_fixed_findings_out_and_strict_fails() {
        let finding = |severity: &str, fixed: bool| json!({"severity": severity, "fixed": fixed});
        let findings = [
            finding("error", false),
            finding("warning", false),
            finding("info", false),
            finding("info", false),
            finding("warning", true),
        ];
        let (status, message, exit, summary) = verdict(&findings, false, &json!(7));
        assert_eq!(status, "issues");
        assert_eq!(message, "Catalogue lint found issues");
        assert_eq!(exit, 0);
        assert_eq!(
            summary,
            json!({"files": 7, "findings": 4, "errors": 1, "warnings": 1, "notes": 2, "fixed": 1})
        );
        let (status, _, exit, _) = verdict(&findings, true, &json!(7));
        assert_eq!((status.as_str(), exit), ("failed", 1));
        // Everything fixed: completed, but the oracle still says it found issues.
        let (status, message, exit, summary) = verdict(&[finding("error", true)], true, &json!(1));
        assert_eq!(
            (status.as_str(), message.as_str(), exit),
            ("completed", "Catalogue lint found issues", 0)
        );
        assert_eq!(summary["fixed"], json!(1));
        assert_eq!(summary["findings"], json!(0));
        let (status, message, exit, _) = verdict(&[], true, &json!(0));
        assert_eq!(
            (status.as_str(), message.as_str(), exit),
            ("completed", "Catalogue lint passed", 0)
        );
    }

    #[test]
    fn a_windows_workspace_reads_ws_on_every_host() {
        let ws = r"C:\Users\runneradmin\AppData\Local\Temp\cases\5\ws";
        assert_eq!(masked_for(ws, ws, true), "<WS>");
        assert_eq!(
            masked_for(&format!("no .git was found from {ws}"), ws, true),
            "no .git was found from <WS>"
        );
        assert_eq!(
            masked_for(&format!("{ws}\\Objects\\a.yaml"), ws, true),
            "<WS>/Objects/a.yaml"
        );
        // The verbatim spelling `std::fs::canonicalize` gives, on either side.
        assert_eq!(masked_for(&format!(r"\\?\{ws}"), ws, true), "<WS>");
        assert_eq!(masked_for(ws, &format!(r"\\?\{ws}"), true), "<WS>");
        // A finding's JSON, its strings escaped.
        let finding = serde_json::to_string(&json!({"file": format!("{ws}\\a.yaml")})).unwrap();
        assert_eq!(
            crate::payloads::placeholder_for(&finding, ws, true),
            r#"{"file":"<WS>/a.yaml"}"#
        );
        assert_eq!(masked_for("/tmp/ws/a", "/tmp/ws", false), "<WS>/a");
        assert_eq!(masked_for("elsewhere", ws, true), "elsewhere");
    }

    #[test]
    fn changed_needs_a_git_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().canonicalize().unwrap();
        match changed_for(&ws) {
            Changed::Failed(message) => {
                assert!(
                    message.contains("--changed needs a git checkout"),
                    "{message}"
                );
                assert!(message.contains(&ws.display().to_string()), "{message}");
            }
            Changed::Files { .. } => panic!("a directory outside git has no changed files"),
        }
        std::fs::create_dir(ws.join(".git")).unwrap();
        assert!(matches!(
            changed_for(&ws),
            Changed::Files { files, warning: None } if files.is_empty()
        ));
    }

    /// `id`'s recording and a fresh copy of its fixture, as `run` lays it out.
    fn laid_out(id: &str, dir: &Path) -> (Recording, PathBuf) {
        let repo = repo_root();
        let spec =
            Spec::parse(&std::fs::read_to_string(repo.join("tests/golden/cases.toml")).unwrap())
                .unwrap();
        let recording = recorded_cases(&repo)
            .unwrap()
            .into_iter()
            .find(|recording| recording.case.id == id)
            .unwrap_or_else(|| panic!("no recorded case {id}"));
        let ws = dir.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        spec.fixtures[&recording.case.fixture]
            .materialise(&repo, &ws)
            .unwrap();
        crate::golden::fixture::fix_modes(&ws).unwrap();
        (recording, dunce::canonicalize(&ws).unwrap())
    }

    fn parts(differences: &[Difference]) -> std::collections::BTreeSet<String> {
        differences.iter().map(|d| d.what.clone()).collect()
    }

    #[test]
    fn a_fix_case_that_matches_its_recording_differs_only_in_approved_findings() {
        let dir = tempfile::tempdir().unwrap();
        let (recording, ws) = laid_out("lint/json/tide-corpus/fix", dir.path());
        let differences = run_case(&recording, &ws).unwrap();
        for difference in &differences {
            assert_eq!(difference.what, "findings", "{difference:?}");
            assert!(
                APPROVED.iter().any(|rule| (rule.applies)(
                    difference.oracle.as_ref(),
                    difference.rust.as_ref(),
                    &difference.oracle_list
                )),
                "{difference:?}"
            );
        }
        // The renames --fix made are the recording's, byte for byte.
        assert!(!recording.files.is_empty());
        assert!(
            ws.join("Objects/Detection Rules/carbon-black-lucene-rule.yaml")
                .is_file()
        );
    }

    /// `recording` with `from`, which its stdout holds once, read as `to`:
    /// text, so the keys keep the recording's order.
    fn edit(recording: &mut Recording, from: &str, to: &str) {
        let text = String::from_utf8(recording.stdout.clone()).unwrap();
        assert_eq!(text.matches(from).count(), 1, "{from}");
        recording.stdout = text.replacen(from, to, 1).into_bytes();
    }

    #[test]
    fn every_part_of_a_case_that_differs_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (mut recording, ws) = laid_out("lint/json/tide-corpus/fix", dir.path());
        edit(
            &mut recording,
            "\"yaml_line\":3,\"uuid\":\"00000000-0000-4000-8001-000000000001\"",
            "\"yaml_line\":30,\"uuid\":\"00000000-0000-4000-8001-000000000001\"",
        );
        edit(&mut recording, "\"fixed\":12,\"ok\"", "\"fixed\":0,\"ok\"");
        edit(
            &mut recording,
            "\"checks\":[\"filenames\",\"metadata\",\"placeholders\",\"queries\"]",
            "\"checks\":[\"filenames\"]",
        );
        edit(
            &mut recording,
            "\"path\":\"<WS>\",",
            "\"path\":\"<WS>\",\"scope\":\"files\",\"unmatched\":[\"nowhere.yaml\"],",
        );
        edit(
            &mut recording,
            "\"next_actions\":[]",
            "\"next_actions\":[{\"command\":\"opentide --json lint\",\"reason\":\"again\"}]",
        );
        recording.files.clear();
        let differences = run_case(&recording, &ws).unwrap();
        let found = parts(&differences);
        assert_eq!(
            found,
            [
                "findings",
                "fixed",
                "checks",
                "scope",
                "unmatched",
                "next_actions",
                "files",
            ]
            .map(str::to_owned)
            .into_iter()
            .collect(),
        );
        // The moved finding is one difference: the oracle's and the Rust run's
        // (the others are the approved quoting of a message).
        let moved: Vec<_> = differences
            .iter()
            .filter(|d| {
                d.what == "findings" && !quoting_only(d.oracle.as_ref(), d.rust.as_ref(), &[])
            })
            .collect();
        assert_eq!(moved.len(), 1, "{moved:?}");
        assert_eq!(moved[0].oracle.as_ref().unwrap()["yaml_line"], json!(30));
        assert_eq!(moved[0].rust.as_ref().unwrap()["yaml_line"], json!(3));
        let next = differences
            .iter()
            .find(|d| d.what == "next_actions")
            .unwrap();
        assert_eq!(
            next.oracle,
            Some(json!([{"command": "opentide lint", "reason": "again"}]))
        );
    }

    #[test]
    fn a_verdict_that_differs_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (mut recording, ws) = laid_out("lint/json/vscode/strict", dir.path());
        // Without --strict, the recording's findings leave lint at "issues":
        // the verdict is recomputed from them, so only the file count differs.
        recording.case.argv.retain(|arg| arg != "--strict");
        edit(&mut recording, "\"files\":2,", "\"files\":99,");
        let differences = run_case(&recording, &ws).unwrap();
        assert_eq!(
            parts(&differences),
            ["summary"].map(str::to_owned).into_iter().collect()
        );
        assert_eq!(differences[0].oracle.as_ref().unwrap()["files"], json!(99));
        assert_eq!(differences[0].rust.as_ref().unwrap()["files"], json!(2));
        // A refusal is compared as recorded: its status, message and exit code.
        let (mut refused, ws) = laid_out(
            "lint/json/tide-corpus/file-missing",
            &dir.path().join("refused"),
        );
        let clean = run_case(&refused, &ws).unwrap();
        assert!(clean.is_empty(), "{clean:?}");
        edit(&mut refused, "\"exit_code\":1", "\"exit_code\":0");
        edit(
            &mut refused,
            "\"status\":\"failed\"",
            "\"status\":\"completed\"",
        );
        let differences = run_case(&refused, &ws).unwrap();
        assert_eq!(
            parts(&differences),
            ["exit_code", "status"]
                .map(str::to_owned)
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn a_case_with_other_options_is_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let (mut recording, ws) = laid_out("lint/json/vscode/default", dir.path());
        recording.case.argv.push("--format".to_owned());
        recording.stdout = b"not json".to_vec();
        assert!(run_case(&recording, &ws).unwrap().is_empty());
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_command_line_is_checked() {
        assert_eq!(run(&[]).unwrap(), 0);
        assert_eq!(run(&strings(&["help"])).unwrap(), 0);
        for bad in [
            &["check"][..],
            &["diff", "--nope"],
            &["diff", "--filter"],
            &["diff", "--keep"],
            &["diff", "--filter", "["],
        ] {
            assert!(run(&strings(bad)).is_err(), "{bad:?}");
        }
        let error = run(&strings(&["diff", "--filter", "lint/json/nowhere/*"])).unwrap_err();
        assert!(error.to_string().contains("no recorded lint case matches"));
    }

    #[test]
    fn a_kept_filtered_run_passes_and_keeps_its_cases() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("kept");
        let code = run(&strings(&[
            "diff",
            "--filter",
            "lint/json/fault/*",
            "--show-approved",
            "--keep",
            keep.to_str().unwrap(),
        ]))
        .unwrap();
        assert_eq!(code, 0);
        assert!(keep.join("fixtures/fault").is_dir());
        assert!(keep.join("cases/0/ws").is_dir());
    }

    /// The whole of `cargo xtask lint diff`, as CI's corpus job runs it: every
    /// recorded case agrees with the oracle or an approved rule, and every
    /// rule explains something.
    #[test]
    fn every_recorded_case_agrees_with_the_oracle() {
        assert_eq!(run(&strings(&["diff"])).unwrap(), 0);
    }
}
