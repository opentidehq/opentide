//! `cargo xtask payloads plan`: `deploy --dry-run`'s plan, made by
//! `opentide_compile::dry_run`, against the oracle's recorded JSON document
//! (`tests/golden/cases/deploy/json/*`) of every dry-run case.
//!
//! The command's result keys are compared value for value: `message`,
//! `status`, `deployed`, `dry_run`, `plan`, `changes`, `strategies`,
//! `tenants`, `missing_tenants`, `advice`, `warnings`, `skipped`, `detail`,
//! `summary`, the exit code, and every payload entry `opentide-compile`
//! compiles (an entry the oracle shows as the block's model dump waits for
//! the platform models, UC-1.4, #810, and is counted).

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result};
use opentide_compile::Owned;
use opentide_compile::dry_run::{self, Request};
use opentide_compile::plan::Scope;
use opentide_schema::vocab::Vocabularies;
use serde::Deserialize;
use serde_json::Value;

/// The keys of the result compared.
pub const KEYS: [&str; 13] = [
    "message",
    "status",
    "deployed",
    "dry_run",
    "plan",
    "changes",
    "strategies",
    "tenants",
    "missing_tenants",
    "advice",
    "warnings",
    "skipped",
    "detail",
];

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    fixture: String,
    argv: Vec<String>,
    #[serde(default)]
    env: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Recorded {
    exit_code: i32,
}

/// The request a case's argv makes.
pub fn request(argv: &[String], cwd: &Path) -> Request {
    let mut request = Request {
        cwd: cwd.to_path_buf(),
        ..Request::default()
    };
    let mut words = argv.iter().skip_while(|arg| *arg != "deploy").skip(1);
    while let Some(arg) = words.next() {
        match arg.as_str() {
            "--strategy" => request.strategies.extend(words.next().cloned()),
            "--uuid" => request.uuids.extend(words.next().cloned()),
            "--file" => request.files.extend(words.next().cloned()),
            "--platform" => request.platform = words.next().cloned(),
            "--all" => request.all = true,
            "--wide" => request.wide = true,
            "--keep-deprecated" => request.keep_deprecated = Some(true),
            "--drop-deprecated" => request.keep_deprecated = Some(false),
            _ => {}
        }
    }
    request
}

/// One case's differences, each `key: oracle != candidate`.
pub fn compare_case(case_dir: &Path, ws: &Path) -> Result<(Vec<String>, usize)> {
    let case: Case = toml::from_str(&fs::read_to_string(case_dir.join("case.toml"))?)
        .context("read case.toml")?;
    let recorded: Recorded = toml::from_str(&fs::read_to_string(case_dir.join("outcome.toml"))?)?;
    let document: Value = serde_json::from_str(&fs::read_to_string(case_dir.join("stdout"))?)
        .with_context(|| format!("{}: the recorded stdout is not JSON", case.id))?;
    let workspace = super::open(ws)?;
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let request = request(&case.argv, ws);
    let env = |name: &str| case.env.get(name).cloned();
    let changed = |rules: &Path, folder: &str| -> Result<(Scope, Option<String>), String> {
        dry_run::git_scope(ws, ws, &env, rules, folder)
    };
    let is_set = |name: &str| case.env.contains_key(name);
    let outcome = dry_run::run(&workspace, &owned, &request, &changed, &is_set);
    let ws_text = ws.to_string_lossy().into_owned();
    let candidate: Value = serde_json::from_str(
        &serde_json::to_string(&opentide_compile::Json::Object(outcome.payload.clone()))?
            .replace(&ws_text, "<WS>"),
    )?;
    let mut differences = Vec::new();
    for key in KEYS {
        let oracle = document.get(key).filter(|value| !value.is_null());
        let mine = candidate.get(key).filter(|value| !value.is_null());
        if oracle != mine {
            differences.push(format!(
                "{key}: oracle {} != candidate {}",
                oracle.map_or_else(|| "absent".to_owned(), Value::to_string),
                mine.map_or_else(|| "absent".to_owned(), Value::to_string)
            ));
        }
    }
    let summary = document
        .get("summary")
        .filter(|value| !value.is_null() && value != &&serde_json::json!({}));
    let mine_summary = outcome
        .summary
        .as_ref()
        .map(|summary| serde_json::from_str::<Value>(&summary.to_compact()))
        .transpose()?;
    if summary != mine_summary.as_ref() {
        differences.push(format!(
            "summary: oracle {summary:?} != candidate {mine_summary:?}"
        ));
    }
    if recorded.exit_code != outcome.exit_code {
        differences.push(format!(
            "exit code: oracle {} != candidate {}",
            recorded.exit_code, outcome.exit_code
        ));
    }
    let mut waiting = 0;
    if let (Some(Value::Object(oracle)), Some(Value::Object(mine))) =
        (document.get("payloads"), candidate.get("payloads"))
    {
        for (platform, entries) in oracle {
            let empty = Vec::new();
            let mine_entries = mine
                .get(platform)
                .and_then(Value::as_array)
                .unwrap_or(&empty);
            let oracle_entries = entries.as_array().unwrap_or(&empty);
            if mine_entries.len() != oracle_entries.len() {
                differences.push(format!("payloads.{platform}: entry count differs"));
                continue;
            }
            for (expected, got) in oracle_entries.iter().zip(mine_entries) {
                if got.is_null() {
                    waiting += 1;
                } else if expected != got {
                    differences.push(format!(
                        "payloads.{platform}: oracle {expected} != candidate {got}"
                    ));
                }
            }
        }
    }
    Ok((differences, waiting))
}

/// One approved difference of a plan key (`[[plan]]` in
/// `tests/golden/payloads/APPROVED.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedPlan {
    /// The case id (`deploy/json/fault/dry-run`).
    pub case: String,
    /// The key.
    pub key: String,
    /// The oracle's value, as JSON.
    pub oracle: String,
    /// The candidate's value, as JSON.
    pub candidate: String,
    /// Why the candidate's is right.
    pub reason: String,
    /// The issue that decided it.
    pub issue: String,
    /// The bold lead of the CHANGELOG.md entry that announces it.
    pub changelog: String,
}

#[derive(Debug, Default, Deserialize)]
struct PlanApprovals {
    #[serde(default)]
    plan: Vec<ApprovedPlan>,
    #[serde(default, rename = "diff")]
    _diff: Vec<toml::Value>,
}

/// Reads the approved plan differences, checking each is complete and announced.
pub fn read_approved(text: &str, changelog: &str) -> Result<Vec<ApprovedPlan>> {
    let file: PlanApprovals = toml::from_str(text).context("parse the approved differences")?;
    for entry in &file.plan {
        anyhow::ensure!(
            !entry.reason.is_empty() && entry.issue.starts_with("https://github.com/opentidehq/"),
            "{}: {} {} needs a reason and an opentidehq issue",
            super::APPROVED,
            entry.case,
            entry.key
        );
        anyhow::ensure!(
            changelog.contains(&entry.changelog),
            "{}: CHANGELOG.md has no entry `{}`",
            super::APPROVED,
            entry.changelog
        );
    }
    Ok(file.plan)
}

/// Runs every dry-run case of `filter` (a prefix of the case id). Whether all
/// agree.
pub fn run(filter: Option<&str>) -> Result<bool> {
    let (repo, _target) = crate::vocab::diff::workspace()?;
    let changelog = fs::read_to_string(repo.join("CHANGELOG.md"))?;
    let approved = match fs::read_to_string(repo.join(super::APPROVED)) {
        Ok(text) => read_approved(&text, &changelog)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let mut used = vec![false; approved.len()];
    let golden = repo.join("tests/golden");
    let spec = crate::golden::case::Spec::parse(&fs::read_to_string(golden.join("cases.toml"))?)?;
    let cases = golden.join("cases/deploy/json");
    let mut passed = true;
    let mut fixtures: Vec<_> = fs::read_dir(&cases)?.flatten().map(|e| e.path()).collect();
    fixtures.sort();
    for fixture_dir in fixtures {
        let mut variants: Vec<_> = fs::read_dir(&fixture_dir)?
            .flatten()
            .map(|e| e.path())
            .collect();
        variants.sort();
        for case_dir in variants {
            let case: Case = toml::from_str(&fs::read_to_string(case_dir.join("case.toml"))?)?;
            if !case.argv.iter().any(|arg| arg == "--dry-run")
                || filter.is_some_and(|filter| !case.id.starts_with(filter))
            {
                continue;
            }
            let Some(fixture) = spec.fixtures.get(&case.fixture) else {
                continue;
            };
            let scratch = tempfile::tempdir()?;
            let ws = scratch.path().join("ws");
            fs::create_dir_all(&ws)?;
            fixture.materialise(&repo, &ws)?;
            let ws = ws.canonicalize()?;
            let (differences, waiting) = compare_case(&case_dir, &ws)?;
            let differences: Vec<String> = differences
                .into_iter()
                .filter(|difference| {
                    let hit = approved.iter().position(|entry| {
                        entry.case == case.id
                            && *difference
                                == format!(
                                    "{}: oracle {} != candidate {}",
                                    entry.key, entry.oracle, entry.candidate
                                )
                    });
                    if let Some(position) = hit {
                        used[position] = true;
                        println!(
                            "{}: approved difference of {}",
                            case.id, approved[position].key
                        );
                    }
                    hit.is_none()
                })
                .collect();
            if differences.is_empty() {
                println!(
                    "{}: the plan agrees ({waiting} payload entries wait for UC-1.4)",
                    case.id
                );
            } else {
                passed = false;
                println!("{}: DIFFERS", case.id);
                for difference in differences {
                    println!("  {}", difference.chars().take(1200).collect::<String>());
                }
            }
        }
    }
    for (entry, used) in approved.iter().zip(&used) {
        if !used && filter.is_none_or(|filter| entry.case.starts_with(filter)) {
            passed = false;
            eprintln!(
                "error: {}: the approval of {} {} matches nothing (stale)",
                super::APPROVED,
                entry.case,
                entry.key
            );
        }
    }
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_recorded_dry_run_plan_agrees() {
        assert!(run(None).unwrap());
        assert!(run(Some("deploy/json/vscode")).unwrap());
    }

    #[test]
    fn a_request_reads_the_recorded_argv() {
        let argv: Vec<String> = [
            "--json",
            "deploy",
            "--dry-run",
            "--strategy",
            "PREVIEW",
            "--all",
            "--uuid",
            "u",
            "--file",
            "f",
            "--platform",
            "sysdig",
            "--wide",
            "--drop-deprecated",
        ]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
        let request = request(&argv, Path::new("/ws"));
        assert!(request.all && request.wide);
        assert_eq!(request.strategies, ["PREVIEW"]);
        assert_eq!(request.uuids, ["u"]);
        assert_eq!(request.files, ["f"]);
        assert_eq!(request.platform.as_deref(), Some("sysdig"));
        assert_eq!(request.keep_deprecated, Some(false));
    }
}
