//! The Rust runner of the cross-SDK conformance suite (UC-5.4, #839).
//!
//! It runs every operation of `tests/conformance/manifest.json` on every
//! corpus of a plan through this crate (the Rust SDK: `Workspace` and
//! `cli::run_json`), and writes each result as a normalised JSON document,
//! `<out>/<corpus>/<operation>.json`. `cargo xtask conformance` runs it next
//! to the Python runner (`tests/conformance/test_python_runner.py`) and the
//! Node runner (`bindings/node/test/conformance.test.mjs`) and requires the
//! three trees to be byte-identical; `tests/conformance/README.md` says how a
//! document is built, the same way in each runner.
//!
//! Driven by xtask, `OPENTIDE_CONFORMANCE_PLAN` names the plan and
//! `OPENTIDE_CONFORMANCE_OUT` the folder to write;
//! `OPENTIDE_CONFORMANCE_DIVERGE` (test-only) makes this runner diverge on
//! purpose. Without them it runs every operation on the tide corpus under a
//! temporary folder.

#![cfg(feature = "cli")]
#![expect(
    clippy::unwrap_used,
    reason = "a test runner: a plan that does not read, or a document that does not write, is a failure"
)]

mod common;

use std::path::{Path, PathBuf};

use opentide::lint::{LintCheck, LintReport};
use opentide::validate::{Check, QueriesMode, Validation};
use opentide::{DeployPlanOptions, LintOptions, Options, Strategy, ValidateOptions, Workspace};
use opentide_compare::json::{self as ordered, Json, Layout};
use serde::Serialize;
use serde_json::Value;

const PLAN_ENV: &str = "OPENTIDE_CONFORMANCE_PLAN";
const OUT_ENV: &str = "OPENTIDE_CONFORMANCE_OUT";
const DIVERGE_ENV: &str = "OPENTIDE_CONFORMANCE_DIVERGE";

/// `value` as an ordered JSON tree: the facade's types serialise in their
/// field order, which the tree keeps.
fn tree<T: Serialize + ?Sized>(value: &T) -> Json {
    ordered::parse_str(&serde_json::to_string(value).unwrap()).unwrap()
}

fn object(members: Vec<(&str, Json)>) -> Json {
    Json::Object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn error(error: &opentide::Error) -> Json {
    object(vec![(
        "error",
        object(vec![
            ("code", Json::String(error.code().to_owned())),
            ("message", Json::String(error.to_string())),
        ]),
    )])
}

/// The members that hold a run's own clock, by their path from the
/// document's root: its wall time and the time it ran, the values two runs of
/// one operation differ in. Every runner writes them as null, and changes
/// nothing else.
const VOLATILE: [&[&str]; 3] = [
    &["duration_ms"],
    &["evaluated_at"],
    &["report", "stats", "wall_ms"],
];

/// `document` with each member of [`VOLATILE`] it has set to null.
fn normalise(mut document: Json) -> Json {
    for path in VOLATILE {
        let Some((last, parents)) = path.split_last() else {
            continue;
        };
        let mut parent = Some(&mut document);
        for key in parents {
            parent = match parent {
                Some(Json::Object(members)) => members
                    .iter_mut()
                    .find(|(k, _)| k == key)
                    .map(|(_, value)| value),
                _ => None,
            };
        }
        if let Some(Json::Object(members)) = parent {
            for (key, value) in members.iter_mut() {
                if key == last {
                    *value = Json::Null;
                }
            }
        }
    }
    document
}

/// The document as every runner writes it: two-space indentation, keys in
/// their order, UTF-8 as is, a final newline.
fn canonical(document: &Json) -> Vec<u8> {
    ordered::write(document, Layout::Indented, true)
}

/// Sorts every object's keys: the test-only divergence.
fn sorted(value: Json) -> Json {
    match value {
        Json::Array(items) => Json::Array(items.into_iter().map(sorted).collect()),
        Json::Object(members) => {
            let mut members: Vec<(String, Json)> = members
                .into_iter()
                .map(|(key, value)| (key, sorted(value)))
                .collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            Json::Object(members)
        }
        other => other,
    }
}

fn strings(options: &Value, key: &str) -> Vec<String> {
    options[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn validation(validation: &Validation) -> Json {
    let checks = Json::Object(
        validation
            .checks
            .iter()
            .map(|(check, status)| {
                (
                    check.name().to_owned(),
                    object(vec![
                        ("check", Json::String(check.name().to_owned())),
                        ("status", Json::String((*status).to_owned())),
                    ]),
                )
            })
            .collect(),
    );
    object(vec![
        ("checks", checks),
        ("report", tree(&validation.report)),
        ("summary", tree(&validation.summary)),
        ("failed", Json::Bool(validation.failed)),
        ("warned", Json::Bool(validation.warned)),
        ("exit_code", tree(&validation.exit_code())),
    ])
}

fn lint(report: &LintReport) -> Json {
    let checks: Vec<&str> = report.checks.iter().map(|check| check.name()).collect();
    object(vec![
        ("path", tree(&report.path.to_string_lossy())),
        ("checks", tree(&checks)),
        ("findings", tree(&report.findings)),
        ("status", tree(&report.status)),
        ("message", tree(&report.message)),
        ("exit_code", tree(&report.exit_code)),
        ("failure_code", tree(&report.failure_code)),
        ("summary", tree(&report.summary)),
        ("outcome", tree(&report.outcome)),
        ("unmatched", tree(&report.unmatched)),
        ("warnings", tree(&report.warnings)),
        ("next_actions", tree(&report.next_actions)),
    ])
}

fn call(ws: &Workspace, operation: &Value) -> Result<Json, opentide::Error> {
    let options = &operation["options"];
    let flag = |key: &str| options[key].as_bool().unwrap_or(false);
    Ok(match operation["call"].as_str().unwrap() {
        "validate" => {
            let queries = match options["queries"].as_str() {
                None | Some("error") => QueriesMode::Error,
                Some("warn") => QueriesMode::Warn,
                Some("off") => QueriesMode::Off,
                Some(other) => panic!("queries: {other}"),
            };
            let mut o = ValidateOptions::default()
                .strict(flag("strict"))
                .queries(queries);
            if let Some(name) = options["check"].as_str() {
                o = o.check(Check::parse(name).unwrap());
            }
            for file in strings(options, "files") {
                o = o.file(file);
            }
            for uuid in strings(options, "uuids") {
                o = o.uuid(uuid);
            }
            for family in strings(options, "types") {
                o = o.object_type(family);
            }
            validation(&ws.validate(&o))
        }
        "lint" => {
            let mut o = LintOptions::default().strict(flag("strict"));
            for name in strings(options, "checks") {
                o = o.check(LintCheck::parse(&name).unwrap());
            }
            for file in strings(options, "files") {
                o = o.file(file);
            }
            lint(&ws.lint(&o))
        }
        "info" => tree(&ws.info()),
        "catalog" => tree(&ws.catalog()),
        "rules" => tree(&ws.rules()),
        "objectives" => tree(&ws.objectives()),
        "threats" => tree(&ws.threats()),
        "coverage" => tree(&ws.coverage(operation["technique"].as_str().unwrap())),
        "deploy_plan" => {
            let mut o = DeployPlanOptions::default();
            let mut strategies = strings(options, "strategies");
            if options["strategies"].is_null() {
                strategies.push("RELEASE".to_owned());
            }
            for name in strategies {
                o = o.strategy(match name.as_str() {
                    "PREVIEW" => Strategy::Preview,
                    "RELEASE" => Strategy::Release,
                    other => panic!("strategies: {other}"),
                });
            }
            for uuid in strings(options, "uuids") {
                o = o.uuid(uuid);
            }
            for file in strings(options, "files") {
                o = o.file(file);
            }
            if let Some(platform) = options["platform"].as_str() {
                o = o.platform(platform);
            }
            o.keep_deprecated = options["keep_deprecated"].as_bool();
            let plan = ws.deploy_plan(&o)?;
            let parse = |document: &opentide::Document| ordered::parse_str(document.as_str());
            object(vec![
                ("document", parse(plan.document()).unwrap()),
                (
                    "summary",
                    plan.summary().map_or(Json::Null, |s| parse(s).unwrap()),
                ),
                ("ok", Json::Bool(plan.ok())),
            ])
        }
        other => panic!("unknown call {other}"),
    })
}

fn run_json(root: &str, operation: &Value) -> Json {
    let mut argv = strings(operation, "argv");
    if operation["repo"].as_bool() != Some(false) {
        argv.splice(0..0, ["--repo".to_owned(), root.to_owned()]);
    }
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(root).unwrap();
    let result = opentide::cli::run_json(argv);
    std::env::set_current_dir(cwd).unwrap();
    match result {
        Ok(document) => ordered::parse_str(document.as_str()).unwrap(),
        Err(e) => error(&e),
    }
}

/// Every file under `dir`, by its path from `root` with `/`, as text.
fn files(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            files(root, &path, out);
        } else {
            let relative: Vec<String> = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            out.push((relative.join("/"), std::fs::read_to_string(&path).unwrap()));
        }
    }
}

fn open(root: &str, mode: &str) -> Result<Workspace, opentide::Error> {
    if mode == "files" {
        let mut all = Vec::new();
        files(Path::new(root), Path::new(root), &mut all);
        Workspace::from_files(root, all)
    } else {
        Workspace::open(root, &Options::default())
    }
}

/// Writes the document of every operation on every corpus of `plan` under
/// `out`; returns the files written, in the plan's order.
fn run_plan(plan: &Value, out: &Path, diverge: bool) -> Vec<PathBuf> {
    let mut written = Vec::new();
    for corpus in plan["corpora"].as_array().unwrap() {
        let name = corpus["name"].as_str().unwrap();
        let root = corpus["root"].as_str().unwrap();
        let family = name.split('/').next().unwrap();
        let mut opened: Vec<(String, Result<Workspace, opentide::Error>)> = Vec::new();
        for operation in plan["operations"].as_array().unwrap() {
            if let Some(only) = operation["corpora"].as_array()
                && !only.iter().any(|c| c.as_str() == Some(family))
            {
                continue;
            }
            let document = if operation["call"] == "run_json" {
                run_json(root, operation)
            } else {
                let mode = operation["open"].as_str().unwrap_or("disk");
                if !opened.iter().any(|(m, _)| m == mode) {
                    opened.push((mode.to_owned(), open(root, mode)));
                }
                let (_, ws) = opened.iter().find(|(m, _)| m == mode).unwrap();
                match ws {
                    Ok(ws) => {
                        let document = call(ws, operation).unwrap_or_else(|e| error(&e));
                        if diverge && operation["call"] == "validate" {
                            // The document as a binding that went through a
                            // sorted map would hand it back.
                            sorted(document)
                        } else {
                            document
                        }
                    }
                    Err(e) => error(e),
                }
            };
            let mut path = out.to_path_buf();
            path.extend(name.split('/'));
            path.push(format!("{}.json", operation["name"].as_str().unwrap()));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, canonical(&normalise(document))).unwrap();
            written.push(path);
        }
    }
    written
}

fn standalone_plan(root: &Path) -> Value {
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(common::repo().join("tests/conformance/manifest.json")).unwrap(),
    )
    .unwrap();
    serde_json::json!({
        "corpora": [{"name": "tide_corpus", "root": root.to_string_lossy()}],
        "operations": manifest["operations"],
    })
}

#[test]
fn the_rust_runner_writes_every_document() {
    let corpus = common::tide_corpus();
    let scratch = tempfile::tempdir().unwrap();
    let (plan, out, driven) = match std::env::var_os(PLAN_ENV) {
        Some(plan) => (
            serde_json::from_str(&std::fs::read_to_string(plan).unwrap()).unwrap(),
            PathBuf::from(std::env::var_os(OUT_ENV).expect("OPENTIDE_CONFORMANCE_OUT")),
            true,
        ),
        None => (
            standalone_plan(corpus.path()),
            scratch.path().to_path_buf(),
            false,
        ),
    };
    let diverge = std::env::var_os(DIVERGE_ENV).is_some_and(|v| !v.is_empty());
    let written = run_plan(&plan, &out, diverge);
    assert!(!written.is_empty(), "the plan names no operation");
    for path in &written {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(ordered::parse_str(&text).is_some(), "{}", path.display());
    }
    if !driven {
        assert_eq!(written.len(), plan["operations"].as_array().unwrap().len());
        let validate: Value = serde_json::from_str(
            &std::fs::read_to_string(out.join("tide_corpus/validate.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(validate["failed"], false);
        assert_eq!(validate["exit_code"], 0);
    }
}

#[test]
fn the_divergence_flag_changes_the_bytes_and_not_the_data() {
    let corpus = common::tide_corpus();
    let scratch = tempfile::tempdir().unwrap();
    let mut plan = standalone_plan(corpus.path());
    plan["operations"]
        .as_array_mut()
        .unwrap()
        .retain(|operation| operation["name"] == "validate");
    let same = run_plan(&plan, &scratch.path().join("same"), false);
    let diverged = run_plan(&plan, &scratch.path().join("diverged"), true);
    let before = std::fs::read_to_string(&same[0]).unwrap();
    let after = std::fs::read_to_string(&diverged[0]).unwrap();
    assert_ne!(before, after);
    let (before, after) = (
        ordered::parse_str(&before).unwrap(),
        ordered::parse_str(&after).unwrap(),
    );
    assert!(before.same(&after));
    let Json::Object(members) = after else {
        panic!("an object")
    };
    assert_eq!(members[1].0, "exit_code");
}
