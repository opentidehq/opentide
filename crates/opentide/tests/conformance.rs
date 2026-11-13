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
//! Driven by xtask, `OPENTIDE_CONFORMANCE_PLAN` names the plan (with the
//! URLs of the stand-in tenants xtask started, which every runner talks to)
//! and `OPENTIDE_CONFORMANCE_OUT` the folder to write;
//! `OPENTIDE_CONFORMANCE_DIVERGE` (test-only) makes this runner diverge on
//! purpose. Without them it starts the stand-ins itself
//! (`tests/cassettes/<name>/tenant.py`, with `$PYTHON`, else `python3`) and
//! runs every operation on the tide corpus under a temporary folder.

#![cfg(all(feature = "cli", feature = "connectors"))]
#![expect(
    clippy::unwrap_used,
    reason = "a test runner: a plan that does not read, or a document that does not write, is a failure"
)]

mod common;

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use opentide::connectors::{
    self, ConnectOptions, Connection, DeployRequest, Operation, QueryOutcome, QueryRequest,
    TenantConfig, TimeWindow, Timestamp,
};
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

/// A tenant operation's error: its code, its message and the vendor's
/// words.
fn tenant_error(error: &opentide::Error) -> Json {
    let detail = match error {
        opentide::Error::Connector {
            detail: Some(detail),
            ..
        } => Json::String(detail.clone()),
        _ => Json::Null,
    };
    object(vec![(
        "error",
        object(vec![
            ("code", Json::String(error.code().to_owned())),
            ("message", Json::String(error.to_string())),
            ("detail", detail),
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
        "tenants" => Json::Array(
            ws.tenants(operation["platform"].as_str().unwrap())
                .iter()
                .map(|tenant| {
                    object(vec![
                        ("platform", Json::String(tenant.platform().to_owned())),
                        ("name", Json::String(tenant.name().to_owned())),
                        ("setup_keys", tree(&tenant.setup_keys().collect::<Vec<_>>())),
                    ])
                })
                .collect(),
        ),
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

/// The calls on a tenant (`Connection`), not on a workspace.
const TENANT_CALLS: [&str; 3] = ["query", "validate_query", "deploy"];

/// How far back `query` searches without a `start`: the Python and Node
/// SDKs' default, 24 hours before `end`.
const QUERY_SINCE: Duration = Duration::from_secs(24 * 60 * 60);

/// `tenant`'s connection, each `{<stand-in>}` of its setup the URL that
/// stand-in listens on.
fn connect(tenant: &Value, urls: &Value) -> Result<Connection, opentide::Error> {
    let setup: Vec<(String, String)> = tenant["setup"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| {
            let mut value = value.as_str().unwrap().to_owned();
            for (name, url) in urls.as_object().into_iter().flatten() {
                value = value.replace(&format!("{{{name}}}"), url.as_str().unwrap());
            }
            (key.clone(), value)
        })
        .collect();
    let config = TenantConfig::new(
        tenant["platform"].as_str().unwrap(),
        tenant["name"].as_str().unwrap(),
        setup,
    );
    let environment: Vec<(String, String)> = tenant["environment"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_owned()))
        .collect();
    Connection::open(&config, &ConnectOptions::default().environment(environment))
}

/// The request of a `query` or `validate_query` operation, with the SDKs'
/// defaults: `end` now, `start` 24 hours before it for a query and the
/// minute before it for a check.
fn query_request(operation: &Value) -> QueryRequest {
    let options = &operation["options"];
    let at = |key: &str| {
        options[key]
            .as_str()
            .map(|text| text.parse::<Timestamp>().unwrap())
    };
    let end = at("end").unwrap_or_else(Timestamp::now);
    let mut window = TimeWindow::check(end);
    if operation["call"] == "query" {
        window.start = end.checked_sub(QUERY_SINCE).unwrap();
    }
    if let Some(start) = at("start") {
        window.start = start;
    }
    let mut request = QueryRequest::new(
        operation["text"].as_str().unwrap(),
        options["language"].as_str().unwrap_or(""),
        window,
    );
    if let Some(limit) = options["limit"].as_u64() {
        request.limit = usize::try_from(limit).unwrap();
    }
    request.index = strings(options, "index");
    request.data_view = options["data_view"].as_str().map(str::to_owned);
    if let Some(seconds) = options["timeout"].as_f64() {
        request.timeout = Duration::from_secs_f64(seconds);
    }
    request
}

/// A query's document, by the facade's names.
fn query_document(outcome: &QueryOutcome) -> Json {
    let text = |value: &Option<String>| value.clone().map_or(Json::Null, Json::String);
    object(vec![
        (
            "columns",
            Json::Array(
                outcome
                    .columns
                    .iter()
                    .map(|column| {
                        object(vec![
                            ("name", Json::String(column.name.clone())),
                            ("type", text(&column.kind)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("rows", tree(&outcome.rows)),
        ("truncated", Json::Bool(outcome.truncated)),
        ("partial", Json::Bool(outcome.partial)),
        ("warnings", tree(&outcome.warnings)),
        ("vendor_query_id", text(&outcome.vendor_query_id)),
        ("sent", text(&outcome.sent)),
        ("language", text(&outcome.language)),
    ])
}

fn tenant_call(connection: &Connection, operation: &Value) -> Result<Json, opentide::Error> {
    Ok(match operation["call"].as_str().unwrap() {
        "query" => {
            let request = query_request(operation);
            query_document(&connectors::block_on(connection.query(&request))??)
        }
        "validate_query" => {
            let request = query_request(operation);
            let check = connectors::block_on(connection.validate_query(&request))??;
            object(vec![
                (
                    "result",
                    check.result.as_ref().map_or(Json::Null, query_document),
                ),
                ("errors", tree(&check.errors)),
                ("warnings", tree(&check.warnings)),
            ])
        }
        "deploy" => {
            let request = DeployRequest {
                rule_id: operation["rule_id"].as_str().unwrap().to_owned(),
                operation: match operation["operation"].as_str().unwrap() {
                    "create" => Operation::Create,
                    "update" => Operation::Update,
                    "disable" => Operation::Disable,
                    "delete" => Operation::Delete,
                    other => panic!("operation: {other}"),
                },
                body: operation["body"].as_str().unwrap().as_bytes().to_vec(),
            };
            let outcome = connectors::block_on(connection.deploy(&request))??;
            let operation = match outcome.operation {
                Operation::Create => "create",
                Operation::Update => "update",
                Operation::Disable => "disable",
                Operation::Delete => "delete",
            };
            object(vec![
                (
                    "remote_id",
                    outcome.remote_id.map_or(Json::Null, Json::String),
                ),
                ("operation", Json::String(operation.to_owned())),
            ])
        }
        other => panic!("unknown tenant call {other}"),
    })
}

/// Every platform with a connector and what each can do.
fn connectors_document() -> Json {
    let platforms = connectors::platforms();
    let capabilities = platforms
        .iter()
        .filter_map(|platform| {
            connectors::capabilities(platform).map(|found| {
                (
                    (*platform).to_owned(),
                    object(vec![
                        ("deploy", Json::Bool(found.deploy)),
                        ("live_validation", Json::Bool(found.live_validation)),
                        ("query", Json::Bool(found.query)),
                    ]),
                )
            })
        })
        .collect();
    object(vec![
        ("platforms", tree(&platforms)),
        ("capabilities", Json::Object(capabilities)),
    ])
}

/// A stand-in tenant this runner started; killed when dropped.
struct StandIn(Child);

impl Drop for StandIn {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

/// Starts each stand-in of `plan` (`tests/cassettes/<name>/tenant.py`) on
/// loopback, for a run of this runner alone, its URL in `plan["urls"]`.
fn start_stand_ins(plan: &mut Value) -> Vec<StandIn> {
    let python = std::env::var_os("PYTHON")
        .unwrap_or_else(|| if cfg!(windows) { "python" } else { "python3" }.into());
    let mut started = Vec::new();
    let specs = plan["stand_ins"].as_array().unwrap().clone();
    for spec in specs {
        let name = spec["name"].as_str().unwrap();
        let script = common::repo()
            .join("tests/cassettes")
            .join(name)
            .join("tenant.py");
        let mut command = Command::new(&python);
        command
            .arg(script)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (key, value) in spec["environment"].as_object().unwrap() {
            command.env(key, value.as_str().unwrap());
        }
        let mut child = StandIn(command.spawn().unwrap());
        let mut line = String::new();
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port: u16 = line.trim().parse().unwrap();
        plan["urls"][name] = Value::String(format!("http://127.0.0.1:{port}"));
        started.push(child);
    }
    started
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
    let tenants = plan["tenants"].as_array().cloned().unwrap_or_default();
    for corpus in plan["corpora"].as_array().unwrap() {
        let name = corpus["name"].as_str().unwrap();
        let root = corpus["root"].as_str().unwrap();
        let family = name.split('/').next().unwrap();
        let mut opened: Vec<(String, Result<Workspace, opentide::Error>)> = Vec::new();
        let mut connected: Vec<(String, Result<Connection, opentide::Error>)> = Vec::new();
        for operation in plan["operations"].as_array().unwrap() {
            if let Some(only) = operation["corpora"].as_array()
                && !only.iter().any(|c| c.as_str() == Some(family))
            {
                continue;
            }
            let kind = operation["call"].as_str().unwrap();
            let document = if kind == "run_json" {
                run_json(root, operation)
            } else if kind == "connectors" {
                connectors_document()
            } else if TENANT_CALLS.contains(&kind) {
                let tenant = operation["tenant"].as_str().unwrap();
                if !connected.iter().any(|(t, _)| t == tenant) {
                    let spec = tenants.iter().find(|t| t["name"] == tenant).unwrap();
                    connected.push((tenant.to_owned(), connect(spec, &plan["urls"])));
                }
                match &connected.iter().find(|(t, _)| t == tenant).unwrap().1 {
                    Ok(connection) => {
                        tenant_call(connection, operation).unwrap_or_else(|e| tenant_error(&e))
                    }
                    Err(e) => tenant_error(e),
                }
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
        "tenants": manifest["tenants"],
        "stand_ins": manifest["stand_ins"],
        "urls": {},
    })
}

#[test]
fn the_rust_runner_writes_every_document() {
    let corpus = common::tide_corpus();
    let scratch = tempfile::tempdir().unwrap();
    let (mut plan, out, driven): (Value, PathBuf, bool) = match std::env::var_os(PLAN_ENV) {
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
    let stand_ins = if driven {
        Vec::new()
    } else {
        start_stand_ins(&mut plan)
    };
    let written = run_plan(&plan, &out, diverge);
    drop(stand_ins);
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
        // The tenant operations reached the stand-ins.
        let read = |name: &str| -> Value {
            serde_json::from_str(
                &std::fs::read_to_string(out.join(format!("tide_corpus/{name}.json"))).unwrap(),
            )
            .unwrap()
        };
        assert_eq!(read("query-soc")["rows"][0]["endpoint.name"], "ws-1");
        assert_eq!(
            read("deploy-soc-create"),
            serde_json::json!({"remote_id": "1900000000000000001", "operation": "create"})
        );
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
