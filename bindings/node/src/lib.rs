//! # opentide-node
//!
//! The napi-rs binding of the [`opentide`] facade, compiled into the npm
//! package `@opentide/opentide` (UC-5.3, #838): the SDK (`Workspace` and its
//! methods), the command line as a function (`main(argv)`, which the
//! package's `opentide` bin calls in-process) and `runJson(argv)`.
//!
//! A thin wrapper (ADR 0005): each function converts its arguments, calls one
//! facade function and converts the result. napi-derive writes the
//! TypeScript declarations (`index.d.ts`) from the `#[napi]` items; the
//! package's `npm run build` regenerates them and CI fails when the
//! committed file differs.
//!
//! Documents keep the command line's JSON: the facade's types serialise in
//! their field order and a [`opentide::Document`] is handed to `JSON.parse`
//! as the CLI wrote it, so keys come in the order `opentide --json` prints
//! them.

use std::collections::HashMap;
use std::io::Write as _;

use napi::bindgen_prelude::{Function, JsObjectValue, JsValue, Null, Object, Unknown};
use napi::{Env, JSON};
use napi_derive::napi;
use serde::Serialize;

use opentide::lint::{LintCheck, LintFinding, LintStatus, LintSummary, NextAction};
use opentide::validate::{Check, QueriesMode, Report, Summary};

/// The version the command line reports (`opentide --version`): the npm
/// package's, which the build passes as `OPENTIDE_VERSION`.
#[napi]
pub const VERSION: &str = opentide::cli::VERSION;

/// Runs `opentide` with `argv` (without the program name) in this process,
/// on its environment, working directory and standard streams, and returns
/// the exit code. The package's `opentide` bin exits with it.
///
/// Ctrl-C stops the run, which then returns 130 (`error: interrupted`); a
/// second Ctrl-C ends the process at once, as the PyPI CLI does.
#[napi]
pub fn main(argv: Vec<String>) -> i32 {
    let code = opentide::cli::main(&argv);
    // Node exits without Rust's runtime: flush what the run left buffered.
    let _ignored = std::io::stdout().flush();
    code
}

/// Runs `opentide --json <argv>` in this process and returns its JSON
/// document, keys in the command line's order: the envelope (`ok`,
/// `command`, `result`, `failure`, ...) or, for `commands`, the command tree.
/// A command that fails still returns its document, with `ok: false`.
///
/// Throws an `Error` whose `code` is `no_json_document` when the command
/// wrote no document (`--version`).
#[napi(ts_return_type = "any")]
pub fn run_json(env: &Env, argv: Vec<String>) -> napi::Result<Unknown<'_>> {
    let document = opentide::cli::run_json(argv).map_err(|e| throw(*env, e.into()))?;
    parse(env, document.as_str())
}

/// How `Workspace.open` opens a workspace.
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    /// The folder paths in findings are shown from (default: the
    /// workspace's own folder).
    pub cwd: Option<String>,
}

/// What `Workspace.validate` runs: `opentide validate`'s options.
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct ValidateOptions {
    /// `--check`: one check, else the default ones.
    #[napi(
        ts_type = "'id-uniqueness' | 'uuid-format' | 'schema' | 'cve' | 'sharing-config' | 'configuration' | 'queries'"
    )]
    pub check: Option<String>,
    /// `--file`: object files, by path or by name.
    pub files: Option<Vec<String>>,
    /// `--uuid`: objects by UUID.
    pub uuids: Option<Vec<String>>,
    /// `--type`: object families (`rule`, `threat`, `objective`).
    pub types: Option<Vec<String>>,
    /// `--strict`: a warning fails the run too.
    pub strict: Option<bool>,
    /// `--queries`: a query the engine rejects as an error (the default), a
    /// warning, or not checked.
    #[napi(ts_type = "'error' | 'warn' | 'off'")]
    pub queries: Option<String>,
}

/// What `Workspace.lint` runs: `opentide lint`'s options, without `--fix`
/// and `--changed` (the command line's).
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct LintOptions {
    /// `--check`; empty runs the checks `lint.toml` enables.
    #[napi(ts_type = "Array<'filenames' | 'metadata' | 'placeholders' | 'queries'>")]
    pub checks: Option<Vec<String>>,
    /// `--strict`: any finding fails the run.
    pub strict: Option<bool>,
    /// `--file`: object files, by path or by name.
    pub files: Option<Vec<String>>,
}

/// What `Workspace.deployPlan` plans: `opentide deploy --dry-run`'s options.
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct DeployPlanOptions {
    /// `--strategy` (repeatable); default `['RELEASE']`.
    #[napi(ts_type = "Array<'PREVIEW' | 'RELEASE'>")]
    pub strategies: Option<Vec<String>>,
    /// `--uuid`: objects by UUID.
    pub uuids: Option<Vec<String>>,
    /// `--file`: object files.
    pub files: Option<Vec<String>>,
    /// `--platform`: one platform.
    pub platform: Option<String>,
    /// `--keep-deprecated` (`true`) or `--no-keep-deprecated` (`false`);
    /// unset: the configuration's.
    pub keep_deprecated: Option<bool>,
}

/// A Tide workspace: its configuration, resolved once, and every object file,
/// read and parsed once into one index. Each method reads that index.
#[napi]
pub struct Workspace {
    inner: opentide::Workspace,
}

#[napi]
impl Workspace {
    /// Opens the workspace at `path` on disk: a repository holding
    /// `.opentide/` or `objects/`, or a folder inside one.
    #[napi(factory)]
    pub fn open(env: &Env, path: String, options: Option<OpenOptions>) -> napi::Result<Self> {
        let mut open = opentide::Options::default();
        if let Some(cwd) = options.and_then(|options| options.cwd) {
            open = open.cwd(cwd);
        }
        Ok(Self {
            inner: opentide::Workspace::open(path, &open).map_err(|e| throw(*env, e.into()))?,
        })
    }

    /// Opens a workspace held in memory, rooted at `root`: each key of
    /// `files` is a path (relative to `root`, or absolute), each value its
    /// text. Nothing is read from or written to the disk.
    #[napi(factory)]
    pub fn from_files(
        env: &Env,
        root: String,
        files: HashMap<String, String>,
    ) -> napi::Result<Self> {
        Ok(Self {
            inner: opentide::Workspace::from_files(root, files)
                .map_err(|e| throw(*env, e.into()))?,
        })
    }

    /// The workspace folder: the one that holds `.opentide/` and `objects/`.
    #[napi(getter)]
    pub fn root(&self) -> String {
        self.inner.root().to_string_lossy().into_owned()
    }

    /// Runs every check of `opentide validate`: `checks`, `report` and
    /// `summary` as `validate --json` writes them, whether the run fails, and
    /// its exit code.
    #[napi(
        ts_return_type = "{ checks: Record<string, { check: string; status: string }>; report: any; summary: any; failed: boolean; warned: boolean; exitCode: number }"
    )]
    pub fn validate<'env>(
        &self,
        env: &'env Env,
        options: Option<ValidateOptions>,
    ) -> napi::Result<Unknown<'env>> {
        let options = validate_options(options.unwrap_or_default()).map_err(|e| throw(*env, e))?;
        let validation = self.inner.validate(&options);
        env.to_js_value(&ValidationJs {
            checks: Checks(&validation.checks),
            report: &validation.report,
            summary: &validation.summary,
            failed: validation.failed,
            warned: validation.warned,
            exit_code: validation.exit_code(),
        })
    }

    /// Runs `opentide lint` (its `lint.toml`, or the checks `options` names)
    /// without fixing anything: `findings` and `summary` as `lint --json`
    /// writes them, the status, the message and the exit code.
    #[napi(
        ts_return_type = "{ path: string; checks: string[]; findings: any[]; status: 'completed' | 'issues' | 'failed'; message: string; exitCode: number; failureCode: string | null; summary: any | null; outcome: string | null; unmatched: string[]; warnings: string[]; nextActions: Array<{ command: string; reason: string }> }"
    )]
    pub fn lint<'env>(
        &self,
        env: &'env Env,
        options: Option<LintOptions>,
    ) -> napi::Result<Unknown<'env>> {
        let options = lint_options(options.unwrap_or_default()).map_err(|e| throw(*env, e))?;
        let report = self.inner.lint(&options);
        env.to_js_value(&LintJs {
            path: report.path.to_string_lossy().into_owned(),
            checks: report.checks.iter().map(|check| check.name()).collect(),
            findings: &report.findings,
            status: report.status,
            message: &report.message,
            exit_code: report.exit_code,
            failure_code: report.failure_code,
            summary: report.summary.as_ref(),
            outcome: report.outcome.as_deref(),
            unmatched: &report.unmatched,
            warnings: &report.warnings,
            next_actions: &report.next_actions,
        })
    }

    /// What `opentide info` reports: the object counts, the files that did
    /// not load and each platform with its tenants (the environment
    /// variables each reads and whether each is set, never their values).
    #[napi(ts_return_type = "any")]
    pub fn info<'env>(&self, env: &'env Env) -> napi::Result<Unknown<'env>> {
        env.to_js_value(&self.inner.info())
    }

    /// The catalogue (`opentide info catalog`): every object with its
    /// techniques and platforms, every edge, the signals and the ATT&CK
    /// matrix.
    #[napi(ts_return_type = "any")]
    pub fn catalog<'env>(&self, env: &'env Env) -> napi::Result<Unknown<'env>> {
        env.to_js_value(&self.inner.catalog())
    }

    /// The detection rules: their rows of the catalogue (`uuid`, `type`,
    /// `schema`, `name`, `path`, `techniques`, ...), in index order.
    #[napi(ts_return_type = "any[]")]
    pub fn rules<'env>(&self, env: &'env Env) -> napi::Result<Unknown<'env>> {
        env.to_js_value(&self.inner.rules())
    }

    /// The detection objectives: their rows of the catalogue.
    #[napi(ts_return_type = "any[]")]
    pub fn objectives<'env>(&self, env: &'env Env) -> napi::Result<Unknown<'env>> {
        env.to_js_value(&self.inner.objectives())
    }

    /// The threat vectors: their rows of the catalogue.
    #[napi(ts_return_type = "any[]")]
    pub fn threats<'env>(&self, env: &'env Env) -> napi::Result<Unknown<'env>> {
        env.to_js_value(&self.inner.threats())
    }

    /// The rules that cover the ATT&CK `technique` (`opentide info coverage
    /// --technique`), their own techniques or inherited ones.
    #[napi(
        ts_return_type = "{ technique: string; rules: string[]; count: number; own: string[]; inherited: string[]; matched_techniques: string[] }"
    )]
    pub fn coverage<'env>(&self, env: &'env Env, technique: String) -> napi::Result<Unknown<'env>> {
        env.to_js_value(&self.inner.coverage(&technique))
    }

    /// The deploy plan: what `opentide deploy --dry-run` would send, computed
    /// locally. Nothing is sent and nothing is written. `document` is
    /// `deploy --dry-run --json`'s `result`.
    #[napi(ts_return_type = "{ document: any; summary: any | null; ok: boolean }")]
    pub fn deploy_plan<'env>(
        &self,
        env: &'env Env,
        options: Option<DeployPlanOptions>,
    ) -> napi::Result<Unknown<'env>> {
        let options =
            deploy_plan_options(options.unwrap_or_default()).map_err(|e| throw(*env, e))?;
        let plan = self
            .inner
            .deploy_plan(&options)
            .map_err(|e| throw(*env, e.into()))?;
        let mut object = Object::new(env)?;
        object.set_named_property("document", parse(env, plan.document().as_str())?)?;
        match plan.summary() {
            Some(summary) => object.set_named_property("summary", parse(env, summary.as_str())?)?,
            None => object.set_named_property("summary", Null)?,
        }
        object.set_named_property("ok", plan.ok())?;
        Ok(object.to_unknown())
    }
}

/// `Workspace.validate`'s result, in this order.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidationJs<'a> {
    checks: Checks<'a>,
    report: &'a Report,
    summary: &'a Summary,
    failed: bool,
    warned: bool,
    exit_code: i32,
}

/// `checks` as `validate --json` writes it, in the order the checks ran:
/// each check's name to its name and status. (`Validation::checks_json` is
/// the same map in a `serde_json::Value`, whose keys come sorted.)
struct Checks<'a>(&'a [(Check, &'static str)]);

impl Serialize for Checks<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (check, status) in self.0 {
            map.serialize_entry(
                check.name(),
                &CheckStatus {
                    check: check.name(),
                    status,
                },
            )?;
        }
        map.end()
    }
}

/// One entry of `checks`.
#[derive(Serialize)]
struct CheckStatus<'a> {
    check: &'a str,
    status: &'a str,
}

/// `Workspace.lint`'s result, in this order.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LintJs<'a> {
    path: String,
    checks: Vec<&'static str>,
    findings: &'a [LintFinding],
    status: LintStatus,
    message: &'a str,
    exit_code: i32,
    failure_code: Option<&'static str>,
    summary: Option<&'a LintSummary>,
    outcome: Option<&'a str>,
    unmatched: &'a [String],
    warnings: &'a [String],
    next_actions: &'a [NextAction],
}

/// `text` (a JSON document) through `JSON.parse`, which keeps its key order.
fn parse<'env>(env: &'env Env, text: &str) -> napi::Result<Unknown<'env>> {
    let json: JSON = env.get_global()?.get_named_property_unchecked("JSON")?;
    let parse: Function<String, Unknown> = json.get_named_property_unchecked("parse")?;
    parse.call(text.to_owned())
}

/// Why a call failed: a stable code (`configuration_invalid`, `io_error`,
/// `no_json_document`, `usage_invalid_choice`, ...) and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Failure {
    code: String,
    message: String,
}

impl Failure {
    fn usage(message: String) -> Self {
        Self {
            code: "usage_invalid_choice".to_owned(),
            message,
        }
    }
}

impl From<opentide::Error> for Failure {
    fn from(error: opentide::Error) -> Self {
        Self {
            code: error.code().to_owned(),
            message: error.to_string(),
        }
    }
}

/// `failure` as the JavaScript `Error` the call throws: its `message`, and
/// its `code` the failure's code.
fn throw(env: Env, failure: Failure) -> napi::Error {
    let built = env
        .create_error(napi::Error::new(
            napi::Status::GenericFailure,
            failure.message.clone(),
        ))
        .and_then(|mut object| {
            object.set_named_property("code", failure.code.as_str())?;
            Ok(napi::Error::from(object.to_unknown()))
        });
    built.unwrap_or_else(|error| error)
}

fn validate_options(options: ValidateOptions) -> Result<opentide::ValidateOptions, Failure> {
    let mut out = opentide::ValidateOptions::default()
        .strict(options.strict.unwrap_or(false))
        .queries(queries_mode(options.queries.as_deref())?);
    if let Some(name) = options.check {
        let check = Check::parse(&name)
            .ok_or_else(|| Failure::usage(format!("check: unknown check `{name}`")))?;
        out = out.check(check);
    }
    for file in options.files.unwrap_or_default() {
        out = out.file(file);
    }
    for uuid in options.uuids.unwrap_or_default() {
        out = out.uuid(uuid);
    }
    for family in options.types.unwrap_or_default() {
        out = out.object_type(family);
    }
    Ok(out)
}

fn queries_mode(name: Option<&str>) -> Result<QueriesMode, Failure> {
    match name {
        None | Some("error") => Ok(QueriesMode::Error),
        Some("warn") => Ok(QueriesMode::Warn),
        Some("off") => Ok(QueriesMode::Off),
        Some(other) => Err(Failure::usage(format!(
            "queries: `{other}` is not error, warn or off"
        ))),
    }
}

fn lint_options(options: LintOptions) -> Result<opentide::LintOptions, Failure> {
    let mut out = opentide::LintOptions::default().strict(options.strict.unwrap_or(false));
    for name in options.checks.unwrap_or_default() {
        let check = LintCheck::parse(&name)
            .ok_or_else(|| Failure::usage(format!("checks: unknown check `{name}`")))?;
        out = out.check(check);
    }
    for file in options.files.unwrap_or_default() {
        out = out.file(file);
    }
    Ok(out)
}

fn deploy_plan_options(options: DeployPlanOptions) -> Result<opentide::DeployPlanOptions, Failure> {
    let mut out = opentide::DeployPlanOptions::default();
    let strategies = options
        .strategies
        .unwrap_or_else(|| vec!["RELEASE".to_owned()]);
    for name in strategies {
        let strategy = match name.as_str() {
            "PREVIEW" => opentide::Strategy::Preview,
            "RELEASE" => opentide::Strategy::Release,
            other => {
                return Err(Failure::usage(format!(
                    "strategies: `{other}` is not PREVIEW or RELEASE"
                )));
            }
        };
        out = out.strategy(strategy);
    }
    for uuid in options.uuids.unwrap_or_default() {
        out = out.uuid(uuid);
    }
    for file in options.files.unwrap_or_default() {
        out = out.file(file);
    }
    if let Some(platform) = options.platform {
        out = out.platform(platform);
    }
    out.keep_deprecated = options.keep_deprecated;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_convert_as_the_command_line_parses_them() {
        let options = validate_options(ValidateOptions {
            check: Some("schema".into()),
            files: Some(vec!["objects/rules/a.yaml".into()]),
            uuids: Some(vec!["u".into()]),
            types: Some(vec!["rule".into()]),
            strict: Some(true),
            queries: Some("off".into()),
        })
        .unwrap();
        assert_eq!(options.check, Some(Check::Schema));
        assert_eq!(options.files, ["objects/rules/a.yaml"]);
        assert_eq!(options.uuids, ["u"]);
        assert_eq!(options.types, ["rule"]);
        assert!(options.strict);
        assert_eq!(options.queries, QueriesMode::Off);
        assert_eq!(
            validate_options(ValidateOptions::default()).unwrap(),
            opentide::ValidateOptions::default()
        );

        let lint = lint_options(LintOptions {
            checks: Some(vec!["metadata".into()]),
            strict: Some(true),
            files: None,
        })
        .unwrap();
        assert_eq!(lint.checks, [LintCheck::Metadata]);

        let plan = deploy_plan_options(DeployPlanOptions {
            strategies: None,
            platform: Some("splunk".into()),
            keep_deprecated: Some(false),
            ..DeployPlanOptions::default()
        })
        .unwrap();
        assert_eq!(plan.strategies, [opentide::Strategy::Release]);
        assert_eq!(plan.platform.as_deref(), Some("splunk"));
        assert_eq!(plan.keep_deprecated, Some(false));
    }

    #[test]
    fn an_unknown_choice_is_a_usage_error() {
        let check = ValidateOptions {
            check: Some("nope".into()),
            ..ValidateOptions::default()
        };
        let queries = ValidateOptions {
            queries: Some("loud".into()),
            ..ValidateOptions::default()
        };
        let lint = LintOptions {
            checks: Some(vec!["nope".into()]),
            ..LintOptions::default()
        };
        let plan = DeployPlanOptions {
            strategies: Some(vec!["LATER".into()]),
            ..DeployPlanOptions::default()
        };
        let errors = [
            validate_options(check).unwrap_err(),
            validate_options(queries).unwrap_err(),
            lint_options(lint).unwrap_err(),
            deploy_plan_options(plan).unwrap_err(),
        ];
        for error in errors {
            assert_eq!(error.code, "usage_invalid_choice", "{error:?}");
        }
    }

    #[test]
    fn checks_keep_the_order_they_ran_in() {
        let ran = [(Check::Schema, "passed"), (Check::Configuration, "failed")];
        assert_eq!(
            serde_json::to_string(&Checks(&ran)).unwrap(),
            "{\"schema\":{\"check\":\"schema\",\"status\":\"passed\"},\
             \"configuration\":{\"check\":\"configuration\",\"status\":\"failed\"}}"
        );
    }

    #[test]
    fn a_facade_error_keeps_its_code() {
        let converted = Failure::from(opentide::Error::NoDocument {
            exit_code: 0,
            stderr: String::new(),
        });
        assert_eq!(converted.code, "no_json_document");
        assert!(converted.message.contains("wrote no JSON document"));
    }
}
