//! `opentide validate query --live` on the connectors (UC-4.6, #979): each
//! rule's queries checked on the tenants a deploy sends it to,
//! `cli/services/validation.py` (`_validate_query_platform`,
//! `_run_live_validator`), `platforms/live_validation.py`
//! (`LiveQueryValidator`) and `platforms/elastic/validator.py`
//! (`ElasticValidator`) step by step.
//!
//! The rules are the deploy plan's (`opentide_compile::plan::select`, with
//! the warnings `make_deploy_plan` logs), each sent to the tenants the plan
//! resolves for it (`rule_tenants`), with the platform's `[[modifiers]]`
//! applied for that tenant (`opentide_compile::modifiers`). Each query is
//! checked through the platform's [`LiveValidator`](opentide_connectors::connector::LiveValidator); an Elastic rule is
//! checked as a whole: its advisories, its Elasticsearch checks and a preview
//! of the rule deploy would create. A refusal fails that query, a query that
//! gets no answer in time fails itself, and three in a row (or a tenant that
//! answers nothing) report the tenant unreachable.
//!
//! Nothing here writes to the workspace. The run's result is the oracle's
//! dictionary ([`Live::result`]), keys in its order, read into the envelope
//! as `CommandResult.from_payload` reads it ([`report_of`]).

use std::path::Path;
use std::time::{Duration, Instant};

use super::interrupt::watched;
use indexmap::IndexMap;
use opentide_compile::Json as CJson;
use opentide_compile::plan::{SelectOptions, Tenant as PlanTenant};
use opentide_compile::strategy::{self, RunStrategies, StatusStrategy};
use opentide_connectors::connector::{LiveCheck, QueryRequest, TenantContext, TimeWindow};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::elastic::{Elastic, ElasticError};
use opentide_connectors::{ConnectorError, Environment, HttpClient, Registry, Tenant};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem as _, OsFs, Workspace};
use tokio_util::sync::CancellationToken;

use super::query::{
    Configured, default_host, http_settings, log_unset, toml_value, unset_credentials,
};
use super::validate_query::{Args, COMMAND};
use super::{Report, placement};
use crate::env::Env;
use crate::envelope::{Failure, NextAction, Outcome, code};
use crate::json::{Json, Object};
use crate::render::progress::{Progress, Step, StepStatus};

/// Queries in a row on one tenant that get no answer in time before the
/// tenant is reported unreachable (`UNREACHABLE_AFTER_TIMEOUTS`).
pub const UNREACHABLE_AFTER_TIMEOUTS: usize = 3;
/// The code of a check that got no answer within the check timeout.
pub const QUERY_CHECK_TIMEOUT: &str = "query_check_timeout";
/// `OPENTIDE_QUERY_CHECK_TIMEOUT`.
const CHECK_TIMEOUT_ENV: &str = super::validate_query::CHECK_TIMEOUT_ENV;
/// What a run that sent no query advises (`_no_tenant_reached`).
const NO_TENANT_ADVICE: &str = "a tenant takes a rule only when its 'strategies' accept the run \
     strategy that deploys the rule's status; a 'manual' tenant only when the rule lists it under \
     tenants; and a rule's tenants list must name a tenant configured for this platform";
/// Where Microsoft documents a custom detection's columns.
const DEFENDER_COLUMNS_DOCS: &str = "Per Microsoft documentation, Defender XDR custom detection \
     queries must include Timestamp or TimeGenerated, event identity columns for the queried \
     table family, and a supported impacted asset identifier in the output. See: \
     https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules";

/// What a run reads besides its options.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// `--repo`.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// `--proxy`.
    pub proxy: Option<&'a str>,
    /// Whether Ctrl-C was pressed.
    pub interrupted: &'a (dyn Fn() -> bool + Sync),
    /// The current time: the end of each check's window.
    pub now: jiff::Timestamp,
    /// The platforms' connectors.
    pub registry: &'a Registry,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("repo", &self.repo)
            .field("cwd", &self.cwd)
            .finish_non_exhaustive()
    }
}

/// A live run's outcome: the oracle's result dictionary and its checklist
/// step.
#[derive(Clone, Debug)]
pub struct Live {
    /// The result, keys in the oracle's order, `_`-keys included.
    pub result: Fields,
    /// The checklist's step, when the run reached the tenants.
    pub step: Option<Step>,
}

impl Live {
    fn of(result: Fields) -> Self {
        Self { result, step: None }
    }

    /// The result as one JSON object (the CI job summary reads it).
    pub fn result_json(&self) -> Json {
        Json::object(self.result.clone())
    }

    /// The report the command prints in *env*: the step's progress event
    /// (`OPENTIDE_PROGRESS=json`) first, written when the step ends, before
    /// its checklist row.
    pub fn report(&self, env: &Env) -> Report {
        let mut report = report_of(COMMAND, &self.result);
        report.steps = self.step.iter().cloned().collect();
        if let Some(step) = &self.step
            && Progress::from_env(env).enabled()
        {
            report.stderr_first = crate::render::progress::event_line(
                &crate::render::progress::progress_event(&step.name, 1, Some(1)),
            );
        }
        report
    }
}

/// The envelope of a service's result (`CommandResult.from_payload`):
/// `message`, `status` and `warnings` leave the data, as do `_exit_code`,
/// `_summary`, `_next_actions`, `_failure_code`, `_failure_argument` and
/// `_failure_suggestion`; a run that failed or exits non-zero has a
/// failure, with `error` (else the message) as its message.
pub fn report_of(command: &str, result: &[(String, Json)]) -> Report {
    let take = |key: &str| result.iter().find(|(name, _)| name == key).map(|(_, v)| v);
    let text = |key: &str| match take(key) {
        Some(Json::Str(text)) => Some(text.clone()),
        _ => None,
    };
    let exit_code = match take("_exit_code") {
        Some(Json::Int(code)) => i32::try_from(*code).unwrap_or(1),
        _ => 0,
    };
    let message = text("message").unwrap_or_else(|| "Completed successfully".to_owned());
    let status = text("status").unwrap_or_else(|| "completed".to_owned());
    let warnings: Vec<String> = match take("warnings") {
        Some(Json::Array(items)) => items
            .iter()
            .map(|item| match item {
                Json::Str(text) => text.clone(),
                other => crate::json::document_text(other, false),
            })
            .collect(),
        _ => Vec::new(),
    };
    let summary = match take("_summary") {
        Some(Json::Object(members)) => members.clone().into_iter().collect(),
        _ => Vec::new(),
    };
    let next_actions = match take("_next_actions") {
        Some(Json::Array(items)) => items
            .iter()
            .map(|item| {
                let field = |key: &str| item.get(key).and_then(Json::as_str).unwrap_or_default();
                NextAction::new(field("command"), field("reason"))
            })
            .collect(),
        _ => Vec::new(),
    };
    let ok = status != "failed";
    let failure = (!ok || exit_code != 0).then(|| {
        let default = match status.as_str() {
            "issues" => super::ISSUES_FOUND,
            "skipped" => "not_run",
            _ => super::COMMAND_FAILED,
        };
        let failure_code = text("_failure_code").unwrap_or_else(|| default.to_owned());
        let mut failure = Failure::new(
            &failure_code,
            text("error").unwrap_or_else(|| message.clone()),
        );
        failure.argument = text("_failure_argument");
        failure.suggestion = text("_failure_suggestion");
        failure
    });
    let data: Fields = result
        .iter()
        .filter(|(key, _)| {
            !key.starts_with('_') && !matches!(key.as_str(), "message" | "status" | "warnings")
        })
        .cloned()
        .collect();
    let mut report = Report::completed(command, data);
    report.outcome = Outcome {
        command: command.to_owned(),
        status,
        message,
        data: report.outcome.data,
        exit_code,
        summary,
        next_actions,
        failure,
    };
    report.warnings = warnings;
    report
}

/// The keys every live result starts with.
fn head(platform: Option<&str>, status: &str) -> Fields {
    vec![
        ("platform".into(), Json::opt_str(platform)),
        ("mode".into(), Json::str("live")),
        ("status".into(), Json::str(status)),
        ("supported".into(), Json::Bool(true)),
    ]
}

/// A failed result (`{**failed, "message": ..., "_exit_code": ...}`).
fn failed(platform: Option<&str>, message: &str, exit_code: i64) -> Fields {
    let mut result = head(platform, "failed");
    result.push(("message".into(), Json::str(message)));
    result.push(("_exit_code".into(), Json::Int(exit_code)));
    result
}

/// `value` set on `result`, in place when the key is there, else last.
fn set(result: &mut Fields, key: &str, value: Json) {
    match result.iter_mut().find(|(name, _)| name == key) {
        Some(entry) => entry.1 = value,
        None => result.push((key.to_owned(), value)),
    }
}

/// `1 rule`, `2 queries` (`plural`).
fn plural(count: usize, noun: &str, plural_noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {plural_noun}")
    }
}

/// The strategies' names, as a JSON list.
fn names(runs: &[StatusStrategy]) -> Json {
    Json::Array(runs.iter().map(|run| Json::str(run.name())).collect())
}

/// The skip message when no rule is checked, by scope label (`_NO_RULES_MESSAGES`).
fn no_rules_message(label: Option<&str>) -> &'static str {
    match label {
        Some("changed") => {
            "No changed rule for this platform has a status that maps to the run's strategies"
        }
        Some(_) => {
            "None of the selected rules has a status for this platform that maps to the run's \
             strategies"
        }
        None => "No rule for this platform has a status that maps to the run's strategies",
    }
}

/// `.opentide/configurations/platforms/<platform>.toml`, as advice names it.
fn config_path(platform: &str) -> String {
    format!(".opentide/configurations/platforms/{platform}.toml")
}

/// The check timeout `--check-timeout` or `OPENTIDE_QUERY_CHECK_TIMEOUT` names,
/// else 120 (`check_timeout`); `validate_query::live_usage` refused a value
/// that is not a positive number.
fn check_timeout(args: &Args, env: &Env) -> f64 {
    let raw = args.check_timeout.as_deref().or_else(|| {
        env.get(CHECK_TIMEOUT_ENV)
            .filter(|value| !value.trim().is_empty())
    });
    raw.and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
        .unwrap_or(120.0)
}

/// Runs `validate query --live` on one of the platforms whose tenants check
/// queries (`validate_query::LIVE_QUERY_PLATFORMS`), after the usage checks
/// (`validate_query::live`).
pub fn run(args: &Args, cx: &Context<'_>) -> Live {
    let platform = args.platform.as_deref();
    let Some(platform) = platform else {
        let mut result = failed(
            None,
            "--live checks one platform's tenants: pass --platform",
            2,
        );
        result.push((
            "_failure_code".into(),
            Json::str(code::USAGE_MISSING_OPTION),
        ));
        result.push(("_failure_argument".into(), Json::str("--platform")));
        return Live::of(result);
    };
    let mut live = live_platform(args, platform, cx);
    if args.changed
        && !live
            .result
            .iter()
            .any(|(key, value)| key == "status" && *value == Json::str("failed"))
    {
        let lookup = |name: &str| cx.env.get(name).map(str::to_owned);
        let (_, options) = placement(cx.repo, cx.env, cx.cwd);
        if let Ok(workspace) = super::open(options) {
            let root = OsFs.resolve(workspace.root());
            if let Some(note) = opentide_compile::git::no_commits_warning(
                &root,
                &lookup,
                "commit the rules, or drop --changed to check every rule",
            ) {
                let mut warnings = vec![Json::str(note)];
                if let Some((_, Json::Array(earlier))) =
                    live.result.iter().find(|(key, _)| key == "warnings")
                {
                    warnings.extend(earlier.iter().cloned());
                }
                set(&mut live.result, "warnings", Json::Array(warnings));
            }
            crate::app::release(workspace);
        }
    }
    live
}

/// The rule files a run reads (`None`: every one) and its scope's label.
type RuleScope = (Option<Vec<std::path::PathBuf>>, Option<&'static str>);

/// The rule scope `--changed`, `--file` and `--uuid` name (`_query_rule_scope`):
/// the files and the scope's label, or the refusal.
fn rule_scope(
    args: &Args,
    platform: &str,
    workspace: &Workspace,
    cx: &Context<'_>,
) -> Result<RuleScope, Fields> {
    if !(args.changed || !args.files.is_empty() || !args.uuids.is_empty()) {
        return Ok((None, None));
    }
    let refused = |message: &str, exit_code: i64| {
        let mut result = failed(Some(platform), message, exit_code);
        if exit_code == 2 {
            result.push(("_failure_code".into(), Json::str(code::USAGE_ERROR)));
        }
        result
    };
    if args.changed && (!args.files.is_empty() || !args.uuids.is_empty()) {
        return Err(refused(
            "--changed cannot be combined with --file or --uuid",
            2,
        ));
    }
    let fs = workspace.fs().as_ref();
    let (rules_dir, folder) = opentide_compile::dry_run::rules_folder(workspace);
    if args.changed {
        let lookup = |name: &str| cx.env.get(name).map(str::to_owned);
        let root = OsFs.resolve(workspace.root());
        let source = opentide_compile::git::diff_source(&lookup);
        let changed = opentide_compile::git::changed_paths(&root, cx.cwd, &lookup, source)
            .map_err(|error| match error {
                opentide_compile::git::GitError::MissingCheckout(searched) => refused(
                    &format!(
                        "--changed needs a git checkout; no .git was found from {}",
                        searched.display()
                    ),
                    1,
                ),
                opentide_compile::git::GitError::Failed(message) => refused(&message, 1),
            })?;
        let (top, _) = opentide_compile::git::split_rule_paths(&changed, &folder);
        let files: Vec<std::path::PathBuf> = top
            .iter()
            .filter_map(|path| Path::new(path).file_name().map(|name| rules_dir.join(name)))
            .collect();
        tracing::info!(rules = files.len(), "query_scope_changed");
        return Ok((Some(files), Some("changed")));
    }
    let local = opentide_compile::plan::local_scope(fs, &rules_dir, &folder);
    let request = opentide_compile::dry_run::Request {
        files: args.files.clone(),
        uuids: args.uuids.clone(),
        cwd: cx.cwd.to_path_buf(),
        ..Default::default()
    };
    let (scope, unmatched) =
        opentide_compile::dry_run::selected_scope(fs, workspace, &local, &request, cx.cwd);
    if !unmatched.is_empty() {
        let mut result = refused(
            &format!(
                "No rule file directly in {folder} matched: {}",
                unmatched.join(", ")
            ),
            1,
        );
        result.push((
            "unmatched".into(),
            Json::Array(unmatched.iter().map(Json::str).collect()),
        ));
        return Err(result);
    }
    Ok((Some(scope.files), Some("selected")))
}

/// `_scoped`: names the narrowed scope in *result*.
fn scoped(mut live: Live, label: Option<&str>) -> Live {
    if let Some(label) = label {
        set(&mut live.result, "scope", Json::str(label));
    }
    live
}

/// One rule as one tenant receives it: the platform's modifiers applied.
#[derive(Clone, Debug)]
pub(crate) struct Sent {
    pub(crate) rule: opentide_compile::Rule,
}

/// The rules of one tenant (`DeploymentBatch`).
#[derive(Debug)]
pub(crate) struct Batch {
    pub(crate) tenant: Configured,
    pub(crate) table: CJson,
    pub(crate) rules: Vec<Sent>,
}

fn live_platform(args: &Args, platform: &str, cx: &Context<'_>) -> Live {
    if let Some(value) = cx
        .env
        .get(strategy::REMOVED_PLAN_ENV)
        .filter(|value| !value.trim().is_empty())
    {
        let mut result = failed(
            Some(platform),
            &strategy::removed_plan_message(Some(value), false),
            2,
        );
        result.push(("_failure_code".into(), Json::str(code::USAGE_INVALID_VALUE)));
        return Live::of(result);
    }
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = match super::open(options) {
        Ok(workspace) => workspace,
        Err(message) => return Live::of(failed(Some(platform), &message, 1)),
    };
    let live = with_workspace(args, platform, &workspace, cx);
    crate::app::release(workspace);
    live
}

/// A run's result as a list of fields (the oracle's result dict).
type Fields = Vec<(String, Json)>;

/// `_validate_query_platform` with a workspace: the strategies, the rules
/// selected, their tenants, then the check and its result.
fn with_workspace(args: &Args, platform: &str, workspace: &Workspace, cx: &Context<'_>) -> Live {
    let owned = opentide_compile::Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let runs = match run_strategies(args, platform, &owned) {
        Ok(runs) => runs,
        Err(result) => return Live::of(result),
    };
    let (files, label) = match rule_scope(args, platform, workspace, cx) {
        Ok(scope) => scope,
        Err(result) => return Live::of(result),
    };
    let config = &owned.config;
    let enabled = opentide_compile::plan::enabled(config);
    let selection = match select_rules(args, platform, workspace, files, &owned, &runs, &enabled) {
        Ok(selection) => selection,
        Err(result) => return Live::of(result),
    };
    let Some(uuids) = selection.platforms.get(platform) else {
        return Live::of(nothing_selected(platform, &enabled, &runs, label));
    };
    let tables = opentide_compile::plan::tenants(config, platform);
    if tables.is_empty() {
        return Live::of(no_tenants(platform));
    }
    log_unset(&configured_tenants(&tables), cx.env, "a live check");
    let compile_cx = owned.context(workspace.index());
    let batches = match batches(
        platform,
        uuids,
        &tables,
        &runs,
        args.wide,
        workspace,
        &compile_cx,
    ) {
        Ok(batches) => batches,
        Err(message) => return Live::of(failed(Some(platform), &message, 1)),
    };
    let reach = Reach {
        runs: &runs,
        tenants: batches
            .iter()
            .map(|batch| (batch.tenant.name.clone(), batch.rules.len()))
            .collect(),
    };
    if reach.tenants.is_empty() {
        let reaches_any = runs != strategy::DEPLOYABLE.to_vec()
            && batches_reach_any(platform, uuids, &tables, args.wide, workspace, &compile_cx);
        return scoped(
            Live::of(no_tenant_reached(platform, uuids.len(), &runs, reaches_any)),
            label,
        );
    }
    let timeout = check_timeout(args, cx.env);
    let mut step = Step::new(&format!("{} queries", system_name(config, platform)));
    step.unit = "rule".into();
    step.count = Some(uuids.len());
    let started = Instant::now();
    let checked = check_batches(platform, &batches, timeout, cx, &compile_cx);
    step.seconds = started.elapsed().as_secs_f64();
    let result = match checked {
        Err(early) => {
            step.status = StepStatus::Failed;
            stopped_early(platform, early, &reach)
        }
        Ok(report) => {
            // A run that rejected a query is no tick (#1658, E8).
            step.status = if report.checks.iter().any(|check| !check.errors.is_empty()) {
                StepStatus::Failed
            } else {
                StepStatus::Ok
            };
            checked_result(platform, &report, &reach, timeout)
        }
    };
    scoped(
        Live {
            result,
            step: Some(step),
        },
        label,
    )
}

/// The strategies `--strategy` names (every deployable one without it), or
/// the usage refusal.
fn run_strategies(
    args: &Args,
    platform: &str,
    owned: &opentide_compile::Owned,
) -> Result<RunStrategies, Fields> {
    if args.strategies.is_empty() {
        return Ok(strategy::DEPLOYABLE.to_vec());
    }
    strategy::parse_strategies(&args.strategies, &owned.statuses, "--strategy").map_err(|message| {
        let mut result = failed(Some(platform), &message, 2);
        result.push((
            "_failure_code".into(),
            Json::str(code::USAGE_INVALID_CHOICE),
        ));
        result
    })
}

/// The rules of the scope the run strategies deploy, per platform, or the
/// failure to read them.
fn select_rules(
    args: &Args,
    platform: &str,
    workspace: &Workspace,
    files: Option<Vec<std::path::PathBuf>>,
    owned: &opentide_compile::Owned,
    runs: &RunStrategies,
    enabled: &[String],
) -> Result<opentide_compile::plan::Selection, Fields> {
    let fs = workspace.fs().as_ref();
    let (rules_dir, folder) = opentide_compile::dry_run::rules_folder(workspace);
    let scope = match files {
        Some(files) => opentide_compile::plan::Scope {
            files,
            nested: Vec::new(),
        },
        None => opentide_compile::plan::local_scope(fs, &rules_dir, &folder),
    };
    let read = |path: &Path| -> Result<opentide_schema::node::Node, String> {
        let bytes = fs.read(path).map_err(|error| error.to_string())?;
        let document =
            opentide_schema::node::load_bytes(&bytes).map_err(|error| error.to_string())?;
        document
            .root()
            .map(|root| (**root).clone())
            .ok_or_else(|| "the file is empty".to_owned())
    };
    opentide_compile::plan::select(
        &owned.statuses,
        &scope,
        &read,
        &SelectOptions {
            runs,
            wide: args.wide,
            keep_deprecated: false,
            enabled,
            folder: &folder,
            log: true,
        },
    )
    .map_err(|error| match error {
        opentide_compile::plan::PlanError::ObjectFile { path, problem } => {
            failed(Some(platform), &format!("{}: {problem}", path.display()), 1)
        }
        opentide_compile::plan::PlanError::Failed(message) => failed(Some(platform), &message, 1),
    })
}

/// No rule selected for the platform: it is disabled, or no rule of the
/// scope and strategies names it.
fn nothing_selected(
    platform: &str,
    enabled: &[String],
    runs: &RunStrategies,
    label: Option<&str>,
) -> Fields {
    if !enabled.iter().any(|known| known == platform) {
        return vec![
            ("platform".into(), Json::str(platform)),
            ("mode".into(), Json::str("live")),
            ("status".into(), Json::str("skipped")),
            ("platform_enabled".into(), Json::Bool(false)),
            (
                "message".into(),
                Json::str(format!(
                    "Platform {platform} is disabled in configurations, so no rule is \
                     checked for it"
                )),
            ),
            (
                "advice".into(),
                Json::str(format!(
                    "enable it with 'opentide setup platforms --{}'",
                    platform.replace('_', "-")
                )),
            ),
        ];
    }
    let mut result = vec![
        ("platform".into(), Json::str(platform)),
        ("mode".into(), Json::str("live")),
        ("status".into(), Json::str("skipped")),
        ("strategies".into(), names(runs)),
        ("message".into(), Json::str(no_rules_message(label))),
    ];
    if let Some(label) = label {
        result.push(("scope".into(), Json::str(label)));
    }
    result
}

/// The platform has no `[[tenants]]` entry.
fn no_tenants(platform: &str) -> Fields {
    let path = config_path(platform);
    let mut result = failed(
        Some(platform),
        &format!(
            "Cannot run live query validation: {platform} has no tenants configured in {path}"
        ),
        1,
    );
    let at = result.len() - 1;
    result.insert(
        at,
        (
            "advice".into(),
            Json::str(format!("add (or uncomment) a [[tenants]] entry in {path}")),
        ),
    );
    result.insert(
        at + 1,
        (
            "missing_tenants".into(),
            Json::object([(platform, Json::str(&path))]),
        ),
    );
    result
}

/// Each tenant table's name and setup.
fn configured_tenants(tables: &[&CJson]) -> Vec<Configured> {
    tables
        .iter()
        .map(|table| Configured {
            name: opentide_compile::deploy::tenant_name(table).to_owned(),
            setup: table
                .get("setup")
                .and_then(CJson::as_object)
                .cloned()
                .unwrap_or_default(),
        })
        .collect()
}

/// No selected rule goes to a tenant: one goes there under another strategy
/// (`reaches_any`), or none goes to any tenant at all (exit 2).
fn no_tenant_reached(
    platform: &str,
    rules: usize,
    runs: &RunStrategies,
    reaches_any: bool,
) -> Fields {
    let mut result = vec![
        ("platform".into(), Json::str(platform)),
        ("mode".into(), Json::str("live")),
        ("status".into(), Json::str("skipped")),
        ("supported".into(), Json::Bool(true)),
        ("strategies".into(), names(runs)),
        ("queries_validated".into(), Json::Int(0)),
        ("queries_per_tenant".into(), Json::Object(Object::new())),
    ];
    if reaches_any {
        let joined: Vec<&str> = runs.iter().map(|run| run.name()).collect();
        result.push((
            "message".into(),
            Json::str(format!(
                "None of the {rules} {platform} rule(s) goes to a tenant accepting {}; they are \
                 checked by a run with the strategy that deploys them, or without --strategy",
                joined.join(" and ")
            )),
        ));
    } else {
        result.push((
            "message".into(),
            Json::str(format!(
                "No query was sent: none of the {rules} {platform} rule(s) goes to a tenant in {}",
                config_path(platform)
            )),
        ));
        result.push(("advice".into(), Json::str(NO_TENANT_ADVICE)));
        result.push(("_exit_code".into(), Json::Int(2)));
        result.push(("_failure_code".into(), Json::str("no_tenant_reached")));
    }
    result
}

/// The platform's configured display name (`[platforms.<p>.platform] name`),
/// or its key.
fn system_name(config: &CJson, platform: &str) -> String {
    config
        .get("platforms")
        .and_then(|platforms| platforms.get(platform))
        .and_then(|table| table.get("platform"))
        .and_then(|block| block.get("name"))
        .filter(|name| name.is_filled())
        .map_or_else(|| platform.to_owned(), opentide_compile::deploy::text)
}

/// The strategies a run checked with and the queries it sends each tenant.
struct Reach<'a> {
    runs: &'a RunStrategies,
    tenants: Vec<(String, usize)>,
}

impl Reach<'_> {
    /// The queries sent, over every tenant.
    fn queries(&self) -> usize {
        self.tenants.iter().map(|(_, count)| count).sum()
    }

    /// `strategies`, `queries_validated` and `queries_per_tenant`.
    fn push_counts(&self, result: &mut Fields) {
        result.push(("strategies".into(), names(self.runs)));
        result.push(("queries_validated".into(), Json::from(self.queries())));
        result.push((
            "queries_per_tenant".into(),
            Json::Object(
                self.tenants
                    .iter()
                    .map(|(tenant, count)| (tenant.clone(), Json::from(*count)))
                    .collect(),
            ),
        ));
    }
}

/// The result of a check that did not finish: a setup that cannot be used,
/// an unreachable tenant, or a crash.
fn stopped_early(platform: &str, early: Early, reach: &Reach<'_>) -> Fields {
    match early {
        Early::Failed(message) => failed(Some(platform), &message, 1),
        Early::Unreachable(unreachable) => unreachable.result(platform),
        Early::Refused(refused) => refused.result(platform),
        Early::Crashed(error) => {
            tracing::error!(
                system = platform,
                detail = error.as_str(),
                "query_validation_failed"
            );
            let mut result = head(Some(platform), "failed");
            reach.push_counts(&mut result);
            result.push((
                "message".into(),
                Json::str(format!("Query validation for {platform} failed: {error}")),
            ));
            result.push(("_exit_code".into(), Json::Int(1)));
            result
        }
    }
}

/// The result of a check every tenant answered: passed, or failed with the
/// rejected queries; the checks that timed out, and the warnings.
fn checked_result(platform: &str, report: &CheckReport, reach: &Reach<'_>, timeout: f64) -> Fields {
    let failed_any = report.checks.iter().any(|check| !check.errors.is_empty());
    let warned = report.checks.iter().any(|check| !check.warnings.is_empty());
    let queries = reach.queries();
    let tenants = plural(reach.tenants.len(), "tenant", "tenants");
    let mut message = if failed_any {
        format!("Queries rejected on {platform} · {queries} checked on {tenants}")
    } else {
        format!("{} valid on {tenants}", plural(queries, "query", "queries"))
    };
    let timed_out: Vec<&RuleCheck> = report
        .checks
        .iter()
        .filter(|check| check.code.is_some())
        .collect();
    if !timed_out.is_empty() {
        message.push_str(&format!(
            " · {} with no answer within {}s",
            timed_out.len(),
            timeout
        ));
    }
    let mut result = head(Some(platform), if failed_any { "failed" } else { "passed" });
    reach.push_counts(&mut result);
    result.push(("message".into(), Json::str(&message)));
    result.push((
        "_summary".into(),
        Json::object([
            ("queries", Json::from(queries)),
            ("tenants", Json::from(reach.tenants.len())),
        ]),
    ));
    result.push(("_exit_code".into(), Json::Int(i64::from(failed_any))));
    if !timed_out.is_empty() {
        push_timed_out(&mut result, report, &timed_out, timeout);
    }
    if failed_any {
        result.push(("error".into(), Json::str(&message)));
    }
    if warned {
        result.push((
            "warnings".into(),
            Json::Array(vec![Json::str(format!(
                "Query validation reported warnings for {platform}"
            ))]),
        ));
    }
    result
}

/// `check_timeout`, `timed_out` and the advice; `query_check_timeout` when
/// every rejection is a timeout.
fn push_timed_out(
    result: &mut Fields,
    report: &CheckReport,
    timed_out: &[&RuleCheck],
    timeout: f64,
) {
    result.push(("check_timeout".into(), Json::Float(timeout)));
    result.push((
        "timed_out".into(),
        Json::Array(timed_out.iter().map(|check| check.to_json()).collect()),
    ));
    result.push((
        "advice".into(),
        Json::str(format!(
            "raise the check timeout with --check-timeout or {CHECK_TIMEOUT_ENV}, or make the \
             queries cheaper"
        )),
    ));
    let rejected = report
        .checks
        .iter()
        .filter(|check| !check.errors.is_empty())
        .count();
    if timed_out.len() == rejected {
        result.push(("_failure_code".into(), Json::str(QUERY_CHECK_TIMEOUT)));
    }
}

/// The rule *uuid* as the index holds it, with its file.
pub(crate) fn rule_of(workspace: &Workspace, uuid: &str) -> Option<opentide_compile::Rule> {
    let object = workspace.index().get("rule", uuid)?;
    let root = object.root()?;
    let file = object
        .path
        .strip_prefix(workspace.root())
        .map(opentide_workspace::index::posix)
        .ok();
    Some(opentide_compile::Rule::new(root, file))
}

/// The rule's block on *platform*, its status and the strategy that maps to.
pub(crate) fn block_strategy(
    rule: &opentide_compile::Rule,
    platform: &str,
    cx: &opentide_compile::Context<'_>,
) -> Result<(CJson, StatusStrategy), String> {
    let block = rule.block(platform).cloned().unwrap_or(CJson::Null);
    let status = block
        .get("status")
        .map(opentide_compile::deploy::text)
        .unwrap_or_default();
    let strategy = cx.statuses.strategy(&status).map_err(|error| match error {
        strategy::StatusError::Invalid(message) => message,
        other @ strategy::StatusError::Unknown(_) => other.to_string(),
    })?;
    Ok((block, strategy))
}

/// The tenants' batches: each rule, in plan order, added to every tenant it
/// reaches, the platform's modifiers applied for that tenant
/// (`TideDeployment.deployment_resolver`). Tenants come in the order a rule
/// first reaches them.
pub(crate) fn batches(
    platform: &str,
    uuids: &[String],
    tables: &[&CJson],
    runs: &[StatusStrategy],
    wide: bool,
    workspace: &Workspace,
    cx: &opentide_compile::Context<'_>,
) -> Result<Vec<Batch>, String> {
    let tenants: Vec<PlanTenant> = tables
        .iter()
        .map(|table| PlanTenant::from_json(table))
        .collect();
    let modifiers = opentide_compile::modifiers::of_platform(cx.config, platform);
    let mut out: IndexMap<String, Batch> = IndexMap::new();
    for uuid in uuids {
        let Some(rule) = rule_of(workspace, uuid) else {
            return Err(format!("rule {uuid} is not in the workspace"));
        };
        let (block, strategy) = block_strategy(&rule, platform, cx)?;
        for tenant in opentide_compile::plan::rule_tenants(&tenants, &block, strategy, runs, wide) {
            let sent = opentide_compile::modifiers::rule_for_tenant(
                &modifiers,
                platform,
                &rule,
                &tenant.name,
            );
            let entry = out.entry(tenant.name.clone()).or_insert_with(|| {
                let position = tenants
                    .iter()
                    .position(|known| known.name == tenant.name)
                    .unwrap_or(0);
                let table = tables
                    .get(position)
                    .map_or(CJson::Null, |table| (*table).clone());
                Batch {
                    tenant: Configured {
                        name: tenant.name.clone(),
                        setup: table
                            .get("setup")
                            .and_then(CJson::as_object)
                            .cloned()
                            .unwrap_or_default(),
                    },
                    table,
                    rules: Vec::new(),
                }
            });
            entry.rules.push(Sent { rule: sent });
        }
    }
    Ok(out.into_values().collect())
}

/// Whether any rule reaches a tenant under every deployable strategy.
fn batches_reach_any(
    platform: &str,
    uuids: &[String],
    tables: &[&CJson],
    wide: bool,
    workspace: &Workspace,
    cx: &opentide_compile::Context<'_>,
) -> bool {
    batches(
        platform,
        uuids,
        tables,
        &strategy::DEPLOYABLE,
        wide,
        workspace,
        cx,
    )
    .is_ok_and(|batches| !batches.is_empty())
}

// ---------------------------------------------------------------- the checks

/// One rule's query, checked on one tenant (`RuleCheck`).
#[derive(Clone, Debug)]
struct RuleCheck {
    rule: String,
    name: String,
    tenant: String,
    label: Option<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
    code: Option<&'static str>,
}

impl RuleCheck {
    fn to_json(&self) -> Json {
        let mut members = vec![
            ("rule".to_owned(), Json::str(&self.rule)),
            ("name".to_owned(), Json::str(&self.name)),
            ("tenant".to_owned(), Json::str(&self.tenant)),
            (
                "status".to_owned(),
                Json::str(if self.errors.is_empty() {
                    "passed"
                } else {
                    "failed"
                }),
            ),
            (
                "errors".to_owned(),
                Json::Array(self.errors.iter().map(Json::str).collect()),
            ),
            (
                "warnings".to_owned(),
                Json::Array(self.warnings.iter().map(Json::str).collect()),
            ),
        ];
        if let Some(label) = &self.label {
            members.push(("label".to_owned(), Json::str(label)));
        }
        if let Some(code) = self.code {
            members.push(("code".to_owned(), Json::str(code)));
        }
        Json::object(members)
    }
}

/// Every check one platform's live validation ran (`LiveCheckReport`).
#[derive(Debug, Default)]
struct CheckReport {
    checks: Vec<RuleCheck>,
}

/// A tenant reported unreachable (`TenantUnreachableError`).
#[derive(Debug)]
struct Unreachable {
    tenant: String,
    host: String,
    message: String,
    timeouts: usize,
}

impl Unreachable {
    /// `_unreachable_tenant_result`.
    fn result(&self, platform: &str) -> Fields {
        let mut advice = format!(
            "check the '{}' tenant in {} and the network path to {}; behind a proxy, pass \
             opentide --proxy",
            self.tenant,
            config_path(platform),
            self.host
        );
        if self.timeouts > 0 {
            advice = format!(
                "if the tenant is up and only slow, raise the check timeout with --check-timeout \
                 or {CHECK_TIMEOUT_ENV}; otherwise {advice}"
            );
        }
        let mut result = head(Some(platform), "failed");
        result.push(("tenant".into(), Json::str(&self.tenant)));
        result.push(("host".into(), Json::str(&self.host)));
        result.push(("message".into(), Json::str(&self.message)));
        result.push(("advice".into(), Json::str(advice)));
        result.push(("_exit_code".into(), Json::Int(1)));
        result
    }
}

/// A tenant that refused the check itself, not a query: the credential or
/// the account's rights (#1658, E8).
#[derive(Debug)]
struct Refused {
    tenant: String,
    host: String,
    message: String,
}

impl Refused {
    fn new(platform: &str, tenant: &str, host: &str, reason: &str) -> Self {
        Self::with_message(
            tenant,
            host,
            format!("{platform} tenant '{tenant}' refused the check: {reason}"),
        )
    }

    fn with_message(tenant: &str, host: &str, message: String) -> Self {
        Self {
            tenant: tenant.to_owned(),
            host: host.to_owned(),
            message,
        }
    }

    /// The failed result: the tenant, its host, why, and what to check.
    fn result(&self, platform: &str) -> Fields {
        let mut result = head(Some(platform), "failed");
        result.push(("tenant".into(), Json::str(&self.tenant)));
        result.push(("host".into(), Json::str(&self.host)));
        result.push(("message".into(), Json::str(&self.message)));
        result.push((
            "advice".into(),
            Json::str(format!(
                "check the credentials of the '{}' tenant in {} (the environment variables its \
                 setup names) and the account's rights on the tenant",
                self.tenant,
                config_path(platform)
            )),
        ));
        result.push(("_exit_code".into(), Json::Int(1)));
        result
    }
}

/// Why the check stopped before it finished.
#[derive(Debug)]
enum Early {
    /// Credentials still `$NAME`, a setup that cannot be used (a `ValueError`).
    Failed(String),
    /// A tenant that cannot be reached.
    Unreachable(Unreachable),
    /// A tenant that refused the credential (or the account's rights): no
    /// query was checked there.
    Refused(Refused),
    /// Anything else, as `Type: detail`.
    Crashed(String),
}

/// The queries in a row that got no answer on one tenant (`TimeoutStreak`).
#[derive(Debug)]
struct Streak {
    platform: String,
    tenant: String,
    host: String,
    timeout: f64,
    count: usize,
    ever_answered: bool,
    last_error: Option<String>,
}

impl Streak {
    fn new(platform: &str, tenant: &str, host: &str, timeout: f64) -> Self {
        Self {
            platform: platform.to_owned(),
            tenant: tenant.to_owned(),
            host: host.to_owned(),
            timeout,
            count: 0,
            ever_answered: false,
            last_error: None,
        }
    }

    fn answered(&mut self) {
        self.count = 0;
        self.ever_answered = true;
    }

    fn unreachable(&self, reason: String) -> Unreachable {
        Unreachable {
            tenant: self.tenant.clone(),
            host: self.host.clone(),
            message: format!(
                "Cannot reach {} tenant '{}' at {}: {reason}",
                self.platform, self.tenant, self.host
            ),
            timeouts: self.count,
        }
    }

    /// A query got no answer in time; *stalled* when the timeout may be a
    /// TLS handshake that never completed (a read timeout, not a gateway's
    /// answer).
    fn timed_out(&mut self, error: &str, stalled: bool) -> Result<(), Unreachable> {
        self.last_error = Some(error.to_owned());
        if !stalled {
            self.ever_answered = true;
        }
        self.count += 1;
        if self.count >= UNREACHABLE_AFTER_TIMEOUTS {
            return Err(self.unreachable(format!(
                "{} queries in a row got no answer within the {}s check timeout (the last: \
                 {error}); a tenant is reported unreachable after {UNREACHABLE_AFTER_TIMEOUTS} \
                 in a row",
                self.count, self.timeout
            )));
        }
        Ok(())
    }

    /// The end of the tenant's batch: one that only ever timed out is unreachable.
    fn finish(&self) -> Result<(), Unreachable> {
        match (&self.last_error, self.ever_answered) {
            (Some(last), false) => Err(self.unreachable(format!(
                "it answered no request: {} timed out after {}s (the last: {last}). A \
                 connection that opens but never completes its TLS handshake, behind a proxy \
                 or a load balancer, looks like this",
                self.count, self.timeout
            ))),
            _ => Ok(()),
        }
    }
}

/// *timeout* seconds as a duration; a value too large for one waits forever
/// in effect (`--check-timeout 1e300` is a positive number).
fn seconds(timeout: f64) -> Duration {
    Duration::try_from_secs_f64(timeout).unwrap_or(Duration::MAX)
}

/// The text of a check that got no answer within *timeout* (`timeout_text`).
fn timeout_text(reason: &str, timeout: f64) -> String {
    format!(
        "no answer within the {timeout}s check timeout ({reason}). Raise it with \
         --check-timeout or {CHECK_TIMEOUT_ENV}, or make the query cheaper"
    )
}

/// The address an unreachable tenant is reported at (`LiveQueryValidator.host`).
fn tenant_host(platform: &str, tenant: &Configured) -> String {
    let text = |key: &str| tenant.setup.get(key).map(opentide_compile::deploy::text);
    if platform == "splunk" {
        let url = text("url").unwrap_or_default();
        return match text("port") {
            Some(port) => format!("{url}:{port}"),
            None => url,
        };
    }
    if platform == "google_secops" {
        // The instance's endpoint, else its location's (`_tenant_host`).
        return text("endpoint")
            .filter(|endpoint| !endpoint.is_empty())
            .or_else(|| {
                text("location")
                    .filter(|location| !location.is_empty())
                    .map(|location| opentide_compile::google_secops::default_endpoint(&location))
            })
            .unwrap_or_default();
    }
    text("url")
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| default_host(platform).to_owned())
}

/// One query a rule sends (`RuleQuery`).
#[derive(Clone, Debug)]
struct RuleQuery {
    text: String,
    language: String,
    label: Option<String>,
    exclusions: Option<CJson>,
    /// The streams a Graylog query is checked against (the block's aliases).
    index: Vec<String>,
}

impl RuleQuery {
    fn plain(text: String) -> Self {
        Self {
            text,
            language: String::new(),
            label: None,
            exclusions: None,
            index: Vec::new(),
        }
    }

    /// The query as deploy sends it to *tenant* (`text_for`).
    fn text_for(&self, tenant: &str) -> String {
        match &self.exclusions {
            Some(exclusions) => {
                opentide_compile::kql::compile_query(&self.text, Some(exclusions), tenant)
            }
            None => self.text.clone(),
        }
    }
}

/// The rule's query on *platform*, or the refusal (`_required`).
fn required(block: &CJson, key: &str, name: &str, platform: &str) -> Result<String, String> {
    let text = block
        .get(key)
        .and_then(CJson::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if text.is_empty() {
        return Err(format!("rule {name:?} has an empty {platform} query"));
    }
    Ok(text.to_owned())
}

/// The queries a deploy of *rule* sends to *platform*, in order
/// (`query/rules.py` `rule_queries`).
fn rule_queries(rule: &opentide_compile::Rule, platform: &str) -> Result<Vec<RuleQuery>, String> {
    let name = rule.name.as_str();
    let Some(block) = rule.block(platform) else {
        return Err(format!("rule {name:?} has no {platform} configuration"));
    };
    match platform {
        "sentinel" | "defender_for_endpoint" => {
            let text = required(block, "query", name, platform)?;
            let exclusions = block
                .get("exclusions")
                .filter(|exclusions| matches!(exclusions, CJson::Array(items) if !items.is_empty()))
                .cloned();
            Ok(vec![RuleQuery {
                exclusions,
                ..RuleQuery::plain(text)
            }])
        }
        "carbon_black_cloud" => {
            let text = required(block, "query", name, platform)?;
            Ok(vec![RuleQuery::plain(
                text.split_whitespace().collect::<Vec<_>>().join(" "),
            )])
        }
        "splunk" => {
            required(block, "query", name, platform)?;
            Ok(vec![RuleQuery::plain(
                opentide_compile::splunk::create_query(rule, block),
            )])
        }
        "sentinel_one" => {
            let condition = block.get("condition");
            let kind = condition
                .and_then(|condition| condition.get("type"))
                .and_then(CJson::as_str)
                .unwrap_or_default();
            if kind == "Single Event"
                && let Some(single) = condition
                    .and_then(|condition| condition.get("single_event"))
                    .filter(|single| single.is_filled())
            {
                return Ok(vec![RuleQuery::plain(required(
                    single, "query", name, platform,
                )?)]);
            }
            if kind == "Correlation"
                && let Some(correlation) = condition
                    .and_then(|condition| condition.get("correlation"))
                    .filter(|correlation| correlation.is_filled())
            {
                let subs = match correlation.get("sub_queries") {
                    Some(CJson::Array(items)) if !items.is_empty() => items,
                    _ => {
                        return Err(format!("rule {name:?} has no SentinelOne sub-queries"));
                    }
                };
                return subs
                    .iter()
                    .enumerate()
                    .map(|(at, sub)| {
                        Ok(RuleQuery {
                            label: Some(format!("sub-query {}", at + 1)),
                            ..RuleQuery::plain(required(sub, "query", name, platform)?)
                        })
                    })
                    .collect();
            }
            Err(format!("rule {name:?} has no SentinelOne query"))
        }
        // The event definition's query on its streams, as `query --rule`
        // runs it (`query/rules.py`'s `graylog`).
        "graylog" => Ok(crate::commands::query_rule::rule_queries(rule, platform)?
            .into_iter()
            .map(|query| RuleQuery {
                language: query.language.unwrap_or_default(),
                index: query.index,
                ..RuleQuery::plain(query.text)
            })
            .collect()),
        // Each sequence's filter (`_exabeam_queries`), as `query --rule` runs it.
        "exabeam" => Ok(crate::commands::query_rule::rule_queries(rule, platform)?
            .into_iter()
            .map(|query| RuleQuery {
                language: query.language.unwrap_or_default(),
                label: query.label,
                ..RuleQuery::plain(query.text)
            })
            .collect()),
        _ => Err(format!("{platform} rules cannot be queried")),
    }
}

/// A tenant's connection, made once per batch.
struct Connection {
    tenant: Tenant,
    http: HttpClient,
}

/// The tenant's connection, or why it cannot be made (`ValueError`).
fn connect(
    platform: &str,
    configured: &Configured,
    timeout: f64,
    cx: &Context<'_>,
    environment: &Environment,
) -> Result<Connection, String> {
    if let Some(message) = unset_credentials(platform, configured, cx.env) {
        return Err(message);
    }
    let setup: toml::Table = configured
        .setup
        .iter()
        .filter_map(|(key, value)| toml_value(value).map(|value| (key.clone(), value)))
        .collect();
    let settings = http_settings(platform, seconds(timeout));
    let tenant = Tenant::from_setup(
        platform,
        &configured.name,
        &setup,
        environment,
        Resolve::Counting,
        &settings,
    )
    .map_err(|error| error.to_string())?;
    let http = HttpClient::new(&tenant.label, &tenant.http, environment, cx.proxy)
        .map_err(|error| error.to_string())?;
    Ok(Connection { tenant, http })
}

/// A read timeout: the request was sent to *address* and got no answer.
fn read_timeout_text(address: &str, seconds: u64) -> String {
    format!("no answer from {address} within {seconds}s")
}

/// Runs the checks on every batch on the process's runtime: here, or on a
/// thread of its own with this thread's log subscriber when a host runs a
/// runtime here (`sync_call`).
fn check_batches(
    platform: &str,
    batches: &[Batch],
    timeout: f64,
    cx: &Context<'_>,
    compile: &opentide_compile::Context<'_>,
) -> Result<CheckReport, Early> {
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let ran = opentide_connectors::runtime::sync_call(|| {
        tracing::dispatcher::with_default(&dispatch, || {
            opentide_connectors::runtime::block_on(async {
                if platform == "elastic" {
                    elastic(batches, timeout, cx, compile).await
                } else if platform == "google_secops" {
                    google_secops(batches, timeout, cx, compile).await
                } else {
                    generic(platform, batches, timeout, cx).await
                }
            })
        })
    });
    match ran {
        Ok(Ok(result)) => result,
        Ok(Err(message)) => Err(Early::Crashed(message)),
        Err(_) => Err(Early::Crashed("the check stopped unexpectedly".to_owned())),
    }
}

/// `LiveQueryValidator.validate`: each rule's queries on each tenant.
async fn generic(
    platform: &str,
    batches: &[Batch],
    timeout: f64,
    cx: &Context<'_>,
) -> Result<CheckReport, Early> {
    let environment = Environment::from_pairs(cx.env.iter());
    let validator = cx
        .registry
        .get(platform)
        .and_then(opentide_connectors::Platform::live_validator)
        .ok_or_else(|| Early::Crashed(format!("{platform} has no live validator")))?;
    let window = check_window(platform, cx.now);
    let cancel = CancellationToken::new();
    let mut report = CheckReport::default();
    for batch in batches {
        let tenant = &batch.tenant;
        let host = tenant_host(platform, tenant);
        let mut streak = Streak::new(platform, &tenant.name, &host, timeout);
        let mut connection: Option<Result<Connection, String>> = None;
        for sent in &batch.rules {
            let rule = &sent.rule;
            if rule.block(platform).is_none() {
                continue;
            }
            let queries = match rule_queries(rule, platform) {
                Ok(queries) => queries,
                Err(error) => {
                    report
                        .checks
                        .push(rejected(platform, rule, &tenant.name, None, &error));
                    continue;
                }
            };
            for item in queries {
                let mut request =
                    QueryRequest::new(item.text_for(&tenant.name), &item.language, window);
                request.limit = 1;
                request.timeout = seconds(timeout);
                request.index = item.index.clone();
                tracing::info!(
                    mdr_name = rule.name.as_str(),
                    uuid = rule.uuid.as_str(),
                    tenant = tenant.name.as_str(),
                    "validating_query"
                );
                let conn = connection
                    .get_or_insert_with(|| connect(platform, tenant, timeout, cx, &environment));
                let conn = match conn {
                    Ok(conn) => &*conn,
                    Err(message) => return Err(Early::Failed(message.clone())),
                };
                let context = TenantContext {
                    tenant: &conn.tenant,
                    http: &conn.http,
                    cancel: &cancel,
                };
                let found = watched(
                    validator.validate(context, &request),
                    &cancel,
                    cx.interrupted,
                )
                .await;
                let asked = Asked {
                    platform,
                    rule,
                    tenant: &tenant.name,
                    label: item.label.clone(),
                    timeout,
                };
                report
                    .checks
                    .push(asked.outcome(found, &request.text, &mut streak)?);
            }
        }
        streak.finish().map_err(Early::Unreachable)?;
    }
    Ok(report)
}

/// The window a rule's query is checked over: Exabeam searches the 15
/// minutes before its end, the console's "Test Last 15 mins"
/// (`ExabeamQueryValidator.check_rule`).
fn check_window(platform: &str, now: jiff::Timestamp) -> TimeWindow {
    let window = TimeWindow::check(now);
    if platform == opentide_compile::exabeam::PLATFORM {
        opentide_connectors::exabeam::rule_check_window(window.end)
    } else {
        window
    }
}

/// One query of a rule asked of a tenant (`check_rule`).
struct Asked<'a> {
    platform: &'a str,
    rule: &'a opentide_compile::Rule,
    tenant: &'a str,
    label: Option<String>,
    timeout: f64,
}

impl Asked<'_> {
    /// The query's check from what the tenant answered: a gateway or a
    /// read that timed out counts toward the tenant's streak of timeouts,
    /// and any other connector error stops the check.
    fn outcome(
        self,
        found: Result<LiveCheck, ConnectorError>,
        text: &str,
        streak: &mut Streak,
    ) -> Result<RuleCheck, Early> {
        let Self {
            platform,
            rule,
            tenant,
            label,
            timeout,
        } = self;
        let timed_out = |reason: &str| {
            timed_out(
                platform,
                rule,
                tenant,
                label.clone(),
                reason,
                timeout,
                Vec::new(),
            )
        };
        match found {
            Ok(found) => {
                streak.answered();
                Ok(answered(platform, rule, tenant, label.clone(), text, found))
            }
            Err(ConnectorError::QueryTimedOut { message, .. }) => {
                streak.answered();
                Ok(timed_out(&message))
            }
            Err(refused @ ConnectorError::Refused { .. }) => {
                streak.answered();
                Ok(rejected(
                    platform,
                    rule,
                    tenant,
                    label.clone(),
                    &refused.text(),
                ))
            }
            Err(ConnectorError::Gateway { message, .. }) => {
                streak
                    .timed_out(&message, false)
                    .map_err(Early::Unreachable)?;
                Ok(timed_out(&message))
            }
            Err(ConnectorError::Timeout {
                address, seconds, ..
            }) => {
                let error = read_timeout_text(&address, seconds);
                streak.timed_out(&error, true).map_err(Early::Unreachable)?;
                Ok(timed_out(&error))
            }
            Err(error) => Err(early(platform, tenant, &streak.host, error)),
        }
    }
}

/// A query the tenant answered: its errors and warnings logged, and on
/// Defender a rejected query's XDR tables named.
fn answered(
    platform: &str,
    rule: &opentide_compile::Rule,
    tenant: &str,
    label: Option<String>,
    text: &str,
    found: LiveCheck,
) -> RuleCheck {
    if platform == "defender_for_endpoint" && !found.errors.is_empty() {
        let mut tables = opentide_connectors::defender::defender_xdr_tables_in_query(text);
        tables.sort();
        tables.dedup();
        let tables = if tables.is_empty() {
            "none".to_owned()
        } else {
            tables.join(", ")
        };
        let detail = format!(
            "{} ({}) | Detected Defender XDR tables: {tables} | {DEFENDER_COLUMNS_DOCS}",
            rule.name, rule.uuid
        );
        tracing::error!(
            detail = detail.as_str(),
            critical = true,
            "defender_xdr_custom_detection_query_is_missing_required_columns"
        );
    }
    for error in &found.errors {
        log_rejected(platform, rule, tenant, error);
    }
    for warning in &found.warnings {
        tracing::warn!(
            detail = format!("{} ({}) on {tenant}", rule.name, rule.uuid).as_str(),
            warning = warning.as_str(),
            "query_validation_warning"
        );
    }
    if found.errors.is_empty() {
        tracing::info!(mdr_name = rule.name.as_str(), tenant, "valid_query");
    }
    RuleCheck {
        rule: rule.uuid.clone(),
        name: rule.name.clone(),
        tenant: tenant.to_owned(),
        label,
        errors: found.errors,
        warnings: found.warnings,
        code: None,
    }
}

/// `GoogleSecopsValidator.validate`: each rule's assembled YARA-L text,
/// compiled by `verifyRuleText` on every instance deploy would send it to.
/// Google's `ERROR` diagnostics fail the rule (`google_secops_compile_error`)
/// and its `WARNING` ones are warnings, each placed on the section key and
/// line it falls in; a `run_frequency` Google does not allow fails it too.
/// Credentials that cannot be loaded, or that the instance refuses, fail
/// the tenant: the check stops there, and no query counts as rejected.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
async fn google_secops(
    batches: &[Batch],
    timeout: f64,
    cx: &Context<'_>,
    compile: &opentide_compile::Context<'_>,
) -> Result<CheckReport, Early> {
    use opentide_connectors::google_secops::client::Client;
    use opentide_connectors::google_secops::{GoogleSecops, Instance, check_rule};
    let platform = "google_secops";
    let environment = Environment::from_pairs(cx.env.iter());
    let connector = GoogleSecops::new(environment.clone());
    let cancel = CancellationToken::new();
    let mut report = CheckReport::default();
    for batch in batches {
        let tenant = &batch.tenant;
        let rules: Vec<&opentide_compile::Rule> = batch
            .rules
            .iter()
            .map(|sent| &sent.rule)
            .filter(|rule| rule.block(platform).is_some())
            .collect();
        if rules.is_empty() {
            continue;
        }
        let host = tenant_host(platform, tenant);
        let conn = connect(platform, tenant, timeout, cx, &environment).map_err(Early::Failed)?;
        let ready = Instance::of(&conn.tenant).and_then(|instance| {
            connector
                .authorizer(&conn.tenant)
                .map(|authorizer| (instance, authorizer))
        });
        let (instance, authorizer) = match ready {
            Ok(ready) => ready,
            // Credentials that cannot be loaded: no rule can be checked on
            // the instance, so the tenant fails, not each query (#1658, D4).
            Err(error) => {
                return Err(Early::Refused(Refused::with_message(
                    &tenant.name,
                    &host,
                    format!("{platform} tenant '{}': {}", tenant.name, error.text()),
                )));
            }
        };
        let context = TenantContext {
            tenant: &conn.tenant,
            http: &conn.http,
            cancel: &cancel,
        };
        let client = Client::new(context, &authorizer, &instance.endpoint, &instance.resource);
        let mut streak = Streak::new(platform, &tenant.name, &host, timeout);
        for rule in rules {
            tracing::info!(
                mdr_name = rule.name.as_str(),
                uuid = rule.uuid.as_str(),
                tenant = tenant.name.as_str(),
                "validating_query"
            );
            let assembled = match opentide_compile::google_secops::assemble(compile, rule) {
                Ok(assembled) => assembled,
                Err(error) => {
                    report
                        .checks
                        .push(rejected(platform, rule, &tenant.name, None, &error.reason));
                    continue;
                }
            };
            let frequency = rule
                .block(platform)
                .and_then(|block| block.get("run_frequency"))
                .and_then(CJson::as_str);
            let found = watched(
                check_rule(&client, &assembled, frequency),
                &cancel,
                cx.interrupted,
            )
            .await;
            match found {
                Ok(check) => {
                    streak.answered();
                    for error in &check.errors {
                        log_rejected(platform, rule, &tenant.name, error);
                    }
                    for warning in &check.warnings {
                        tracing::warn!(
                            detail = format!("{} ({}) on {}", rule.name, rule.uuid, tenant.name)
                                .as_str(),
                            warning = warning.as_str(),
                            "query_validation_warning"
                        );
                    }
                    if check.errors.is_empty() {
                        tracing::info!(
                            mdr_name = rule.name.as_str(),
                            tenant = tenant.name.as_str(),
                            "valid_query"
                        );
                    }
                    report.checks.push(RuleCheck {
                        rule: rule.uuid.clone(),
                        name: rule.name.clone(),
                        tenant: tenant.name.clone(),
                        label: None,
                        errors: check.errors,
                        warnings: check.warnings,
                        code: None,
                    });
                }
                Err(refused @ ConnectorError::Authentication { .. }) => {
                    // The instance refuses every rule alike: the tenant fails,
                    // and no query of it counts as rejected (#1658, D4).
                    let text = refused.text();
                    tracing::error!(
                        tenant = tenant.name.as_str(),
                        error = text.as_str(),
                        critical = true,
                        "google_secops_tenant_validation_failed"
                    );
                    return Err(Early::Refused(Refused::with_message(
                        &tenant.name,
                        &host,
                        format!("{platform} tenant '{}': {text}", tenant.name),
                    )));
                }
                Err(ConnectorError::Timeout {
                    address, seconds, ..
                }) => {
                    let error = read_timeout_text(&address, seconds);
                    streak.timed_out(&error, true).map_err(Early::Unreachable)?;
                    report.checks.push(timed_out(
                        platform,
                        rule,
                        &tenant.name,
                        None,
                        &error,
                        timeout,
                        Vec::new(),
                    ));
                }
                Err(error) => return Err(early(platform, &tenant.name, &host, error)),
            }
        }
        streak.finish().map_err(Early::Unreachable)?;
    }
    Ok(report)
}

/// A failure that stops the check (`reaching_tenant`, then the service's
/// handlers).
fn early(platform: &str, tenant: &str, host: &str, error: ConnectorError) -> Early {
    match error {
        ConnectorError::Unreachable {
            address, reason, ..
        } => Early::Unreachable(Unreachable {
            tenant: tenant.to_owned(),
            message: format!("Cannot reach {platform} tenant '{tenant}' at {address}: {reason}"),
            host: address,
            timeouts: 0,
        }),
        ConnectorError::Setup { message, .. } => Early::Failed(message),
        ConnectorError::Cancelled => Early::Failed("interrupted".to_owned()),
        ConnectorError::Authentication { message, .. } => {
            Early::Refused(Refused::new(platform, tenant, host, &message))
        }
        other => Early::Crashed(other.to_string()),
    }
}

/// Logs a refusal (`_log_rejected`).
fn log_rejected(platform: &str, rule: &opentide_compile::Rule, tenant: &str, error: &str) {
    tracing::error!(
        detail = format!(
            "{} ({}) on {platform} tenant {tenant}",
            rule.name, rule.uuid
        )
        .as_str(),
        reason = error,
        critical = true,
        "query_rejected"
    );
}

/// A refused check (`_rejected`).
fn rejected(
    platform: &str,
    rule: &opentide_compile::Rule,
    tenant: &str,
    label: Option<String>,
    error: &str,
) -> RuleCheck {
    log_rejected(platform, rule, tenant, error);
    RuleCheck {
        rule: rule.uuid.clone(),
        name: rule.name.clone(),
        tenant: tenant.to_owned(),
        label,
        errors: vec![error.to_owned()],
        warnings: Vec::new(),
        code: None,
    }
}

/// A check that got no answer within *timeout* (`timed_out`).
fn timed_out(
    platform: &str,
    rule: &opentide_compile::Rule,
    tenant: &str,
    label: Option<String>,
    reason: &str,
    timeout: f64,
    warnings: Vec<String>,
) -> RuleCheck {
    let error = timeout_text(reason, timeout);
    tracing::error!(
        detail = format!(
            "{} ({}) on {platform} tenant {tenant}",
            rule.name, rule.uuid
        )
        .as_str(),
        reason = error.as_str(),
        critical = true,
        "query_check_timed_out"
    );
    RuleCheck {
        rule: rule.uuid.clone(),
        name: rule.name.clone(),
        tenant: tenant.to_owned(),
        label,
        errors: vec![error],
        warnings,
        code: Some(QUERY_CHECK_TIMEOUT),
    }
}

// ---------------------------------------------------------------- Elastic

/// One advisory's log line (`warn_advisory`, `_emit_rule_advisories`).
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn log_advisory(code: &str, rule: &str, block: &CJson, tenant: &str, uuid: &str, severity: &str) {
    let scheduling = block.get("scheduling").filter(|s| s.is_filled());
    let text = |key: &str, default: &str| {
        scheduling
            .and_then(|s| s.get(key))
            .filter(|value| !value.is_null())
            .map_or_else(|| default.to_owned(), opentide_compile::deploy::text)
    };
    let interval = text("interval", "5m");
    let lookback = text("lookback", "1m");
    let legacy = opentide_connectors::elastic::legacy_event(code);
    match code {
        "lookback_zero" => tracing::warn!(
            code,
            legacy_event = legacy,
            rule,
            lookback = lookback.as_str(),
            advice = "scheduling.lookback is 0m; Elastic recommends at least 1m overlap",
            "lookback_zero"
        ),
        "lookback_long" => tracing::warn!(
            code,
            legacy_event = legacy,
            rule,
            lookback = lookback.as_str(),
            interval = interval.as_str(),
            advice = "scheduling.lookback exceeds 1h; in Elastic, lookback is additional overlap \
                      added to interval (from = now-(interval+lookback)), not the total query \
                      window",
            "lookback_long"
        ),
        "threshold_lookback" => tracing::warn!(
            code,
            legacy_event = legacy,
            rule,
            lookback = lookback.as_str(),
            interval = interval.as_str(),
            advice = "threshold rule has scheduling.lookback > scheduling.interval; threshold \
                      rules count across interval + lookback and do not deduplicate alerts \
                      across overlapping runs",
            "threshold_lookback"
        ),
        "esql_metadata_id" => tracing::warn!(
            code,
            legacy_event = legacy,
            rule,
            advice = "Non-aggregating ES|QL query lacks METADATA _id; alerts will not be \
                      deduplicated",
            "esql_metadata_id"
        ),
        "risk_band" => {
            let score = match block.get("risk") {
                Some(CJson::Int(score)) => *score,
                Some(risk) => match risk.get("score") {
                    Some(CJson::Int(score)) => *score,
                    _ => 0,
                },
                None => 0,
            };
            let (low, high) = opentide_connectors::elastic::risk_band(severity).unwrap_or((0, 0));
            tracing::warn!(
                code,
                legacy_event = legacy,
                rule,
                severity,
                risk_score = score,
                expected_band = format!("{low}-{high}").as_str(),
                advice = format!(
                    "risk score {score} is outside the RFC 0007 band ({low}-{high}) for severity \
                     '{severity}'"
                )
                .as_str(),
                "risk_band"
            );
        }
        "eql_maxspan_window" | "eql_maxspan_lookback" => {
            let query = block
                .get("query")
                .map(opentide_compile::deploy::text)
                .unwrap_or_default();
            let maxspan = opentide_connectors::elastic::eql_maxspan(&query)
                .map(|(text, _)| text)
                .unwrap_or_default();
            if code == "eql_maxspan_window" {
                tracing::warn!(
                    code,
                    legacy_event = legacy,
                    rule,
                    maxspan = maxspan.as_str(),
                    interval = interval.as_str(),
                    lookback = lookback.as_str(),
                    advice = format!(
                        "EQL sequence maxspan ({maxspan}) exceeds the total search window \
                         interval + lookback ({interval} + {lookback}); sequences spanning the \
                         full maxspan cannot match"
                    )
                    .as_str(),
                    "eql_maxspan_window"
                );
            } else {
                tracing::warn!(
                    code,
                    legacy_event = legacy,
                    rule,
                    maxspan = maxspan.as_str(),
                    interval = interval.as_str(),
                    lookback = lookback.as_str(),
                    advice = format!(
                        "EQL sequence maxspan ({maxspan}) exceeds scheduling.lookback \
                         ({lookback}); sequences straddling two runs can be missed"
                    )
                    .as_str(),
                    "eql_maxspan_lookback"
                );
            }
        }
        "suppression_omitted_basic_license" => tracing::warn!(
            rule,
            rule_id = uuid,
            tenant,
            advice = "Tenant setup.suppression is false; alert_suppression will be omitted",
            "suppression_omitted_basic_license"
        ),
        _ => {}
    }
}

/// Why an Elastic rule's check failed.
enum RuleFailure {
    /// The tenant refused the rule (`ElasticRuleCheckError`).
    Rule(String),
    /// The tenant cannot check any rule (`ElasticTenantError`).
    Tenant(String),
    /// The tenant could not be reached, or did not answer in time.
    Connector(ConnectorError),
    /// Anything else (a `ValueError`, a rule that does not compile).
    Other(Early),
}

/// `ElasticValidator._validate_rule`: the advisories, the Elasticsearch
/// checks, then a preview of the rule deploy would create.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
async fn elastic_rule(
    connector: &Elastic,
    context: TenantContext<'_>,
    rule: &opentide_compile::Rule,
    batch: &Batch,
    compile: &opentide_compile::Context<'_>,
    now: jiff::Timestamp,
    warnings: &mut Vec<String>,
) -> Result<(), RuleFailure> {
    let Some(raw) = rule.block("elastic") else {
        return Ok(());
    };
    let block = opentide_compile::preview::config_dump("elastic", raw);
    let setup = opentide_compile::elastic::Setup::from_tenant(&batch.table);
    let payload = opentide_compile::elastic::compile(compile, rule, &setup)
        .map_err(|error| RuleFailure::Other(Early::Crashed(format!("CompileError: {error}"))))?;
    let severity = payload
        .get("severity")
        .and_then(CJson::as_str)
        .unwrap_or("low")
        .to_owned();
    let non_enterprise = opentide_compile::elastic::rule_techniques(compile, rule)
        .iter()
        .any(|id| {
            compile
                .attack
                .name(id)
                .is_some_and(opentide_compile::attack::non_enterprise)
        });
    let codes = opentide_connectors::elastic::advisories(
        &block,
        &severity,
        setup.suppression,
        non_enterprise,
    )
    .map_err(|message| RuleFailure::Other(Early::Failed(message)))?;
    for code in &codes {
        log_advisory(
            code,
            &rule.name,
            &block,
            &batch.tenant.name,
            &rule.uuid,
            &severity,
        );
    }
    warnings.extend(codes);
    let index: Vec<String> = setup.index.clone().unwrap_or_default();
    match connector.checks(context, &block, &index).await {
        Ok(found) => {
            for warning in found {
                tracing::warn!(
                    rule = rule.name.as_str(),
                    warning = warning.as_str(),
                    "elasticsearch_check_warning"
                );
                warnings.push(warning);
            }
        }
        Err(ElasticError::Rule(message)) => return Err(RuleFailure::Rule(message)),
        Err(ElasticError::Tenant(message)) => return Err(RuleFailure::Tenant(message)),
        Err(ElasticError::Connector(error)) => return Err(RuleFailure::Connector(error)),
    }
    let preview = match connector.preview_rule(context, &payload, now).await {
        Ok(preview) => preview,
        Err(ConnectorError::Authentication { message, .. }) => {
            return Err(RuleFailure::Tenant(message));
        }
        Err(refused @ (ConnectorError::Refused { .. } | ConnectorError::QueryTimedOut { .. })) => {
            return Err(RuleFailure::Rule(refused.text()));
        }
        Err(error) => return Err(RuleFailure::Connector(error)),
    };
    if matches!(preview.get("isAborted"), Some(CJson::Bool(true))) {
        tracing::warn!(rule = rule.name.as_str(), "preview_inconclusive_aborted");
        warnings.push("Kibana aborted the preview before it finished".into());
    }
    let mut errors: Vec<String> = Vec::new();
    if let Some(CJson::Array(logs)) = preview.get("logs") {
        for entry in logs.iter().filter(|entry| entry.as_object().is_some()) {
            if let Some(CJson::Array(items)) = entry.get("warnings") {
                for item in items {
                    let warning = opentide_connectors::text::json_text(item);
                    tracing::warn!(
                        rule = rule.name.as_str(),
                        warning = warning.as_str(),
                        "preview_log_warning"
                    );
                    warnings.push(warning);
                }
            }
            if let Some(CJson::Array(items)) = entry.get("errors") {
                for item in items {
                    let error = opentide_connectors::text::json_text(item);
                    if error.contains("preview-index") || error.contains("preview.alerts") {
                        return Err(RuleFailure::Tenant(format!(
                            "Tenant configuration error: missing preview-index privilege ({error})"
                        )));
                    }
                    errors.push(error);
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(RuleFailure::Rule(format!(
            "Preview validation failed for rule '{}': {}",
            rule.name,
            errors.join("; ")
        )));
    }
    Ok(())
}

/// `ElasticValidator.validate`: each rule checked as a whole on each tenant.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
async fn elastic(
    batches: &[Batch],
    timeout: f64,
    cx: &Context<'_>,
    compile: &opentide_compile::Context<'_>,
) -> Result<CheckReport, Early> {
    let environment = Environment::from_pairs(cx.env.iter());
    let connector = Elastic;
    let cancel = CancellationToken::new();
    let mut report = CheckReport::default();
    for batch in batches {
        let tenant = &batch.tenant;
        let conn = connect("elastic", tenant, timeout, cx, &environment).map_err(Early::Failed)?;
        let host = tenant_host("elastic", tenant);
        let mut streak = Streak::new("elastic", &tenant.name, &host, timeout);
        let context = TenantContext {
            tenant: &conn.tenant,
            http: &conn.http,
            cancel: &cancel,
        };
        for sent in &batch.rules {
            let rule = &sent.rule;
            let mut warnings = Vec::new();
            let outcome = watched(
                async {
                    Ok(elastic_rule(
                        &connector,
                        context,
                        rule,
                        batch,
                        compile,
                        cx.now,
                        &mut warnings,
                    )
                    .await)
                },
                &cancel,
                cx.interrupted,
            )
            .await;
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => Err(RuleFailure::Connector(error)),
            };
            let failed_check = |error: &str, warnings: Vec<String>| RuleCheck {
                rule: rule.uuid.clone(),
                name: rule.name.clone(),
                tenant: tenant.name.clone(),
                label: None,
                errors: vec![error.to_owned()],
                warnings,
                code: None,
            };
            match outcome {
                Ok(()) => {
                    streak.answered();
                    if rule.block("elastic").is_some() {
                        report.checks.push(RuleCheck {
                            rule: rule.uuid.clone(),
                            name: rule.name.clone(),
                            tenant: tenant.name.clone(),
                            label: None,
                            errors: Vec::new(),
                            warnings,
                            code: None,
                        });
                    }
                }
                Err(RuleFailure::Tenant(error)) => {
                    tracing::error!(
                        rule = rule.name.as_str(),
                        uuid = rule.uuid.as_str(),
                        error = error.as_str(),
                        critical = true,
                        "elastic_tenant_validation_failed"
                    );
                    // The tenant refused the check itself (a key, a
                    // privilege): no query was checked (#1658, E8).
                    return Err(Early::Refused(Refused::new(
                        "elastic",
                        &tenant.name,
                        &host,
                        &error,
                    )));
                }
                Err(RuleFailure::Rule(error)) => {
                    streak.answered();
                    report.checks.push(failed_check(&error, warnings));
                    tracing::error!(
                        rule = rule.name.as_str(),
                        uuid = rule.uuid.as_str(),
                        error = error.as_str(),
                        critical = true,
                        "elastic_rule_validation_failed"
                    );
                }
                Err(RuleFailure::Connector(ConnectorError::Timeout {
                    address, seconds, ..
                })) => {
                    let error = read_timeout_text(&address, seconds);
                    streak.timed_out(&error, true).map_err(Early::Unreachable)?;
                    report.checks.push(timed_out(
                        "elastic",
                        rule,
                        &tenant.name,
                        None,
                        &error,
                        timeout,
                        warnings,
                    ));
                }
                Err(RuleFailure::Connector(ConnectorError::Gateway { message, .. })) => {
                    streak
                        .timed_out(&message, false)
                        .map_err(Early::Unreachable)?;
                    report.checks.push(timed_out(
                        "elastic",
                        rule,
                        &tenant.name,
                        None,
                        &message,
                        timeout,
                        warnings,
                    ));
                }
                Err(RuleFailure::Connector(error)) => {
                    return Err(early("elastic", &tenant.name, &host, error));
                }
                Err(RuleFailure::Other(early)) => return Err(early),
            }
        }
        streak.finish().map_err(Early::Unreachable)?;
    }
    Ok(report)
}

/// The tenants' names, for tests.
#[cfg(test)]
fn tenant_names(batches: &[Batch]) -> Vec<String> {
    batches
        .iter()
        .map(|batch| batch.tenant.name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(yaml: &str) -> opentide_compile::Rule {
        let document = opentide_schema::node::load(yaml).unwrap();
        opentide_compile::Rule::new(document.root().unwrap(), None)
    }

    #[test]
    fn rule_queries_follow_each_platform() {
        let r = rule(
            "name: R\nmetadata: {uuid: 00000000-0000-4000-8000-000000000001}\nconfigurations:\n  \
             carbon_black_cloud: {query: \"a\n  b   c \"}\n  sentinel_one:\n    condition:\n      \
             type: Correlation\n      correlation:\n        sub_queries: [{query: x}, {query: ' y '}]\n  \
             sentinel: {query: '  '}\n  defender_for_endpoint:\n    query: T\n    exclusions: [{query: '| where a', tenant: lab}]\n",
        );
        let cb = rule_queries(&r, "carbon_black_cloud").unwrap();
        assert_eq!(cb[0].text, "a b c");
        let s1 = rule_queries(&r, "sentinel_one").unwrap();
        assert_eq!(s1.len(), 2);
        assert_eq!(s1[1].text, "y");
        assert_eq!(s1[1].label.as_deref(), Some("sub-query 2"));
        assert_eq!(
            rule_queries(&r, "sentinel").unwrap_err(),
            "rule \"R\" has an empty sentinel query"
        );
        assert_eq!(
            rule_queries(&r, "splunk").unwrap_err(),
            "rule \"R\" has no splunk configuration"
        );
        let defender = rule_queries(&r, "defender_for_endpoint").unwrap();
        assert_eq!(defender[0].text_for("lab"), "T\n| where a");
        assert_eq!(defender[0].text_for("prod"), "T");
        let graylog = rule(
            "name: G\nmetadata: {uuid: 00000000-0000-4000-8000-000000000002}\nconfigurations:\n  \
             graylog: {query: 'source:host', streams: [sysmon, dns]}\n",
        );
        let gl = rule_queries(&graylog, "graylog").unwrap();
        assert_eq!(gl[0].text, "source:host");
        assert_eq!(gl[0].language, "lucene");
        assert_eq!(gl[0].index, ["sysmon", "dns"]);
        let exabeam = rule(
            "name: R\nmetadata: {uuid: 00000000-0000-4000-8000-000000000001}\nconfigurations:\n  \
             exabeam:\n    sequences: [{query: ' a '}, {query: b}]\n",
        );
        let sequences = rule_queries(&exabeam, "exabeam").unwrap();
        let shown: Vec<(&str, &str, Option<&str>)> = sequences
            .iter()
            .map(|query| {
                (
                    query.text.as_str(),
                    query.language.as_str(),
                    query.label.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                ("a", "exabeam", Some("sequence 1")),
                ("b", "exabeam", Some("sequence 2"))
            ]
        );
    }

    #[test]
    fn a_streak_reports_the_tenant_after_three_or_when_nothing_answered() {
        let mut streak = Streak::new("splunk", "lab", "splunk.invalid:8089", 5.0);
        assert!(streak.timed_out("timed out", false).is_ok());
        assert!(streak.finish().is_ok());
        let mut stalled = Streak::new("sentinel", "lab", "https://x", 5.0);
        stalled.timed_out("read", true).unwrap();
        let unreachable = stalled.finish().unwrap_err();
        assert!(unreachable.message.starts_with(
            "Cannot reach sentinel tenant 'lab' at https://x: it answered no request: 1 timed out after 5s"
        ));
        stalled.timed_out("read", true).unwrap();
        let third = stalled.timed_out("read", true).unwrap_err();
        assert_eq!(third.timeouts, 3);
        assert!(
            third.result("sentinel")[7]
                .1
                .as_str()
                .unwrap()
                .starts_with("if the tenant")
        );
        stalled.answered();
        assert!(stalled.finish().is_ok());
    }

    #[test]
    fn results_read_into_the_envelope_as_the_oracle_reads_them() {
        let mut result = failed(Some("splunk"), "nope", 2);
        result.push(("_failure_code".into(), Json::str("usage_error")));
        result.push(("warnings".into(), Json::Array(vec![Json::str("w")])));
        let report = report_of(COMMAND, &result);
        assert_eq!(report.outcome.exit_code, 2);
        assert_eq!(report.outcome.status, "failed");
        assert_eq!(report.warnings, ["w"]);
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.code, "usage_error");
        assert_eq!(failure.message, "nope");
        let keys: Vec<&str> = report
            .outcome
            .data
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(keys, ["platform", "mode", "supported"]);
        let skipped = report_of(
            COMMAND,
            &[
                ("status".into(), Json::str("skipped")),
                ("_exit_code".into(), Json::Int(2)),
            ],
        );
        assert_eq!(skipped.outcome.failure.unwrap().code, "not_run");
        let passed = report_of(COMMAND, &[("status".into(), Json::str("passed"))]);
        assert!(passed.outcome.failure.is_none());
        assert!(tenant_names(&[]).is_empty());
    }

    #[test]
    fn hosts_and_timeouts_read_as_python_writes_them() {
        let tenant = |pairs: &[(&str, CJson)]| Configured {
            name: "lab".into(),
            setup: pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        };
        assert_eq!(
            tenant_host(
                "splunk",
                &tenant(&[
                    ("url", CJson::Str("s.invalid".into())),
                    ("port", CJson::Int(8089))
                ])
            ),
            "s.invalid:8089"
        );
        assert_eq!(
            tenant_host("sentinel", &tenant(&[])),
            "https://api.loganalytics.io"
        );
        assert_eq!(
            tenant_host(
                "google_secops",
                &tenant(&[("location", CJson::Str("eu".into()))])
            ),
            "https://eu-chronicle.googleapis.com"
        );
        assert_eq!(
            tenant_host(
                "google_secops",
                &tenant(&[
                    ("location", CJson::Str("eu".into())),
                    ("endpoint", CJson::Str("https://proxy.invalid".into()))
                ])
            ),
            "https://proxy.invalid"
        );
        assert_eq!(tenant_host("google_secops", &tenant(&[])), "");
        assert_eq!(
            read_timeout_text("https://s1.invalid", 5),
            "no answer from https://s1.invalid within 5s"
        );
        assert_eq!(seconds(1e300), Duration::MAX);
        assert_eq!(seconds(2.5), Duration::from_millis(2500));
        assert!(timeout_text("r", 2.5).starts_with("no answer within the 2.5s check timeout (r)."));
    }
}
