//! `opentide deploy` without `--dry-run` on the connectors (UC-4.6, #979):
//! `cli/services/deploy.py` `run_deploy` and `_deploy`, the platforms'
//! deployers (`platforms/<platform>/deployer.py`), `deployment/external_ids.py`
//! and `cli/ui/deploy_log.py`, step by step.
//!
//! The plan is the dry run's (`opentide_compile::plan`): the rules the run
//! reads, their platforms, the tenants each reaches, with the platform's
//! `[[modifiers]]` applied per tenant. Each rule is then sent through its
//! platform's connector, one tenant after another, and each finished rule
//! prints one line on stderr as it ends (`DeployLog`). A platform that
//! raises stops the run: the rules it never reached are not attempted. The
//! ids CrowdStrike, Defender for Endpoint, SentinelOne and Sysdig give a
//! rule are kept in deployment state ([`super::deploy_state`]).
//!
//! The run's result is the oracle's dictionary, keys in its order, read into
//! the envelope as `CommandResult.from_payload` reads it
//! ([`super::validate_live::report_of`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::interrupt::watched;
use indexmap::IndexMap;
use opentide_compile::Json as CJson;
use opentide_compile::plan::{self, Change, Scope, SelectOptions};
use opentide_compile::strategy::{self, RunStrategies, StatusStrategy};
use opentide_connectors::connector::{
    DeployError, DeployFailure, DeployOutcome, DeployRequest, DeployScope, Deployer as _,
    Operation, TenantContext,
};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::{ConnectorError, Environment, HttpClient, Registry, Tenant};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, Workspace, root};
use tokio_util::sync::CancellationToken;

use super::deploy_state::{self, ExternalId, StateError};
use super::query::{Configured, log_unset, toml_value};
use super::validate_live::{Batch, batches};
use super::{Report, placement};
use crate::env::Env;
use crate::envelope::code;
use crate::json::{Json, Object};
use crate::logging::Sink;
use crate::render::glyphs;
use crate::render::outcome::Console;
use crate::render::progress::{Step, StepStatus, plural, seconds_text};
use crate::render::text::Text;
use anstyle::{AnsiColor, Style};
use opentide_schema::platforms::PlatformId;

/// The command path.
pub const COMMAND: &str = "deploy";
/// The wording of a rule an earlier failure kept from running (`NOT_ATTEMPTED`).
pub const NOT_ATTEMPTED: &str = "not attempted after a failure";
/// The longest error kept on a result (`MAX_ERROR_LENGTH`).
const MAX_ERROR_LENGTH: usize = 400;
/// Longest rule name padded into a column (`NAME_WIDTH`).
const NAME_WIDTH: usize = 48;
/// A wrapped error is never narrower than this (`MIN_ERROR_WIDTH`).
const MIN_ERROR_WIDTH: usize = 30;
/// Nor longer than this many lines (`MAX_ERROR_LINES`).
const MAX_ERROR_LINES: usize = 4;
/// Set by `--persist-state-externally` for the run (`PERSIST_EXTERNALLY_ENV`).
pub const PERSIST_EXTERNALLY_ENV: &str = "OPENTIDE_PERSIST_STATE_EXTERNALLY";
/// The actions in tally order, with what each reads as once done (`_DONE`).
const DONE: [(&str, &str); 5] = [
    ("create", "created"),
    ("update", "updated"),
    ("upsert", "created or updated"),
    ("disable", "disabled"),
    ("delete", "deleted"),
];
/// What a sent rule is called by planned action (`_VERBS`).
const VERBS: [(&str, &str); 5] = [
    ("create", "created"),
    ("update", "updated"),
    ("upsert", "deployed"),
    ("disable", "disabled"),
    ("delete", "deleted"),
];
/// Codes that skip the rule on that tenant without failing the run.
const WARNING_CODES: [&str; 1] = ["external_id_missing"];

/// The command's arguments.
#[derive(Clone, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the command's flags, each its own option"
)]
pub struct Args {
    /// `--strategy` values, as typed.
    pub strategies: Vec<String>,
    /// `--all`.
    pub all: bool,
    /// `--uuid` values.
    pub uuids: Vec<String>,
    /// `--file` values.
    pub files: Vec<String>,
    /// `--platform`.
    pub platform: Option<String>,
    /// `--wide`.
    pub wide: bool,
    /// `--keep-deprecated` / `--drop-deprecated`.
    pub keep_deprecated: Option<bool>,
    /// `--skip-promotion`.
    pub skip_promotion: bool,
    /// `--skip-unconfigured`.
    pub skip_unconfigured: bool,
    /// `--persist-state-externally`.
    pub persist_state_externally: bool,
}

/// Where the run's lines go while it runs: the checklist's lines and steps
/// (`Checklist.line`, `_finished`) and the progress events, on the stream
/// log lines go to, so they keep their order.
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "what the run's mode and flags say about its lines"
)]
pub struct Lines {
    /// The stream.
    pub sink: Sink,
    /// stderr's styles and width.
    pub console: Console,
    /// `--json` or MCP: no line is drawn.
    pub silent: bool,
    /// `--quiet`: only a failed rule's line is drawn.
    pub quiet: bool,
    /// `OPENTIDE_PROGRESS=json`.
    pub progress: bool,
    /// Whether stderr is a terminal: a failed rule's error wraps under itself.
    pub terminal: bool,
    /// `human` mode at a terminal: the finished steps print as the checklist's
    /// rows once the run ends, as the live display leaves them.
    pub live: Option<usize>,
}

impl std::fmt::Debug for Lines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lines")
            .field("silent", &self.silent)
            .field("quiet", &self.quiet)
            .finish_non_exhaustive()
    }
}

impl Lines {
    fn write(&self, text: &str) {
        let mut sink = self
            .sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = sink.write_all(text.as_bytes());
        let _ = sink.flush();
    }

    /// One line above the running step (`Checklist.line`): none in JSON or
    /// MCP mode; none under `--quiet` unless *always* (a failure).
    fn line(&self, text: &Text, always: bool) {
        if self.silent || (self.quiet && !always) {
            return;
        }
        self.write(&self.console.line(text));
    }

    /// A finished step: its progress event in every mode, then its row.
    pub(crate) fn step(&self, step: &Step, completed: usize, total: usize) {
        if self.progress {
            self.write(&crate::render::progress::event_line(
                &crate::render::progress::progress_event(&step.name, completed, Some(total)),
            ));
        }
        if self.silent || self.quiet || self.live.is_some() {
            return;
        }
        self.write(&self.console.line(&crate::render::progress::step_line(step)));
    }

    /// The finished steps as the live display leaves them (`_final`).
    pub(crate) fn checklist(&self, steps: &[Step]) {
        let Some(width) = self.live else {
            return;
        };
        if self.silent || self.quiet || steps.is_empty() {
            return;
        }
        self.write(&crate::render::progress::checklist(
            steps,
            width,
            self.console.colour,
        ));
    }
}

/// What a run reads besides its options.
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
    /// The current time: Carbon Black's report stamp, Splunk's clock.
    pub now: jiff::Timestamp,
    /// The platforms' connectors.
    pub registry: &'a Registry,
    /// Where the run's lines go.
    pub lines: Lines,
    /// `--json` (the CI annotation of a run that matched nothing is not written).
    pub json: bool,
    /// `--debug`: status promotion reads every rule file.
    pub debug: bool,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("repo", &self.repo)
            .field("cwd", &self.cwd)
            .finish_non_exhaustive()
    }
}

/// A run's result, keys in the oracle's order, `_`-keys included.
#[derive(Clone, Debug)]
pub struct Sent {
    /// The result.
    pub result: Vec<(String, Json)>,
}

impl Sent {
    /// The result as one JSON object (the CI job summary reads it).
    pub fn result_json(&self) -> Json {
        Json::Object(
            self.result
                .iter()
                .filter(|(key, _)| !key.starts_with('_'))
                .cloned()
                .collect(),
        )
    }

    /// The report the command prints.
    pub fn report(&self) -> Report {
        let mut report = super::validate_live::report_of(COMMAND, &self.result);
        report.outcome_line = text_of(&self.result, "_outcome");
        report.bare_exit = has(&self.result, super::deploy_promote::BARE_EXIT);
        report
    }
}

fn text_of(result: &[(String, Json)], key: &str) -> Option<String> {
    result
        .iter()
        .find(|(name, _)| name == key)
        .and_then(|(_, value)| match value {
            Json::Str(text) => Some(text.clone()),
            _ => None,
        })
}

/// `value` set on `result`, in place when the key is there, else last.
fn set(result: &mut Vec<(String, Json)>, key: &str, value: Json) {
    match result.iter_mut().find(|(name, _)| name == key) {
        Some(entry) => entry.1 = value,
        None => result.push((key.to_owned(), value)),
    }
}

fn has(result: &[(String, Json)], key: &str) -> bool {
    result.iter().any(|(name, _)| name == key)
}

fn convert(value: &CJson) -> Json {
    super::deploy::convert(value)
}

fn names(runs: &[StatusStrategy]) -> Json {
    Json::Array(runs.iter().map(|run| Json::str(run.name())).collect())
}

fn usage(message: &str, failure_code: &str, argument: Option<&str>) -> Vec<(String, Json)> {
    let mut result = vec![
        ("status".to_owned(), Json::str("failed")),
        ("message".to_owned(), Json::str(message)),
        ("_exit_code".to_owned(), Json::Int(2)),
        ("_failure_code".to_owned(), Json::str(failure_code)),
    ];
    if let Some(argument) = argument {
        result.push(("_failure_argument".to_owned(), Json::str(argument)));
    }
    result
}

fn failed(message: &str) -> Vec<(String, Json)> {
    vec![
        ("status".to_owned(), Json::str("failed")),
        ("message".to_owned(), Json::str(message)),
        ("_exit_code".to_owned(), Json::Int(1)),
    ]
}

/// Runs `deploy` without `--dry-run` on the process's runtime: here, or on
/// a thread of its own with this thread's log subscriber when a host runs a
/// runtime here (`sync_call`).
pub fn run(args: &Args, cx: &Context<'_>) -> Sent {
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let ran = opentide_connectors::runtime::sync_call(|| {
        tracing::dispatcher::with_default(&dispatch, || run_deploy(args, cx))
    });
    Sent {
        result: ran.unwrap_or_else(|_| failed("the deploy stopped unexpectedly")),
    }
}

/// `run_deploy`: the plan and the sends, then the warnings and the blocks
/// a status kept out.
fn run_deploy(args: &Args, cx: &Context<'_>) -> Vec<(String, Json)> {
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = match super::open(options) {
        Ok(workspace) => workspace,
        Err(message) => return failed(&message),
    };
    let mut warnings: Vec<String> = Vec::new();
    let mut skipped: Vec<plan::Skipped> = Vec::new();
    let mut result = deploy(args, cx, &workspace, &mut warnings, &mut skipped);
    if (!args.uuids.is_empty() || !args.files.is_empty()) && !has(&result, "scope") {
        result.push(("scope".into(), Json::str("selected")));
    }
    let unread = opentide_compile::dry_run::unread_files(&workspace, cx.cwd);
    if !unread.is_empty() {
        warnings.push(format!(
            "{} could not be read: {}; opentide validate shows where",
            plan::plural(unread.len(), "object file"),
            unread.join(", ")
        ));
    }
    if !warnings.is_empty() {
        let mut all: Vec<Json> = warnings.iter().map(Json::str).collect();
        if let Some((_, Json::Array(own))) = result.iter().find(|(key, _)| key == "warnings") {
            all.extend(own.iter().cloned());
        }
        set(&mut result, "warnings", Json::Array(all));
    }
    if !skipped.is_empty() {
        report_skipped(&mut result, &skipped, &workspace);
    }
    let skipped_run = text_of(&result, "status").as_deref() == Some("skipped");
    if skipped_run
        && !has(&result, "_next_actions")
        && !root::is_workspace_root(&OsFs, workspace.root())
    {
        result.push((
            "_next_actions".into(),
            Json::Array(vec![Json::object([
                ("command", Json::str("opentide setup")),
                ("reason", Json::str("no workspace here: create one")),
            ])]),
        ));
    }
    crate::app::release(workspace);
    result
}

/// How many rules a status kept out of the plan, and what it says of them
/// (`3 rules in DESIGN`, `3 rules left out: 2 in DESIGN, 1 in DRAFT`).
fn left_out(skipped: &[plan::Skipped]) -> (usize, String) {
    let mut rules: Vec<&str> = Vec::new();
    let mut counts: IndexMap<&str, usize> = IndexMap::new();
    for entry in skipped {
        if !rules.contains(&entry.uuid.as_str()) {
            rules.push(&entry.uuid);
        }
        *counts.entry(entry.status.as_str()).or_default() += 1;
    }
    let in_status = if counts.len() == 1 {
        format!(
            "{} in {}",
            plan::plural(rules.len(), "rule"),
            counts.keys().next().copied().unwrap_or_default()
        )
    } else {
        let mut ordered: Vec<(&str, usize)> = counts.into_iter().collect();
        ordered.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        let listed: Vec<String> = ordered
            .iter()
            .map(|(status, count)| format!("{count} in {status}"))
            .collect();
        format!(
            "{} left out: {}",
            plan::plural(rules.len(), "rule"),
            listed.join(", ")
        )
    };
    (rules.len(), in_status)
}

/// The run's strategies, as the result's `strategies` names them.
fn run_strategies(result: &[(String, Json)]) -> Vec<StatusStrategy> {
    match result.iter().find(|(key, _)| key == "strategies") {
        Some((_, Json::Array(items))) => items
            .iter()
            .filter_map(Json::as_str)
            .filter_map(|name| {
                strategy::DEPLOYABLE
                    .iter()
                    .chain([StatusStrategy::Disablement, StatusStrategy::Deletion].iter())
                    .find(|run| run.name() == name)
                    .copied()
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Counts the blocks a status kept out of the plan (`_report_skipped`).
fn report_skipped(
    result: &mut Vec<(String, Json)>,
    skipped: &[plan::Skipped],
    workspace: &Workspace,
) {
    let (rules, in_status) = left_out(skipped);
    let runs = run_strategies(result);
    let run_names = if runs.is_empty() {
        "this run".to_owned()
    } else {
        runs.iter()
            .map(|run| run.name())
            .collect::<Vec<_>>()
            .join(" or ")
    };
    result.push((
        "skipped".into(),
        Json::Array(
            skipped
                .iter()
                .map(|entry| convert(&entry.to_json()))
                .collect(),
        ),
    ));
    let mut summary = match result.iter().find(|(key, _)| key == "_summary") {
        Some((_, Json::Object(members))) => members.clone(),
        _ => Object::new(),
    };
    summary.insert("skipped".into(), Json::from(rules));
    set(result, "_summary", Json::Object(summary));
    let owned = opentide_compile::Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let deployable = if runs.is_empty() {
        Vec::new()
    } else {
        owned.statuses.deployed_by(&runs)
    };
    let listed = match deployable.as_slice() {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    };
    let advice = if listed.is_empty() {
        format!("no configured status deploys with {run_names}")
    } else {
        format!("set a platform block's status to {listed} for {run_names} to deploy it")
    };
    let planned = matches!(
        result.iter().find(|(key, _)| key == "plan"),
        Some((_, Json::Object(members))) if !members.is_empty()
    );
    if text_of(result, "status").as_deref() == Some("skipped") && !planned {
        result.push((
            "_outcome".into(),
            Json::str(format!(
                "No rule has a status {run_names} deploys {} {in_status}",
                glyphs::SEPARATOR
            )),
        ));
        if !has(result, "advice") {
            result.push(("advice".into(), Json::str(advice)));
        }
    } else if !has(result, "detail") {
        result.push((
            "detail".into(),
            Json::str(format!("not in the plan: {in_status}; {advice}")),
        ));
    }
}

/// A skipped deploy, in the same envelope as one that planned rules
/// (`_nothing_to_deploy`); a run whose planning refused a rule failed.
fn nothing(message: &str, refused: bool, field: (&str, Json)) -> Vec<(String, Json)> {
    let mut result = vec![
        (field.0.to_owned(), field.1),
        (
            "status".into(),
            Json::str(if refused { "failed" } else { "skipped" }),
        ),
        (
            "message".into(),
            Json::str(if refused {
                format!("{message}; planning reported rule errors")
            } else {
                message.to_owned()
            }),
        ),
        ("deployed".into(), Json::Array(Vec::new())),
        ("dry_run".into(), Json::Bool(false)),
        ("plan".into(), Json::Object(Object::new())),
    ];
    if refused {
        result.push(("_exit_code".into(), Json::Int(1)));
    }
    result
}

/// Whether the run would promote statuses (`StatusStrategy.RELEASE in run`
/// on a push in CI, reading the changed files, without `--skip-promotion`).
fn promotes(args: &Args, runs: &[StatusStrategy], env: &Env) -> bool {
    let lookup = |name: &str| env.get(name).map(str::to_owned);
    let ci = opentide_compile::git::ci(&lookup);
    runs.contains(&StatusStrategy::Release)
        && !args.all
        && args.uuids.is_empty()
        && args.files.is_empty()
        && !args.skip_promotion
        && ci != opentide_compile::git::Ci::Local
        && !opentide_compile::git::is_change_request(ci, &lookup)
}

/// `_deploy` for a run that sends.
#[expect(
    clippy::too_many_lines,
    reason = "the oracle's steps in order (_deploy), read top to bottom"
)]
fn deploy(
    args: &Args,
    cx: &Context<'_>,
    workspace: &Workspace,
    plan_warnings: &mut Vec<String>,
    plan_skipped: &mut Vec<plan::Skipped>,
) -> Vec<(String, Json)> {
    if let Some(value) = cx
        .env
        .get(strategy::REMOVED_PLAN_ENV)
        .filter(|value| !value.trim().is_empty())
    {
        return usage(
            &strategy::removed_plan_message(Some(value), false),
            code::USAGE_INVALID_VALUE,
            None,
        );
    }
    if args.strategies.is_empty() {
        return usage(
            opentide_compile::dry_run::STRATEGY_REQUIRED,
            code::USAGE_MISSING_OPTION,
            Some("--strategy"),
        );
    }
    let owned = opentide_compile::Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let runs: RunStrategies =
        match strategy::parse_strategies(&args.strategies, &owned.statuses, "--strategy") {
            Ok(runs) => runs,
            Err(message) => {
                let mut result = usage(&message, code::USAGE_INVALID_CHOICE, Some("--strategy"));
                if let Some(suggestion) =
                    opentide_compile::dry_run::strategy_suggestion(&args.strategies)
                {
                    result.push(("_failure_suggestion".into(), Json::str(suggestion)));
                }
                return result;
            }
        };
    let fs = workspace.fs().as_ref();
    let (rules_dir, folder) = opentide_compile::dry_run::rules_folder(workspace);
    let local = plan::local_scope(fs, &rules_dir, &folder);
    let selecting = !args.uuids.is_empty() || !args.files.is_empty();
    let request = opentide_compile::dry_run::Request {
        strategies: args.strategies.clone(),
        all: args.all,
        uuids: args.uuids.clone(),
        files: args.files.clone(),
        platform: args.platform.clone(),
        wide: args.wide,
        keep_deprecated: args.keep_deprecated,
        removed_plan: None,
        cwd: cx.cwd.to_path_buf(),
        plugins: crate::plugins::plugin_ids(),
    };
    let scope: Scope = if selecting {
        let (scope, unmatched) =
            opentide_compile::dry_run::selected_scope(fs, workspace, &local, &request, cx.cwd);
        if !unmatched.is_empty() {
            let mut result = failed(&format!(
                "No rule file directly in {folder} matched: {}",
                unmatched.join(", ")
            ));
            let at = result.len() - 1;
            result.insert(at, ("scope".into(), Json::str("selected")));
            result.insert(
                at + 1,
                (
                    "unmatched".into(),
                    Json::Array(unmatched.iter().map(Json::str).collect()),
                ),
            );
            result.insert(at + 2, ("dry_run".into(), Json::Bool(false)));
            return result;
        }
        scope
    } else if args.all {
        local
    } else {
        let lookup = |name: &str| cx.env.get(name).map(str::to_owned);
        let top = workspace.root().to_path_buf();
        match opentide_compile::dry_run::git_scope(&top, cx.cwd, &lookup, &rules_dir, &folder) {
            Ok((scope, warning)) => {
                plan_warnings.extend(warning);
                scope
            }
            Err(message) => return failed(&message),
        }
    };
    // Promotion rewrites the promoted rules' status on disk; the workspace
    // read before it still holds the old status, which routes those rules
    // to no RELEASE tenant and compiles them with the old status.
    let reopened;
    let workspace = if promotes(args, &runs, cx.env) {
        let settings = opentide_compile::promotion::Settings::new(&owned.config, &owned.statuses);
        let debug = cx.debug || cx.env.opentide_debug();
        let local = if debug {
            plan::local_scope(fs, &rules_dir, &folder).files
        } else {
            Vec::new()
        };
        let promotion = super::deploy_promote::Promotion {
            settings: &settings,
            changed: &scope.files,
            local: &local,
            debug,
        };
        if let Err(stop) = super::deploy_promote::run(&promotion, &cx.lines) {
            return super::deploy_promote::stopped(&stop);
        }
        // Read it again, so the plan and the payloads see the promoted status.
        let (_, options) = placement(cx.repo, cx.env, cx.cwd);
        reopened = match super::open(options) {
            Ok(workspace) => workspace,
            Err(message) => return failed(&message),
        };
        &reopened
    } else {
        workspace
    };
    let enabled = plan::enabled_with(&owned.config, &crate::plugins::plugin_ids());
    let read = |path: &Path| -> Result<opentide_schema::node::Node, String> {
        let bytes = fs.read(path).map_err(|error| error.to_string())?;
        let document =
            opentide_schema::node::load_bytes(&bytes).map_err(|error| error.to_string())?;
        document
            .root()
            .map(|root| (**root).clone())
            .ok_or_else(|| "the file is empty".to_owned())
    };
    let keep_deprecated = args.keep_deprecated.unwrap_or(!args.all);
    let selection = plan::select(
        &owned.statuses,
        &scope,
        &read,
        &SelectOptions {
            runs: &runs,
            wide: args.wide,
            keep_deprecated,
            enabled: &enabled,
            folder: &folder,
            log: false,
        },
    );
    let selection = match selection {
        Ok(selection) => selection,
        Err(plan::PlanError::ObjectFile { path, problem }) => {
            return failed(&format!("{}: {problem}", path.display()));
        }
        Err(plan::PlanError::Failed(message)) => {
            if !scope.nested.is_empty() {
                plan_warnings.push(plan::nested_warning(&scope.nested, &folder));
            }
            return failed(&message);
        }
    };
    plan_warnings.extend(selection.warnings.iter().cloned());
    plan_skipped.extend(selection.skipped.iter().cloned());
    let refused = !selection.refused.is_empty();
    let refused_rules = selection.refused.clone();
    let mut deployment = selection.platforms.clone();
    if let Some(platform) = &args.platform {
        let Some(uuids) = deployment.shift_remove(platform) else {
            return nothing(
                "No rules to deploy for this platform",
                refused,
                ("platform", Json::str(platform)),
            );
        };
        deployment = IndexMap::from([(platform.clone(), uuids)]);
    }
    let run_names = names(&runs);
    if deployment.is_empty() {
        // A run without --platform: the command writes `emit_warning`'s CI
        // annotation (`no_rules_warning`); with one, the platform's absence
        // returned above.
        return nothing(
            opentide_compile::dry_run::NO_RULES_MATCHED,
            refused,
            ("strategies", run_names),
        );
    }
    let plan_payload = Json::Object(
        deployment
            .iter()
            .map(|(platform, uuids)| {
                (
                    platform.clone(),
                    Json::Array(uuids.iter().map(Json::str).collect()),
                )
            })
            .collect(),
    );
    let config = &owned.config;
    let tenantless: Vec<&String> = deployment
        .keys()
        .filter(|platform| plan::tenants(config, platform).is_empty())
        .collect();
    if !tenantless.is_empty() {
        let path = |platform: &str| format!(".opentide/configurations/platforms/{platform}.toml");
        let detail: Vec<String> = tenantless
            .iter()
            .map(|platform| format!("{platform} has no tenants configured in {}", path(platform)))
            .collect();
        let advice: Vec<String> = tenantless
            .iter()
            .map(|platform| {
                format!(
                    "add (or uncomment) a [[tenants]] entry in {}",
                    path(platform)
                )
            })
            .collect();
        let missing = Json::Object(
            tenantless
                .iter()
                .map(|platform| ((*platform).clone(), Json::str(path(platform))))
                .collect(),
        );
        let detail = detail.join("; ");
        let skip = args.skip_unconfigured && tenantless.len() == deployment.len() && !refused;
        let mut result = vec![
            (
                "status".to_owned(),
                Json::str(if skip { "skipped" } else { "failed" }),
            ),
            (
                "message".into(),
                Json::str(if skip {
                    format!("Skipped deploy: {detail}")
                } else if refused {
                    format!("Planning refused rules; {detail}")
                } else {
                    format!("Cannot deploy: {detail}")
                }),
            ),
            ("advice".into(), Json::str(advice.join("; "))),
            ("missing_tenants".into(), missing),
            ("deployed".into(), Json::Array(Vec::new())),
            ("dry_run".into(), Json::Bool(false)),
            ("plan".into(), plan_payload),
        ];
        if !skip {
            result.push(("_exit_code".into(), Json::Int(1)));
        }
        return result;
    }
    // Each platform's tenants, resolved before anything is sent.
    let mut targets: IndexMap<String, IndexMap<String, Vec<String>>> = IndexMap::new();
    let index = workspace.index();
    for (platform, uuids) in &deployment {
        let tables = plan::tenants(config, platform);
        let configured: Vec<Configured> = tables
            .iter()
            .map(|table| Configured {
                name: opentide_compile::deploy::tenant_name(table).to_owned(),
                setup: table
                    .get("setup")
                    .and_then(CJson::as_object)
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect();
        log_unset(&configured, cx.env);
        let tenants: Vec<plan::Tenant> = tables
            .iter()
            .map(|table| plan::Tenant::from_json(table))
            .collect();
        let mut per_tenant: IndexMap<String, Vec<String>> = IndexMap::new();
        for uuid in uuids {
            let Some(rule) = index.get("rule", uuid).and_then(|object| object.root()) else {
                continue;
            };
            let block = CJson::from_node(rule)
                .get("configurations")
                .and_then(|configurations| configurations.get(platform))
                .cloned()
                .unwrap_or(CJson::Null);
            let status = block
                .get("status")
                .and_then(CJson::as_str)
                .unwrap_or_default();
            let Ok(rule_strategy) = owned.statuses.strategy(status) else {
                continue;
            };
            for tenant in plan::rule_tenants(&tenants, &block, rule_strategy, &runs, args.wide) {
                per_tenant
                    .entry(tenant.name.clone())
                    .or_default()
                    .push(opentide_compile::rule::canonical_uuid(uuid));
            }
        }
        targets.insert(platform.clone(), per_tenant);
    }
    let changes = plan_changes(workspace, &owned, &deployment, &targets);
    let tenant_count: usize = targets.values().map(IndexMap::len).sum();
    let started = Instant::now();
    let separator = format!(" {} ", glyphs::SEPARATOR);
    // The header is bold throughout, its labels bold and dim.
    let bold_dim = Style::new().bold().dimmed();
    let mut header = Text::styled("Deploy plan", &Style::new().bold());
    header.append(&format!("{separator}strategy "), &bold_dim);
    let strategy_names: Vec<&str> = runs.iter().map(|run| run.name()).collect();
    header.append(&strategy_names.join(" "), &Style::new().bold());
    header.append(
        &format!(
            "{separator}{}",
            plan::scope_text(deployment.len(), tenant_count)
        ),
        &bold_dim,
    );
    cx.lines.line(&header, false);
    cx.lines.line(
        &Text::styled(&plan::message(&changes), &Style::new().dimmed()),
        false,
    );
    let compile_cx = owned.context(index);
    let mut log = DeployLog::new(&cx.lines, &changes);
    let mut sender = Sender {
        cx,
        workspace,
        compile: &compile_cx,
        runs: &runs,
        wide: args.wide,
        persist: args.persist_state_externally
            || cx
                .env
                .get(PERSIST_EXTERNALLY_ENV)
                .is_some_and(|v| !v.is_empty()),
        failed: false,
        failures: Vec::new(),
        stopped_tenants: Vec::new(),
        warned: false,
        environment: Environment::from_pairs(cx.env.iter()),
        cancel: CancellationToken::new(),
        runtime: opentide_connectors::runtime::shared(),
    };
    let total = deployment.len();
    let mut deployed: Vec<String> = Vec::new();
    let mut failure: Option<(String, Raised)> = None;
    let mut completed = 0;
    let mut steps: Vec<Step> = Vec::new();
    for (system, uuids) in &deployment {
        let mut step = Step::new(system);
        step.unit = "rule".into();
        step.count = Some(uuids.len());
        let step_started = Instant::now();
        let failed_before = sender.failed;
        let mut sent = false;
        let deployed_here = sender.platform(system, uuids, &mut log);
        // A platform that stopped its own tenants on an interrupt returns:
        // the run stops after it all the same.
        let deployed_here = match deployed_here {
            Ok(()) if sender.interrupted() => Err(Raised::new("interrupted").stopping(Stops::Run)),
            other => other,
        };
        match deployed_here {
            // An interrupt: nothing more is sent.
            Err(raised) if raised.stops == Stops::Run => {
                step.status = StepStatus::Failed;
                log.unreached(None, "not_attempted", NOT_ATTEMPTED);
                step.outcome = Some(counts_text(&log.platform_results(system)));
                failure = Some((system.clone(), raised));
            }
            // The platform could not deploy (its tenants, its plugin): the
            // run fails, its rules not sent are not attempted, and the other
            // platforms go on.
            Err(raised) => {
                let error = raised.error();
                tracing::error!(
                    system = system.as_str(),
                    detail = error.as_str(),
                    critical = true,
                    "platform_deployment_failed"
                );
                sender.unusable(system, None, &error);
                log.unreached(
                    Some(system),
                    "not_attempted",
                    &format!("not attempted: {system} failed"),
                );
                step.status = StepStatus::Failed;
                step.outcome = Some(counts_text(&log.platform_results(system)));
            }
            Ok(()) => {
                sent = true;
                log.settle(system);
                let mine = log.platform_results(system);
                step.outcome = Some(counts_text(&mine));
                step.status = if mine.iter().any(|result| result.status == "failed")
                    || (sender.failed && !failed_before)
                {
                    StepStatus::Failed
                } else {
                    StepStatus::Ok
                };
            }
        }
        step.seconds = step_started.elapsed().as_secs_f64();
        completed += 1;
        cx.lines.step(&step, completed, total);
        steps.push(step);
        if failure.is_some() {
            break;
        }
        // A platform none of whose tenants could be used deployed nothing.
        let planned_on: Vec<Option<&str>> = log
            .planned
            .keys()
            .filter(|(name, _)| name == system)
            .map(|(_, tenant)| tenant.as_deref())
            .collect();
        let unusable = !planned_on.is_empty()
            && planned_on.iter().all(|tenant| {
                sender.stopped_tenants.iter().any(|(platform, stopped)| {
                    platform == system && Some(stopped.as_str()) == *tenant
                })
            });
        if sent && !unusable {
            deployed.push(system.clone());
        }
    }
    if let Some((system, _)) = &failure {
        let after = deployment
            .keys()
            .position(|name| name == system)
            .map_or(deployment.len(), |at| at + 1);
        for rest in deployment.keys().skip(after) {
            let mut step = Step::new(rest);
            step.unit = "rule".into();
            step.status = StepStatus::Skipped;
            step.detail = NOT_ATTEMPTED.into();
            completed += 1;
            cx.lines.step(&step, completed, total);
            steps.push(step);
        }
    }
    cx.lines.checklist(&steps);
    let seconds = started.elapsed().as_secs_f64();
    let results = log.results.clone();
    let platforms = deployment.len();
    let common = |result: &mut Vec<(String, Json)>| {
        result.push((
            "deployed".into(),
            Json::Array(deployed.iter().map(Json::str).collect()),
        ));
        result.push(("dry_run".into(), Json::Bool(false)));
        result.push(("plan".into(), plan_payload.clone()));
    };
    let changes_json = Json::Array(
        changes
            .iter()
            .map(|change| convert(&change.to_json()))
            .collect(),
    );
    let results_json = Json::Array(results.iter().map(RuleResult::to_json).collect());
    if let Some((system, raised)) = failure {
        let error = raised.error();
        let mut result = vec![
            ("status".to_owned(), Json::str("failed")),
            (
                "message".into(),
                Json::str(format!("Deployment to {system} failed: {error}")),
            ),
        ];
        common(&mut result);
        result.push(("strategies".into(), run_names));
        result.push(("changes".into(), changes_json));
        result.push(("results".into(), results_json));
        result.push((
            "_summary".into(),
            run_summary(&results, platforms, tenant_count, seconds),
        ));
        result.push(("_exit_code".into(), Json::Int(1)));
        // The rule the stop came on: its error is the stop's own (a rule
        // refused before it on the same platform is not the culprit).
        let culprit = results.iter().rev().find(|result| {
            result.platform == system
                && result.status == "failed"
                && result.error.as_deref() == Some(raised.describe().as_str())
        });
        if let Some(culprit) = culprit {
            tracing::debug!(
                system = system.as_str(),
                detail = error.as_str(),
                "platform_deployment_failed"
            );
            set(
                &mut result,
                "message",
                Json::str(outcome_message(&results, seconds, true)),
            );
            result.push((
                "error".into(),
                Json::str(format!(
                    "Deployment to {system} failed on {}: {}",
                    culprit.name,
                    culprit.error.clone().unwrap_or_default()
                )),
            ));
            result.push(("_failure_code".into(), Json::str(super::ISSUES_FOUND)));
        } else {
            tracing::error!(
                system = system.as_str(),
                detail = error.as_str(),
                "platform_deployment_failed"
            );
        }
        // Every failure before the stop, and the stop itself when no rule
        // carries it.
        let mut unusable = sender.failures.clone();
        if culprit.is_none() {
            unusable.push(Unusable {
                platform: system.clone(),
                tenant: None,
                error: bounded(&error),
            });
        }
        let failures = failures(&results, &unusable, &refused_rules);
        result.push((
            "failures".into(),
            Json::Array(failures.into_iter().map(|(_, failure)| failure).collect()),
        ));
        return result;
    }
    let outcome_failed = sender.failed || refused;
    let any_failed = results.iter().any(|result| result.status == "failed");
    let failures = failures(&results, &sender.failures, &refused_rules);
    // No rule failed: the first tenant or platform that could not deploy
    // says why the run failed.
    let message = if outcome_failed && !any_failed {
        failures.first().map_or_else(
            || "Deployment finished with errors".to_owned(),
            |(line, _)| format!("{line}{}", more_failures(failures.len())),
        )
    } else {
        outcome_message(&results, seconds, outcome_failed)
    };
    let mut result = vec![
        ("message".to_owned(), Json::str(message)),
        (
            "status".into(),
            Json::str(if outcome_failed {
                "failed"
            } else {
                "completed"
            }),
        ),
    ];
    common(&mut result);
    result.push(("changes".into(), changes_json));
    result.push((
        "_summary".into(),
        run_summary(&results, platforms, tenant_count, seconds),
    ));
    result.push(("_exit_code".into(), Json::Int(i64::from(outcome_failed))));
    result.push(("results".into(), results_json));
    if outcome_failed && any_failed {
        result.push(("_failure_code".into(), Json::str(super::ISSUES_FOUND)));
    }
    if let Some((first, _)) = failures.first() {
        // The run's error names its first failure, as the Python deployer's
        // did when that failure stopped it.
        let more = more_failures(failures.len());
        result.push(("error".into(), Json::str(format!("{first}{more}"))));
        result.push((
            "failures".into(),
            Json::Array(failures.into_iter().map(|(_, failure)| failure).collect()),
        ));
    }
    if sender.warned {
        result.push((
            "warnings".into(),
            Json::Array(vec![Json::str("Some rules reported deployment warnings")]),
        ));
    }
    result.push(("strategies".into(), names(&runs)));
    result
}

/// Every rule on every tenant the targets resolved; rules on tenantless
/// platforms once (`plan_changes`).
fn plan_changes(
    workspace: &Workspace,
    owned: &opentide_compile::Owned,
    deployment: &IndexMap<String, Vec<String>>,
    targets: &IndexMap<String, IndexMap<String, Vec<String>>>,
) -> Vec<Change> {
    let fs = workspace.fs().as_ref();
    let index = workspace.index();
    let root = workspace.root().to_path_buf();
    let mut changes = Vec::new();
    for (platform, uuids) in deployment {
        let tenants = targets.get(platform).filter(|tenants| !tenants.is_empty());
        let pairs: Vec<(Option<String>, String)> = match tenants {
            Some(tenants) => tenants
                .iter()
                .flat_map(|(tenant, ids)| ids.iter().map(|id| (Some(tenant.clone()), id.clone())))
                .collect(),
            None => uuids.iter().map(|uuid| (None, uuid.clone())).collect(),
        };
        for (tenant, uuid) in pairs {
            let data = index
                .get("rule", &uuid)
                .and_then(|object| object.root())
                .map(CJson::from_node);
            let name = data
                .as_ref()
                .and_then(|data| data.get("name"))
                .and_then(CJson::as_str)
                .unwrap_or(&uuid)
                .to_owned();
            let status = data
                .as_ref()
                .and_then(|data| data.get("configurations"))
                .and_then(|configurations| configurations.get(platform))
                .and_then(|block| block.get("status"))
                .and_then(CJson::as_str)
                .unwrap_or_default()
                .to_owned();
            let known = || match &tenant {
                Some(tenant) => plan::state_id(fs, &root, &uuid, platform, tenant),
                None => None,
            };
            let action = plan::action(&owned.statuses, platform, tenant.is_some(), &status, &known);
            changes.push(Change {
                platform: platform.clone(),
                tenant,
                uuid,
                name,
                status,
                action,
                fails: false,
            });
        }
    }
    changes
}

// ------------------------------------------------------------------ results

/// One rule on one tenant: what was sent and how it went (`RuleResult`).
#[derive(Clone, Debug)]
struct RuleResult {
    platform: String,
    tenant: Option<String>,
    id: String,
    name: String,
    status: &'static str,
    action: Option<String>,
    seconds: Option<f64>,
    error: Option<String>,
    reason: Option<String>,
    started: Instant,
}

impl RuleResult {
    fn new(platform: &str, tenant: Option<&str>, id: &str, name: &str) -> Self {
        Self {
            platform: platform.to_owned(),
            tenant: tenant.map(str::to_owned),
            id: id.to_owned(),
            name: name.to_owned(),
            status: "deployed",
            action: None,
            seconds: None,
            error: None,
            reason: None,
            started: Instant::now(),
        }
    }

    /// Records a failure the deployer reports without raising (`fail`).
    fn fail(&mut self, error: &str) {
        if self.status != "failed" {
            self.status = "failed";
            self.error = Some(bounded(error));
        }
    }

    /// Records that the engine chose not to send it (`skip`).
    fn skip(&mut self, reason: &str) {
        if self.status != "failed" {
            self.status = "skipped";
            self.reason = Some(reason.to_owned());
        }
    }

    /// The row `results` carries (`to_dict`).
    fn to_json(&self) -> Json {
        let text = |value: &Option<String>| value.as_ref().map_or(Json::Null, Json::str);
        Json::object([
            ("platform", Json::str(&self.platform)),
            ("tenant", text(&self.tenant)),
            ("id", Json::str(&self.id)),
            ("name", Json::str(&self.name)),
            ("status", Json::str(self.status)),
            ("action", text(&self.action)),
            (
                "seconds",
                self.seconds.map_or(Json::Null, |seconds| {
                    Json::Float((seconds * 1000.0).round() / 1000.0)
                }),
            ),
            ("error", text(&self.error)),
            ("reason", text(&self.reason)),
        ])
    }
}

/// *text* on one line, cut at [`MAX_ERROR_LENGTH`] (`_bounded`).
fn bounded(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > MAX_ERROR_LENGTH {
        let cut: String = text.chars().take(MAX_ERROR_LENGTH - 1).collect();
        return format!("{}…", cut.trim_end());
    }
    text
}

/// `2 deployed, 1 failed, 88 not attempted` (`counts_text`).
fn counts_text(results: &[&RuleResult]) -> String {
    let count = |status: &str| {
        results
            .iter()
            .filter(|result| result.status == status)
            .count()
    };
    let mut parts = vec![
        format!("{} deployed", count("deployed")),
        format!("{} failed", count("failed")),
    ];
    if count("skipped") > 0 {
        parts.push(format!("{} skipped", count("skipped")));
    }
    parts.push(format!("{} not attempted", count("not_attempted")));
    parts.join(", ")
}

/// What a real run did, rule by rule (`run_counts`).
fn run_counts(results: &[RuleResult]) -> IndexMap<&'static str, usize> {
    let mut counts: IndexMap<&'static str, usize> =
        DONE.iter().map(|(action, _)| (*action, 0)).collect();
    for key in ["failed", "skipped", "not_attempted"] {
        counts.insert(key, 0);
    }
    for result in results {
        let key = if result.status == "deployed" {
            let action = result.action.as_deref().unwrap_or("upsert");
            DONE.iter()
                .find(|(name, _)| *name == action)
                .map_or("upsert", |(name, _)| *name)
        } else {
            result.status
        };
        *counts.entry(key).or_default() += 1;
    }
    counts
}

/// The JSON `summary` of a real run (`run_summary`).
fn run_summary(results: &[RuleResult], platforms: usize, tenants: usize, seconds: f64) -> Json {
    let counts = run_counts(results);
    let mut members: Vec<(String, Json)> = counts
        .iter()
        .map(|(key, count)| ((*key).to_owned(), Json::from(*count)))
        .collect();
    members.push((
        "seconds".into(),
        Json::Float((seconds * 1000.0).round() / 1000.0),
    ));
    members.push(("platforms".into(), Json::from(platforms)));
    members.push(("tenants".into(), Json::from(tenants)));
    Json::object(members)
}

/// The run's last line, for a pass and for a failure alike (`outcome_message`).
fn outcome_message(results: &[RuleResult], seconds: f64, failed: bool) -> String {
    let counts = run_counts(results);
    let mut done: Vec<String> = DONE
        .iter()
        .filter(|(action, _)| counts[action] > 0)
        .map(|(action, word)| format!("{} {word}", counts[action]))
        .collect();
    if counts["skipped"] > 0 {
        done.push(format!("{} skipped", counts["skipped"]));
    }
    let sent: Vec<&RuleResult> = results.iter().filter(|r| r.status == "deployed").collect();
    let mut rules: Vec<&str> = sent.iter().map(|r| r.id.as_str()).collect();
    rules.sort_unstable();
    rules.dedup();
    let mut tenants: Vec<(&str, &str)> = sent
        .iter()
        .filter_map(|r| {
            r.tenant
                .as_deref()
                .map(|tenant| (r.platform.as_str(), tenant))
        })
        .collect();
    tenants.sort_unstable();
    tenants.dedup();
    let tail = format!(
        "{} failed, {} not attempted",
        counts["failed"], counts["not_attempted"]
    );
    let mut parts: Vec<String> = Vec::new();
    if failed {
        parts.push("Deployment failed".into());
        done.push(tail);
        parts.push(done.join(", "));
    } else {
        parts.push(format!(
            "Deployed {} to {}",
            plural(rules.len(), "rule", None),
            plural(tenants.len(), "tenant", None)
        ));
        if !done.is_empty() {
            parts.push(done.join(", "));
        }
        parts.push(tail);
    }
    parts.push(seconds_text(seconds));
    parts.join(&format!(" {} ", glyphs::SEPARATOR))
}

// ---------------------------------------------------------------- the log

type Key = (String, Option<String>);

/// Follows a deploy: one line per finished rule (`DeployLog`).
struct DeployLog<'l> {
    lines: &'l Lines,
    results: Vec<RuleResult>,
    planned: IndexMap<Key, Vec<Change>>,
    actions: HashMap<(String, Option<String>, String), String>,
    printed: HashMap<Key, usize>,
}

impl<'l> DeployLog<'l> {
    fn new(lines: &'l Lines, changes: &[Change]) -> Self {
        let mut planned: IndexMap<Key, Vec<Change>> = IndexMap::new();
        let mut actions = HashMap::new();
        for change in changes {
            planned
                .entry((change.platform.clone(), change.tenant.clone()))
                .or_default()
                .push(change.clone());
            actions.insert(
                (
                    change.platform.clone(),
                    change.tenant.clone(),
                    change.uuid.clone(),
                ),
                change.action.to_owned(),
            );
        }
        Self {
            lines,
            results: Vec::new(),
            planned,
            actions,
            printed: HashMap::new(),
        }
    }

    /// A rule ended (`rule_finished`).
    fn finished(&mut self, mut result: RuleResult) {
        if result.seconds.is_none() {
            result.seconds = Some(result.started.elapsed().as_secs_f64());
        }
        if result.action.is_none() {
            for tenant in [result.tenant.clone(), None] {
                if let Some(action) =
                    self.actions
                        .get(&(result.platform.clone(), tenant, result.id.clone()))
                {
                    result.action = Some(action.clone());
                    break;
                }
            }
        }
        self.print(&result);
        self.results.push(result);
    }

    /// A rule planning refused before anything was sent (`refused`).
    fn refused(&mut self, platform: &str, tenant: &str, id: &str, name: &str, error: &str) {
        let mut result = RuleResult::new(platform, Some(tenant), id, name);
        result.status = "failed";
        result.error = Some(bounded(error));
        result.seconds = Some(0.0);
        self.finished(result);
    }

    /// A rule the engine decided not to send (`skipped`).
    fn skipped(&mut self, platform: &str, tenant: &str, id: &str, name: &str, reason: &str) {
        let mut result = RuleResult::new(platform, Some(tenant), id, name);
        result.status = "skipped";
        result.reason = Some(reason.to_owned());
        result.seconds = Some(0.0);
        self.finished(result);
    }

    fn platform_results(&self, platform: &str) -> Vec<&RuleResult> {
        self.results
            .iter()
            .filter(|result| result.platform == platform)
            .collect()
    }

    /// A platform returned without raising (`settle`).
    fn settle(&mut self, platform: &str) {
        let mine = self.platform_results(platform);
        if mine.is_empty() {
            let mut added = Vec::new();
            for ((name, tenant), changes) in &self.planned {
                if name != platform {
                    continue;
                }
                for change in changes {
                    let mut result =
                        RuleResult::new(name, tenant.as_deref(), &change.uuid, &change.name);
                    result.action = Some(change.action.to_owned());
                    added.push(result);
                }
            }
            self.results.extend(added);
            return;
        }
        if mine.iter().any(|result| result.status == "failed") {
            self.unreached(Some(platform), "not_attempted", NOT_ATTEMPTED);
        } else {
            self.unreached(Some(platform), "skipped", "not reported by the engine");
        }
    }

    /// Reports each planned rule that has no result (`unreached`).
    fn unreached(&mut self, platform: Option<&str>, status: &'static str, reason: &str) {
        self.unreached_where(platform, None, status, reason);
    }

    /// Reports each rule planned on one tenant that has no result.
    fn unreached_on(&mut self, platform: &str, tenant: &str, status: &'static str, reason: &str) {
        self.unreached_where(Some(platform), Some(tenant), status, reason);
    }

    /// Reports each planned rule of `platform` (every one when `None`) and of
    /// `tenant` (every tenant when `None`) that has no result.
    fn unreached_where(
        &mut self,
        platform: Option<&str>,
        tenant: Option<&str>,
        status: &'static str,
        reason: &str,
    ) {
        let done: Vec<(String, String)> = self
            .results
            .iter()
            .map(|result| (result.platform.clone(), result.id.clone()))
            .collect();
        let tenanted: Vec<(String, Option<String>, String)> = self
            .results
            .iter()
            .map(|result| {
                (
                    result.platform.clone(),
                    result.tenant.clone(),
                    result.id.clone(),
                )
            })
            .collect();
        let mut missing = Vec::new();
        for ((name, planned_on), changes) in &self.planned {
            if platform.is_some_and(|platform| platform != name)
                || tenant.is_some_and(|tenant| planned_on.as_deref() != Some(tenant))
            {
                continue;
            }
            let tenant = planned_on;
            for change in changes {
                if tenanted.contains(&(name.clone(), tenant.clone(), change.uuid.clone()))
                    || (tenant.is_none() && done.contains(&(name.clone(), change.uuid.clone())))
                {
                    continue;
                }
                let mut result =
                    RuleResult::new(name, tenant.as_deref(), &change.uuid, &change.name);
                result.status = status;
                result.action = Some(change.action.to_owned());
                result.seconds = Some(0.0);
                result.reason = Some(reason.to_owned());
                missing.push(result);
            }
        }
        for result in missing {
            self.print(&result);
            self.results.push(result);
        }
    }

    fn key(&self, result: &RuleResult) -> Key {
        for key in [
            (result.platform.clone(), result.tenant.clone()),
            (result.platform.clone(), None),
        ] {
            if self.planned.contains_key(&key) {
                return key;
            }
        }
        (result.platform.clone(), result.tenant.clone())
    }

    fn print(&mut self, result: &RuleResult) {
        let key = self.key(result);
        let planned = self
            .planned
            .get(&key)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let total_planned = planned.len();
        let name_width = planned
            .iter()
            .map(|change| change.name.chars().count())
            .max()
            .unwrap_or(0)
            .min(NAME_WIDTH);
        if !self.printed.contains_key(&key) {
            self.lines.line(&Text::default(), false);
            self.lines.line(
                &header_line(
                    &key.0,
                    key.1.as_deref(),
                    (total_planned > 0).then_some(total_planned),
                ),
                false,
            );
            self.printed.insert(key.clone(), 0);
        }
        let printed = self.printed.entry(key).or_default();
        *printed += 1;
        let index = *printed;
        let total = total_planned.max(index);
        let width = if self.lines.terminal {
            self.lines.console.width
        } else {
            None
        };
        self.lines.line(
            &result_line(result, index, total, name_width, width),
            result.status == "failed",
        );
    }
}

/// `Deploying to sentinel / contoso · 91 rules` (`header_line`).
fn header_line(platform: &str, tenant: Option<&str>, rules: Option<usize>) -> Text {
    let place = match tenant {
        Some(tenant) if !tenant.is_empty() => format!("{platform} / {tenant}"),
        _ => platform.to_owned(),
    };
    let bold = Style::new().bold();
    let mut line = Text::styled("Deploying to ", &bold);
    line.append(&place, &bold);
    if let Some(rules) = rules {
        line.append(
            &format!(" {} {}", glyphs::SEPARATOR, plural(rules, "rule", None)),
            &Style::new().bold().dimmed(),
        );
    }
    line
}

/// What a finished rule is called (`verb`).
fn verb(result: &RuleResult) -> &'static str {
    match result.status {
        "deployed" => VERBS
            .iter()
            .find(|(action, _)| Some(*action) == result.action.as_deref())
            .map_or("deployed", |(_, verb)| verb),
        "skipped" | "not_attempted" => "skipped",
        _ => "failed",
    }
}

/// `  [ 2/91] ✓ updated   <name>   0.9s` for one finished rule (`result_line`).
fn result_line(
    result: &RuleResult,
    index: usize,
    total: usize,
    name_width: usize,
    width: Option<usize>,
) -> Text {
    let digits = total.to_string().len();
    let failed = result.status == "failed";
    let skipped = matches!(result.status, "skipped" | "not_attempted");
    let mark = if failed {
        glyphs::FAILED
    } else if skipped {
        glyphs::SEPARATOR
    } else {
        glyphs::OK
    };
    let style = if failed {
        AnsiColor::Red.on_default().bold()
    } else if skipped {
        Style::new().dimmed()
    } else {
        AnsiColor::Green.on_default()
    };
    let mut line = Text::plain("  ");
    line.append(
        &format!("[{index:>digits$}/{total}]"),
        &Style::new().dimmed(),
    );
    line.push_str(" ");
    line.append(&format!("{mark} {:<9} ", verb(result)), &style);
    let pad = name_width.saturating_sub(result.name.chars().count());
    let name = format!("{}{}", result.name, " ".repeat(pad));
    if failed {
        line.append(&name, &Style::new().bold());
    } else {
        line.push_str(&name);
    }
    line.push_str("  ");
    if failed {
        let mut detail = result.error.clone().unwrap_or_else(|| "failed".to_owned());
        if let Some(width) = width {
            let lead = line.as_plain().chars().count();
            let mut pieces: Vec<String> =
                textwrap::wrap(&detail, width.saturating_sub(lead).max(MIN_ERROR_WIDTH))
                    .into_iter()
                    .map(|piece| piece.into_owned())
                    .collect();
            if pieces.is_empty() {
                pieces.push(detail.clone());
            }
            if pieces.len() > MAX_ERROR_LINES {
                pieces.truncate(MAX_ERROR_LINES);
                if let Some(last) = pieces.last_mut() {
                    *last = format!("{}…", last.trim_end());
                }
            }
            detail = pieces.join(&format!("\n{}", " ".repeat(lead)));
        }
        line.append(&detail, &AnsiColor::Red.on_default());
    } else if skipped {
        line.append(
            result.reason.as_deref().unwrap_or_default(),
            &Style::new().dimmed(),
        );
    } else {
        line.append(
            &seconds_text(result.seconds.unwrap_or(0.0)),
            &Style::new().dimmed(),
        );
    }
    line
}

// ---------------------------------------------------------------- sending

/// A tenant (or a whole platform, with no tenant) that could not deploy.
#[derive(Debug, Clone)]
struct Unusable {
    platform: String,
    tenant: Option<String>,
    error: String,
}

impl Unusable {
    fn to_json(&self) -> Json {
        let mut fields = vec![("platform".to_owned(), Json::str(&self.platform))];
        if let Some(tenant) = &self.tenant {
            fields.push(("tenant".into(), Json::str(tenant)));
        }
        fields.push(("error".into(), Json::str(&self.error)));
        Json::Object(fields.into_iter().collect())
    }
}

/// What a failure stops: one rule, the rest of its tenant, or the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stops {
    /// The rule fails; the run goes on with the next one.
    Rule,
    /// The tenant cannot be used (its credentials, its connection): its
    /// remaining rules are not attempted, the other tenants go on.
    Tenant,
    /// An interrupt: nothing more is sent.
    Run,
}

/// A failure, in words: the failed rule's line and the run's message say it
/// (`failure`), and what it stops.
#[derive(Debug, Clone)]
struct Raised {
    problem: String,
    stops: Stops,
}

impl Raised {
    /// A failure of the rule being sent.
    fn new(problem: impl Into<String>) -> Self {
        Self {
            problem: problem.into(),
            stops: Stops::Rule,
        }
    }

    /// The same failure, stopping `stops`.
    fn stopping(self, stops: Stops) -> Self {
        Self { stops, ..self }
    }

    /// The problem, for the run's message.
    fn error(&self) -> String {
        self.problem.trim().to_owned()
    }

    /// The problem on one bounded line, for the rule being sent.
    fn describe(&self) -> String {
        bounded(&self.problem)
    }
}

/// What follows the first of `count` failures in the run's error.
fn more_failures(count: usize) -> String {
    match count.saturating_sub(1) {
        0 => String::new(),
        1 => " (and 1 more failure)".to_owned(),
        more => format!(" (and {more} more failures)"),
    }
}

/// Every failure of a run, each with its line for the run's `error`: the
/// failed rules (platform, tenant, id, name, error), then the tenants and
/// platforms that could not deploy.
fn failures(
    results: &[RuleResult],
    unusable: &[Unusable],
    refused: &[String],
) -> Vec<(String, Json)> {
    // Rules refused before any platform was planned (`external_id_in_rule`).
    let refused = refused.iter().map(|uuid| {
        let error = "external_id_in_rule: the rule still carries vendor ids; deploy reads them \
                     only from .opentide/states/deployment/";
        (
            format!("Deployment refused rule {uuid}: {error}"),
            Json::object([("id", Json::str(uuid)), ("error", Json::str(error))]),
        )
    });
    let rules = results
        .iter()
        .filter(|result| result.status == "failed")
        .map(|result| {
            let error = result.error.clone().unwrap_or_default();
            let mut fields = vec![("platform".to_owned(), Json::str(&result.platform))];
            if let Some(tenant) = &result.tenant {
                fields.push(("tenant".into(), Json::str(tenant)));
            }
            fields.push(("id".into(), Json::str(&result.id)));
            fields.push(("name".into(), Json::str(&result.name)));
            fields.push(("error".into(), Json::str(&error)));
            (
                format!(
                    "Deployment to {} failed on {}: {error}",
                    result.platform, result.name
                ),
                Json::Object(fields.into_iter().collect()),
            )
        });
    let tenants = unusable.iter().map(|failure| {
        let line = match &failure.tenant {
            Some(tenant) => format!(
                "Deployment to {} failed on tenant {tenant}: {}",
                failure.platform, failure.error
            ),
            None => format!(
                "Deployment to {} failed: {}",
                failure.platform, failure.error
            ),
        };
        (line, failure.to_json())
    });
    refused.chain(rules).chain(tenants).collect()
}

/// A connector error as a failure: of the rule for an answer the tenant
/// refused, of the tenant for its connection or credentials, of the run for
/// an interrupt.
fn raised(error: &ConnectorError) -> Raised {
    let stops = match error {
        ConnectorError::Cancelled => Stops::Run,
        ConnectorError::Unreachable { .. }
        | ConnectorError::Timeout { .. }
        | ConnectorError::Setup { .. }
        | ConnectorError::MissingCredential { .. }
        | ConnectorError::Crashed { .. }
        | ConnectorError::Authentication { .. }
        | ConnectorError::Gateway { .. }
        | ConnectorError::NetworkUnavailable { .. } => Stops::Tenant,
        // Exhaustive: a new kind must say what it stops, as
        // `DeployError::from` must say what it fails.
        ConnectorError::Answer { .. }
        | ConnectorError::Refused { .. }
        | ConnectorError::QueryTimedOut { .. } => Stops::Rule,
    };
    described(error).stopping(stops)
}

/// A `Deployer`'s failure, raised by `raise` from its connector error: the
/// tenant stopped whenever the `Deployer` says the tenant failed, as the SDKs
/// report it (`DeployError::scope`), whatever the error's kind.
fn scoped(failed: DeployError, raise: impl FnOnce(ConnectorError) -> Raised) -> Raised {
    let tenant = failed.scope == DeployScope::Tenant;
    let raised = raise(failed.into_connector());
    if tenant && raised.stops == Stops::Rule {
        raised.stopping(Stops::Tenant)
    } else {
        raised
    }
}

/// A connector error's words: its own message, the tenant's reason after a
/// refusal, and the tenant that refused the credentials.
fn described(error: &ConnectorError) -> Raised {
    match error {
        ConnectorError::Cancelled => Raised::new("interrupted"),
        ConnectorError::Authentication {
            platform,
            tenant,
            message,
            ..
        } => Raised::new(format!("{platform} tenant '{tenant}': {message}")),
        ConnectorError::Refused {
            message,
            detail: Some(detail),
            ..
        } if !detail.trim().is_empty() && !message.contains(detail.trim()) => {
            Raised::new(format!("{message}: {}", detail.trim()))
        }
        other => Raised::new(other.to_string()),
    }
}

/// `create`, `update` or `delete`: what a planned change does.
fn action_verb(action: &Planned) -> &'static str {
    match action {
        Planned::Create => "create",
        Planned::Update(_) => "update",
        Planned::Delete(_) => "delete",
    }
}

/// The run's state while it sends.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the oracle's flags (`DEPLOYMENT_ERROR_RAISED`, `DEPLOYMENT_WARNING_RAISED`) and the run's options"
)]
struct Sender<'s, 'c> {
    cx: &'s Context<'c>,
    workspace: &'s Workspace,
    compile: &'s opentide_compile::Context<'s>,
    runs: &'s [StatusStrategy],
    wide: bool,
    persist: bool,
    /// `DEPLOYMENT_ERROR_RAISED`.
    failed: bool,
    /// The tenants and platforms that could not deploy, in order: each
    /// failed rule is in the log's results.
    failures: Vec<Unusable>,
    /// Every tenant that stopped before its last rule (platform, tenant).
    stopped_tenants: Vec<(String, String)>,
    /// `DEPLOYMENT_WARNING_RAISED`.
    warned: bool,
    environment: Environment,
    cancel: CancellationToken,
    /// The process's network runtime, or why it could not start: a run
    /// whose runtime does not start fails each tenant with that reason.
    runtime: Result<&'static tokio::runtime::Runtime, String>,
}

/// A tenant's connection.
struct Connection {
    tenant: Tenant,
    http: HttpClient,
}

/// What screening planned for one rule on a tenant that records ids.
enum Planned {
    Create,
    Update(String),
    Delete(String),
}

impl Sender<'_, '_> {
    /// Runs *work* on the process's runtime, with Ctrl-C watched.
    fn block<T>(
        &self,
        work: impl std::future::Future<Output = Result<T, ConnectorError>>,
    ) -> Result<T, ConnectorError> {
        if let Err(message) = &self.runtime {
            return Err(ConnectorError::Crashed {
                platform: String::new(),
                tenant: String::new(),
                message: message.clone(),
            });
        }
        let cancel = &self.cancel;
        let interrupted = self.cx.interrupted;
        // The process's runtime (#1558), driven from this thread.
        opentide_connectors::runtime::block_on(watched(work, cancel, interrupted)).unwrap_or_else(
            |message| {
                Err(ConnectorError::Crashed {
                    platform: String::new(),
                    tenant: String::new(),
                    message,
                })
            },
        )
    }

    fn context<'a>(&'a self, connection: &'a Connection) -> TenantContext<'a> {
        TenantContext {
            tenant: &connection.tenant,
            http: &connection.http,
            cancel: &self.cancel,
        }
    }

    /// The tenant's connection (`Tenant.from_setup`, one client per tenant).
    fn connect(&self, platform: &str, batch: &Batch) -> Result<Connection, Raised> {
        let setup: toml::Table = batch
            .tenant
            .setup
            .iter()
            .filter_map(|(key, value)| toml_value(value).map(|value| (key.clone(), value)))
            .collect();
        let settings = opentide_connectors::deploy_http_settings(platform);
        let tenant = Tenant::from_setup(
            platform,
            &batch.tenant.name,
            &setup,
            &self.environment,
            Resolve::Counting,
            &settings,
        )
        .map_err(|error| Raised::new(error.to_string()))?;
        let http = HttpClient::new(
            &tenant.label,
            &tenant.http,
            &self.environment,
            self.cx.proxy,
        )
        .map_err(|error| Raised::new(error.to_string()))?;
        Ok(Connection { tenant, http })
    }

    /// The tenants' batches of *uuids* (`TideDeployment`).
    fn batches(&self, platform: &str, uuids: &[String]) -> Result<Vec<Batch>, Raised> {
        let tables = plan::tenants(&self.compile.config.clone(), platform)
            .into_iter()
            .cloned()
            .collect::<Vec<CJson>>();
        let refs: Vec<&CJson> = tables.iter().collect();
        batches(
            platform,
            uuids,
            &refs,
            self.runs,
            self.wide,
            self.workspace,
            self.compile,
        )
        .map_err(Raised::new)
    }

    /// One platform's deploy (`deployer.deploy(mdr_deployment=uuids, strategies=run)`).
    fn platform(
        &mut self,
        platform: &str,
        uuids: &[String],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let batches = self.batches(platform, uuids)?;
        match PlatformId::parse(platform) {
            Some(PlatformId::Elastic) => self.elastic(&batches, log),
            Some(PlatformId::Sysdig) => self.sysdig(&batches, log),
            Some(PlatformId::Bitdefender) => self.bitdefender(&batches, log),
            Some(PlatformId::Exabeam) => self.exabeam(&batches, log),
            Some(PlatformId::GoogleSecops) => self.google_secops(&batches, log),
            Some(PlatformId::Graylog) => self.graylog(&batches, log),
            Some(
                PlatformId::DefenderForEndpoint | PlatformId::SentinelOne | PlatformId::Crowdstrike,
            ) => self.with_state(platform, &batches, log),
            Some(
                PlatformId::Sentinel
                | PlatformId::Splunk
                | PlatformId::CarbonBlackCloud
                | PlatformId::Harfanglab,
            ) => self.by_uuid(platform, &batches, log),
            None if crate::plugins::is_plugin(platform) => self.plugin(platform, &batches, log),
            None => self.by_uuid(platform, &batches, log),
        }
    }

    /// Ends a rule's block. A failure fails the rule and the run, and the
    /// run goes on with the next rule; a failure of the tenant or the run
    /// is returned, to stop them.
    fn close(
        &mut self,
        log: &mut DeployLog<'_>,
        mut result: RuleResult,
        outcome: Result<(), Raised>,
    ) -> Result<(), Raised> {
        let Err(raised) = outcome else {
            log.finished(result);
            return Ok(());
        };
        result.fail(&raised.describe());
        log.finished(result);
        self.failed = true;
        match raised.stops {
            Stops::Rule => Ok(()),
            Stops::Tenant | Stops::Run => Err(raised),
        }
    }

    /// A tenant that cannot be used: the run fails, its rules not sent yet
    /// are not attempted, and the other tenants go on. An interrupt is
    /// returned, to stop the run. `on_a_rule`: the failure came on a rule,
    /// whose failed row already reports it.
    fn tenant_failed(
        &mut self,
        platform: &str,
        tenant: &str,
        log: &mut DeployLog<'_>,
        raised: Raised,
        on_a_rule: bool,
    ) -> Result<(), Raised> {
        if raised.stops == Stops::Run {
            return Err(raised);
        }
        let error = raised.error();
        tracing::error!(
            platform,
            tenant,
            error = error.as_str(),
            critical = true,
            "tenant_deployment_failed"
        );
        if on_a_rule {
            self.stop_tenant(platform, tenant, log);
        } else {
            self.unusable(platform, Some(tenant), &error);
            log.unreached_on(
                platform,
                tenant,
                "not_attempted",
                &format!("not attempted: tenant {tenant} failed"),
            );
        }
        Ok(())
    }

    /// A deploy the tenant failed on: the rule fails with the connector's
    /// text, an interrupt stops the run, and otherwise the tenant's other
    /// rules are not attempted.
    fn tenant_deploy_failed(
        &mut self,
        platform: &str,
        event: &str,
        tenant: &str,
        error: DeployError,
        mut result: RuleResult,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let text = error.into_connector().text();
        tracing::error!(tenant, error = text.as_str(), critical = true, "{event}");
        self.failed = true;
        result.fail(&text);
        log.finished(result);
        // An interrupt stops the run, not the tenant.
        if self.interrupted() {
            return Err(Raised::new("interrupted").stopping(Stops::Run));
        }
        self.stop_tenant(platform, tenant, log);
        Ok(())
    }

    /// A tenant that failed on a rule, whose failed row and log line already
    /// report it: the run fails, the tenant counts as stopped (a platform
    /// none of whose tenants deployed is not in `deployed`), and its rules
    /// not sent yet are not attempted.
    fn stop_tenant(&mut self, platform: &str, tenant: &str, log: &mut DeployLog<'_>) {
        self.failed = true;
        self.stopped_tenants
            .push((platform.to_owned(), tenant.to_owned()));
        log.unreached_on(
            platform,
            tenant,
            "not_attempted",
            &format!("not attempted: tenant {tenant} failed"),
        );
    }

    /// Records a tenant (or a platform) that could not deploy: the run fails.
    fn unusable(&mut self, platform: &str, tenant: Option<&str>, error: &str) {
        self.failed = true;
        if let Some(tenant) = tenant {
            self.stopped_tenants
                .push((platform.to_owned(), tenant.to_owned()));
        }
        self.failures.push(Unusable {
            platform: platform.to_owned(),
            tenant: tenant.map(str::to_owned),
            error: bounded(error),
        });
    }

    /// Whether the run was interrupted (Ctrl-C, or the MCP client's cancel).
    fn interrupted(&self) -> bool {
        self.cancel.is_cancelled() || (self.cx.interrupted)()
    }

    /// The tenant's connection, or `None` when it cannot be made: the tenant
    /// failed, and the run goes on. An interrupted run stops here, before
    /// the next tenant.
    fn connect_or_fail(
        &mut self,
        platform: &str,
        batch: &Batch,
        log: &mut DeployLog<'_>,
    ) -> Result<Option<Connection>, Raised> {
        if self.interrupted() {
            return Err(Raised::new("interrupted").stopping(Stops::Run));
        }
        let connected = if crate::plugins::is_plugin(platform) {
            self.connect_plugin(platform, batch)
        } else {
            self.connect(platform, batch)
        };
        match connected {
            Ok(connection) => Ok(Some(connection)),
            Err(raised) => {
                // Making a connection sends nothing: its failure is the tenant's.
                let raised = raised.stopping(Stops::Tenant);
                self.tenant_failed(platform, &batch.tenant.name, log, raised, false)?;
                Ok(None)
            }
        }
    }

    /// `_deployment_error`: the run fails, the rule says why.
    fn rule_error(&mut self, result: &mut RuleResult, message: &str) {
        self.failed = true;
        result.fail(message);
    }

    /// Sentinel, Splunk, Carbon Black Cloud and HarfangLab: the rule's UUID
    /// (or name) addresses it, nothing is kept in deployment state.
    fn by_uuid(
        &mut self,
        platform: &str,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        for batch in batches {
            let tenant = batch.tenant.name.clone();
            let Some(connection) = self.connect_or_fail(platform, batch, log)? else {
                continue;
            };
            for sent in &batch.rules {
                let rule = &sent.rule;
                // A HarfangLab tenant takes both kinds: each rule goes to the
                // endpoint of its own block's kind.
                if PlatformId::parse(platform) == Some(PlatformId::Harfanglab) {
                    let block = rule.block(platform);
                    if block.is_none() {
                        tracing::warn!(
                            detail = rule.name.as_str(),
                            "skipping_rule_no_harfanglab_config"
                        );
                        log.skipped(
                            platform,
                            &tenant,
                            &rule.uuid,
                            &rule.name,
                            "no HarfangLab configuration",
                        );
                        continue;
                    }
                    if opentide_compile::harfanglab::Kind::of(rule).is_none() {
                        log.skipped(
                            platform,
                            &tenant,
                            &rule.uuid,
                            &rule.name,
                            "neither a sigma nor a yara rule",
                        );
                        continue;
                    }
                }
                let mut result = RuleResult::new(platform, Some(&tenant), &rule.uuid, &rule.name);
                let outcome = self.by_uuid_rule(platform, &connection, batch, rule, &mut result);
                if let Err(raised) = self.close(log, result, outcome) {
                    self.tenant_failed(platform, &tenant, log, raised, true)?;
                    break;
                }
            }
        }
        Ok(())
    }

    fn strategy_of(
        &self,
        rule: &opentide_compile::Rule,
        platform: &str,
    ) -> Result<StatusStrategy, Raised> {
        let status = rule
            .block(platform)
            .and_then(|block| block.get("status"))
            .map(opentide_compile::deploy::text)
            .unwrap_or_default();
        self.compile
            .statuses
            .strategy(&status)
            .map_err(|error| Raised::new(error.to_string()))
    }

    fn deployer(
        &self,
        platform: &str,
    ) -> Result<&dyn opentide_connectors::connector::Deployer, Raised> {
        self.cx
            .registry
            .get(platform)
            .and_then(opentide_connectors::Platform::deployer)
            .ok_or_else(|| Raised::new(format!("Cannot find a deployment engine for {platform}")))
    }

    /// The request a Sentinel rule sends: the compiled analytic rule, or its
    /// deletion (announced).
    fn sentinel_request(
        &self,
        platform: &str,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        deletion: bool,
    ) -> Result<DeployRequest, Raised> {
        let tenant = batch.tenant.name.as_str();
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        // The engine is found before the rule compiles, as before.
        self.deployer(platform)?;
        Ok(if deletion {
            tracing::warn!(
                arg0 = rule.name.as_str(),
                "the_rule_will_be_removed_from_the_sentinel_workspace"
            );
            DeployRequest::delete(rule.uuid.clone())
        } else {
            let body = opentide_compile::sentinel::compile(self.compile, rule, tenant)
                .map_err(compile_error)?;
            DeployRequest::new(
                rule.uuid.clone(),
                Operation::Update,
                body.to_compact().into_bytes(),
            )
        })
    }

    /// The request a Splunk rule sends: its saved search's settings under its
    /// name (` - Rule` for a correlation search), or its deletion.
    fn splunk_request(
        &self,
        platform: &str,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        deletion: bool,
    ) -> Result<DeployRequest, Raised> {
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        let splunk_cx = self.compile;
        let bytes: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
        let civil = jiff::tz::Offset::UTC.to_datetime(self.cx.now);
        let clock = opentide_compile::splunk::Clock {
            random: (u32::from(bytes[0]) % 60, u32::from(bytes[1]) % 24),
            now: (
                u32::try_from(civil.minute()).unwrap_or(0),
                u32::try_from(civil.hour()).unwrap_or(0),
            ),
        };
        let writes = opentide_compile::splunk::compile(splunk_cx, rule, &batch.table, clock)
            .map_err(compile_error)?;
        let mut name = rule.name.trim().to_owned();
        let correlation = match rule
            .block(platform)
            .and_then(|block| block.get("correlation_search"))
        {
            Some(CJson::Bool(set)) => *set,
            _ => opentide_compile::splunk::enterprise_security(&batch.table)
                .map_err(compile_error)?,
        };
        if correlation {
            name.push_str(" - Rule");
        }
        let mut settings = opentide_compile::json::Object::new();
        for write in writes.iter().skip(1) {
            if let CJson::Object(members) = &write.body {
                for (key, value) in members {
                    settings.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(DeployRequest::new(
            name,
            if deletion {
                Operation::Delete
            } else {
                Operation::Update
            },
            if deletion {
                Vec::new()
            } else {
                CJson::Object(settings).to_compact().into_bytes()
            },
        ))
    }

    /// The request a Carbon Black Cloud rule sends: its report, retired when
    /// it is not deployed; `None` when the rule compiles to no report.
    fn carbon_black_request(
        &self,
        batch: &Batch,
        rule: &opentide_compile::Rule,
    ) -> Result<Option<DeployRequest>, Raised> {
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        let Some(report) = opentide_compile::carbon_black::report(self.compile, rule, &batch.table)
            .map_err(compile_error)?
        else {
            return Ok(None);
        };
        // The report's fields, as the Deployer reads them; a rule that
        // is not deployed retires its IOC.
        let body = serde_json::json!({
            "uuid": rule.uuid,
            "name": report.name,
            "description": report.description,
            "query": report.query,
            "tags": report.tags,
            "severity": report.severity,
            "watchlist": report.watchlist,
            "report": report.report,
        });
        let operation = if report.deployment {
            Operation::Update
        } else {
            Operation::Delete
        };
        Ok(Some(
            DeployRequest::new(
                rule.uuid.clone(),
                operation,
                serde_json::to_vec(&body).unwrap_or_default(),
            )
            .at(self.cx.now),
        ))
    }

    /// The request a HarfangLab rule sends: its own kind and the rule
    /// compiled for it (`harfanglab::request_body`); a delete names the kind.
    fn harfanglab_request(
        &self,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        deletion: bool,
    ) -> Result<DeployRequest, Raised> {
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        // The block's own kind picks the endpoint (platform-harfanglab 1.6).
        let Some(kind) = opentide_compile::harfanglab::Kind::of(rule) else {
            return Err(Raised::new(format!(
                "HarfangLab rule {} is neither a sigma nor a yara rule",
                rule.uuid
            )));
        };
        let writes = opentide_compile::harfanglab::compile(self.compile, rule, &batch.table)
            .map_err(compile_error)?;
        let Some(write) = writes.first() else {
            return Err(Raised::new(format!(
                "HarfangLab compiled no request for rule {}",
                rule.uuid
            )));
        };
        let body = opentide_compile::harfanglab::request_body(
            kind,
            (!write.body.is_null()).then_some(&write.body),
        );
        Ok(DeployRequest::new(
            rule.uuid.clone(),
            if deletion {
                Operation::Delete
            } else {
                Operation::Update
            },
            serde_json::to_vec(&body).unwrap_or_default(),
        ))
    }

    fn by_uuid_rule(
        &mut self,
        platform: &str,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        result: &mut RuleResult,
    ) -> Result<(), Raised> {
        let strategy = self.strategy_of(rule, platform)?;
        let deletion = strategy == StatusStrategy::Deletion;
        let id = PlatformId::parse(platform);
        let request = match id {
            Some(PlatformId::Sentinel) => self.sentinel_request(platform, batch, rule, deletion)?,
            Some(PlatformId::Splunk) => self.splunk_request(platform, batch, rule, deletion)?,
            Some(PlatformId::CarbonBlackCloud) => match self.carbon_black_request(batch, rule)? {
                Some(request) => request,
                None => return Ok(()),
            },
            _ => self.harfanglab_request(batch, rule, deletion)?,
        };
        let deployer = self.deployer(platform)?;
        let context = self.context(connection);
        let outcome = self
            .block(async { Ok(deployer.deploy(context, &request).await) })
            .map_err(|error| raised(&error))?
            .map_err(|failed| scoped(failed, |error| raised(&error)))?;
        for warning in &outcome.warnings {
            match id {
                // `splunk_alert_deleted`: the saved search the tenant had.
                Some(PlatformId::Splunk) => {
                    tracing::warn!(name = warning.message.as_str(), "{}", warning.code);
                }
                // `report_deleted_with_rule`, `report_auto_deleted`: said, not raised.
                Some(PlatformId::CarbonBlackCloud) => {
                    tracing::warn!(report = warning.message.as_str(), "{}", warning.code);
                }
                _ => {}
            }
        }
        let _ = result;
        Ok(())
    }

    /// `report_failure`: a coded refusal of one rule on one tenant.
    fn report_failure(&mut self, error: &StateError, uuid: &str, platform: &str, tenant: &str) {
        let tenant = tenant.trim();
        if WARNING_CODES.contains(&error.code) {
            self.warned = true;
            tracing::warn!(
                detail = error.message.as_str(),
                code = error.code,
                uuid,
                platform,
                tenant,
                "{}",
                error.code
            );
            return;
        }
        self.failed = true;
        tracing::error!(
            detail = error.message.as_str(),
            code = error.code,
            uuid,
            platform,
            tenant,
            "{}",
            error.code
        );
    }

    /// Why a rule whose remote copy is gone must not be created again: the
    /// deployment state is ignored by git, or this run does not persist it.
    fn recreate_refusal(&self, uuid: &str, platform: &str, tenant: &str) -> Option<StateError> {
        match opentide_compile::git::state_ignore(self.workspace.root()) {
            Some(ignore) => Some(StateError {
                code: "deployment_state_ignored",
                message: deploy_state::ignored_message(&ignore),
            }),
            None => self.unpersisted(uuid, platform, tenant),
        }
    }

    /// `unpersisted_error`: a create in CI whose id nobody would commit.
    fn unpersisted(&self, uuid: &str, platform: &str, tenant: &str) -> Option<StateError> {
        if self.persist {
            return None;
        }
        let lookup = |name: &str| self.cx.env.get(name).map(str::to_owned);
        let ci = opentide_compile::git::ci(&lookup);
        if ci == opentide_compile::git::Ci::Local {
            return None;
        }
        let change_request = opentide_compile::git::is_change_request(ci, &lookup);
        if self.runs.contains(&StatusStrategy::Release) && !change_request {
            return None;
        }
        let place = if change_request {
            "pull or merge request"
        } else {
            "push"
        };
        let names: Vec<&str> = self.runs.iter().map(|run| run.name()).collect();
        let names = if names.is_empty() {
            "no strategy".to_owned()
        } else {
            names.join(" ")
        };
        Some(StateError {
            code: "deployment_state_unpersisted",
            message: format!(
                "rule {uuid} has no {platform} id for tenant {:?}, and this {place} run ({names}) \
                 in CI cannot keep the id a create would return: only the generated production \
                 job (--strategy RELEASE on the default branch) commits \
                 .opentide/states/deployment/. The create was refused before any vendor call. \
                 Deploy the rule from the production job, or pass --persist-state-externally if \
                 this pipeline commits .opentide/states/deployment/ itself.",
                tenant.trim()
            ),
        })
    }

    /// `plan_external_id`: create, update or delete from the shard alone.
    fn plan_external_id(
        &mut self,
        uuid: &str,
        platform: &str,
        tenant: &str,
        strategy: StatusStrategy,
    ) -> Result<Planned, StateError> {
        let root = self.workspace.root().to_path_buf();
        let shard = deploy_state::Shard::load(&root, uuid)?;
        if let Some(id) = shard.get(platform, tenant) {
            if let Some(rule) = opentide_compile::git::state_ignore(&root) {
                self.warned = true;
                tracing::warn!(
                    detail = deploy_state::ignored_message(&rule).as_str(),
                    code = "deployment_state_ignored",
                    object_uuid = uuid,
                    platform,
                    tenant,
                    "deployment_state_ignored"
                );
            }
            return Ok(if strategy == StatusStrategy::Deletion {
                Planned::Delete(id.to_owned())
            } else {
                Planned::Update(id.to_owned())
            });
        }
        if matches!(
            strategy,
            StatusStrategy::Deletion | StatusStrategy::Disablement
        ) {
            return Err(StateError {
                code: "external_id_missing",
                message: format!(
                    "rule {uuid} has no {platform} id for tenant {:?} in {}, so nothing is known \
                     to exist on that tenant and there is nothing to {}. If a remote copy \
                     exists, it must be removed by hand.",
                    tenant.trim(),
                    shard.path.display(),
                    strategy.name().to_lowercase()
                ),
            });
        }
        if let Some(rule) = opentide_compile::git::state_ignore(&root) {
            return Err(StateError {
                code: "deployment_state_ignored",
                message: deploy_state::ignored_message(&rule),
            });
        }
        if let Some(error) = self.unpersisted(uuid, platform, tenant) {
            return Err(error);
        }
        Ok(Planned::Create)
    }

    /// `screen_tenant`: every rule planned before the client is built.
    fn screen<'b>(
        &mut self,
        platform: &str,
        batch: &'b Batch,
        log: &mut DeployLog<'_>,
    ) -> Vec<(&'b opentide_compile::Rule, Planned)> {
        let mut planned = Vec::new();
        for sent in &batch.rules {
            let rule = &sent.rule;
            let Ok(strategy) = self.strategy_of(rule, platform) else {
                continue;
            };
            match self.plan_external_id(&rule.uuid, platform, &batch.tenant.name, strategy) {
                Ok(action) => planned.push((rule, action)),
                Err(error) => {
                    self.report_failure(&error, &rule.uuid, platform, &batch.tenant.name);
                    if WARNING_CODES.contains(&error.code) {
                        log.skipped(
                            platform,
                            &batch.tenant.name,
                            &rule.uuid,
                            &rule.name,
                            &error.message,
                        );
                    } else {
                        log.refused(
                            platform,
                            &batch.tenant.name,
                            &rule.uuid,
                            &rule.name,
                            &error.message,
                        );
                    }
                }
            }
        }
        planned
    }

    /// `record_created`, its refusal reported on the rule.
    fn record_created(
        &mut self,
        result: &mut RuleResult,
        platform: &str,
        tenant: &str,
        id: &ExternalId,
    ) {
        let root = self.workspace.root().to_path_buf();
        match deploy_state::record_created(&root, &result.id.clone(), platform, tenant, id) {
            Ok(stored) => {
                tracing::warn!(
                    uuid = result.id.as_str(),
                    platform,
                    tenant = tenant.trim(),
                    external_id = stored.as_str(),
                    "external_id_recorded"
                );
            }
            Err(error) => {
                self.report_failure(&error, &result.id.clone(), platform, tenant);
                result.fail(&error.message);
            }
        }
    }

    /// `record_deleted`, its refusal reported on the rule.
    fn record_deleted(&mut self, result: &mut RuleResult, platform: &str, tenant: &str) {
        let root = self.workspace.root().to_path_buf();
        if let Err(error) =
            deploy_state::record_deleted(&root, &result.id.clone(), platform, tenant)
        {
            self.report_failure(&error, &result.id.clone(), platform, tenant);
            result.fail(&error.message);
        }
    }

    /// Defender for Endpoint, SentinelOne and CrowdStrike: each rule planned
    /// from deployment state, then created (its id recorded), updated or
    /// deleted (its id forgotten).
    fn with_state(
        &mut self,
        platform: &str,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        for batch in batches {
            let planned = self.screen(platform, batch, log);
            if planned.is_empty() {
                continue;
            }
            let Some(connection) = self.connect_or_fail(platform, batch, log)? else {
                continue;
            };
            let cancel = self.cancel.clone();
            let context = TenantContext {
                tenant: &connection.tenant,
                http: &connection.http,
                cancel: &cancel,
            };
            let defender = opentide_connectors::defender::Defender::new();
            let session = match PlatformId::parse(platform) {
                Some(PlatformId::DefenderForEndpoint) => self
                    .block(async {
                        defender
                            .token(context)
                            .await
                            .map_err(|error| error.into_connector(&batch.tenant.name))
                    })
                    .map(|_| None),
                // A platform of the tenant's own, signed in once before any
                // rule: its Deployer sends every rule on that token.
                Some(PlatformId::Crowdstrike) => {
                    let crowdstrike = opentide_connectors::crowdstrike::Crowdstrike::new();
                    self.block(crowdstrike.sign_in(context))
                        .map(|()| Some(crowdstrike))
                }
                _ => Ok(None),
            };
            // No token or session: no rule on the tenant can deploy.
            let session = match session {
                Ok(session) => session,
                Err(error) => {
                    let stops = if matches!(error, ConnectorError::Cancelled) {
                        Stops::Run
                    } else {
                        Stops::Tenant
                    };
                    let failure = raised(&error).stopping(stops);
                    self.tenant_failed(platform, &batch.tenant.name, log, failure, false)?;
                    continue;
                }
            };
            for (rule, action) in planned {
                let tenant = batch.tenant.name.as_str();
                let mut result = RuleResult::new(platform, Some(tenant), &rule.uuid, &rule.name);
                let outcome = self.state_rule(
                    platform,
                    &batch.table,
                    tenant,
                    context,
                    &defender,
                    session.as_ref(),
                    rule,
                    &action,
                    &mut result,
                );
                if let Err(raised) = self.close(log, result, outcome) {
                    self.tenant_failed(platform, tenant, log, raised, true)?;
                    break;
                }
            }
        }
        Ok(())
    }

    /// A platform plugin (UC-4.5b, #835): each rule planned from deployment
    /// state as the built-in platforms that keep ids are, then sent through
    /// the plugin's `Deployer`: created (the id it returns recorded), updated
    /// or disabled (by the stored id), or deleted (the id forgotten).
    fn plugin(
        &mut self,
        platform: &str,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let cx = self.cx;
        let deployer = cx
            .registry
            .get(platform)
            .and_then(opentide_connectors::Platform::deployer)
            .ok_or_else(|| Raised::new(format!("platform plugin {platform} cannot deploy")))?;
        for batch in batches {
            let planned = self.screen(platform, batch, log);
            if planned.is_empty() {
                continue;
            }
            let Some(connection) = self.connect_or_fail(platform, batch, log)? else {
                continue;
            };
            for (rule, action) in planned {
                let tenant = batch.tenant.name.as_str();
                let mut result = RuleResult::new(platform, Some(tenant), &rule.uuid, &rule.name);
                let outcome =
                    self.plugin_rule(deployer, platform, &connection, rule, &action, &mut result);
                if let Err(raised) = self.close(log, result, outcome) {
                    self.tenant_failed(platform, tenant, log, raised, true)?;
                    break;
                }
            }
        }
        Ok(())
    }

    /// A plugin tenant's connection: every `$NAME` of its setup must be set,
    /// since no built-in check names the keys a plugin reads.
    fn connect_plugin(&self, platform: &str, batch: &Batch) -> Result<Connection, Raised> {
        let setup: toml::Table = batch
            .tenant
            .setup
            .iter()
            .filter_map(|(key, value)| toml_value(value).map(|value| (key.clone(), value)))
            .collect();
        let tenant = Tenant::from_setup(
            platform,
            &batch.tenant.name,
            &setup,
            &self.environment,
            Resolve::Required,
            &opentide_connectors::HttpSettings::default(),
        )
        .map_err(|error| Raised::new(error.to_string()))?;
        let http = HttpClient::new(
            &tenant.label,
            &tenant.http,
            &self.environment,
            self.cx.proxy,
        )
        .map_err(|error| Raised::new(error.to_string()))?;
        Ok(Connection { tenant, http })
    }

    /// One rule on a plugin's tenant: the request the plugin receives (its
    /// `body` the rule, its block for the platform, and the stored id), then
    /// the deployment state the answer changes.
    fn plugin_rule(
        &mut self,
        deployer: &dyn opentide_connectors::connector::Deployer,
        platform: &str,
        connection: &Connection,
        rule: &opentide_compile::Rule,
        action: &Planned,
        result: &mut RuleResult,
    ) -> Result<(), Raised> {
        let tenant = connection.tenant.label.tenant.clone();
        let disables = self.strategy_of(rule, platform)? == StatusStrategy::Disablement;
        let (operation, stored) = match action {
            Planned::Create => (Operation::Create, None),
            Planned::Update(id) if disables => (Operation::Disable, Some(id.as_str())),
            Planned::Update(id) => (Operation::Update, Some(id.as_str())),
            Planned::Delete(id) => (Operation::Delete, Some(id.as_str())),
        };
        let request = DeployRequest::new(
            rule.uuid.clone(),
            operation,
            plugin_body(rule, platform, stored)
                .to_compact()
                .into_bytes(),
        );
        let context = self.context(connection);
        let done = self
            .block(async { Ok(deployer.deploy(context, &request).await) })
            .map_err(|error| plugin_raised(&error))?
            .map_err(|failed| scoped(failed, |error| plugin_raised(&error)))?;
        match (operation, done.remote_id) {
            (Operation::Delete, _) => self.record_deleted(result, platform, &tenant),
            (Operation::Create, Some(id)) if !id.trim().is_empty() => {
                self.record_created(result, platform, &tenant, &ExternalId::Text(id));
            }
            (Operation::Create, _) => self.rule_error(
                result,
                &format!(
                    "platform plugin {platform} created rule {} on tenant {} but returned no \
                     remote_id, so deployment state cannot record it: the next deploy creates \
                     it again",
                    rule.uuid,
                    tenant.trim()
                ),
            ),
            (_, Some(id)) if Some(id.as_str()) != stored && !id.trim().is_empty() => {
                // The plugin answered another id for the rule (it recreated
                // it): the state follows the platform.
                self.record_created(result, platform, &tenant, &ExternalId::Text(id));
            }
            _ => {}
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one rule's send, as deploy_mdr takes it"
    )]
    fn state_rule(
        &mut self,
        platform: &str,
        table: &CJson,
        tenant: &str,
        context: TenantContext<'_>,
        defender: &opentide_connectors::defender::Defender,
        session: Option<&opentide_connectors::crowdstrike::Crowdstrike>,
        rule: &opentide_compile::Rule,
        action: &Planned,
        result: &mut RuleResult,
    ) -> Result<(), Raised> {
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        let body = match PlatformId::parse(platform) {
            Some(PlatformId::DefenderForEndpoint) => {
                opentide_compile::defender::body(self.compile, rule, tenant)
            }
            Some(PlatformId::SentinelOne) => {
                opentide_compile::sentinel_one::body(self.compile, rule, table)
            }
            _ => opentide_compile::crowdstrike::body(self.compile, rule, table),
        }
        .map_err(compile_error)?;
        let (remote_id, name) = match PlatformId::parse(platform) {
            Some(PlatformId::DefenderForEndpoint) => (
                self.defender_deploy(tenant, context, defender, rule, action, &body)?,
                "Defender",
            ),
            Some(PlatformId::SentinelOne) => (
                self.sentinel_one_deploy(tenant, context, rule, action, &body)?,
                "SentinelOne",
            ),
            _ => {
                let Some(session) = session else {
                    return Err(Raised::new(format!(
                        "{platform} tenant '{tenant}': Cannot authenticate with the tenant configuration"
                    )));
                };
                (
                    self.crowdstrike_deploy(context, session, rule, action, &body)?,
                    "CrowdStrike",
                )
            }
        };
        match (action, remote_id) {
            (Planned::Delete(_), _) => self.record_deleted(result, platform, tenant),
            // CrowdStrike's ids are text; Defender's and SentinelOne's numbers.
            (Planned::Create, Some(id)) if name == "CrowdStrike" => {
                self.record_created(result, platform, tenant, &ExternalId::Text(id));
            }
            (Planned::Create, Some(id)) => match id.parse::<i64>() {
                Ok(id) => self.record_created(result, platform, tenant, &ExternalId::Int(id)),
                Err(_) => self.rule_error(
                    result,
                    &format!("{name} created the rule with an id that is not a number: {id}"),
                ),
            },
            // A create must give its id: without it the rule cannot be
            // updated or deleted later.
            (Planned::Create, None) => {
                self.rule_error(
                    result,
                    &format!("{name} created the rule without an id to record"),
                );
            }
            (Planned::Update(_), _) => {}
        }
        Ok(())
    }

    /// One rule sent to Defender for Endpoint: the id the tenant gave it.
    /// Graph's refusal is raised with its answer, and a partial deploy's
    /// warnings are logged.
    fn defender_deploy(
        &mut self,
        tenant: &str,
        context: TenantContext<'_>,
        defender: &opentide_connectors::defender::Defender,
        rule: &opentide_compile::Rule,
        action: &Planned,
        body: &CJson,
    ) -> Result<Option<String>, Raised> {
        let advice = opentide_connectors::text::json_text(body);
        // Graph's refusal of a rule call, its answer the detail.
        let refused = |error: ConnectorError, action: &Planned| match error {
            ConnectorError::Refused {
                message, detail, ..
            } => {
                let context = detail.unwrap_or_default();
                match action {
                    Planned::Create => tracing::error!(
                        detail = message.as_str(),
                        context = context.as_str(),
                        critical = true,
                        "fatal_error"
                    ),
                    Planned::Update(_) => tracing::error!(
                        detail = message.as_str(),
                        context = context.as_str(),
                        advice = advice.as_str(),
                        critical = true,
                        "fatal_error"
                    ),
                    Planned::Delete(_) => tracing::error!(
                        detail = message.as_str(),
                        context_1 =
                            "Double check scope permissions, and whether the ID actually exists",
                        critical = true,
                        "fatal_error"
                    ),
                }
                let context = if context.is_empty() {
                    String::new()
                } else {
                    format!(" ({context})")
                };
                Raised::new(format!(
                    "could not {} the rule on tenant '{tenant}': {message}{context}",
                    action_verb(action)
                ))
            }
            other => raised(&other),
        };
        // The Deployer's request: the stored id addresses an update
        // or a delete; the body is the compiled rule.
        let compiled = || body.to_compact().into_bytes();
        let request = match action {
            Planned::Delete(id) => DeployRequest::delete(id.clone()),
            Planned::Update(id) => DeployRequest::new(id.clone(), Operation::Update, compiled()),
            Planned::Create => DeployRequest::new(rule.uuid.clone(), Operation::Create, compiled()),
        };
        let outcome = self
            .block(async { Ok(defender.deploy(context, &request).await) })
            .map_err(|error| refused(error, action))?
            .map_err(|failed| scoped(failed, |error| refused(error, action)))?;
        // The partial deployment: raised, as the warnings exit.
        for warning in &outcome.warnings {
            self.warned |= warning.raised;
            tracing::warn!("{}", warning.code);
        }
        Ok(outcome.remote_id)
    }

    /// One rule sent to SentinelOne: the id the tenant gave it. The console's
    /// refusal is raised by its code, a refused key failing the tenant.
    fn sentinel_one_deploy(
        &mut self,
        tenant: &str,
        context: TenantContext<'_>,
        rule: &opentide_compile::Rule,
        action: &Planned,
        body: &CJson,
    ) -> Result<Option<String>, Raised> {
        use opentide_connectors::sentinel_one::SentinelOne;
        // The console's refusal, by its code: each kind's event.
        let refused = |error: DeployError, action: &Planned| {
            let failure = &error.failure;
            let detail = failure.field("detail").unwrap_or_default();
            match failure.code {
                _ if error.connector.is_some() => {
                    return raised(&error.into_connector());
                }
                "sentinel_one_rule_invalid" => tracing::error!(
                    detail,
                    critical = true,
                    "received_code_400_invalid_user_input_received"
                ),
                "sentinel_one_unauthorized" => tracing::error!(
                    detail,
                    advice = "Check your configuration and API permissions again",
                    critical = true,
                    "received_code_401_unauthorized_access"
                ),
                "sentinel_one_rule_not_found" => tracing::error!(
                    detail,
                    advice = "Check in the SentinelOne console whether the rule still exists. If not, remove its sentinel_one entry from the rule's deployment state in .opentide/states/deployment/",
                    critical = true,
                    "fatal_error"
                ),
                "sentinel_one_request_failed" => tracing::error!(
                    detail = format!(
                        "Unforeseen error with code [{}]",
                        failure.status.unwrap_or_default()
                    )
                    .as_str(),
                    context = detail,
                    critical = true,
                    "fatal_error"
                ),
                _ => {}
            }
            // A refused key (`sentinel_one_unauthorized`) fails the
            // tenant: its other rules are not attempted.
            let stops = if error.scope == DeployScope::Tenant {
                Stops::Tenant
            } else {
                Stops::Rule
            };
            Raised::new(format!(
                "could not {} the rule on tenant '{tenant}': {}",
                action_verb(action),
                failure.message
            ))
            .stopping(stops)
        };
        // The Deployer's request: the stored id addresses an update
        // or a delete; the body is the compiled rule.
        let compiled = || body.to_compact().into_bytes();
        let request = match action {
            Planned::Delete(id) => DeployRequest::delete(id.clone()),
            Planned::Update(id) => DeployRequest::new(id.clone(), Operation::Update, compiled()),
            Planned::Create => DeployRequest::new(rule.uuid.clone(), Operation::Create, compiled()),
        };
        let outcome = self
            .block(async { Ok(SentinelOne.deploy(context, &request).await) })
            .map_err(|error| raised(&error))?
            .map_err(|error| refused(error, action))?;
        Ok(outcome.remote_id)
    }

    /// One rule sent to CrowdStrike through a signed-in session: the id the
    /// tenant gave it. The tenant's refusal is raised with its answer.
    fn crowdstrike_deploy(
        &mut self,
        context: TenantContext<'_>,
        session: &opentide_connectors::crowdstrike::Crowdstrike,
        rule: &opentide_compile::Rule,
        action: &Planned,
        body: &CJson,
    ) -> Result<Option<String>, Raised> {
        let refused = |error: ConnectorError, action: &Planned| match &error {
            ConnectorError::Refused {
                message, detail, ..
            } => {
                let context = detail
                    .as_deref()
                    .and_then(|text| serde_json::from_str::<CJson>(text).ok())
                    .map(|value| opentide_connectors::text::json_text(&value))
                    .unwrap_or_default();
                tracing::error!(
                    detail = message.as_str(),
                    context = context.as_str(),
                    critical = true,
                    "fatal_error"
                );
                Raised::new(format!(
                    "could not {} the rule: {message}",
                    action_verb(action)
                ))
            }
            other => raised(other),
        };
        // The Deployer's request: the stored id addresses an update
        // (its one-rule list, the id in it) or a delete.
        let request = match action {
            Planned::Delete(id) => DeployRequest::delete(id.clone()),
            Planned::Update(id) => {
                let mut list = body.clone();
                if let CJson::Object(object) = &mut list {
                    object.insert("id".into(), id.clone().into());
                }
                let bytes = serde_json::to_vec(&CJson::Array(vec![list])).unwrap_or_default();
                DeployRequest::new(id.clone(), Operation::Update, bytes)
            }
            Planned::Create => DeployRequest::new(
                rule.uuid.clone(),
                Operation::Create,
                serde_json::to_vec(&body).unwrap_or_default(),
            ),
        };
        let outcome = self
            .block(async { Ok(session.deploy(context, &request).await) })
            .map_err(|error| refused(error, action))?
            .map_err(|failed| scoped(failed, |error| refused(error, action)))?;
        Ok(outcome.remote_id)
    }

    /// Elastic: each rule deleted, or checked then created or updated; a
    /// tenant that refuses the key stops its batch (`ElasticDeploy`).
    fn elastic(&mut self, batches: &[Batch], log: &mut DeployLog<'_>) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Elastic.as_str();
        for batch in batches {
            let Some(connection) = self.connect_or_fail(PLATFORM, batch, log)? else {
                continue;
            };
            let mut tenant_state = ElasticTenant {
                setup: opentide_compile::elastic::Setup::from_tenant(&batch.table),
                suppression_off: matches!(
                    opentide_compile::deploy::setup(&batch.table, "suppression"),
                    Some(CJson::Bool(false))
                ),
                warned_rules: Vec::new(),
            };
            for sent in &batch.rules {
                if self.elastic_rule(&connection, batch, &sent.rule, &mut tenant_state, log)? {
                    break;
                }
            }
        }
        Ok(())
    }

    /// An Elastic deploy the tenant failed on (unreachable, or a key or
    /// privilege it refuses): the rule fails, an interrupt stops the run, and
    /// otherwise the tenant's other rules are not attempted.
    fn elastic_tenant_failed(
        &mut self,
        error: DeployError,
        mut result: RuleResult,
        tenant: &str,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let stopped = match error.connector {
            // The tenant could not be reached.
            Some(connector) => {
                result.fail(&raised(&connector).describe());
                connector.to_string()
            }
            // A key or privilege the tenant refuses.
            None => {
                result.fail(&error.failure.message);
                error.failure.message
            }
        };
        log.finished(result);
        tracing::error!(
            tenant = tenant,
            error = stopped.as_str(),
            critical = true,
            "elastic_tenant_deployment_failed"
        );
        // An interrupt stops the run, not the tenant.
        if self.interrupted() {
            return Err(Raised::new("interrupted").stopping(Stops::Run));
        }
        self.stop_tenant(PlatformId::Elastic.as_str(), tenant, log);
        Ok(())
    }

    /// One Elastic rule: screened by its status, compiled, sent, and its
    /// result logged. `true` when the tenant failed and the rest of its rules
    /// are left out.
    fn elastic_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        tenant_state: &mut ElasticTenant,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        const PLATFORM: &str = PlatformId::Elastic.as_str();
        use opentide_connectors::elastic::{Elastic, FAILURE_EVENTS};
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(PLATFORM, Some(&tenant), &rule.uuid, &rule.name);
        let Some(raw) = rule.block(PLATFORM).filter(|block| block.is_filled()) else {
            result.skip("no Elastic configuration");
            log.finished(result);
            return Ok(false);
        };
        let status = raw
            .get("status")
            .map(opentide_compile::deploy::text)
            .unwrap_or_default();
        let strategy = match self.compile.statuses.strategy(&status) {
            Ok(strategy) => strategy,
            Err(error) => {
                self.rule_error(&mut result, &error.to_string());
                log.finished(result);
                return Ok(false);
            }
        };
        if strategy == StatusStrategy::Inert {
            result.skip(&format!("status {status} is inert"));
            log.finished(result);
            return Ok(false);
        }
        let request = match self.elastic_request(rule, raw, strategy, tenant_state, &tenant) {
            Ok(request) => request,
            Err(text) => {
                self.rule_error(&mut result, &text);
                log.finished(result);
                return Ok(false);
            }
        };
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(Elastic.deploy(context, &request).await) })
            .unwrap_or_else(|error| {
                let mut failed = DeployError::from(error);
                failed.scope = DeployScope::Tenant;
                Err(failed)
            });
        match deployed {
            Ok(done) => {
                self.elastic_warnings(rule, &done);
                log.finished(result);
            }
            // The rule itself failed: the other rules go on.
            Err(error) if error.scope == DeployScope::Rule => {
                if let Some(done) = &error.partial {
                    self.elastic_warnings(rule, done);
                }
                let failure = &error.failure;
                if FAILURE_EVENTS.contains(&failure.code) {
                    self.elastic_failure(
                        &mut result,
                        rule,
                        failure.code,
                        failure.status,
                        &failure.message,
                    );
                } else {
                    self.rule_error(&mut result, &failure.message);
                }
                log.finished(result);
            }
            Err(error) if error.is_interrupted() => {
                result.fail("interrupted");
                log.finished(result);
                self.failed = true;
                tracing::error!(
                    tenant = tenant.as_str(),
                    error = "interrupted",
                    critical = true,
                    "elastic_tenant_deployment_failed"
                );
                return Err(Raised::new("interrupted").stopping(Stops::Run));
            }
            Err(error) => {
                self.elastic_tenant_failed(error, result, &tenant, log)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The request an Elastic rule sends, compiled for its tenant (a
    /// deletion compiles nothing), after its warnings: suppression the
    /// tenant's licence omits, techniques outside the enterprise matrix.
    /// `Err` is the reason the rule fails.
    fn elastic_request(
        &mut self,
        rule: &opentide_compile::Rule,
        raw: &CJson,
        strategy: StatusStrategy,
        tenant_state: &mut ElasticTenant,
        tenant: &str,
    ) -> Result<DeployRequest, String> {
        const PLATFORM: &str = PlatformId::Elastic.as_str();
        let block = opentide_compile::preview::config_dump(PLATFORM, raw);
        if strategy != StatusStrategy::Deletion
            && tenant_state.suppression_off
            && block
                .get("suppression")
                .is_some_and(|value| !value.is_null())
            && !tenant_state.warned_rules.contains(&rule.uuid)
        {
            self.warned = true;
            tracing::warn!(
                rule = rule.name.as_str(),
                rule_id = rule.uuid.as_str(),
                tenant,
                "suppression_omitted_basic_license"
            );
            tenant_state.warned_rules.push(rule.uuid.clone());
        }
        let payload = if strategy == StatusStrategy::Deletion {
            CJson::Null
        } else {
            match opentide_compile::elastic::compile(self.compile, rule, &tenant_state.setup) {
                Ok(payload) => payload,
                Err(error) => {
                    return Err(format!("Rule {} ({}): {error}", rule.uuid, rule.name));
                }
            }
        };
        let non_enterprise = strategy != StatusStrategy::Deletion
            && opentide_compile::elastic::rule_techniques(self.compile, rule)
                .iter()
                .any(|id| {
                    self.compile
                        .attack
                        .name(id)
                        .is_some_and(opentide_compile::attack::non_enterprise)
                });
        if non_enterprise {
            self.warned = true;
        }
        Ok(match strategy {
            StatusStrategy::Deletion => DeployRequest::delete(rule.uuid.clone()),
            _ => {
                // The body `deploy_plan` shows for it.
                let body = opentide_compile::preview::elastic_request(rule, payload);
                let operation = if strategy == StatusStrategy::Disablement {
                    Operation::Disable
                } else {
                    Operation::Update
                };
                match serde_json::to_vec(&body) {
                    Ok(body) => DeployRequest::new(rule.uuid.clone(), operation, body),
                    Err(error) => {
                        return Err(format!("the compiled rule is not JSON: {error}"));
                    }
                }
            }
        })
    }

    /// The Elasticsearch checks' warnings of an Elastic deploy, failed or not.
    fn elastic_warnings(&mut self, rule: &opentide_compile::Rule, done: &DeployOutcome) {
        for warning in &done.warnings {
            if warning.code != opentide_connectors::elastic::CHECK_WARNING {
                continue;
            }
            self.warned = true;
            tracing::warn!(
                rule_id = rule.uuid.as_str(),
                rule = rule.name.as_str(),
                warning = warning.message.as_str(),
                "elasticsearch_check_warning"
            );
        }
    }

    /// `_deployment_error` for an Elastic rule, with the fields its event logs.
    fn elastic_failure(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        event: &str,
        status: Option<u16>,
        error: &str,
    ) {
        let rule_id = rule.uuid.as_str();
        match (event, status) {
            ("elasticsearch_checks_failed", _) => {
                tracing::error!(rule_id, rule = rule.name.as_str(), error, "{}", event);
            }
            ("refusing_to_modify_prebuilt_rule", _) => {
                tracing::error!(rule_id, name = rule.name.as_str(), "{}", event);
            }
            (_, Some(status)) => {
                tracing::error!(rule_id, status_code = status, error, "{}", event);
            }
            (_, None) => tracing::error!(rule_id, error, "{}", event),
        }
        if event == "recreate_elastic_rule_failed" {
            tracing::error!(rule_id, "elastic_rule_deleted_not_recreated");
        }
        let message = match status {
            Some(status) => format!("HTTP {status}: {error}"),
            None if event == "refusing_to_modify_prebuilt_rule" => event.replace('_', " "),
            None => error.to_owned(),
        };
        self.rule_error(result, &message);
    }

    /// Sysdig: each rule planned from deployment state, then created and
    /// added to its runtime policies, updated, disabled or deleted
    /// (`SysdigDeploy`).
    fn sysdig(&mut self, batches: &[Batch], log: &mut DeployLog<'_>) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Sysdig.as_str();
        for batch in batches {
            let planned = self.screen(PLATFORM, batch, log);
            if planned.is_empty() {
                continue;
            }
            let Some(connection) = self.connect_or_fail(PLATFORM, batch, log)? else {
                continue;
            };
            let tenant_policies: Vec<String> =
                match opentide_compile::deploy::setup(&batch.table, "policies") {
                    Some(CJson::Array(items)) => {
                        items.iter().map(opentide_compile::deploy::text).collect()
                    }
                    _ => Vec::new(),
                };
            for (rule, action) in planned {
                if self.sysdig_rule(&connection, batch, rule, &action, &tenant_policies, log)? {
                    break;
                }
            }
        }
        Ok(())
    }

    /// One Sysdig rule: compiled, sent, and its result logged. `true` when
    /// the tenant failed and the rest of its rules are left out.
    fn sysdig_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        tenant_policies: &[String],
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        const PLATFORM: &str = PlatformId::Sysdig.as_str();
        use opentide_connectors::sysdig::Sysdig;
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(PLATFORM, Some(&tenant), &rule.uuid, &rule.name);
        let strategy = self.strategy_of(rule, PLATFORM);
        let body = strategy.clone().and_then(|_| {
            opentide_compile::sysdig::compile_body(self.compile, rule, Some(&batch.table)).map_err(
                |error| Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name)),
            )
        });
        let (strategy, body) = match (strategy, body) {
            (Ok(strategy), Ok(body)) => (strategy, body),
            (Err(raised), _) | (_, Err(raised)) => {
                self.close(log, result, Err(raised.clone()))?;
                return Ok(false);
            }
        };
        let policies = opentide_compile::sysdig::block_policies(rule)
            .unwrap_or_else(|| tenant_policies.to_vec());
        let recreate_refusal = self.recreate_refusal(&rule.uuid, PLATFORM, &tenant);
        let (operation, stored) = operation_of(action, strategy);
        let mut request = DeployRequest::new(
            stored.unwrap_or_default(),
            operation,
            serde_json::to_vec(&body).unwrap_or_default(),
        )
        .with_policies(Some(policies));
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(Sysdig.deploy(context, &request).await) })
            .unwrap_or_else(|error| Err(DeployError::from(error)));
        match deployed {
            Ok(done) => {
                let forget = done.remote_id.is_none();
                self.sysdig_done(&mut result, &rule.uuid, &tenant, &done, stored);
                if forget {
                    self.record_deleted(&mut result, PLATFORM, &tenant);
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                if let Some(done) = &error.partial {
                    self.sysdig_done(&mut result, &rule.uuid, &tenant, done, stored);
                }
                match recreate_refusal
                    .as_ref()
                    .filter(|refusal| refusal.code == error.failure.code)
                {
                    Some(refusal) => {
                        self.report_failure(refusal, &rule.uuid, PLATFORM, &tenant);
                        result.fail(&refusal.message);
                    }
                    None => {
                        tracing::error!(
                            uuid = rule.uuid.as_str(),
                            tenant = tenant.as_str(),
                            status_code = error.failure.status,
                            error = error.failure.message.as_str(),
                            "sysdig_request_failed"
                        );
                        self.rule_error(&mut result, &error.failure.message);
                    }
                }
                log.finished(result);
            }
            Err(error) => {
                self.tenant_deploy_failed(
                    PlatformId::Sysdig.as_str(),
                    "sysdig_tenant_deployment_failed",
                    &tenant,
                    error,
                    result,
                    log,
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What a Sysdig deploy did, failed or not: its warnings, then the id
    /// of a rule it created (its `sysdig_rule_created` event), recorded
    /// when it is not the `stored` one.
    fn sysdig_done(
        &mut self,
        result: &mut RuleResult,
        uuid: &str,
        tenant: &str,
        done: &DeployOutcome,
        stored: Option<&str>,
    ) {
        const PLATFORM: &str = PlatformId::Sysdig.as_str();
        for warning in &done.warnings {
            self.warned = true;
            tracing::warn!(
                uuid,
                tenant,
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            tracing::info!(
                uuid,
                rule_id = event
                    .fields
                    .iter()
                    .find(|(key, _)| key == "rule_id")
                    .map_or("", |(_, id)| id.as_str()),
                "{}",
                event.name
            );
        }
        if let Some(id) = done.remote_id.as_deref().filter(|id| Some(*id) != stored) {
            let external = id
                .parse::<i64>()
                .map_or_else(|_| ExternalId::Text(id.to_owned()), ExternalId::Int);
            self.record_created(result, PLATFORM, tenant, &external);
        }
    }
    /// Bitdefender GravityZone: each rule planned from deployment state,
    /// compiled for the tenant (its targets resolved), then created (its id
    /// recorded), updated or disabled with the whole payload, or deleted
    /// (its id forgotten) (`BitdefenderDeploy.deploy_tenant`).
    fn bitdefender(&mut self, batches: &[Batch], log: &mut DeployLog<'_>) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Bitdefender.as_str();
        for batch in batches {
            let planned = self.screen(PLATFORM, batch, log);
            let planned = self.bitdefender_yara_limit(batch, planned, log);
            if planned.is_empty() {
                continue;
            }
            let Some(connection) = self.connect_or_fail(PLATFORM, batch, log)? else {
                continue;
            };
            // A value that is not a boolean fails each rule `compile_rule` compiles,
            // naming the key; a deletion compiles nothing and sends no actions.
            let automatic =
                opentide_compile::bitdefender::automatic_actions_on(&batch.table).unwrap_or(true);
            for (rule, action) in planned {
                if self.bitdefender_rule(&connection, batch, rule, &action, automatic, log)? {
                    break;
                }
            }
        }
        Ok(())
    }

    /// The request a Bitdefender rule sends: a delete names the recorded id
    /// alone; anything else sends the compiled rule's `params`, and says when
    /// the tenant runs no automatic actions while the rule has some.
    fn bitdefender_request(
        &self,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        strategy: StatusStrategy,
        automatic: bool,
    ) -> Result<DeployRequest, opentide_compile::rule::CompileError> {
        use opentide_compile::bitdefender::{compile_rule, create_params};
        const PLATFORM: &str = PlatformId::Bitdefender.as_str();
        if let Planned::Delete(id) = action {
            // A delete sends the recorded id alone.
            return Ok(DeployRequest::delete(id.clone()));
        }
        let (operation, stored) = operation_of(action, strategy);
        let actions_unsupported = !automatic
            && rule
                .block(PLATFORM)
                .and_then(|block| block.get("actions"))
                .is_some_and(|actions| !actions.is_null());
        let compiled = compile_rule(self.compile, rule, strategy, Some(&batch.table))?;
        let mut body = opentide_compile::json::Object::new();
        body.insert("params".into(), create_params(&compiled));
        if actions_unsupported {
            body.insert("actions_unsupported".into(), CJson::Bool(true));
        }
        Ok(DeployRequest::new(
            stored.unwrap_or_default(),
            operation,
            serde_json::to_vec(&CJson::Object(body)).unwrap_or_default(),
        ))
    }

    /// One Bitdefender rule: compiled, sent, and its result logged. `true` when
    /// the tenant failed and the rest of its rules are left out.
    fn bitdefender_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        automatic: bool,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        use opentide_connectors::bitdefender::Bitdefender;
        const PLATFORM: &str = PlatformId::Bitdefender.as_str();
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(PLATFORM, Some(&tenant), &rule.uuid, &rule.name);
        let strategy = match self.strategy_of(rule, PLATFORM) {
            Ok(strategy) => strategy,
            Err(raised) => {
                self.close(log, result, Err(raised.clone()))?;
                return Ok(false);
            }
        };
        let (_, stored) = operation_of(action, strategy);
        let mut request = match self.bitdefender_request(batch, rule, action, strategy, automatic) {
            Ok(request) => request,
            Err(error) => {
                let message = format!("{}: {}", error.code, error.reason);
                tracing::error!(
                    code = error.code,
                    uuid = rule.uuid.as_str(),
                    tenant = tenant.as_str(),
                    name = rule.name.as_str(),
                    error = message.as_str(),
                    "{}",
                    error.code
                );
                self.rule_error(&mut result, &message);
                log.finished(result);
                return Ok(false);
            }
        };
        let recreate_refusal = self.recreate_refusal(&rule.uuid, PLATFORM, &tenant);
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(Bitdefender.deploy(context, &request).await) })
            .unwrap_or_else(|error| Err(DeployError::from(error)));
        match deployed {
            Ok(done) => {
                self.bitdefender_done(&rule.uuid, &tenant, &done);
                match done.remote_id.as_deref() {
                    None => self.record_deleted(&mut result, PLATFORM, &tenant),
                    Some(id) if Some(id) != stored => self.record_created(
                        &mut result,
                        PLATFORM,
                        &tenant,
                        &ExternalId::Text(id.to_owned()),
                    ),
                    Some(_) => {}
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                if let Some(done) = &error.partial {
                    self.bitdefender_done(&rule.uuid, &tenant, done);
                }
                let failure = &error.failure;
                if let Some(refusal) = recreate_refusal
                    .as_ref()
                    .filter(|refusal| refusal.code == failure.code)
                {
                    self.report_failure(refusal, &rule.uuid, PLATFORM, &tenant);
                    self.failed = true;
                    result.fail(&refusal.message);
                } else {
                    tracing::error!(
                        code = failure.code,
                        uuid = rule.uuid.as_str(),
                        tenant = tenant.as_str(),
                        error = failure.message.as_str(),
                        detail = failure.field("detail").unwrap_or_default(),
                        "{}",
                        failure.code
                    );
                    self.rule_error(
                        &mut result,
                        &format!("{}: {}", failure.code, failure.message),
                    );
                }
                log.finished(result);
            }
            Err(error) => {
                self.tenant_deploy_failed(
                    PlatformId::Bitdefender.as_str(),
                    "bitdefender_tenant_deployment_failed",
                    &tenant,
                    error,
                    result,
                    log,
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What a Bitdefender deploy did, failed or not: its warnings (the
    /// unraised ones only said), then what was done.
    fn bitdefender_done(&mut self, uuid: &str, tenant: &str, done: &DeployOutcome) {
        for warning in &done.warnings {
            if warning.raised {
                self.warned = true;
            }
            tracing::warn!(
                uuid,
                tenant,
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            match event.fields.iter().find(|(key, _)| key == "rule_id") {
                Some((_, rule_id)) => {
                    tracing::info!(uuid, rule_id = rule_id.as_str(), "{}", event.name);
                }
                None => tracing::info!(uuid, "{}", event.name),
            }
        }
    }

    /// GravityZone's cap on YARA rules per company: when the YARA rules
    /// deployment state records on the tenant plus those the run creates pass
    /// the limit, each YARA create is refused before anything is sent.
    /// Updates and deletes go on; a deletion makes no room in the same run,
    /// since the rules are sent in plan order. A recorded rule is counted by
    /// the kind its workspace block has now; one the workspace no longer
    /// holds, or whose block does not read, is not counted.
    fn bitdefender_yara_limit<'b>(
        &mut self,
        batch: &Batch,
        planned: Vec<(&'b opentide_compile::Rule, Planned)>,
        log: &mut DeployLog<'_>,
    ) -> Vec<(&'b opentide_compile::Rule, Planned)> {
        use opentide_compile::bitdefender::{
            PLATFORM, YARA_RULE_LIMIT_CODE, is_yara, yara_rule_limit,
        };
        let tenant = batch.tenant.name.as_str();
        let created = planned
            .iter()
            .filter(|(rule, action)| matches!(action, Planned::Create) && is_yara(rule))
            .count();
        if created == 0 {
            return planned;
        }
        let root = self.workspace.root().to_path_buf();
        let recorded = deploy_state::recorded(&root, PLATFORM, tenant)
            .iter()
            .filter(|uuid| {
                crate::commands::validate_live::rule_of(self.workspace, uuid)
                    .is_some_and(|rule| is_yara(&rule))
            })
            .count();
        let Some(message) = yara_rule_limit(tenant, recorded, created) else {
            return planned;
        };
        let error = StateError {
            code: YARA_RULE_LIMIT_CODE,
            message,
        };
        planned
            .into_iter()
            .filter(|(rule, action)| {
                let refused = matches!(action, Planned::Create) && is_yara(rule);
                if refused {
                    self.report_failure(&error, &rule.uuid, PLATFORM, tenant);
                    log.refused(PLATFORM, tenant, &rule.uuid, &rule.name, &error.message);
                }
                !refused
            })
            .collect()
    }

    /// Google Security Operations: each rule verified, created, updated,
    /// disabled, archived or deleted by the id deployment state records
    /// (`GoogleSecopsDeploy`). Credentials that cannot be loaded, refused
    /// credentials or an instance that cannot be reached stop the tenant.
    fn google_secops(&mut self, batches: &[Batch], log: &mut DeployLog<'_>) -> Result<(), Raised> {
        use opentide_connectors::google_secops::{GoogleSecops, Instance};
        let platform = PlatformId::GoogleSecops.as_str();
        let connector = GoogleSecops::new(self.environment.clone());
        for batch in batches {
            let tenant = batch.tenant.name.clone();
            let planned = self.screen(platform, batch, log);
            if planned.is_empty() {
                continue;
            }
            let Some(connection) = self.connect_or_fail(platform, batch, log)? else {
                continue;
            };
            let ready = Instance::of(&connection.tenant).and_then(|instance| {
                connector
                    .authorizer(&connection.tenant)
                    .map(|authorizer| (instance, authorizer))
            });
            match ready {
                Ok(_) => {}
                Err(error) => {
                    // Unset or unreadable credentials: no rule on the tenant can deploy.
                    let text = error.text();
                    self.google_secops_tenant_failed(&tenant, &text);
                    self.unusable(platform, Some(&tenant), &text);
                    log.unreached_on(
                        platform,
                        &tenant,
                        "not_attempted",
                        &format!("not attempted: tenant {tenant} failed"),
                    );
                    continue;
                }
            }
            for (rule, action) in planned {
                if self.google_secops_rule(&connection, batch, rule, &action, &connector, log)? {
                    break;
                }
            }
        }
        Ok(())
    }

    /// A Google SecOps rule the tenant refused: what the deploy did before
    /// the failure, then each failure, a refused re-creation as its own.
    fn google_secops_rule_failed(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        tenant: &str,
        stored: Option<&str>,
        error: &DeployError,
        recreate_refusal: Option<&StateError>,
    ) {
        let platform = PlatformId::GoogleSecops.as_str();
        if let Some(done) = &error.partial {
            self.google_secops_done(result, &rule.uuid, tenant, done, stored);
            // A rule to retire that the tenant lost: its id
            // is forgotten, before the failure that preceded it.
            if done
                .warnings
                .iter()
                .any(|warning| warning.code == "google_secops_rule_missing")
            {
                self.record_deleted(result, platform, tenant);
            }
        }
        for failure in std::iter::once(&error.failure).chain(&error.more) {
            match recreate_refusal.filter(|refusal| refusal.code == failure.code) {
                Some(refusal) => {
                    self.report_failure(refusal, &rule.uuid, platform, tenant);
                    result.fail(&refusal.message);
                }
                None => {
                    tracing::error!(
                        uuid = rule.uuid.as_str(),
                        tenant = tenant,
                        name = rule.name.as_str(),
                        code = failure.code,
                        error = failure.message.as_str(),
                        "{}",
                        failure.code
                    );
                    self.rule_error(result, &format!("{}: {}", failure.code, failure.message));
                }
            }
        }
    }

    /// One Google SecOps rule: compiled, sent, and its result logged. `true`
    /// when the tenant failed and the rest of its rules are left out.
    fn google_secops_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        connector: &opentide_connectors::google_secops::GoogleSecops,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        let platform = PlatformId::GoogleSecops.as_str();
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(platform, Some(&tenant), &rule.uuid, &rule.name);
        let strategy = match self.strategy_of(rule, platform) {
            Ok(strategy) => strategy,
            Err(raised) => {
                self.close(log, result, Err(raised))?;
                return Ok(false);
            }
        };
        // The plan's payload: the text, and the run state, run
        // frequency and sections the deploy reads beside it.
        let payload = match opentide_compile::google_secops::compile_deployment(self.compile, rule)
        {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!(
                    uuid = rule.uuid.as_str(),
                    tenant = tenant.as_str(),
                    name = rule.name.as_str(),
                    error = error.reason.as_str(),
                    "compile_failed"
                );
                self.rule_error(&mut result, &format!("compile_failed: {}", error.reason));
                log.finished(result);
                return Ok(false);
            }
        };
        let recreate_refusal = self.recreate_refusal(&rule.uuid, platform, &tenant);
        let (operation, stored) = operation_of(action, strategy);
        let body = match serde_json::to_vec(&payload) {
            Ok(body) => body,
            Err(error) => {
                self.rule_error(&mut result, &format!("compile_failed: {error}"));
                log.finished(result);
                return Ok(false);
            }
        };
        let mut request = DeployRequest::new(stored.unwrap_or_default(), operation, body);
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(connector.deploy(context, &request).await) })
            .unwrap_or_else(|error| Err(DeployError::from(error)));
        match deployed {
            Ok(done) => {
                self.google_secops_done(&mut result, &rule.uuid, &tenant, &done, stored);
                if done.remote_id.is_none() {
                    self.record_deleted(&mut result, platform, &tenant);
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                self.google_secops_rule_failed(
                    &mut result,
                    rule,
                    &tenant,
                    stored,
                    &error,
                    recreate_refusal.as_ref(),
                );
                log.finished(result);
            }
            Err(error) => {
                // Refused credentials or an unreachable instance fail every rule on it.
                let text = error.into_connector().text();
                self.google_secops_tenant_failed(&tenant, &text);
                result.fail(&text);
                log.finished(result);
                // An interrupt stops the run, not the tenant.
                if self.interrupted() {
                    return Err(Raised::new("interrupted").stopping(Stops::Run));
                }
                self.stop_tenant(PlatformId::GoogleSecops.as_str(), &tenant, log);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What a Google SecOps deploy did, failed or not: its warnings, then the
    /// id of a rule it created (`google_secops_rule_created`), recorded when
    /// it is not the `stored` one.
    fn google_secops_done(
        &mut self,
        result: &mut RuleResult,
        uuid: &str,
        tenant: &str,
        done: &DeployOutcome,
        stored: Option<&str>,
    ) {
        const PLATFORM: &str = PlatformId::GoogleSecops.as_str();
        for warning in &done.warnings {
            self.warned = true;
            tracing::warn!(
                uuid,
                tenant,
                code = warning.code.as_str(),
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            let rule_id = event
                .fields
                .iter()
                .find(|(key, _)| key == "rule_id")
                .map_or("", |(_, id)| id.as_str());
            tracing::info!(uuid, rule_id, "{}", event.name);
        }
        if let Some(id) = done.remote_id.as_deref().filter(|id| Some(*id) != stored) {
            self.record_created(result, PLATFORM, tenant, &ExternalId::Text(id.to_owned()));
        }
    }

    /// A Google SecOps tenant no rule can deploy to (`_tenant_failed`): its
    /// code (`google_secops_credentials_missing`,
    /// `google_secops_tenant_unauthorized`) when the error names one, else
    /// `google_secops_tenant_unreachable`.
    fn google_secops_tenant_failed(&mut self, tenant: &str, text: &str) {
        let code = text
            .split_once(": ")
            .map(|(code, _)| code)
            .filter(|code| code.starts_with("google_secops_") && !code.contains(' '))
            .unwrap_or("google_secops_tenant_unreachable");
        tracing::error!(
            code,
            tenant,
            error = text,
            critical = true,
            "google_secops_tenant_deployment_failed"
        );
        self.failed = true;
    }

    /// Graylog: the version is read once per tenant (a vulnerable one warned
    /// about), then each rule's event definition, compiled for it, is
    /// created, updated, unscheduled or deleted through the platform's
    /// `Deployer` (`GraylogDeploy`).
    fn graylog(&mut self, batches: &[Batch], log: &mut DeployLog<'_>) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Graylog.as_str();
        use opentide_connectors::graylog::Client;
        for batch in batches {
            let tenant = batch.tenant.name.clone();
            let planned = self.screen(PLATFORM, batch, log);
            if planned.is_empty() {
                continue;
            }
            let Some(connection) = self.connect_or_fail(PLATFORM, batch, log)? else {
                continue;
            };
            // The version is read once, before any write. A refused token, an
            // unsupported version or an unreachable tenant stops the tenant.
            let version = match self.block(Client::new(self.context(&connection)).version()) {
                Ok(Ok(version)) => version,
                Ok(Err(error)) => {
                    let code = if error.forbidden() {
                        "graylog_forbidden"
                    } else {
                        "graylog_request_failed"
                    };
                    self.unusable(PLATFORM, Some(&tenant), &error.reason());
                    log.unreached_on(
                        PLATFORM,
                        &tenant,
                        "not_attempted",
                        &format!("not attempted: tenant {tenant} failed"),
                    );
                    tracing::error!(
                        tenant = tenant.as_str(),
                        code,
                        error = error.reason().as_str(),
                        critical = true,
                        "graylog_tenant_deployment_failed"
                    );
                    continue;
                }
                Err(error) => {
                    let code = match &error {
                        ConnectorError::Refused { .. } => "graylog_version_unsupported",
                        ConnectorError::Authentication { .. } => "graylog_tenant_unauthenticated",
                        _ => "graylog_tenant_unreachable",
                    };
                    self.unusable(PLATFORM, Some(&tenant), &error.text());
                    log.unreached_on(
                        PLATFORM,
                        &tenant,
                        "not_attempted",
                        &format!("not attempted: tenant {tenant} failed"),
                    );
                    tracing::error!(
                        tenant = tenant.as_str(),
                        code,
                        error = error.text().as_str(),
                        critical = true,
                        "graylog_tenant_deployment_failed"
                    );
                    continue;
                }
            };
            if opentide_compile::graylog::is_vulnerable(version) {
                self.warned = true;
                tracing::warn!(
                    tenant = tenant.as_str(),
                    detail = format!(
                        "Graylog {version} does not revoke access tokens reliably ({}); upgrade \
                         to 6.3.12, 7.0.16, 7.1.12 or later",
                        opentide_compile::graylog::ADVISORY
                    ),
                    "graylog_version_vulnerable"
                );
            }
            for (rule, action) in planned {
                if self.graylog_rule(&connection, batch, rule, &action, version, log)? {
                    break;
                }
            }
        }
        Ok(())
    }

    /// A Graylog rule the tenant refused: what the deploy did before the
    /// failure, then the failure; a refused re-creation is logged as the
    /// request it stopped.
    fn graylog_rule_failed(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        tenant: &str,
        error: &DeployError,
        recreate_refusal: Option<&StateError>,
    ) {
        if let Some(done) = &error.partial {
            self.graylog_done(&rule.uuid, tenant, done);
        }
        let failure = &error.failure;
        // The state's refusal is logged as the request it
        // stopped, as before.
        let code = if recreate_refusal.is_some_and(|refusal| refusal.code == failure.code) {
            "graylog_request_failed"
        } else {
            failure.code
        };
        match failure.status {
            Some(status) => tracing::error!(
                uuid = rule.uuid.as_str(),
                tenant = tenant,
                status_code = status,
                code,
                error = failure.message.as_str(),
                "{}",
                code
            ),
            None => tracing::error!(
                uuid = rule.uuid.as_str(),
                tenant = tenant,
                code,
                error = failure.message.as_str(),
                detail = failure.field("detail").unwrap_or_default(),
                "{}",
                code
            ),
        }
        self.rule_error(result, &failure.message);
    }

    /// The request a Graylog rule sends: a delete names the recorded id
    /// alone (no compile); anything else sends the definition compiled for
    /// the tenant's version, after logging that version's warnings. `Err` is
    /// the reason the rule fails, a compile failure logged with its code.
    fn graylog_request(
        &mut self,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        version: opentide_compile::graylog::Version,
        operation: Operation,
        stored: Option<&str>,
    ) -> Result<DeployRequest, String> {
        use opentide_compile::graylog::create_body;
        if let Planned::Delete(id) = action {
            // A delete sends the recorded id alone: no rule compile.
            return Ok(DeployRequest::delete(id.clone()));
        }
        let tenant = batch.tenant.name.as_str();
        let setup = opentide_compile::deploy::setup(&batch.table, "setup");
        let compiled = opentide_compile::graylog::compile_definition(
            self.compile,
            rule,
            version,
            setup,
            Some(tenant),
        )
        .map_err(|error| {
            // An alias the tenant does not define (or any other compile
            // failure) fails the rule with its own code
            // (`_deployment_error(exc.code)`).
            tracing::error!(
                uuid = rule.uuid.as_str(),
                tenant,
                name = rule.name.as_str(),
                code = error.code,
                error = error.reason.as_str(),
                "{}",
                error.code
            );
            error.reason
        })?;
        // The version's own warnings (a field it cannot take, a priority it
        // collapses).
        for (code, message) in &compiled.warnings {
            self.warned = true;
            tracing::warn!(
                uuid = rule.uuid.as_str(),
                tenant,
                detail = message.as_str(),
                "{code}"
            );
        }
        serde_json::to_vec(&create_body(&compiled))
            .map(|body| DeployRequest::new(stored.unwrap_or(&rule.uuid), operation, body))
            .map_err(|error| format!("the compiled definition is not JSON: {error}"))
    }

    /// One Graylog rule: compiled for the tenant's version, sent, and its
    /// result logged. `true` when the tenant failed and the rest of its rules
    /// are left out.
    fn graylog_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        version: opentide_compile::graylog::Version,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        const PLATFORM: &str = PlatformId::Graylog.as_str();
        // The version is read: the deployer reads it no more.
        let graylog = opentide_connectors::graylog::Graylog::on_version(version);
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(PLATFORM, Some(&tenant), &rule.uuid, &rule.name);
        let disable = self.strategy_of(rule, PLATFORM)? == StatusStrategy::Disablement;
        let (operation, stored) = match &action {
            Planned::Create => (Operation::Create, None),
            Planned::Update(id) if disable => (Operation::Disable, Some(id.as_str())),
            Planned::Update(id) => (Operation::Update, Some(id.as_str())),
            Planned::Delete(id) => (Operation::Delete, Some(id.as_str())),
        };
        let mut request =
            match self.graylog_request(batch, rule, action, version, operation, stored) {
                Ok(request) => request,
                Err(reason) => {
                    self.rule_error(&mut result, &reason);
                    log.finished(result);
                    return Ok(false);
                }
            };
        let recreate_refusal = self.recreate_refusal(&rule.uuid, PLATFORM, &tenant);
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(graylog.deploy(context, &request).await) })
            .unwrap_or_else(|error| Err(DeployError::from(error)));
        match deployed {
            Ok(done) => {
                self.graylog_done(&rule.uuid, &tenant, &done);
                match done.remote_id.as_deref() {
                    None => self.record_deleted(&mut result, PLATFORM, &tenant),
                    Some(id) if Some(id) != stored => self.record_created(
                        &mut result,
                        PLATFORM,
                        &tenant,
                        &ExternalId::Text(id.to_owned()),
                    ),
                    Some(_) => {}
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                self.graylog_rule_failed(
                    &mut result,
                    rule,
                    &tenant,
                    &error,
                    recreate_refusal.as_ref(),
                );
                log.finished(result);
            }
            Err(error) => {
                let error = error.into_connector();
                let text = error.text();
                let code = match &error {
                    ConnectorError::Authentication { .. } => "graylog_tenant_unauthenticated",
                    _ => "graylog_tenant_unreachable",
                };
                self.failed = true;
                tracing::error!(
                    tenant = tenant.as_str(),
                    code,
                    error = text.as_str(),
                    critical = true,
                    "graylog_tenant_deployment_failed"
                );
                result.fail(&text);
                log.finished(result);
                // An interrupt stops the run, not the tenant.
                if self.interrupted() {
                    return Err(Raised::new("interrupted").stopping(Stops::Run));
                }
                self.stop_tenant(PlatformId::Graylog.as_str(), &tenant, log);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What a Graylog deploy did, failed or not: its warnings, but the
    /// version's, which the tenant warned of once; then what was done.
    fn graylog_done(&mut self, uuid: &str, tenant: &str, done: &DeployOutcome) {
        for warning in &done.warnings {
            if warning.code == opentide_connectors::graylog::VERSION_VULNERABLE {
                continue;
            }
            self.warned = true;
            tracing::warn!(
                uuid,
                tenant,
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            let definition_id = event
                .fields
                .iter()
                .find(|(key, _)| key == "definition_id")
                .map_or("", |(_, id)| id.as_str());
            tracing::info!(uuid, definition_id, "{}", event.name);
        }
    }
}

impl Sender<'_, '_> {
    /// Exabeam New-Scale SIEM (`ExabeamDeploy`): each rule planned from
    /// deployment state, then created after a name check, updated (or
    /// disabled) by the recorded id, or deleted. A refused key, a tenant
    /// without the licence or with no answer stops its batch.
    fn exabeam(&mut self, batches: &[Batch], log: &mut DeployLog<'_>) -> Result<(), Raised> {
        use opentide_connectors::exabeam::Exabeam;
        let platform = opentide_compile::exabeam::PLATFORM;
        let exabeam = Exabeam::new();
        for batch in batches {
            let tenant = batch.tenant.name.clone();
            let planned = self.screen(platform, batch, log);
            if planned.is_empty() {
                continue;
            }
            let Some(connection) = self.connect_or_fail(platform, batch, log)? else {
                continue;
            };
            let cancel = self.cancel.clone();
            let context = TenantContext {
                tenant: &connection.tenant,
                http: &connection.http,
                cancel: &cancel,
            };
            if let Err(error) = exabeam.session(context) {
                // An unset credential variable: no rule on the tenant can deploy.
                let text = error.text();
                tracing::error!(
                    tenant = tenant.as_str(),
                    error = text.as_str(),
                    critical = true,
                    "exabeam_tenant_deployment_failed"
                );
                self.unusable(platform, Some(&tenant), &text);
                log.unreached_on(
                    platform,
                    &tenant,
                    "not_attempted",
                    &format!("not attempted: tenant {tenant} failed"),
                );
                continue;
            }
            for (rule, action) in planned {
                if self.exabeam_rule(&connection, batch, rule, &action, &exabeam, log)? {
                    break;
                }
            }
        }
        Ok(())
    }

    /// An Exabeam rule the tenant refused: what the deploy did before the
    /// failure, then the failure, a refused re-creation as its own.
    fn exabeam_rule_failed(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        tenant: &str,
        error: &DeployError,
        recreate_refusal: Option<&StateError>,
        object_name: Option<&str>,
    ) {
        let platform = opentide_compile::exabeam::PLATFORM;
        if let Some(done) = &error.partial {
            self.exabeam_done(&rule.uuid, &rule.name, tenant, done);
        }
        let failure = &error.failure;
        match recreate_refusal.filter(|refusal| refusal.code == failure.code) {
            Some(refusal) => {
                self.report_failure(refusal, &rule.uuid, platform, tenant);
                result.fail(&refusal.message);
            }
            None => {
                tracing::error!(
                    code = failure.code,
                    error = failure.message.as_str(),
                    detail = failure.field("detail"),
                    existing_id = failure.field("existing_id"),
                    errors = failure.field("errors"),
                    trace_id = failure.field("trace_id"),
                    uuid = rule.uuid.as_str(),
                    tenant = tenant,
                    name = failure.field("name").or(object_name),
                    "{}",
                    failure.code
                );
                self.rule_error(result, &format!("{}: {}", failure.code, failure.message));
            }
        }
    }

    /// One Exabeam rule: compiled, sent, and its result logged. `true` when
    /// the tenant failed and the rest of its rules are left out.
    fn exabeam_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        exabeam: &opentide_connectors::exabeam::Exabeam,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        let platform = opentide_compile::exabeam::PLATFORM;
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(platform, Some(&tenant), &rule.uuid, &rule.name);
        let strategy = match self.strategy_of(rule, platform) {
            Ok(strategy) => strategy,
            Err(raised) => {
                self.close(log, result, Err(raised))?;
                return Ok(false);
            }
        };
        let compiled = if matches!(action, Planned::Delete(_)) {
            // A delete sends no body.
            Ok(None)
        } else {
            opentide_compile::exabeam::compile_rule(
                self.compile,
                rule,
                strategy,
                Some(&batch.table),
            )
            .map(Some)
            .map_err(|error| Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name)))
        };
        let compiled = match compiled {
            Ok(compiled) => compiled,
            Err(raised) => {
                self.close(log, result, Err(raised))?;
                return Ok(false);
            }
        };
        let recreate_refusal = self.recreate_refusal(&rule.uuid, platform, &tenant);
        let (operation, stored) = operation_of(action, strategy);
        let body = compiled.map_or(CJson::Null, |compiled| compiled.body);
        let mut request = DeployRequest::new(
            stored.unwrap_or_default(),
            operation,
            serde_json::to_vec(&body).unwrap_or_default(),
        );
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        // The update path's lines name the object; the create path's
        // name the Exabeam rule (the event carries it); a delete's none.
        let object_name = (!matches!(action, Planned::Delete(_))).then_some(rule.name.as_str());
        let context = self.context(connection);
        match self
            .block(async { Ok(exabeam.deploy(context, &request).await) })
            .map_err(|error| raised(&error))?
        {
            Ok(done) => {
                self.exabeam_done(&rule.uuid, &rule.name, &tenant, &done);
                match done.remote_id.as_deref() {
                    None => self.record_deleted(&mut result, platform, &tenant),
                    Some(id) if Some(id) != stored => self.record_created(
                        &mut result,
                        platform,
                        &tenant,
                        &ExternalId::Text(id.to_owned()),
                    ),
                    Some(_) => {}
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                self.exabeam_rule_failed(
                    &mut result,
                    rule,
                    &tenant,
                    &error,
                    recreate_refusal.as_ref(),
                    object_name,
                );
                log.finished(result);
            }
            Err(error) => {
                tracing::error!(
                    code = error.failure.code,
                    tenant = tenant.as_str(),
                    error = error.failure.message.as_str(),
                    critical = true,
                    "exabeam_tenant_deployment_failed"
                );
                self.failed = true;
                result.fail(&error.failure.message);
                log.finished(result);
                // An interrupt stops the run, not the tenant.
                if self.interrupted() {
                    return Err(Raised::new("interrupted").stopping(Stops::Run));
                }
                self.stop_tenant(PlatformId::Exabeam.as_str(), &tenant, log);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What an Exabeam deploy did, failed or not: its warnings (the two
    /// about the deployed rule name it), then what was done.
    fn exabeam_done(&mut self, uuid: &str, name: &str, tenant: &str, done: &DeployOutcome) {
        for warning in &done.warnings {
            self.warned = true;
            let named = matches!(
                warning.code.as_str(),
                "exabeam_schedule_retained" | "exabeam_rule_auto_disabled"
            );
            tracing::warn!(
                code = warning.code.as_str(),
                uuid,
                tenant,
                name = named.then_some(name),
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            let rule_id = event
                .fields
                .iter()
                .find(|(key, _)| key == "rule_id")
                .map_or("", |(_, id)| id.as_str());
            tracing::info!(uuid, rule_id, "{}", event.name);
        }
    }
}

/// What a platform plugin's `Deployer` receives as the body (UC-4.5b): the
/// rule's document with the tenant's modifiers applied, its block for the
/// platform, and, for an update, a disable or a delete, the id deployment
/// state holds. `opentide.plugins` hands the plugin `remote_id` as the
/// request's own field.
fn plugin_body(rule: &opentide_compile::Rule, platform: &str, stored: Option<&str>) -> CJson {
    let mut body = opentide_compile::json::Object::new();
    body.insert("rule".into(), rule.data.clone());
    body.insert(
        "configuration".into(),
        rule.block(platform).cloned().unwrap_or(CJson::Null),
    );
    if let Some(id) = stored {
        body.insert("remote_id".into(), CJson::Str(id.to_owned()));
    }
    CJson::Object(body)
}

/// A plugin's failure as the exception that stops the run: the tenant
/// refused the rule or the credentials, or the plugin raised.
fn plugin_raised(error: &ConnectorError) -> Raised {
    match error {
        ConnectorError::Refused {
            message,
            detail: Some(detail),
            ..
        } => Raised::new(format!("PlatformRefused: {message}: {detail}")),
        ConnectorError::Refused { message, .. } => {
            Raised::new(format!("PlatformRefused: {message}"))
        }
        ConnectorError::Authentication { message, .. } => {
            Raised::new(format!("PlatformAuthenticationError: {message}")).stopping(Stops::Tenant)
        }
        ConnectorError::Crashed { message, .. } => Raised::new(format!("PluginError: {message}")),
        other => raised(other),
    }
}

/// The path the rule's state shard is written to, for messages and tests.
pub fn shard_path(workspace: &Path, uuid: &str) -> PathBuf {
    deploy_state::state_dir(workspace).join(format!(
        "{}.json",
        deploy_state::canonical(uuid).unwrap_or_else(|| uuid.to_owned())
    ))
}

/// The operation a planned action sends, and the remote id it names: an
/// update of a rule whose strategy disables it is a disable.
fn operation_of(action: &Planned, strategy: StatusStrategy) -> (Operation, Option<&str>) {
    match action {
        Planned::Create => (Operation::Create, None),
        Planned::Update(id) if strategy == StatusStrategy::Disablement => {
            (Operation::Disable, Some(id.as_str()))
        }
        Planned::Update(id) => (Operation::Update, Some(id.as_str())),
        Planned::Delete(id) => (Operation::Delete, Some(id.as_str())),
    }
}

/// What an Elastic tenant's rules share: its `setup`, whether it turns
/// suppression off, and the rules already warned about that.
struct ElasticTenant {
    setup: opentide_compile::elastic::Setup,
    suppression_off: bool,
    warned_rules: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failure a `Deployer` builds itself has no connector error: its
    /// scope still says what stops (a Rust plugin's own tenant failure),
    /// whatever the connector error the arm reads its words from.
    #[test]
    fn a_deployers_own_tenant_failure_stops_the_tenant() {
        let tenant = DeployError::tenant(DeployFailure::new("acme_key_refused", "no"));
        assert_eq!(scoped(tenant, |error| raised(&error)).stops, Stops::Tenant);
        let rule = DeployError::rule(DeployFailure::new("acme_rule_refused", "no"));
        assert_eq!(scoped(rule, |error| raised(&error)).stops, Stops::Rule);
        // An interrupt stays the run's.
        let cancelled = DeployError::from(ConnectorError::Cancelled);
        assert_eq!(scoped(cancelled, |error| raised(&error)).stops, Stops::Run);
    }

    /// A connector error stops what the SDK's `DeployError` says it fails:
    /// the platforms whose arm reads a connector error (`raised`) stop the
    /// tenant exactly when the SDK reports the tenant's failure.
    #[test]
    fn a_connector_error_stops_what_the_sdk_says_it_fails() {
        let (p, t) = (String::from("p"), String::from("t"));
        let every = [
            ConnectorError::Unreachable {
                platform: p.clone(),
                tenant: t.clone(),
                address: String::new(),
                reason: String::new(),
            },
            ConnectorError::Timeout {
                platform: p.clone(),
                tenant: t.clone(),
                address: String::new(),
                seconds: 1,
            },
            ConnectorError::Answer {
                platform: p.clone(),
                tenant: t.clone(),
                address: String::new(),
                reason: String::new(),
            },
            ConnectorError::Setup {
                platform: p.clone(),
                tenant: t.clone(),
                message: String::new(),
            },
            ConnectorError::MissingCredential {
                platform: p.clone(),
                tenant: t.clone(),
                key: String::new(),
                variable: String::new(),
            },
            ConnectorError::Crashed {
                platform: p.clone(),
                tenant: t.clone(),
                message: String::new(),
            },
            ConnectorError::refused(&p, &t, "no", None),
            ConnectorError::Authentication {
                platform: p.clone(),
                tenant: t.clone(),
                message: String::new(),
                detail: None,
            },
            ConnectorError::QueryTimedOut {
                platform: p.clone(),
                tenant: t.clone(),
                message: String::new(),
                detail: None,
                timeout: std::time::Duration::from_secs(1),
            },
            ConnectorError::Gateway {
                platform: p.clone(),
                tenant: t.clone(),
                message: String::new(),
                status: 502,
            },
            ConnectorError::Cancelled,
            ConnectorError::NetworkUnavailable {
                platform: p.clone(),
                tenant: t.clone(),
            },
        ];
        for error in every {
            let stops = raised(&error).stops;
            let shown = format!("{error:?}");
            let scope = DeployError::from(error).scope;
            assert_eq!(
                stops == Stops::Rule,
                scope == DeployScope::Rule,
                "{shown}: the CLI stops {stops:?}, the SDK fails the {scope:?}"
            );
        }
    }

    fn result(status: &'static str, action: &str, tenant: Option<&str>, id: &str) -> RuleResult {
        let mut result = RuleResult::new("elastic", tenant, id, "Rule");
        result.status = status;
        result.action = Some(action.to_owned());
        result.seconds = Some(0.0);
        result
    }

    #[test]
    fn the_outcome_line_counts_what_was_sent() {
        let results = vec![
            result("deployed", "create", Some("t"), "a"),
            result("deployed", "upsert", Some("t"), "b"),
            result("failed", "upsert", Some("t"), "c"),
            result("not_attempted", "upsert", Some("t"), "d"),
        ];
        assert_eq!(
            outcome_message(&results, 1.25, false),
            "Deployed 2 rules to 1 tenant · 1 created, 1 created or updated · 1 failed, 1 not attempted · 1.2s"
        );
        assert_eq!(
            outcome_message(&results, 1.0, true),
            "Deployment failed · 1 created, 1 created or updated, 1 failed, 1 not attempted · 1.0s"
        );
        let refs: Vec<&RuleResult> = results.iter().collect();
        assert_eq!(counts_text(&refs), "2 deployed, 1 failed, 1 not attempted");
        let Json::Object(summary) = run_summary(&results, 1, 1, 0.0) else {
            panic!("an object")
        };
        let keys: Vec<&str> = summary.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "create",
                "update",
                "upsert",
                "disable",
                "delete",
                "failed",
                "skipped",
                "not_attempted",
                "seconds",
                "platforms",
                "tenants"
            ]
        );
    }

    #[test]
    fn an_error_is_one_bounded_line() {
        assert_eq!(bounded("a\n  b\tc"), "a b c");
        let long = "x".repeat(500);
        let cut = bounded(&long);
        assert_eq!(cut.chars().count(), MAX_ERROR_LENGTH);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn a_failure_says_what_went_wrong_without_an_exception_class() {
        let splunk = Raised::new("Splunk answered HTTP 400 Bad Request: bad");
        assert_eq!(
            splunk.describe(),
            "Splunk answered HTTP 400 Bad Request: bad"
        );
        assert_eq!(splunk.error(), "Splunk answered HTTP 400 Bad Request: bad");
        assert_eq!(raised(&ConnectorError::Cancelled).describe(), "interrupted");
        // A refusal carries the tenant's own reason, not only the log line.
        let refused = ConnectorError::Refused {
            platform: "crowdstrike".into(),
            tenant: "lab".into(),
            message: "CrowdStrike refused the rule".into(),
            detail: Some("severity is out of range".into()),
        };
        assert_eq!(
            raised(&refused).error(),
            "CrowdStrike refused the rule: severity is out of range"
        );
        // A refused credential names the tenant.
        let denied = ConnectorError::Authentication {
            platform: "sentinel".into(),
            tenant: "soc".into(),
            message: "Cannot authenticate with the tenant configuration".into(),
            detail: None,
        };
        assert_eq!(
            raised(&denied).error(),
            "sentinel tenant 'soc': Cannot authenticate with the tenant configuration"
        );
        // A plugin's failure keeps the plugin API's documented type names.
        let refused = ConnectorError::Refused {
            platform: "acme".into(),
            tenant: "lab".into(),
            message: "Acme answered 422".into(),
            detail: None,
        };
        assert_eq!(
            plugin_raised(&refused).error(),
            "PlatformRefused: Acme answered 422"
        );
    }

    #[test]
    fn a_rule_line_pads_its_name_and_counts_its_place() {
        let mut ok = result("deployed", "update", Some("t"), "a");
        ok.name = "Short".into();
        assert_eq!(
            result_line(&ok, 2, 10, 8, None).as_plain(),
            "  [ 2/10] ✓ updated   Short     0.0s"
        );
        let mut failed = result("failed", "upsert", Some("t"), "a");
        failed.error =
            Some("one two three four five six seven eight nine ten eleven twelve".into());
        let wrapped = result_line(&failed, 1, 1, 4, Some(40)).as_plain();
        assert!(wrapped.contains('\n'), "{wrapped}");
        let skipped = result("not_attempted", "upsert", None, "b");
        assert_eq!(verb(&skipped), "skipped");
        assert_eq!(
            header_line("sentinel", Some("prod"), Some(2)).as_plain(),
            "Deploying to sentinel / prod · 2 rules"
        );
        assert_eq!(
            header_line("sentinel", None, None).as_plain(),
            "Deploying to sentinel"
        );
    }
}
