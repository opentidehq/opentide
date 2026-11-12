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
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use opentide_compile::Json as CJson;
use opentide_compile::plan::{self, Change, Scope, SelectOptions};
use opentide_compile::strategy::{self, RunStrategies, StatusStrategy};
use opentide_connectors::connector::{DeployRequest, Operation, TenantContext};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::{ConnectorError, Environment, HttpClient, Registry, Tenant};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, Workspace, root};
use tokio_util::sync::CancellationToken;

use super::deploy_state::{self, ExternalId, StateError};
use super::query::{Configured, http_settings, log_unset, toml_value};
use super::validate_live::{Batch, batches};
use super::{Report, placement};
use crate::env::Env;
use crate::envelope::code;
use crate::json::Json;
use crate::logging::Sink;
use crate::render::glyphs;
use crate::render::outcome::Console;
use crate::render::progress::{Step, StepStatus, plural, seconds_text};
use crate::render::text::{Style, Text};

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
/// The loggers of the modules a port logs for.
const DEPLOY_LOGGER: &str = "opentide.cli.services.deploy";
const IDS_LOGGER: &str = "opentide.deployment.external_ids";

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

/// Runs `deploy` without `--dry-run`, on a thread of its own with this
/// thread's log subscriber (a host may already run a runtime here).
pub fn run(args: &Args, cx: &Context<'_>) -> Sent {
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let ran = std::thread::scope(|scope| {
        scope
            .spawn(|| tracing::dispatcher::with_default(&dispatch, || run_deploy(args, cx)))
            .join()
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

/// Counts the blocks a status kept out of the plan (`_report_skipped`).
fn report_skipped(
    result: &mut Vec<(String, Json)>,
    skipped: &[plan::Skipped],
    workspace: &Workspace,
) {
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
    let runs: Vec<StatusStrategy> = match result.iter().find(|(key, _)| key == "strategies") {
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
    };
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
        _ => Vec::new(),
    };
    match summary.iter_mut().find(|(key, _)| key == "skipped") {
        Some(entry) => entry.1 = Json::from(rules.len()),
        None => summary.push(("skipped".into(), Json::from(rules.len()))),
    }
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
        ("plan".into(), Json::Object(Vec::new())),
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
    if promotes(args, &runs, cx.env) {
        let settings = opentide_compile::promotion::Settings::new(&owned.config, &owned.statuses);
        let debug = cx.debug || super::deploy_promote::is_debug(cx.env);
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
    }
    let enabled = plan::enabled(&owned.config);
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
        // `emit_warning`'s CI annotation is for a run without --platform,
        // which stays Python's: with one, the platform's absence returned above.
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
    let mut header = Text::styled("Deploy plan", &Style::new("bold"));
    header.append(&format!("{separator}strategy "), &Style::new("dim"));
    let strategy_names: Vec<&str> = runs.iter().map(|run| run.name()).collect();
    header.append(&strategy_names.join(" "), &Style::new("bold"));
    header.append(
        &format!(
            "{separator}{}",
            plan::scope_text(deployment.len(), tenant_count)
        ),
        &Style::new("dim"),
    );
    // The header's own style is bold, under the dim parts too (a Rich
    // `Text` with a base style).
    let length = header.len();
    header.stylize(&Style::new("bold"), 0, length);
    cx.lines.line(&header, false);
    cx.lines.line(
        &Text::styled(&plan::message(&changes), &Style::new("dim")),
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
        warned: false,
        environment: Environment::from_pairs(cx.env.iter()),
        cancel: CancellationToken::new(),
        runtime: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok(),
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
        match sender.platform(system, uuids, &mut log) {
            Err(raised) => {
                step.status = StepStatus::Failed;
                log.unreached(None, "not_attempted", NOT_ATTEMPTED);
                step.outcome = Some(counts_text(&log.platform_results(system)));
                failure = Some((system.clone(), raised));
            }
            Ok(()) => {
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
        deployed.push(system.clone());
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
        let culprit = results
            .iter()
            .find(|result| result.platform == system && result.status == "failed");
        if let Some(culprit) = culprit {
            tracing::debug!(
                system = system.as_str(),
                detail = error.as_str(),
                logger = DEPLOY_LOGGER,
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
                logger = DEPLOY_LOGGER,
                "platform_deployment_failed"
            );
        }
        return result;
    }
    let outcome_failed = sender.failed || refused;
    let any_failed = results.iter().any(|result| result.status == "failed");
    let message = if outcome_failed && !any_failed {
        "Deployment finished with errors".to_owned()
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
        Json::Object(vec![
            ("platform".into(), Json::str(&self.platform)),
            ("tenant".into(), text(&self.tenant)),
            ("id".into(), Json::str(&self.id)),
            ("name".into(), Json::str(&self.name)),
            ("status".into(), Json::str(self.status)),
            ("action".into(), text(&self.action)),
            (
                "seconds".into(),
                self.seconds.map_or(Json::Null, |seconds| {
                    Json::Float((seconds * 1000.0).round() / 1000.0)
                }),
            ),
            ("error".into(), text(&self.error)),
            ("reason".into(), text(&self.reason)),
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
    Json::Object(members)
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
        for ((name, tenant), changes) in &self.planned {
            if platform.is_some_and(|platform| platform != name) {
                continue;
            }
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
    let bold = Style::new("bold");
    let mut line = Text::styled("Deploying to ", &bold);
    line.append(&place, &bold);
    if let Some(rules) = rules {
        line.append(
            &format!(" {} {}", glyphs::SEPARATOR, plural(rules, "rule", None)),
            &Style::new("dim"),
        );
    }
    // Rich's `Text("Deploying to ", style="bold")`: bold is the base style.
    let length = line.len();
    line.stylize(&bold, 0, length);
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
        "bold red"
    } else if skipped {
        "dim"
    } else {
        "green"
    };
    let mut line = Text::plain("  ");
    line.append(&format!("[{index:>digits$}/{total}]"), &Style::new("dim"));
    line.push_str(" ");
    line.append(&format!("{mark} {:<9} ", verb(result)), &Style::new(style));
    let pad = name_width.saturating_sub(result.name.chars().count());
    let name = format!("{}{}", result.name, " ".repeat(pad));
    if failed {
        line.append(&name, &Style::new("bold"));
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
        line.append(&detail, &Style::new("red"));
    } else if skipped {
        line.append(
            result.reason.as_deref().unwrap_or_default(),
            &Style::new("dim"),
        );
    } else {
        line.append(
            &seconds_text(result.seconds.unwrap_or(0.0)),
            &Style::new("dim"),
        );
    }
    line
}

// ---------------------------------------------------------------- sending

/// An exception a platform raised: it stops the run (`failure`).
#[derive(Debug, Clone)]
struct Raised {
    /// The exception's type name.
    kind: String,
    /// `str(exc)`.
    detail: String,
}

impl Raised {
    fn new(kind: &str, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.to_owned(),
            detail: detail.into(),
        }
    }

    /// `Type: detail`, or the type alone.
    fn error(&self) -> String {
        let detail = self.detail.trim();
        if detail.is_empty() {
            self.kind.clone()
        } else {
            format!("{}: {detail}", self.kind)
        }
    }

    /// What the rule being sent says about it (`describe_error`).
    fn describe(&self) -> String {
        if self.kind == "KeyboardInterrupt" {
            return "interrupted".into();
        }
        if let Some(status) = http_status(&self.detail) {
            return bounded(&format!("HTTP {status}: {}", self.detail));
        }
        let detail = self.detail.trim();
        if detail.is_empty() || detail == self.kind {
            bounded(&self.kind)
        } else {
            bounded(&format!("{}: {detail}", self.kind))
        }
    }
}

/// The HTTP status an SDK exception carries: Splunk's `HTTP 400 Bad
/// Request -- ...`, Sentinel's `... failed with HTTP 400 ...`.
fn http_status(detail: &str) -> Option<u16> {
    let rest = detail.strip_prefix("HTTP ").or_else(|| {
        detail
            .split_once(" failed with HTTP ")
            .map(|(_, rest)| rest)
    })?;
    rest.split(' ').next()?.parse().ok()
}

/// A connector error as the exception the oracle's client raised.
fn raised(error: &ConnectorError, refused_kind: &str) -> Raised {
    match error {
        ConnectorError::Cancelled => Raised::new("KeyboardInterrupt", ""),
        ConnectorError::Authentication { message, .. } => {
            Raised::new("TenantConnectionError", message.clone())
        }
        ConnectorError::Refused { message, .. } => Raised::new(refused_kind, message.clone()),
        ConnectorError::Setup { .. } | ConnectorError::MissingCredential { .. } => {
            Raised::new("ValueError", error.to_string())
        }
        ConnectorError::Timeout { .. } => Raised::new("ReadTimeout", error.to_string()),
        _ => Raised::new("ConnectionError", error.to_string()),
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
    /// `DEPLOYMENT_WARNING_RAISED`.
    warned: bool,
    environment: Environment,
    cancel: CancellationToken,
    runtime: Option<tokio::runtime::Runtime>,
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
    /// Runs *work* on the run's runtime, with Ctrl-C watched.
    fn block<T>(
        &self,
        work: impl std::future::Future<Output = Result<T, ConnectorError>>,
    ) -> Result<T, ConnectorError> {
        let Some(runtime) = &self.runtime else {
            return Err(ConnectorError::Crashed {
                platform: String::new(),
                tenant: String::new(),
                message: "cannot start the network runtime".into(),
            });
        };
        let cancel = &self.cancel;
        let interrupted = self.cx.interrupted;
        runtime.block_on(async {
            let watch = async {
                while !interrupted() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                cancel.cancel();
                std::future::pending::<()>().await;
            };
            tokio::select! {
                result = work => result,
                () = watch => Err(ConnectorError::Cancelled),
            }
        })
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
        let timeout = match platform {
            "elastic" => 30,
            "sentinel" => 60,
            _ => 120,
        };
        let settings = match platform {
            "sysdig" => opentide_connectors::sysdig::http_defaults(),
            _ => http_settings(platform, Duration::from_secs(timeout)),
        };
        let tenant = Tenant::from_setup(
            platform,
            &batch.tenant.name,
            &setup,
            &self.environment,
            Resolve::Counting,
            &settings,
        )
        .map_err(|error| Raised::new("ValueError", error.to_string()))?;
        let http = HttpClient::new(
            &tenant.label,
            &tenant.http,
            &self.environment,
            self.cx.proxy,
        )
        .map_err(|error| Raised::new("ValueError", error.to_string()))?;
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
        .map_err(|message| Raised::new("KeyError", message))
    }

    /// One platform's deploy (`deployer.deploy(mdr_deployment=uuids, strategies=run)`).
    fn platform(
        &mut self,
        platform: &str,
        uuids: &[String],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let batches = self.batches(platform, uuids)?;
        match platform {
            "elastic" => self.elastic(&batches, log),
            "sysdig" => self.sysdig(&batches, log),
            "defender_for_endpoint" | "sentinel_one" | "crowdstrike" => {
                self.with_state(platform, &batches, log)
            }
            _ => self.by_uuid(platform, &batches, log),
        }
    }

    /// Ends a rule's block: a raised exception fails the rule and goes on.
    fn close(
        &mut self,
        log: &mut DeployLog<'_>,
        mut result: RuleResult,
        outcome: Result<(), Raised>,
    ) -> Result<(), Raised> {
        if let Err(raised) = &outcome {
            result.fail(&raised.describe());
        }
        log.finished(result);
        outcome
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
            let connection = self.connect(platform, batch)?;
            for sent in &batch.rules {
                let rule = &sent.rule;
                if platform == "harfanglab" {
                    let block = rule.block(platform);
                    let kind = block.and_then(|block| {
                        if block.get("sigma").is_some_and(|value| !value.is_null()) {
                            Some("Sigma")
                        } else if block.get("yara").is_some_and(|value| !value.is_null()) {
                            Some("YARA")
                        } else {
                            None
                        }
                    });
                    let tenant_kind = opentide_compile::deploy::setup_text(&batch.table, "type");
                    if block.is_none() {
                        tracing::warn!(
                            detail = rule.name.as_str(),
                            logger = "opentide.platforms.harfanglab.deployer",
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
                    if kind != Some(tenant_kind.as_str()) {
                        log.skipped(
                            platform,
                            &tenant,
                            &rule.uuid,
                            &rule.name,
                            &format!("{} rule, {tenant_kind} tenant", kind.unwrap_or("unknown")),
                        );
                        continue;
                    }
                }
                let mut result = RuleResult::new(platform, Some(&tenant), &rule.uuid, &rule.name);
                let outcome = self.by_uuid_rule(platform, &connection, batch, rule, &mut result);
                self.close(log, result, outcome)?;
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
            .map_err(|error| Raised::new("ValueError", error.exception_text()))
    }

    fn deployer(
        &self,
        platform: &str,
    ) -> Result<&dyn opentide_connectors::connector::Deployer, Raised> {
        self.cx
            .registry
            .get(platform)
            .and_then(opentide_connectors::Platform::deployer)
            .ok_or_else(|| {
                Raised::new(
                    "ValueError",
                    format!("Cannot find a deployment engine for {platform}"),
                )
            })
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
        let tenant = batch.tenant.name.as_str();
        let compile_error = |kind: &str, error: opentide_compile::rule::CompileError| {
            Raised::new(kind, format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        match platform {
            "sentinel" => {
                let deployer = self.deployer(platform)?;
                let request = if deletion {
                    tracing::warn!(
                        arg0 = rule.name.as_str(),
                        logger = "opentide.platforms.sentinel.deployer",
                        "the_rule_will_be_removed_from_the_sentinel_workspace"
                    );
                    DeployRequest {
                        rule_id: rule.uuid.clone(),
                        operation: Operation::Delete,
                        body: Vec::new(),
                    }
                } else {
                    let body = opentide_compile::sentinel::compile(self.compile, rule, tenant)
                        .map_err(|error| compile_error("SentinelCompileError", error))?;
                    DeployRequest {
                        rule_id: rule.uuid.clone(),
                        operation: Operation::Update,
                        body: body.to_compact().into_bytes(),
                    }
                };
                let context = self.context(connection);
                self.block(deployer.deploy(context, &request))
                    .map_err(|error| raised(&error, "SentinelApiError"))?;
            }
            "splunk" => {
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
                let writes =
                    opentide_compile::splunk::compile(splunk_cx, rule, &batch.table, clock)
                        .map_err(|error| compile_error("ValueError", error))?;
                let mut name = rule.name.trim().to_owned();
                let correlation = match rule
                    .block(platform)
                    .and_then(|block| block.get("correlation_search"))
                {
                    Some(CJson::Bool(set)) => *set,
                    _ => opentide_compile::deploy::setup(&batch.table, "enterprise_security")
                        .is_some_and(CJson::truthy),
                };
                if correlation {
                    name.push_str(" - Rule");
                }
                let splunk = opentide_connectors::splunk::Splunk::new();
                let context = self.context(connection);
                if deletion {
                    let found = self
                        .block(splunk.saved_search(context, &name))
                        .map_err(|error| raised(&error, "HTTPError"))?;
                    if found.is_some() {
                        self.block(splunk.delete_saved_search(context, &name))
                            .map_err(|error| raised(&error, "HTTPError"))?;
                        tracing::warn!(
                            name = name.as_str(),
                            logger = "opentide.platforms.splunk.deployer",
                            "splunk_alert_deleted"
                        );
                    }
                    return Ok(());
                }
                let mut settings = opentide_compile::json::Object::new();
                for write in writes.iter().skip(1) {
                    if let CJson::Object(members) = &write.body {
                        for (key, value) in members {
                            settings.insert(key.clone(), value.clone());
                        }
                    }
                }
                self.block(splunk.apply_saved_search(context, &name, &settings, false))
                    .map_err(|error| raised(&error, "HTTPError"))?;
            }
            "carbon_black_cloud" => {
                let Some(report) =
                    opentide_compile::carbon_black::report(self.compile, rule, &batch.table)
                        .map_err(|error| compile_error("ValueError", error))?
                else {
                    return Ok(());
                };
                let plan = opentide_connectors::carbon_black::ReportDeploy {
                    uuid: rule.uuid.clone(),
                    name: report.name,
                    description: report.description,
                    query: report.query,
                    deployment: report.deployment,
                    tags: report.tags,
                    severity: report.severity,
                    watchlist: report.watchlist,
                    report: report.report.clone(),
                    now: self.cx.now.as_second(),
                };
                let context = self.context(connection);
                let change = self
                    .block(
                        opentide_connectors::carbon_black::CarbonBlack
                            .deploy_report(context, &plan),
                    )
                    .map_err(|error| {
                        let kind = if error.to_string().starts_with("The CBC Deployer cannot") {
                            "RuntimeError"
                        } else {
                            "ApiError"
                        };
                        raised(&error, kind)
                    })?;
                let logger = "opentide.platforms.carbon_black.deployer";
                match change {
                    opentide_connectors::carbon_black::ReportChange::Deleted
                        if report.report == plan.name =>
                    {
                        tracing::warn!(
                            report = report.report.as_str(),
                            logger,
                            "report_deleted_with_rule"
                        );
                    }
                    opentide_connectors::carbon_black::ReportChange::Deleted => {
                        tracing::warn!(
                            report = report.report.as_str(),
                            logger,
                            "report_auto_deleted"
                        );
                    }
                    _ => {}
                }
            }
            _ => {
                let writes =
                    opentide_compile::harfanglab::compile(self.compile, rule, &batch.table)
                        .map_err(|error| compile_error("Exception", error))?;
                let Some(write) = writes.first() else {
                    return Ok(());
                };
                let deployer = self.deployer(platform)?;
                let request = DeployRequest {
                    rule_id: rule.uuid.clone(),
                    operation: if deletion {
                        Operation::Delete
                    } else {
                        Operation::Update
                    },
                    body: if write.body.is_null() {
                        Vec::new()
                    } else {
                        opentide_connectors::body::python_json(&write.body).unwrap_or_default()
                    },
                };
                let context = self.context(connection);
                self.block(deployer.deploy(context, &request))
                    .map_err(|error| raised(&error, "DetectionRuleCreationFailed"))?;
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
                logger = IDS_LOGGER,
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
            logger = IDS_LOGGER,
            "{}",
            error.code
        );
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
                "rule {uuid} has no {platform} id for tenant {}, and this {place} run ({names}) \
                 in CI cannot keep the id a create would return: only the generated production \
                 job (--strategy RELEASE on the default branch) commits \
                 .opentide/states/deployment/. The create was refused before any vendor call. \
                 Deploy the rule from the production job, or pass --persist-state-externally if \
                 this pipeline commits .opentide/states/deployment/ itself.",
                opentide_connectors::python::python_string_repr(tenant.trim())
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
                    logger = IDS_LOGGER,
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
                    "rule {uuid} has no {platform} id for tenant {} in {}, so nothing is known \
                     to exist on that tenant and there is nothing to {}. If a remote copy \
                     exists, it must be removed by hand.",
                    opentide_connectors::python::python_string_repr(tenant.trim()),
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
                    logger = IDS_LOGGER,
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
            let connection = self.connect(platform, batch)?;
            let cancel = self.cancel.clone();
            let context = TenantContext {
                tenant: &connection.tenant,
                http: &connection.http,
                cancel: &cancel,
            };
            let defender = opentide_connectors::defender::Defender::new();
            let session = match platform {
                "defender_for_endpoint" => {
                    self.block(async {
                        defender
                            .token(context)
                            .await
                            .map_err(|error| error.into_connector(&batch.tenant.name))
                    })
                    .map_err(|error| raised(&error, "TenantConnectionError"))?;
                    None
                }
                "crowdstrike" => Some(
                    self.block(opentide_connectors::crowdstrike::Session::connect(context))
                        .map_err(|error| raised(&error, "TenantConnectionError"))?,
                ),
                _ => None,
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
                self.close(log, result, outcome)?;
            }
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
        session: Option<&opentide_connectors::crowdstrike::Session<'_>>,
        rule: &opentide_compile::Rule,
        action: &Planned,
        result: &mut RuleResult,
    ) -> Result<(), Raised> {
        use opentide_connectors::defender::DefenderError;
        use opentide_connectors::sentinel_one::{SentinelOne, SentinelOneError};
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(
                "TideRuleDataModelErrors",
                format!("Rule {} ({}): {error}", rule.uuid, rule.name),
            )
        };
        let body = match platform {
            "defender_for_endpoint" => opentide_compile::defender::body(self.compile, rule, tenant),
            "sentinel_one" => opentide_compile::sentinel_one::body(self.compile, rule, table),
            _ => opentide_compile::crowdstrike::body(self.compile, rule, table),
        }
        .map_err(compile_error)?;
        let kind = |action: &Planned| match action {
            Planned::Create => "DetectionRuleCreationFailed",
            Planned::Update(_) => "DetectionRuleUpdateFailed",
            Planned::Delete(_) => "DetectionRuleDeletionFailed",
        };
        match platform {
            "defender_for_endpoint" => {
                let logger = "opentide.platforms.defender_for_endpoint.client";
                let advice = opentide_connectors::python::python_str(&body);
                let refused = |error: DefenderError, action: &Planned| match error {
                    DefenderError::Refused { message, context } => {
                        let context = context.unwrap_or_default();
                        match action {
                            Planned::Create => tracing::error!(
                                detail = message.as_str(),
                                context = context.as_str(),
                                critical = true,
                                logger,
                                "fatal_error"
                            ),
                            Planned::Update(_) => tracing::error!(
                                detail = message.as_str(),
                                context = context.as_str(),
                                advice = advice.as_str(),
                                critical = true,
                                logger,
                                "fatal_error"
                            ),
                            Planned::Delete(_) => tracing::error!(
                                detail = message.as_str(),
                                context_1 = "Double check scope permissions, and whether the ID actually exists",
                                critical = true,
                                logger,
                                "fatal_error"
                            ),
                        }
                        Raised::new(kind(action), "")
                    }
                    other => raised(&other.into_connector(tenant), "TenantConnectionError"),
                };
                match action {
                    Planned::Delete(id) => {
                        self.block(async { Ok(defender.delete_rule(context, id).await) })
                            .map_err(|error| raised(&error, "ConnectionError"))?
                            .map_err(|error| refused(error, action))?;
                        self.record_deleted(result, platform, tenant);
                    }
                    Planned::Update(id) => {
                        self.block(async { Ok(defender.update_rule(context, &body, id).await) })
                            .map_err(|error| raised(&error, "ConnectionError"))?
                            .map_err(|error| refused(error, action))?;
                    }
                    Planned::Create => {
                        let created = self
                            .block(async { Ok(defender.create_rule(context, &body).await) })
                            .map_err(|error| raised(&error, "ConnectionError"))?
                            .map_err(|error| refused(error, action))?;
                        if created.partial {
                            self.warned = true;
                            tracing::warn!(
                                logger = "opentide.platforms.defender_for_endpoint.client",
                                "this_is_a_partial_deployment_check_the_mde_gui_to_see_the_availa"
                            );
                        }
                        self.record_created(result, platform, tenant, &ExternalId::Int(created.id));
                    }
                }
            }
            "sentinel_one" => {
                let logger = "opentide.platforms.sentinel_one.client";
                let refused = |error: SentinelOneError, action: &Planned| {
                    match &error {
                        SentinelOneError::Invalid { detail } => tracing::error!(
                            detail = detail.as_str(),
                            critical = true,
                            logger,
                            "received_code_400_invalid_user_input_received"
                        ),
                        SentinelOneError::Unauthorized { detail } => {
                            tracing::error!(
                                detail = detail.as_str(),
                                advice = "Check your configuration and API permissions again",
                                critical = true,
                                logger,
                                "received_code_401_unauthorized_access"
                            );
                            return Raised::new("TideTenantConfigurationMissingPermissions", "");
                        }
                        SentinelOneError::NotFound { detail } => tracing::error!(
                            detail = detail.as_str(),
                            advice = "Check in the SentinelOne console whether the rule still exists. If not, remove its sentinel_one entry from the rule's deployment state in .opentide/states/deployment/",
                            critical = true,
                            logger,
                            "fatal_error"
                        ),
                        SentinelOneError::Unforeseen { status, context } => tracing::error!(
                            detail = format!("Unforeseen error with code [{status}]").as_str(),
                            context = context.as_str(),
                            critical = true,
                            logger,
                            "fatal_error"
                        ),
                        SentinelOneError::Connector(error) => {
                            return raised(error, "ConnectionError");
                        }
                        SentinelOneError::BadId(text) => {
                            return Raised::new(
                                "ValueError",
                                format!(
                                    "invalid literal for int() with base 10: {}",
                                    opentide_connectors::python::python_string_repr(text)
                                ),
                            );
                        }
                        SentinelOneError::Unreadable { detail } => {
                            return Raised::new("KeyError", detail.clone());
                        }
                    }
                    // A create or an update raises the creation error class.
                    Raised::new(
                        if matches!(action, Planned::Delete(_)) {
                            "DetectionRuleDeletionFailed"
                        } else {
                            "DetectionRuleCreationFailed"
                        },
                        "",
                    )
                };
                match action {
                    Planned::Delete(id) => {
                        let id = opentide_connectors::sentinel_one::rule_id(id)
                            .map_err(|error| refused(error, action))?;
                        self.block(async { Ok(SentinelOne.delete_rule(context, id).await) })
                            .map_err(|error| raised(&error, "ConnectionError"))?
                            .map_err(|error| refused(error, action))?;
                        self.record_deleted(result, platform, tenant);
                    }
                    Planned::Update(id) => {
                        let id = opentide_connectors::sentinel_one::rule_id(id)
                            .map_err(|error| refused(error, action))?;
                        self.block(async {
                            Ok(SentinelOne
                                .create_update_rule(context, &body, Some(id))
                                .await)
                        })
                        .map_err(|error| raised(&error, "ConnectionError"))?
                        .map_err(|error| refused(error, action))?;
                    }
                    Planned::Create => {
                        let id = self
                            .block(async {
                                Ok(SentinelOne.create_update_rule(context, &body, None).await)
                            })
                            .map_err(|error| raised(&error, "ConnectionError"))?
                            .map_err(|error| refused(error, action))?;
                        self.record_created(result, platform, tenant, &ExternalId::Int(id));
                    }
                }
            }
            _ => {
                let Some(session) = session else {
                    return Err(Raised::new(
                        "TenantConnectionError",
                        "Cannot authenticate with the tenant configuration",
                    ));
                };
                let logger = "opentide.platforms.crowdstrike.client";
                let refused = |error: ConnectorError, action: &Planned| match &error {
                    ConnectorError::Refused {
                        message, detail, ..
                    } => {
                        let context = detail
                            .as_deref()
                            .and_then(|text| serde_json::from_str::<CJson>(text).ok())
                            .map(|value| opentide_connectors::python::python_str(&value))
                            .unwrap_or_default();
                        tracing::error!(
                            detail = message.as_str(),
                            context = context.as_str(),
                            critical = true,
                            logger,
                            "fatal_error"
                        );
                        let words = match action {
                            Planned::Create => "Could not create rule",
                            Planned::Update(_) => "Could not update rule",
                            Planned::Delete(_) => "Could not delete rule",
                        };
                        Raised::new(kind(action), words)
                    }
                    other => raised(other, "ConnectionError"),
                };
                match action {
                    Planned::Delete(id) => {
                        self.block(session.delete_detection_rule(id))
                            .map_err(|error| refused(error, action))?;
                        self.record_deleted(result, platform, tenant);
                    }
                    Planned::Update(id) => {
                        let mut list = body.clone();
                        if let CJson::Object(object) = &mut list {
                            object.insert("id".into(), id.clone().into());
                        }
                        let bytes =
                            opentide_connectors::body::python_json(&CJson::Array(vec![list]))
                                .unwrap_or_default();
                        self.block(session.update_detection_rule(id, &bytes))
                            .map_err(|error| refused(error, action))?;
                    }
                    Planned::Create => {
                        let bytes =
                            opentide_connectors::body::python_json(&body).unwrap_or_default();
                        let id = self
                            .block(session.create_detection_rule(&bytes))
                            .map_err(|error| refused(error, action))?;
                        self.record_created(result, platform, tenant, &ExternalId::Text(id));
                    }
                }
            }
        }
        Ok(())
    }

    /// Elastic: each rule deleted, or checked then created or updated; a
    /// tenant that refuses the key stops its batch (`ElasticDeploy`).
    fn elastic(&mut self, batches: &[Batch], log: &mut DeployLog<'_>) -> Result<(), Raised> {
        use opentide_connectors::elastic::{
            Deployed, Elastic, ElasticError, ElasticRule, Strategy,
        };
        let logger = "opentide.platforms.elastic.deployer";
        for batch in batches {
            let tenant = batch.tenant.name.clone();
            let connection = self.connect("elastic", batch)?;
            let setup = opentide_compile::elastic::Setup::from_tenant(&batch.table);
            let suppression_off = matches!(
                opentide_compile::deploy::setup(&batch.table, "suppression"),
                Some(CJson::Bool(false))
            );
            let mut warned_rules: Vec<String> = Vec::new();
            let mut stopped: Option<String> = None;
            for sent in &batch.rules {
                let rule = &sent.rule;
                let mut result = RuleResult::new("elastic", Some(&tenant), &rule.uuid, &rule.name);
                let Some(raw) = rule.block("elastic").filter(|block| block.truthy()) else {
                    result.skip("no Elastic configuration");
                    log.finished(result);
                    continue;
                };
                let status = raw
                    .get("status")
                    .map(opentide_compile::deploy::text)
                    .unwrap_or_default();
                let strategy = match self.compile.statuses.strategy(&status) {
                    Ok(strategy) => strategy,
                    Err(error) => {
                        result.fail(&format!("ValueError: {}", error.exception_text()));
                        log.finished(result);
                        stopped = Some(error.exception_text());
                        break;
                    }
                };
                if strategy == StatusStrategy::Inert {
                    result.skip(&format!("status {status} is inert"));
                    log.finished(result);
                    continue;
                }
                let block = opentide_compile::preview::config_dump("elastic", raw);
                if strategy != StatusStrategy::Deletion
                    && suppression_off
                    && block
                        .get("suppression")
                        .is_some_and(|value| !value.is_null())
                    && !warned_rules.contains(&rule.uuid)
                {
                    self.warned = true;
                    tracing::warn!(
                        rule = rule.name.as_str(),
                        rule_id = rule.uuid.as_str(),
                        tenant = tenant.as_str(),
                        logger,
                        "suppression_omitted_basic_license"
                    );
                    warned_rules.push(rule.uuid.clone());
                }
                let payload = if strategy == StatusStrategy::Deletion {
                    CJson::Null
                } else {
                    match opentide_compile::elastic::compile(self.compile, rule, &setup) {
                        Ok(payload) => payload,
                        Err(error) => {
                            let text = format!("Rule {} ({}): {error}", rule.uuid, rule.name);
                            result.fail(&format!("TideRuleDataModelErrors: {text}"));
                            log.finished(result);
                            stopped = Some(text);
                            break;
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
                let elastic_rule = ElasticRule {
                    rule_id: rule.uuid.clone(),
                    name: rule.name.clone(),
                    strategy: match strategy {
                        StatusStrategy::Deletion => Strategy::Deletion,
                        StatusStrategy::Disablement => Strategy::Disablement,
                        _ => Strategy::Active,
                    },
                    block,
                    payload,
                };
                let index = setup.index.clone().unwrap_or_default();
                let context = self.context(&connection);
                let outcome = self.block(async {
                    match Elastic.deploy_rule(context, &elastic_rule, &index).await {
                        Ok(outcome) => Ok(Ok(outcome)),
                        Err(ElasticError::Connector(error)) => Err(error),
                        Err(other) => Ok(Err(other)),
                    }
                });
                match outcome {
                    Ok(Ok(outcome)) => {
                        for warning in &outcome.warnings {
                            self.warned = true;
                            tracing::warn!(
                                rule_id = rule.uuid.as_str(),
                                rule = rule.name.as_str(),
                                warning = warning.as_str(),
                                logger,
                                "elasticsearch_check_warning"
                            );
                        }
                        if let Deployed::Failed {
                            event,
                            status,
                            error,
                        } = &outcome.deployed
                        {
                            self.elastic_failure(&mut result, rule, event, *status, error);
                        }
                        log.finished(result);
                    }
                    Ok(Err(other)) => {
                        let text = other.to_string();
                        result.fail(&format!("ElasticTenantError: {text}"));
                        log.finished(result);
                        stopped = Some(text);
                        break;
                    }
                    Err(error) => {
                        let text = error.to_string();
                        result.fail(&raised(&error, "ConnectionError").describe());
                        log.finished(result);
                        stopped = Some(text);
                        break;
                    }
                }
            }
            if let Some(error) = stopped {
                self.failed = true;
                tracing::error!(
                    tenant = tenant.as_str(),
                    error = error.as_str(),
                    critical = true,
                    logger,
                    "elastic_tenant_deployment_failed"
                );
            }
        }
        Ok(())
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
        let logger = "opentide.platforms.elastic.deployer";
        let rule_id = rule.uuid.as_str();
        match (event, status) {
            ("elasticsearch_checks_failed", _) => tracing::error!(
                rule_id,
                rule = rule.name.as_str(),
                error,
                logger,
                "{}",
                event
            ),
            ("refusing_to_modify_prebuilt_rule", _) => {
                tracing::error!(rule_id, name = rule.name.as_str(), logger, "{}", event);
            }
            (_, Some(status)) => {
                tracing::error!(rule_id, status_code = status, error, logger, "{}", event);
            }
            (_, None) => tracing::error!(rule_id, error, logger, "{}", event),
        }
        if event == "recreate_elastic_rule_failed" {
            tracing::error!(rule_id, logger, "elastic_rule_deleted_not_recreated");
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
        use opentide_connectors::sysdig::{Action, RuleDeploy, StateChange, deploy_rule};
        let logger = "opentide.platforms.sysdig.deployer";
        for batch in batches {
            let tenant = batch.tenant.name.clone();
            let planned = self.screen("sysdig", batch, log);
            if planned.is_empty() {
                continue;
            }
            let connection = self.connect("sysdig", batch)?;
            let tenant_policies: Vec<String> =
                match opentide_compile::deploy::setup(&batch.table, "policies") {
                    Some(CJson::Array(items)) => {
                        items.iter().map(opentide_compile::deploy::text).collect()
                    }
                    _ => Vec::new(),
                };
            for (rule, action) in planned {
                let mut result = RuleResult::new("sysdig", Some(&tenant), &rule.uuid, &rule.name);
                let strategy = self.strategy_of(rule, "sysdig");
                let body = strategy.clone().and_then(|_| {
                    opentide_compile::sysdig::compile_body(self.compile, rule, Some(&batch.table))
                        .map_err(|error| {
                            Raised::new(
                                "TideRuleDataModelErrors",
                                format!("Rule {} ({}): {error}", rule.uuid, rule.name),
                            )
                        })
                });
                let (strategy, body) = match (strategy, body) {
                    (Ok(strategy), Ok(body)) => (strategy, body),
                    (Err(raised), _) | (_, Err(raised)) => {
                        self.close(log, result, Err(raised.clone()))?;
                        continue;
                    }
                };
                let name = body
                    .get("name")
                    .and_then(CJson::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let tuning = body
                    .get("details")
                    .and_then(|details| details.get("append"))
                    .is_some_and(CJson::truthy);
                let policies = match rule.block("sysdig").and_then(|block| block.get("policies")) {
                    Some(CJson::Array(items)) => {
                        items.iter().map(opentide_compile::deploy::text).collect()
                    }
                    _ => tenant_policies.clone(),
                };
                let root = self.workspace.root().to_path_buf();
                let recreate_refusal = match opentide_compile::git::state_ignore(&root) {
                    Some(ignore) => Some(StateError {
                        code: "deployment_state_ignored",
                        message: deploy_state::ignored_message(&ignore),
                    }),
                    None => self.unpersisted(&rule.uuid, "sysdig", &tenant),
                };
                let request = RuleDeploy {
                    action: match &action {
                        Planned::Create => Action::Create,
                        Planned::Update(id) => Action::Update(id.clone()),
                        Planned::Delete(id) => Action::Delete(id.clone()),
                    },
                    body: opentide_connectors::body::python_json(&body).unwrap_or_default(),
                    name,
                    tuning,
                    disable: strategy == StatusStrategy::Disablement,
                    policies,
                    recreate_refusal: recreate_refusal
                        .as_ref()
                        .map(|refusal| refusal.message.clone()),
                };
                let context = self.context(&connection);
                match self.block(deploy_rule(context, &request)) {
                    Ok(outcome) => {
                        for warning in &outcome.warnings {
                            self.warned = true;
                            tracing::warn!(
                                uuid = rule.uuid.as_str(),
                                tenant = tenant.as_str(),
                                detail = warning.detail,
                                logger,
                                "{}",
                                warning.event
                            );
                        }
                        match &outcome.state {
                            StateChange::Record(id) => {
                                tracing::info!(
                                    uuid = rule.uuid.as_str(),
                                    rule_id = id.as_str(),
                                    logger,
                                    "sysdig_rule_created"
                                );
                                let external = id
                                    .parse::<i64>()
                                    .map_or_else(|_| ExternalId::Text(id.clone()), ExternalId::Int);
                                self.record_created(&mut result, "sysdig", &tenant, &external);
                            }
                            StateChange::Forget => {
                                self.record_deleted(&mut result, "sysdig", &tenant);
                            }
                            StateChange::Keep => {}
                        }
                        if let Some(failure) = &outcome.failure {
                            match recreate_refusal
                                .as_ref()
                                .filter(|refusal| refusal.message == failure.message)
                            {
                                Some(refusal) => {
                                    self.report_failure(refusal, &rule.uuid, "sysdig", &tenant);
                                    result.fail(&refusal.message);
                                }
                                None => {
                                    match failure.status {
                                        Some(status) => tracing::error!(
                                            uuid = rule.uuid.as_str(),
                                            tenant = tenant.as_str(),
                                            status_code = status,
                                            error = failure.message.as_str(),
                                            logger,
                                            "sysdig_request_failed"
                                        ),
                                        None => tracing::error!(
                                            uuid = rule.uuid.as_str(),
                                            tenant = tenant.as_str(),
                                            status_code = "None",
                                            error = failure.message.as_str(),
                                            logger,
                                            "sysdig_request_failed"
                                        ),
                                    }
                                    self.rule_error(&mut result, &failure.message);
                                }
                            }
                        }
                        log.finished(result);
                    }
                    Err(error) => {
                        let text = error.text();
                        tracing::error!(
                            tenant = tenant.as_str(),
                            error = text.as_str(),
                            critical = true,
                            logger,
                            "sysdig_tenant_deployment_failed"
                        );
                        self.failed = true;
                        result.fail(&text);
                        log.finished(result);
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}

/// The path the rule's state shard is written to, for messages and tests.
pub fn shard_path(workspace: &Path, uuid: &str) -> PathBuf {
    deploy_state::state_dir(workspace).join(format!(
        "{}.json",
        deploy_state::canonical(uuid).unwrap_or_else(|| uuid.to_owned())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_raised_error_reads_as_describe_error() {
        let splunk = Raised::new("HTTPError", "HTTP 400 Bad Request -- bad");
        assert_eq!(splunk.describe(), "HTTP 400: HTTP 400 Bad Request -- bad");
        assert_eq!(splunk.error(), "HTTPError: HTTP 400 Bad Request -- bad");
        let bare = Raised::new("DetectionRuleCreationFailed", "");
        assert_eq!(bare.describe(), "DetectionRuleCreationFailed");
        assert_eq!(bare.error(), "DetectionRuleCreationFailed");
        assert_eq!(
            Raised::new(
                "SentinelApiError",
                "PUT https://x failed with HTTP 409 Conflict: busy"
            )
            .describe(),
            "HTTP 409: PUT https://x failed with HTTP 409 Conflict: busy"
        );
        assert_eq!(
            Raised::new("KeyboardInterrupt", "").describe(),
            "interrupted"
        );
        assert_eq!(
            Raised::new("RuntimeError", "no watchlist").describe(),
            "RuntimeError: no watchlist"
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
