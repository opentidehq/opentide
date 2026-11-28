//! `opentide deploy` without `--dry-run` on the connectors (UC-4.6, #979):
//! the run's plan, each platform's sender (`deploy_send/<platform>.rs`), the
//! vendor ids kept in deployment state, and the log printed as rules finish.
//!
//! The plan is the dry run's (`opentide_compile::plan`): the rules the run
//! reads, their platforms, the tenants each reaches, with the platform's
//! `[[modifiers]]` applied per tenant. Each rule is then sent through its
//! platform's connector, the platforms one after another and up to
//! `TENANTS_AT_ONCE` tenants of a platform at once, and each finished rule
//! prints one line on stderr as it ends (`DeployLog`): the lines of tenants
//! deploying at once may interleave, while the result keeps the plan's order
//! and deployment state is the same as one tenant after another. A platform that
//! raises stops the run: the rules it never reached are not attempted. The
//! ids CrowdStrike, Microsoft Defender, SentinelOne and Sysdig give a
//! rule are kept in deployment state ([`super::deploy_state`]).
//!
//! The run's result is a list of keys in the order the run adds them (the
//! `--json` contract the `deploy` snapshot cases hold), `_`-keys included,
//! read into the envelope by [`super::validate_live::report_of`].

use std::path::{Path, PathBuf};
use std::time::Instant;

use super::interrupt::watched;
use indexmap::IndexMap;
use opentide_compile::Json as CJson;
use opentide_compile::plan::{self, Change, Scope, SelectOptions};
use opentide_compile::strategy::{self, RunStrategies, StatusStrategy};
use opentide_connectors::connector::{DeployError, Deployer, Operation, TenantContext};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::{ConnectorError, Environment, HttpClient, Registry, Tenant};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, Workspace, root};
use tokio_util::sync::CancellationToken;

use super::deploy_retire;
use super::deploy_state::{self, ExternalId, StateError};
use super::query::{Configured, log_unset};
use super::validate_live::{Batch, batches};
use super::{Report, placement};
use crate::env::Env;
use crate::envelope::code;
use crate::json::{Json, Object};
use crate::logging::Sink;
use crate::render::glyphs;
use crate::render::outcome::Console;
use crate::render::progress::{Step, StepStatus};
use crate::render::text::Text;
use anstyle::Style;
use opentide_schema::platforms::{PlatformId, PlatformKey};

mod bitdefender;
mod by_uuid;
mod crowdstrike;
mod datadog;
mod elastic;
mod exabeam;
mod google_secops;
mod graylog;
mod log;
mod plugin;
mod raised;
mod retire;
mod sentinel_one;
mod sysdig;

use log::{DeployLog, LogPlan, RuleResult, bounded, counts_text, outcome_message, run_summary};
use raised::{
    Raised, Stops, Unusable, coded_failure, failures, more_failures, raised, scoped, unset_variable,
};

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
/// `unchanged`: the tenant already held the rule as the run would write it,
/// so nothing was written (#1711).
const DONE: [(&str, &str); 6] = [
    ("create", "created"),
    ("update", "updated"),
    ("upsert", "created or updated"),
    ("disable", "disabled"),
    ("delete", "deleted"),
    ("unchanged", "unchanged"),
];
/// What a sent rule is called by planned action (`_VERBS`).
const VERBS: [(&str, &str); 6] = [
    ("create", "created"),
    ("update", "updated"),
    ("upsert", "deployed"),
    ("disable", "disabled"),
    ("delete", "deleted"),
    ("unchanged", "unchanged"),
];
/// At most this many tenants of a platform deploy at once (#1940); the
/// platforms still deploy one after another. A platform plugin's tenants
/// deploy one at a time.
const TENANTS_AT_ONCE: usize = 4;
/// The action of a rule the tenant already held as the run would write it.
const UNCHANGED: &str = "unchanged";
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
    /// `--prune`: retire the rules whose file is gone (#1713).
    pub prune: bool,
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

/// A run's result, keys in the order `--json` prints them, `_`-keys included.
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

/// The run: the plan and the sends, then the warnings and the blocks
/// a status kept out.
fn run_deploy(args: &Args, cx: &Context<'_>) -> Vec<(String, Json)> {
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = match super::open_for(COMMAND, options) {
        Ok(workspace) => workspace,
        Err(refused) => {
            // A TOML file that does not parse keeps `config_parse`.
            let (code, message, diagnostics) = super::refusal_parts(&refused);
            let mut result = failed(&message);
            result.push(("_failure_code".to_owned(), Json::Str(code)));
            if let Some(diagnostics) = diagnostics {
                result.insert(2, ("diagnostics".to_owned(), diagnostics));
            }
            return result;
        }
    };
    let mut warnings: Vec<String> = Vec::new();
    let mut skipped: Vec<plan::Skipped> = Vec::new();
    let mut promoted = Unpromote::default();
    let mut retirable: Option<Json> = None;
    let mut result = deploy(
        args,
        cx,
        &workspace,
        &mut warnings,
        &mut skipped,
        &mut promoted,
        &mut retirable,
    );
    promoted.finish().apply(&mut result, &mut warnings);
    // What `--prune` would retire, sent nowhere (#1713).
    if let Some(retirable) = retirable {
        result.push(("retirable".into(), retirable));
    }
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
        report_skipped(&mut result, &skipped, &workspace, &args.strategies);
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
    strategies: &[String],
) {
    let (_, in_status) = left_out(skipped);
    let owned = opentide_compile::Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    // The result's `strategies`, else `--strategy`'s: a run that planned
    // nothing for its `--platform` names the platform instead (#1662, D11).
    let mut runs = run_strategies(result);
    if runs.is_empty() {
        runs = strategy::parse_strategies(strategies, &owned.statuses, "--strategy")
            .unwrap_or_default();
    }
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
    // The rows the run skipped (a rule no tenant takes, an `INERT` block),
    // and the rules a status left out that have no such row: a rule is
    // never counted twice.
    let rows = match summary.get("skipped") {
        Some(Json::Int(rows)) => usize::try_from(*rows).unwrap_or(0),
        _ => 0,
    };
    let skipped_rows: std::collections::HashSet<String> =
        match result.iter().find(|(key, _)| key == "results") {
            Some((_, Json::Array(rows))) => rows
                .iter()
                .filter(|row| row.get("status").and_then(Json::as_str) == Some("skipped"))
                .filter_map(|row| row.get("id").and_then(Json::as_str))
                .map(opentide_compile::rule::canonical_uuid)
                .collect(),
            _ => std::collections::HashSet::new(),
        };
    let mut left: Vec<String> = skipped
        .iter()
        .map(|entry| opentide_compile::rule::canonical_uuid(&entry.uuid))
        .filter(|uuid| !skipped_rows.contains(uuid))
        .collect();
    left.sort_unstable();
    left.dedup();
    summary.insert("skipped".into(), Json::from(rows + left.len()));
    set(result, "_summary", Json::Object(summary));
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

/// A skipped deploy, in the same envelope as one that planned rules; a run whose planning refused a rule failed.
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
    let reads_changes = !args.all && args.uuids.is_empty() && args.files.is_empty();
    !args.skip_promotion && super::promotion_preview::applies(runs, reads_changes, env)
}

/// The batch that opens `tenant` (one of `tables`) for its retirements: no
/// rule of its own.
fn tenant_batch(tables: &[CJson], tenant: &str) -> Batch {
    let table = tables
        .iter()
        .find(|table| opentide_compile::deploy::tenant_name(table) == tenant)
        .cloned()
        .unwrap_or(CJson::Null);
    Batch {
        tenant: Configured {
            name: tenant.to_owned(),
            setup: table
                .get("setup")
                .and_then(CJson::as_object)
                .cloned()
                .unwrap_or_default(),
        },
        table,
        rules: Vec::new(),
    }
}

/// Why `--prune` cannot run with these arguments (#1713): only a `RELEASE`
/// run retires rules, and `--uuid` and `--file` name rules whose file is
/// there.
pub fn prune_refusal(
    prune: bool,
    runs: &[StatusStrategy],
    uuids: &[String],
    files: &[String],
) -> Option<&'static str> {
    if !prune {
        None
    } else if !uuids.is_empty() || !files.is_empty() {
        Some(
            "--prune retires the rules whose file is gone; --uuid and --file name rules that \
             exist. Pass one or the other",
        )
    } else if !runs.contains(&StatusStrategy::Release) {
        Some("--prune retires rules, which only a --strategy RELEASE run does")
    } else {
        None
    }
}

/// Which rules the run reads, as [`super::deploy_retire::find`] reads
/// evidence of deleted ones.
fn retire_mode(args: &Args) -> super::deploy_retire::Mode {
    if !args.uuids.is_empty() || !args.files.is_empty() {
        super::deploy_retire::Mode::Selected
    } else if args.all {
        super::deploy_retire::Mode::All
    } else {
        super::deploy_retire::Mode::Changes
    }
}

/// A run that sends: checks the run's options, plans, compiles, sends each
/// rule and builds the result.
#[expect(
    clippy::too_many_lines,
    reason = "the run's steps in order, read top to bottom; split by #1959's split 9"
)]
fn deploy(
    args: &Args,
    cx: &Context<'_>,
    workspace: &Workspace,
    plan_warnings: &mut Vec<String>,
    plan_skipped: &mut Vec<plan::Skipped>,
    promoted: &mut Unpromote,
    retirable: &mut Option<Json>,
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
    if let Some(message) = prune_refusal(args.prune, &runs, &args.uuids, &args.files) {
        return usage(message, code::USAGE_ERROR, Some("--prune"));
    }
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
    let mut scope: Scope = if selecting {
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
            Err(error) if error.exit_code == 2 => {
                return usage(&error.message, "usage_error", None);
            }
            Err(error) => return failed(&error.message),
        }
    };
    // Promotion rewrites the promoted rules' status on disk; the workspace
    // read before it still holds the old status, which routes those rules
    // to no RELEASE tenant and compiles them with the old status.
    if !args.skip_promotion {
        let reads_changes = !args.all && args.uuids.is_empty() && args.files.is_empty();
        plan_warnings.extend(super::promotion_preview::warnings(
            &runs,
            reads_changes,
            cx.env,
            opentide_compile::promotion::Settings::new(&owned.config, &owned.statuses).enabled,
        ));
    }
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
        super::deploy_promote::guard_termination();
        // The files it rewrote, even when a write failed part-way: put
        // back unless a tenant receives their rule (#1653).
        let (rewritten, outcome) = super::deploy_promote::run(&promotion, &cx.lines);
        promoted.files = rewritten;
        if let Err(stop) = outcome {
            return super::deploy_promote::stopped(&stop);
        }
        if debug {
            // Whole-folder promotion: deploy what it promoted besides the
            // files the push changed, never the rest of the folder (#1653).
            for file in &promoted.files {
                if !scope.files.contains(&file.path) {
                    scope.files.push(file.path.clone());
                }
            }
        }
        // Read the files the promotion may have rewritten again (a clone
        // shares every other parse), so the plan and the payloads see the
        // promoted status.
        let changes: Vec<opentide_workspace::Change> = scope
            .files
            .iter()
            .chain(&local)
            .map(opentide_workspace::Change::changed)
            .collect();
        let mut promoted = workspace.clone();
        if let Err(error) = promoted.invalidate(&changes) {
            return failed(&error.to_string());
        }
        reopened = promoted;
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
    // `--platform`: another platform's blocks are not this run's to count
    // as left out (#1662, D11).
    plan_skipped.extend(
        selection
            .skipped
            .iter()
            .filter(|entry| args.platform.as_ref().is_none_or(|p| p == &entry.platform))
            .cloned(),
    );
    // The rules deployed earlier whose file is gone (#1713): warned about,
    // and with `--prune` retired below.
    let found = super::deploy_retire::find(&super::deploy_retire::Search {
        workspace,
        owned: &owned,
        env: cx.env,
        cwd: cx.cwd,
        mode: retire_mode(args),
        platform: args.platform.as_deref(),
        prune: args.prune,
    });
    plan_warnings.extend(found.warnings.iter().cloned());
    *retirable = found.retirable_json().as_ref().map(convert);
    let retiring = !found.retirements.is_empty();
    // The commits changed no rule file: say so, rather than blame a status.
    let unchanged = !selecting && !args.all && scope.files.is_empty() && scope.nested.is_empty();
    let refused = !selection.refused.is_empty();
    let refused_rules = selection.refused.clone();
    let mut deployment = selection.platforms.clone();
    if let Some(platform) = &args.platform {
        match deployment.shift_remove(platform) {
            Some(uuids) => deployment = IndexMap::from([(platform.clone(), uuids)]),
            None if retiring => deployment = IndexMap::new(),
            None => {
                return nothing(
                    if unchanged {
                        opentide_compile::dry_run::NO_RULE_FILE_CHANGED
                    } else {
                        "No rules to deploy for this platform"
                    },
                    refused,
                    ("platform", Json::str(platform)),
                );
            }
        }
    }
    let run_names = names(&runs);
    if deployment.is_empty() && !retiring {
        // A run without --platform: the command writes `emit_warning`'s CI
        // annotation (`no_rules_warning`); with one, the platform's absence
        // returned above.
        return nothing(
            if unchanged {
                opentide_compile::dry_run::NO_RULE_FILE_CHANGED
            } else {
                opentide_compile::dry_run::NO_RULES_MATCHED
            },
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
        .filter(|platform| plan::tenants(config, &PlatformKey::new(platform)).is_empty())
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
    // The rules no tenant of a platform takes: (platform, uuid, reason).
    let mut unrouted: Vec<(String, String, String)> = Vec::new();
    let index = workspace.index();
    for (platform, uuids) in &deployment {
        let tables = plan::tenants(config, &PlatformKey::new(platform));
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
        log_unset(&configured, cx.env, "a deploy");
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
            let routed = plan::rule_tenants(&tenants, &block, rule_strategy, &runs, args.wide);
            if routed.is_empty() {
                unrouted.push((
                    platform.clone(),
                    opentide_compile::rule::canonical_uuid(uuid),
                    plan::unrouted_reason(
                        platform,
                        &tenants,
                        &block,
                        status,
                        rule_strategy,
                        &runs,
                        args.wide,
                    ),
                ));
            }
            for tenant in routed {
                per_tenant
                    .entry(tenant.name.clone())
                    .or_default()
                    .push(opentide_compile::rule::canonical_uuid(uuid));
            }
        }
        targets.insert(platform.clone(), per_tenant);
    }
    let mut changes = plan_changes(workspace, &owned, &deployment, &targets);
    changes.extend(
        found
            .retirements
            .iter()
            .map(super::deploy_retire::Retirement::change),
    );
    // Each platform the run sends to: those it deploys, then those it only
    // retires on.
    let mut order: IndexMap<String, Vec<String>> = deployment.clone();
    for platform in found.platforms() {
        order.entry(platform).or_default();
    }
    let mut reached: Vec<(&str, &str)> = targets
        .iter()
        .flat_map(|(platform, tenants)| {
            tenants
                .keys()
                .map(move |tenant| (platform.as_str(), tenant.as_str()))
        })
        .chain(
            found
                .retirements
                .iter()
                .map(|r| (r.platform.as_str(), r.tenant.as_str())),
        )
        .collect();
    reached.sort_unstable();
    reached.dedup();
    let tenant_count = reached.len();
    let started = Instant::now();
    let separator = format!(" {} ", glyphs::SEPARATOR);
    // The header is bold throughout, its labels bold and dim.
    let bold_dim = Style::new().bold().dimmed();
    let mut header = Text::styled("Deploy plan", &Style::new().bold());
    header.append(&format!("{separator}strategy "), &bold_dim);
    let strategy_names: Vec<&str> = runs.iter().map(|run| run.name()).collect();
    header.append(&strategy_names.join(" "), &Style::new().bold());
    header.append(
        &format!("{separator}{}", plan::scope_text(order.len(), tenant_count)),
        &bold_dim,
    );
    cx.lines.line(&header, false);
    cx.lines.line(
        &Text::styled(&plan::message(&changes), &Style::new().dimmed()),
        false,
    );
    let compile_cx = owned.context(index);
    let log_plan = LogPlan::new(&changes);
    let mut log = DeployLog::new(&cx.lines, &log_plan);
    // A rule no tenant takes was never sent: skipped, with why, never
    // `deployed` (#1653).
    for (platform, uuid, reason) in &unrouted {
        let name = index
            .get("rule", uuid)
            .and_then(|object| object.root())
            .map(CJson::from_node)
            .and_then(|data| data.get("name").and_then(CJson::as_str).map(str::to_owned))
            .unwrap_or_else(|| uuid.clone());
        log.unrouted(platform, uuid, &name, reason);
    }
    let sentinel_warned = std::sync::Mutex::new(std::collections::HashSet::new());
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
        sentinel_warned: &sentinel_warned,
        environment: Environment::from_pairs(cx.env.iter()),
        cancel: CancellationToken::new(),
        runtime: opentide_connectors::runtime::shared(),
    };
    let total = order.len();
    let mut deployed: Vec<String> = Vec::new();
    let mut failure: Option<(String, Raised)> = None;
    let mut completed = 0;
    let mut steps: Vec<Step> = Vec::new();
    for (system, uuids) in &order {
        let mut step = Step::new(system);
        step.unit = "rule".into();
        let retirements: Vec<&super::deploy_retire::Retirement> = found.on(system).collect();
        step.count = Some(uuids.len() + retirements.len());
        let step_started = Instant::now();
        let failed_before = sender.failed;
        let mut sent = false;
        let deployed_here = if uuids.is_empty() {
            Ok(())
        } else {
            sender.platform(system, uuids, &mut log)
        };
        // The rules whose file is gone, once the platform's own are sent.
        let deployed_here = match deployed_here {
            Ok(()) if !retirements.is_empty() && !sender.interrupted() => {
                sender.retire(system, &retirements, &mut log)
            }
            other => other,
        };
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
        // What reached a tenant stays promoted, whatever ends the run next.
        promoted.received(&log.results);
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
        if sent && !unusable && !planned_on.is_empty() {
            deployed.push(system.clone());
        }
    }
    if let Some((system, _)) = &failure {
        let after = order
            .keys()
            .position(|name| name == system)
            .map_or(order.len(), |at| at + 1);
        for rest in order.keys().skip(after) {
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
    let platforms = order.len();
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
        // The run's error names its first failure, and how many more there
        // were.
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

/// The files a status promotion rewrote: put back as they were before the
/// result is built ([`Unpromote::finish`]) unless a tenant received their
/// rule, so the write-back commits no status that was never deployed
/// (#1653). A file is kept promoted when any platform block of its rule
/// reached any tenant. Dropping the guard puts back what `finish` did not
/// (a panic); a forced exit puts back what is still pending
/// ([`super::deploy_promote::restore_pending`]).
#[derive(Default)]
struct Unpromote {
    files: Vec<super::deploy_promote::Promoted>,
    /// The canonical UUIDs of the rules a tenant received.
    sent: std::collections::HashSet<String>,
}

/// What putting the promoted files back did: warnings for the files left
/// as they were, failures for the files that could not be written.
#[derive(Debug, Default)]
struct Settled {
    warnings: Vec<String>,
    failures: Vec<(String, String)>,
}

impl Unpromote {
    /// The rules of `results` a tenant received (`deployed`): their files
    /// are kept promoted, and a forced exit no longer puts them back.
    fn received(&mut self, results: &[RuleResult]) {
        self.sent.extend(
            results
                .iter()
                .filter(|result| reached(result))
                .map(|result| opentide_compile::rule::canonical_uuid(&result.id)),
        );
        let kept: Vec<_> = self
            .files
            .iter()
            .filter(|file| self.keeps(file))
            .cloned()
            .collect();
        super::deploy_promote::settle(&kept);
    }

    fn keeps(&self, file: &super::deploy_promote::Promoted) -> bool {
        file.uuid
            .as_ref()
            .is_some_and(|uuid| self.sent.contains(uuid))
    }

    /// Puts back every file no tenant received the rule of, once, holding
    /// the pending files' lock: a signal meanwhile waits for it, then finds
    /// nothing left to put back.
    fn finish(&mut self) -> Settled {
        use super::deploy_promote::Restored;
        let files = std::mem::take(&mut self.files);
        let mut settled = Settled::default();
        // Restored under the pending lock, logged once it is released: a
        // log line may wait for stderr, which a signal's thread can hold
        // while it waits for the pending files.
        let mut undone = Vec::new();
        let mut held = super::deploy_promote::pending();
        for file in files.iter().filter(|file| !self.keeps(file)) {
            let path = file.path.display().to_string();
            match file.restore() {
                Ok(Restored::Done) => undone.push(path),
                Ok(Restored::Missing) => settled.warnings.push(format!(
                    "{path} was deleted during the deploy, so its status promotion was not undone"
                )),
                // The write-back would commit the edit, and with it a
                // status no tenant received.
                Ok(Restored::Edited) => settled.failures.push((
                    path,
                    "the file changed during the deploy, so it was left as it is; set its \
                     status back before committing"
                        .to_owned(),
                )),
                Err(error) => settled.failures.push((path, error)),
            }
        }
        held.retain(|pending| !files.iter().any(|file| file.path == pending.path));
        drop(held);
        for path in undone {
            tracing::info!(
                path = path.as_str(),
                detail = "no tenant received the rule, so its status stays as it was",
                "rule_promotion_undone"
            );
        }
        for (path, error) in &settled.failures {
            tracing::error!(
                path = path.as_str(),
                detail = error.as_str(),
                critical = true,
                "rule_promotion_undo_failed"
            );
        }
        settled
    }
}

/// A result a tenant received: `deployed`, on a tenant.
fn reached(result: &RuleResult) -> bool {
    result.status == "deployed" && result.tenant.is_some()
}

impl Settled {
    /// The run's result with the files left as they were among its
    /// warnings, and a file that could not be put back as a failure: the
    /// run fails (exit 1), since a commit would carry a status no tenant
    /// received.
    fn apply(self, result: &mut Vec<(String, Json)>, warnings: &mut Vec<String>) {
        warnings.extend(self.warnings);
        if self.failures.is_empty() {
            return;
        }
        let lines: Vec<String> = self
            .failures
            .iter()
            .map(|(path, error)| {
                format!(
                    "Could not undo the status promotion of {path}, which no tenant received: \
                     {error}"
                )
            })
            .collect();
        let entries = self.failures.iter().zip(&lines).map(|((path, _), line)| {
            Json::object([("path", Json::str(path)), ("error", Json::str(line))])
        });
        let mut all = match result.iter().find(|(key, _)| key == "failures") {
            Some((_, Json::Array(own))) => own.clone(),
            _ => Vec::new(),
        };
        all.extend(entries);
        set(result, "failures", Json::Array(all));
        if text_of(result, "status").as_deref() != Some("failed") {
            set(result, "status", Json::str("failed"));
            set(result, "message", Json::str(&lines[0]));
            set(result, "error", Json::str(&lines[0]));
        }
        set(result, "_exit_code", Json::Int(1));
    }
}

impl Drop for Unpromote {
    fn drop(&mut self) {
        let settled = self.finish();
        for warning in settled.warnings {
            tracing::warn!(detail = warning.as_str(), "rule_promotion_not_undone");
        }
    }
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
        // A platform whose tenants were resolved plans what they take: a
        // rule none takes is reported skipped, never sent (#1653).
        let pairs: Vec<(Option<String>, String)> = match targets.get(platform) {
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
                retired: false,
            });
        }
    }
    changes
}

// ---------------------------------------------------------------- sending

/// The tenant's table with each `setup` string that names a variable
/// (`$NAME`, `${NAME}`) replaced by what the variable holds, for the compile
/// crates, which are I/O-free and read the raw table: without this a
/// CrowdStrike `customer_id` or a SentinelOne `site_id` written as `$NAME`
/// went into the body as the text `$NAME` (#1721).
///
/// The values come from the connection's [`Tenant`], resolved the way the
/// connectors resolve them. A reference whose variable is unset is the
/// [`ConnectorError::MissingCredential`] that names the variable (never a
/// value, never the literal); the caller fails the rule with it. The copy
/// holds secrets: it goes to the compile and nowhere else, and everything
/// the compile writes into a body is redacted from the log like the rest of
/// the tenant's values.
fn resolved_table(table: &CJson, tenant: &Tenant) -> Result<CJson, ConnectorError> {
    let mut resolved = table.clone();
    let Some(setup) = resolved.get_mut("setup").and_then(CJson::as_object_mut) else {
        return Ok(resolved);
    };
    let keys: Vec<String> = setup
        .iter()
        .filter(|(_, value)| matches!(value, CJson::Str(text) if text.starts_with('$')))
        .map(|(key, _)| key.clone())
        .collect();
    for key in keys {
        // `ssl` is read by the connection, not here: it holds no entry.
        if tenant.setup.contains_key(&key) {
            let value = tenant.secret(&key)?.expose().to_owned();
            setup.insert(key, CJson::Str(value));
        }
    }
    Ok(resolved)
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
    reason = "whether a rule failed or warned, and the run's options: independent flags"
)]
struct Sender<'s, 'c> {
    cx: &'s Context<'c>,
    workspace: &'s Workspace,
    compile: &'s opentide_compile::Context<'s>,
    runs: &'s [StatusStrategy],
    wide: bool,
    persist: bool,
    /// Whether a rule or tenant failed: the run's status is `failed` and it
    /// exits 1.
    failed: bool,
    /// The tenants and platforms that could not deploy, in order: each
    /// failed rule is in the log's results.
    failures: Vec<Unusable>,
    /// Every tenant that stopped before its last rule (platform, tenant).
    stopped_tenants: Vec<(String, String)>,
    /// Whether a rule reported a deployment warning: the result carries
    /// `warnings`.
    warned: bool,
    /// The Sentinel and Microsoft Defender rules whose technique warnings
    /// were logged, shared by every tenant's sender ([`Sender::fork`]).
    sentinel_warned: &'s std::sync::Mutex<std::collections::HashSet<String>>,
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
    /// The requests sent to the tenant once it was opened (its sign-in).
    opened_sent: std::cell::Cell<usize>,
    /// The writes the tenant may have taken once it was opened: while none
    /// more is taken, the tenant has taken no rule.
    opened_taken: std::cell::Cell<usize>,
    /// The requests sent to the tenant when its current rule began.
    rule_sent: std::cell::Cell<usize>,
    /// Whether a request may have left for the tenant outside `http`,
    /// which counts none of them: a platform plugin sends its own, from
    /// Python. Once one may have, the tenant may have taken a rule.
    sent_elsewhere: std::cell::Cell<bool>,
}

impl Connection {
    fn new(tenant: Tenant, http: HttpClient) -> Self {
        Self {
            tenant,
            http,
            opened_sent: std::cell::Cell::new(0),
            opened_taken: std::cell::Cell::new(0),
            rule_sent: std::cell::Cell::new(0),
            sent_elsewhere: std::cell::Cell::new(false),
        }
    }

    /// The tenant is open: what it accepts from now on is a rule's.
    fn mark_opened(&self) {
        self.opened_sent.set(self.http.requests_sent());
        self.opened_taken.set(self.http.writes_taken());
        self.rule_sent.set(self.http.requests_sent());
    }

    /// A rule of the tenant begins: what was sent before is earlier rules'.
    fn rule_begins(&self) {
        self.rule_sent.set(self.http.requests_sent());
    }

    /// A request may leave for the tenant without `http` counting it (a
    /// plugin's call): from now on, the tenant may have taken a write.
    fn sends_elsewhere(&self) {
        self.sent_elsewhere.set(true);
    }
}

impl Sender<'_, '_> {
    /// A sender for one tenant's deploy: the run's options, its
    /// cancellation and its once-per-rule warnings, but an outcome of its
    /// own, which [`absorb`](Self::absorb) adds to the run's.
    fn fork(&self) -> Self {
        Self {
            cx: self.cx,
            workspace: self.workspace,
            compile: self.compile,
            runs: self.runs,
            wide: self.wide,
            persist: self.persist,
            failed: false,
            failures: Vec::new(),
            stopped_tenants: Vec::new(),
            warned: false,
            sentinel_warned: self.sentinel_warned,
            environment: self.environment.clone(),
            cancel: self.cancel.clone(),
            runtime: self.runtime.clone(),
        }
    }

    /// Adds the outcome of a tenant's sender ([`fork`](Self::fork)) after
    /// the run's.
    fn absorb(&mut self, tenant: Self) {
        self.failed |= tenant.failed;
        self.warned |= tenant.warned;
        self.failures.extend(tenant.failures);
        self.stopped_tenants.extend(tenant.stopped_tenants);
    }

    /// Whether the technique warnings of `key` (a rule, on a platform) are
    /// to be logged: the first time only, whichever tenant asks.
    fn warn_once(&self, key: String) -> bool {
        self.sentinel_warned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key)
    }

    /// Each tenant's deploy, `unit`, at most `at_once` tenants at a time
    /// (#1940): each on its own sender and log ([`fork`](Self::fork),
    /// [`DeployLog::fork`]), on a thread of its own when several run, whose
    /// results and outcome are added to the run's in the order of `batches`
    /// once every tenant ended, whatever order they ended in. Only the lines
    /// each prints as its rules end may interleave. A tenant that stops the
    /// run (an interrupt) starts no tenant after it; the first stop in the
    /// order of `batches` is returned.
    fn tenants<'b, 'l>(
        &mut self,
        at_once: usize,
        batches: &'b [Batch],
        log: &mut DeployLog<'l>,
        unit: impl Fn(&mut Self, &'b Batch, &mut DeployLog<'l>) -> Result<(), Raised> + Sync,
    ) -> Result<(), Raised> {
        let at_once = if crate::threads::AVAILABLE {
            at_once.min(batches.len())
        } else {
            1
        };
        if at_once <= 1 {
            for batch in batches {
                let mut sender = self.fork();
                let mut tenant_log = log.fork();
                let outcome = unit(&mut sender, batch, &mut tenant_log);
                self.absorb(sender);
                log.merge(tenant_log);
                outcome?;
            }
            return Ok(());
        }
        // Each row says its tenant: its header again whenever the row
        // before it was another tenant's.
        log.interleave();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let stopped = std::sync::atomic::AtomicBool::new(false);
        type Ended<'s, 'c, 'l> = (Sender<'s, 'c>, DeployLog<'l>, Result<(), Raised>);
        let ended: Vec<std::sync::Mutex<Option<Ended<'_, '_, 'l>>>> = batches
            .iter()
            .map(|_| std::sync::Mutex::new(None))
            .collect();
        // The run's log lines go where the calling thread's go.
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let panicked = {
            let (run, run_log, unit) = (&*self, &*log, &unit);
            let (next, stopped, ended, dispatch) = (&next, &stopped, &ended, &dispatch);
            std::thread::scope(|scope| {
                let workers: Vec<_> = (0..at_once)
                    .map(|_| {
                        scope.spawn(move || {
                            tracing::dispatcher::with_default(dispatch, || {
                                use std::sync::atomic::Ordering;
                                // The next tenant in plan order, until none
                                // is left or one stopped the run.
                                while !stopped.load(Ordering::SeqCst) {
                                    let at = next.fetch_add(1, Ordering::SeqCst);
                                    let (Some(batch), Some(slot)) =
                                        (batches.get(at), ended.get(at))
                                    else {
                                        break;
                                    };
                                    let mut sender = run.fork();
                                    let mut tenant_log = run_log.fork();
                                    // A panic stops the run as it did one
                                    // tenant after another: no tenant starts
                                    // after it, and it is raised again on
                                    // the calling thread with its trace.
                                    let outcome = match crate::app::catch_panic(|| {
                                        unit(&mut sender, batch, &mut tenant_log)
                                    }) {
                                        Ok(outcome) => outcome,
                                        Err(caught) => {
                                            stopped.store(true, Ordering::SeqCst);
                                            return Some(caught);
                                        }
                                    };
                                    if let Err(raised) = &outcome {
                                        // Only an interrupt leaves a unit:
                                        // the tenants in flight go on.
                                        debug_assert_eq!(raised.stops, Stops::Run, "{raised:?}");
                                        stopped.store(true, Ordering::SeqCst);
                                    }
                                    *slot
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                        Some((sender, tenant_log, outcome));
                                }
                                None
                            })
                        })
                    })
                    .collect();
                let mut panicked = None;
                for worker in workers {
                    let caught = worker.join().unwrap_or_else(|payload| {
                        Some(crate::app::CaughtPanic::from_payload(payload))
                    });
                    if let Some(caught) = caught {
                        panicked.get_or_insert(caught);
                    }
                }
                panicked
            })
        };
        if let Some(caught) = panicked {
            caught.resume();
        }
        let mut stop = Ok(());
        for slot in ended {
            let Some((sender, tenant_log, outcome)) = slot
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            else {
                continue;
            };
            self.absorb(sender);
            log.merge(tenant_log);
            if stop.is_ok() {
                stop = outcome;
            }
        }
        stop
    }
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
        let settings = opentide_connectors::deploy_http_settings(platform);
        let tenant = Tenant::from_setup(
            platform,
            &batch.tenant.name,
            &batch.tenant.setup,
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
        Ok(Connection::new(tenant, http))
    }

    /// The tenants' batches of *uuids* (`TideDeployment`).
    fn batches(&self, platform: &str, uuids: &[String]) -> Result<Vec<Batch>, Raised> {
        let tables = plan::tenants(&self.compile.config.clone(), &PlatformKey::new(platform))
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
            Some(PlatformId::Datadog) => self.datadog(&batches, log),
            Some(PlatformId::GoogleSecops) => self.google_secops(&batches, log),
            Some(PlatformId::Graylog) => self.graylog(&batches, log),
            Some(PlatformId::SentinelOne | PlatformId::Crowdstrike) => {
                self.with_state(platform, &batches, log)
            }
            Some(
                PlatformId::Sentinel
                | PlatformId::MicrosoftDefender
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
            self.unused(platform, tenant, log, &error);
        }
        Ok(())
    }

    /// A tenant that failed before any rule was sent to it: the run fails,
    /// and every rule of the tenant is `not attempted`, the one it failed
    /// on included (#1701).
    fn unused(&mut self, platform: &str, tenant: &str, log: &mut DeployLog<'_>, error: &str) {
        self.unusable(platform, Some(tenant), error);
        log.unreached_on(
            platform,
            tenant,
            "not_attempted",
            &format!("not attempted: tenant {tenant} failed"),
        );
    }

    /// Whether a failure of the tenant on a rule came before the tenant took
    /// anything, so before any rule was sent (#1701): no write the rule's
    /// requests made may have been taken (none left, or the tenant refused
    /// it, [`HttpClient::writes_taken`]), no earlier rule of the tenant sent
    /// a request since it was opened, and none was deployed. Its connection
    /// or its credentials, resolved on that first rule's first requests,
    /// failed: the platforms with no sign-in of their own reach the tenant
    /// first with a rule's own request. A write that left and may have
    /// landed (no answer, a dropped connection, a 5xx) keeps the rule
    /// `failed`. A platform plugin's requests are not counted, so once the
    /// plugin was called for a rule its tenant may have taken it: only its
    /// `open` can fail before any rule.
    fn before_any_rule(
        &self,
        connection: &Connection,
        platform: &str,
        tenant: &str,
        log: &DeployLog<'_>,
    ) -> bool {
        !self.interrupted()
            && !connection.sent_elsewhere.get()
            && connection.http.writes_taken() == connection.opened_taken.get()
            && connection.rule_sent.get() == connection.opened_sent.get()
            && !log.deployed_on(platform, tenant)
    }

    /// [`before_any_rule`](Self::before_any_rule) for a raised failure that
    /// stops the tenant: when it came before any rule, the tenant is
    /// reported as one that could not be used, and `true` is returned.
    fn raised_before_any_rule(
        &mut self,
        connection: &Connection,
        platform: &str,
        tenant: &str,
        log: &mut DeployLog<'_>,
        outcome: &Result<(), Raised>,
    ) -> bool {
        let Err(raised) = outcome else {
            return false;
        };
        if raised.stops != Stops::Tenant || !self.before_any_rule(connection, platform, tenant, log)
        {
            return false;
        }
        let error = raised.error();
        tracing::error!(
            platform,
            tenant,
            error = error.as_str(),
            critical = true,
            "tenant_deployment_failed"
        );
        self.unused(platform, tenant, log, &error);
        true
    }

    /// A deploy the tenant failed on: the rule fails with the connector's
    /// text, an interrupt stops the run, and otherwise the tenant's other
    /// rules are not attempted. A failure before the tenant took anything
    /// ([`Sender::before_any_rule`]) leaves the rule `not attempted` too.
    #[expect(
        clippy::too_many_arguments,
        reason = "one rule's failure on its tenant, the connection telling whether it took anything"
    )]
    fn tenant_deploy_failed(
        &mut self,
        connection: &Connection,
        platform: &str,
        event: &str,
        tenant: &str,
        error: DeployError,
        mut result: RuleResult,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let before_any = self.before_any_rule(connection, platform, tenant, log);
        let text = error.into_connector().text();
        tracing::error!(tenant, error = text.as_str(), critical = true, "{event}");
        if before_any {
            // The key or the connection failed on the tenant's first
            // request: no rule was sent (#1701).
            self.unused(platform, tenant, log, &text);
            return Ok(());
        }
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

    /// The tenant's connection, opened by *deployer* before its first rule
    /// ([`Deployer::open`]: its credentials resolved, its sign-in made), or
    /// `None` when either fails: the tenant failed before any rule was
    /// sent, each of its rules `not attempted`, and the run goes on.
    fn open_or_fail(
        &mut self,
        platform: &str,
        batch: &Batch,
        log: &mut DeployLog<'_>,
        deployer: &dyn Deployer,
    ) -> Result<Option<Connection>, Raised> {
        let Some(connection) = self.connect_or_fail(platform, batch, log)? else {
            return Ok(None);
        };
        let opened = self
            .block(async { Ok(deployer.open(self.context(&connection)).await) })
            .map_err(DeployError::from)
            .and_then(|opened| opened);
        if let Err(failed) = opened {
            let raised = scoped(failed, |error| raised(&error));
            // An interrupt stops the run; anything else, the tenant.
            let stops = if raised.stops == Stops::Run {
                Stops::Run
            } else {
                Stops::Tenant
            };
            self.tenant_failed(
                platform,
                &batch.tenant.name,
                log,
                raised.stopping(stops),
                false,
            )?;
            return Ok(None);
        }
        connection.mark_opened();
        Ok(Some(connection))
    }

    /// `_deployment_error`: the run fails, the rule says why.
    fn rule_error(&mut self, result: &mut RuleResult, message: &str) {
        self.failed = true;
        result.fail(message);
    }

    fn strategy_of(
        &self,
        rule: &opentide_compile::Rule,
        platform: &str,
    ) -> Result<StatusStrategy, Raised> {
        let status = rule
            .block(platform)
            .and_then(|block| block.get("status"))
            .map(Json::to_text)
            .unwrap_or_default();
        self.compile
            .statuses
            .strategy(&status)
            .map_err(|error| Raised::new(error.to_string()))
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

    /// SentinelOne and CrowdStrike: each rule planned
    /// from deployment state, then created (its id recorded), updated or
    /// deleted (its id forgotten).
    fn with_state(
        &mut self,
        platform: &str,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        self.tenants(TENANTS_AT_ONCE, batches, log, |sender, batch, log| {
            sender.with_state_tenant(platform, batch, log)
        })
    }

    /// One tenant's rules of [`with_state`](Self::with_state).
    fn with_state_tenant(
        &mut self,
        platform: &str,
        batch: &Batch,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let planned = self.screen(platform, batch, log);
        if planned.is_empty() {
            return Ok(());
        }
        let crowdstrike = opentide_connectors::crowdstrike::Crowdstrike::new();
        let opener: &dyn Deployer = match PlatformId::parse(platform) {
            Some(PlatformId::Crowdstrike) => &crowdstrike,
            _ => &opentide_connectors::sentinel_one::SentinelOne,
        };
        let Some(connection) = self.open_or_fail(platform, batch, log, opener)? else {
            return Ok(());
        };
        let cancel = self.cancel.clone();
        let context = TenantContext {
            tenant: &connection.tenant,
            http: &connection.http,
            cancel: &cancel,
        };
        let session = match PlatformId::parse(platform) {
            // A platform of the tenant's own, signed in once before any
            // rule: its Deployer sends every rule on that token.
            Some(PlatformId::Crowdstrike) => self
                .block(crowdstrike.sign_in(context))
                .map(|()| Some(&crowdstrike)),
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
                return Ok(());
            }
        };
        connection.mark_opened();
        for (rule, action) in planned {
            let tenant = batch.tenant.name.as_str();
            let mut result = RuleResult::new(platform, Some(tenant), &rule.uuid, &rule.name);
            connection.rule_begins();
            let outcome = self.state_rule(
                platform,
                &batch.table,
                tenant,
                context,
                session,
                rule,
                &action,
                &mut result,
            );
            if self.raised_before_any_rule(&connection, platform, tenant, log, &outcome) {
                break;
            }
            if let Err(raised) = self.close(log, result, outcome) {
                self.tenant_failed(platform, tenant, log, raised, true)?;
                break;
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
        session: Option<&opentide_connectors::crowdstrike::Crowdstrike>,
        rule: &opentide_compile::Rule,
        action: &Planned,
        result: &mut RuleResult,
    ) -> Result<(), Raised> {
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        let body = match PlatformId::parse(platform) {
            Some(PlatformId::SentinelOne) => {
                let table =
                    resolved_table(table, context.tenant).map_err(|e| unset_variable(&e))?;
                opentide_compile::sentinel_one::body(self.compile, rule, &table)
            }
            _ => {
                let table =
                    resolved_table(table, context.tenant).map_err(|e| unset_variable(&e))?;
                opentide_compile::crowdstrike::body(self.compile, rule, &table)
            }
        }
        .map_err(compile_error)?;
        let (remote_id, name) = match PlatformId::parse(platform) {
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
            // CrowdStrike's ids are text; SentinelOne's numbers.
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

#[cfg(test)]
mod tests {
    use super::log::{header_line, result_line, verb};
    use super::plugin::plugin_raised;
    use super::*;
    use opentide_connectors::connector::{DeployFailure, DeployScope};

    /// Every `action` a deploy result row can carry (`DONE` and `VERBS` name
    /// them all; a row's action is a plan's action or `unchanged`) is in the
    /// `RuleOutcome.action` enum that `opentide --json commands` publishes
    /// for `deploy`, so a consumer validating `deploy --json` against it
    /// accepts every row (#1711).
    #[test]
    fn every_action_a_result_row_can_carry_is_in_the_published_schema() {
        let defs = crate::schemas::Schemas::load().defs();
        let allowed: Vec<&str> = defs
            .get("RuleOutcome")
            .and_then(|outcome| outcome.get("properties"))
            .and_then(|properties| properties.get("action"))
            .and_then(|action| action.get("anyOf"))
            .and_then(Json::as_array)
            .and_then(|variants| variants.iter().find_map(|variant| variant.get("enum")))
            .and_then(Json::as_array)
            .expect("RuleOutcome.action is an enum")
            .iter()
            .filter_map(Json::as_str)
            .collect();
        let emitted = DONE
            .iter()
            .map(|(action, _)| *action)
            .chain(VERBS.iter().map(|(action, _)| *action))
            .chain([UNCHANGED]);
        for action in emitted {
            assert!(
                allowed.contains(&action),
                "a deploy row's action `{action}` is not in RuleOutcome.action ({allowed:?}) in data/output-schemas.json"
            );
        }
    }

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
                "unchanged",
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
